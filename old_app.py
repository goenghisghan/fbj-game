import os, requests, json, time
import psycopg2, psycopg2.extras
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'devsecret')

app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,
)

DATABASE_URL = os.environ.get("DATABASE_URL")  # Supabase Postgres connection string

# ----------------- GIST HANDLING -----------------
_fpl_cache = None
_fpl_cache_time = 0
CACHE_TTL = 300  # 5 minutes

def load_fpl_from_gist():
    global _fpl_cache, _fpl_cache_time
    now = time.time()

    if _fpl_cache and (now - _fpl_cache_time < CACHE_TTL):
        return _fpl_cache

    gist_id = os.getenv("GIST_ID")
    github_token = os.getenv("GITHUB_TOKEN")
    if not gist_id or not github_token:
        raise RuntimeError("⚠️ Missing GIST_ID or GITHUB_TOKEN in environment")

    url = f"https://api.github.com/gists/{gist_id}"
    headers = {"Authorization": f"Bearer {github_token}"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    gist_data = r.json()

    file_info = gist_data["files"]["fpl_stats.json"]
    if file_info.get("truncated"):
        rr = requests.get(file_info["raw_url"], headers=headers, timeout=60)
        rr.raise_for_status()
        data = rr.json()
    else:
        data = json.loads(file_info["content"])

    _fpl_cache = data
    _fpl_cache_time = now
    return data

# ----------------- DB HANDLING -----------------
def db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def init_db():
    conn = db(); cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS picks (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            gameweek_id INTEGER NOT NULL,
            position TEXT NOT NULL,
            player_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, gameweek_id, position)
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            gameweek_id INTEGER NOT NULL,
            gw_points INTEGER NOT NULL,
            league_points INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, gameweek_id)
        );
    """)
    conn.commit(); conn.close()

init_db()

# ----------------- FPL HELPERS -----------------
def bootstrap():
    data = load_fpl_from_gist()
    bootstrap_data = data.get("bootstrap", {})
    teams = {t['id']: t for t in bootstrap_data.get('teams', [])}
    positions = {1:'GK',2:'DEF',3:'MID',4:'FWD'}
    events = bootstrap_data.get('events', [])
    return bootstrap_data, teams, positions, events

def league_points_from_total(total):
    if total == 21: return 10
    if total == 20: return 4
    if total == 19: return 3
    if total == 18: return 2
    if total == 17: return 1
    return 0

def next_opponents_by_team(teams):
    data = load_fpl_from_gist()
    fixtures = data.get("fixtures", [])
    choice = {}
    for f in fixtures:
        if f.get('finished') or f.get('finished_provisional'):
            continue
        h,a = f['team_h'], f['team_a']
        if h not in choice: choice[h] = teams[a]['short_name']+' (H)'
        if a not in choice: choice[a] = teams[h]['short_name']+' (A)'
    return choice

def decorate_players(players,teams,positions,opp_map):
    out=[]
    for p in players:
        d=dict(p)
        d['team_name']=teams[p['team']]['name']
        d['position_name']=positions[p['element_type']]
        d['next_opp']=opp_map.get(p['team'],'-')
        out.append(d)
    return out

def get_user_id(username):
    conn=db(); cur=conn.cursor()
    cur.execute('SELECT id FROM users WHERE username=%s', (username,))
    r=cur.fetchone()
    conn.close()
    return r[0] if r else None

def get_locked_picks(user_id, events):
    now = datetime.now(timezone.utc)
    cur_ev = next((e for e in events if e.get('is_current')), None)
    if not cur_ev: return {}, None
    deadline = datetime.fromisoformat(cur_ev['deadline_time'].replace('Z','+00:00'))
    if now < deadline: return {}, None
    gw_id = cur_ev['id']
    conn=db(); cur=conn.cursor()
    cur.execute(
        'SELECT position, player_id FROM picks WHERE user_id=%s AND gameweek_id=%s',
        (user_id, gw_id)
    )
    rows = cur.fetchall()
    conn.close()
    return ({pos: pid for pos, pid in rows}, gw_id)

def get_pending_picks(user_id, events):
    nxt = next((e for e in events if e.get('is_next')), None)
    if not nxt: nxt = next((e for e in events if not e.get('finished')), None)
    if not nxt: return {}, None
    gw_id = nxt['id']
    conn=db(); cur=conn.cursor()
    cur.execute(
        'SELECT position, player_id FROM picks WHERE user_id=%s AND gameweek_id=%s',
        (user_id, gw_id)
    )
    rows=cur.fetchall()
    conn.close()
    print("Loading pending picks:", user_id, gw_id, rows)
    return ({pos:pid for pos,pid in rows}, gw_id)

def gw_stats_for_player(player_id, gw_round):
    data = load_fpl_from_gist()
    return data.get("stats", {}).get(str(gw_round), {}).get(str(player_id), {})

def all_users():
    conn=db(); cur=conn.cursor()
    cur.execute('SELECT id, username FROM users ORDER BY username ASC')
    rows=cur.fetchall(); conn.close()
    return [{'id':r[0],'username':r[1]} for r in rows]

def gw_stats_for_user(uid, gw_id):
    conn=db(); cur=conn.cursor()
    cur.execute(
        'SELECT position, player_id FROM picks WHERE user_id=%s AND gameweek_id=%s',
        (uid, gw_id)
    )
    rows=cur.fetchall(); conn.close()
    if not rows: return 0
    total=0
    for _, pid in rows:
        hist=gw_stats_for_player(pid, gw_id)
        total += hist.get('total_points',0) if hist else 0
    return total

def get_gw_lineup_for_users(events, data):
    cur_ev = next((e for e in events if e.get('is_current')), None)
    if not cur_ev:
        return [], None
    gw_id = cur_ev['id']

    team_map = {t['id']: t for t in data['teams']}
    player_map = {p['id']: p for p in data['elements']}
    users = all_users()

    results = []
    for u in users:
        uid = u['id']
        conn = db()
        cur = conn.cursor()
        cur.execute(
            'SELECT position, player_id FROM picks WHERE user_id=%s AND gameweek_id=%s',
            (uid, gw_id)
        )
        rows = cur.fetchall()
        conn.close()
        picks = {pos: pid for pos, pid in rows}

        user_total = 0
        lineup = {}
        for pos in ["GK", "DEF", "MID", "FWD"]:
            pid = picks.get(pos)
            if pid and pid in player_map:
                p = player_map[pid]
                photo_id = p.get('photo', '').split('.')[0] if p.get('photo') else "placeholder"
                photo_url = f'https://resources.premierleague.com/premierleague/photos/players/40x40/p{photo_id}.png'
                hist = gw_stats_for_player(pid, gw_id) or {}
                pts = hist.get('total_points', 0)
                user_total += pts
                lineup[pos] = {
                    "name": f"{p.get('first_name','')} {p.get('second_name','')}".strip(),
                    "photo_url": photo_url,
                    "points": pts,
                }
            else:
                lineup[pos] = {
                    "name": None,
                    "photo_url": url_for('static', filename='question.png'),
                    "points": 0,
                }
        results.append({
            "username": u['username'],
            "lineup": lineup,
            "total": user_total
        })
    return results, gw_id

# ----------------- ROUTES -----------------
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password']
        try:
            conn = db(); cur = conn.cursor()
            cur.execute(
                'INSERT INTO users (username, password) VALUES (%s, %s)',
                (u, generate_password_hash(p))
            )
            conn.commit(); conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except psycopg2.Error:
            flash('Username already exists.', 'danger')
    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password']
        conn = db(); cur = conn.cursor()
        cur.execute('SELECT id, username, password FROM users WHERE username=%s', (u,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[2], p):
            session['username'] = user[1]
            return redirect(url_for('welcome'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', title='Login')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('welcome.html', title='Welcome')

@app.route('/my_squad')
def my_squad():
    if 'username' not in session: return redirect(url_for('login'))
    username=session['username']; uid=get_user_id(username)
    data,teams,positions,events=bootstrap()
    locked, gw_id = get_locked_picks(uid, events)
    total_points=0; squad={'GK':None,'DEF':None,'MID':None,'FWD':None}
    if locked and gw_id:
        team_map={t['id']:t for t in data['teams']}
        player_map={p['id']:p for p in data['elements']}
        for pos in squad.keys():
            pid = locked.get(pos)
            if not pid: continue
            p = player_map.get(pid)
            if not p: continue
            photo_id=p.get('photo','').split('.')[0]
            photo_url=f'https://resources.premierleague.com/premierleague/photos/players/110x140/p{photo_id}.png'
            hist=gw_stats_for_player(pid, gw_id)
            gw_pts=hist.get('total_points',0) if hist else 0
            total_points+=gw_pts
            squad[pos]={
                'name':f"{p.get('first_name','')} {p.get('second_name','')}".strip(),
                'team_name':teams[p['team']]['name'],
                'photo_url':photo_url,
                'gw_points':gw_pts,
                'stats': ({
                    'position':positions[p['element_type']],
                    'minutes':hist.get('minutes',0),
                    'saves':hist.get('saves',0),
                    'goals_conceded':hist.get('goals_conceded',0),
                    'assists':hist.get('assists',0),
                    'goals_scored':hist.get('goals_scored',0),
                    'bonus':hist.get('bonus',0),
                    'def_contrib':hist.get('defensive_contribution',0),
                    'yellow_cards':hist.get('yellow_cards',0),
                    'red_cards':hist.get('red_cards',0),
                    'penalties_missed':hist.get('penalties_missed',0),
                    'own_goals':hist.get('own_goals',0),
                } if hist else None)
            }
    league_lineups, gw_id_all = get_gw_lineup_for_users(events, data)
    return render_template(
        'my_squad.html',
        title='GW Lineup',
        username=username,
        total_points=total_points,
        squad=squad,
        league_lineups=league_lineups,
        gw_id_all=gw_id_all
    )

@app.route('/squad')
def squad():
    if 'username' not in session: return redirect(url_for('login'))
    username=session['username']; uid=get_user_id(username)
    club=request.args.get('club'); position=request.args.get('position'); page=int(request.args.get('page',1))
    data,teams,positions,events=bootstrap()
    team_map={t['id']:t for t in data['teams']}
    opp_map=next_opponents_by_team(team_map)
    players=decorate_players(data['elements'],team_map,positions,opp_map)
    players.sort(key=lambda x:x.get('total_points',0), reverse=True)
    if club: players=[p for p in players if p['team_name']==club]
    if position: players=[p for p in players if p['position_name']==position]
    page_size=20; start=(page-1)*page_size; end=start+page_size
    subset=players[start:end]; total_pages=(len(players)+page_size-1)//page_size

    pending, gw_next = get_pending_picks(uid, events)
    selected={'GK':None,'DEF':None,'MID':None,'FWD':None}
    player_map={p['id']:p for p in data['elements']}
    badge_template = load_fpl_from_gist().get("badge_template")
    for pos,pid in pending.items():
        p=player_map.get(pid)
        if not p: continue
        team=team_map[p['team']]
        badge_url=badge_template.format(team['code'])
        selected[pos]={'first_name':p['first_name'],'second_name':p['second_name'],'team_name':team['name'],'kit_url':badge_url}
    selected_clubs=set([selected[pos]['team_name'] for pos in selected if selected[pos]])

    class O(dict): __getattr__=dict.get
    subset=[O(p) for p in subset]
    clubs=sorted({team_map[p['team']]['name'] for p in data['elements']})
    return render_template('squad.html',title='Pick Team',players=subset,selected=selected,selected_clubs=selected_clubs,clubs=clubs,current_page=page,total_pages=total_pages)

@app.route('/pick_player', methods=['POST'])
def pick_player():
    if 'username' not in session: return ('',401)
    data_json = request.get_json(force=True)
    position=data_json['position']; player_id=int(data_json['player_id'])
    username=session['username']; uid=get_user_id(username)
    data,teams,positions,events=bootstrap()
    player=next((p for p in data['elements'] if p['id']==player_id),None)
    if not player: return jsonify({'status':'error'}),400
    pos_name=positions[player['element_type']]
    if pos_name!=position: return jsonify({'status':'error'}),400
    pending, gw_next = get_pending_picks(uid, events)
    team_map={t['id']:t for t in data['teams']}
    chosen_clubs=set()
    for pos,pid in pending.items():
        pp=next((e for e in data['elements'] if e['id']==pid),None)
        if pp: chosen_clubs.add(team_map[pp['team']]['name'])
    if team_map[player['team']]['name'] in chosen_clubs:
        return jsonify({'status':'error','msg':'Club already selected'}),400
    print("Saving pick:", uid, gw_next, position, player_id)
    conn=db(); cur=conn.cursor()
    cur.execute("""
        INSERT INTO picks (user_id, gameweek_id, position, player_id)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (user_id, gameweek_id, position)
        DO UPDATE SET player_id = EXCLUDED.player_id
    """, (uid, gw_next, position, player_id))
    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/remove_player', methods=['POST'])
def remove_player():
    if 'username' not in session: return ('',401)
    position=request.get_json(force=True)['position']
    username=session['username']; uid=get_user_id(username)
    data,teams,positions,events=bootstrap()
    pending, gw_next = get_pending_picks(uid, events)
    conn=db(); cur=conn.cursor()
    cur.execute('DELETE FROM picks WHERE user_id=%s AND gameweek_id=%s AND position=%s', (uid, gw_next, position))
    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/clear_team', methods=['POST'])
def clear_team():
    if 'username' not in session: return ('',401)
    username=session['username']; uid=get_user_id(username)
    data,teams,positions,events=bootstrap()
    pending, gw_next = get_pending_picks(uid, events)
    conn=db(); cur=conn.cursor()
    cur.execute('DELETE FROM picks WHERE user_id=%s AND gameweek_id=%s', (uid, gw_next))
    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/league', methods=['GET'])
def league():
    if 'username' not in session: return redirect(url_for('login'))
    data,teams,positions,events=bootstrap()
    users=all_users()
    conn=db(); cur=conn.cursor()
    cur.execute("""
        SELECT u.username,
               COALESCE(SUM(r.league_points),0) as total_lp,
               CASE WHEN COUNT(r.gw_points)>0
                    THEN AVG(CASE WHEN r.gw_points BETWEEN 0 AND 21 THEN r.gw_points ELSE 0 END)
                    ELSE 0 END as avg_gw
        FROM users u
        LEFT JOIN results r ON r.user_id=u.id
        GROUP BY u.id
        ORDER BY total_lp DESC, avg_gw DESC, u.username ASC
    """)
    league_rows=[{'username':r[0],'total_lp':int(r[1]),'avg_gw':float(r[2])} for r in cur.fetchall()]

    sel_gw=request.args.get('gw',type=int)
    cur_ev = next((e for e in events if e.get('is_current')), None)
    nxt_ev = next((e for e in events if e.get('is_next')), None)
    default_gw = cur_ev['id'] if cur_ev else (nxt_ev['id'] if nxt_ev else 1)
    selected_gw = sel_gw or default_gw

    cur.execute('SELECT user_id, gw_points, league_points FROM results WHERE gameweek_id=%s', (selected_gw,))
    resmap={row[0]:{'gw_points':row[1],'league_points':row[2]} for row in cur.fetchall()}
    history_rows=[]
    for u in users:
        if u['id'] in resmap:
            gwp=resmap[u['id']]['gw_points']; lp=resmap[u['id']]['league_points']
        else:
            gwp=gw_stats_for_user(u['id'], selected_gw); lp=league_points_from_total(gwp)
        display_points = f"{gwp}" if gwp<=21 else f"Bust ({gwp})"
        history_rows.append({'username':u['username'],'gw_points':gwp,'display_points':display_points,'league_points':lp})
    history_rows.sort(key=lambda r:(r['league_points'], r['gw_points']), reverse=True)

    fixtures = load_fpl_from_gist().get("fixtures", [])
    relevant=[f for f in fixtures if f.get('event')==selected_gw]
    can_finalize=bool(relevant) and all(f.get('finished') for f in relevant)

    all_gws=[{'id':e['id']} for e in events]
    return render_template(
        'league.html',
        title='League & History',
        league_rows=league_rows,
        history_rows=history_rows,
        all_gws=all_gws,
        selected_gw=selected_gw,
        can_finalize=can_finalize
    )

@app.route('/finalize_gw', methods=['POST'])
def finalize_gw():
    if 'username' not in session: return redirect(url_for('login'))
    data,teams,positions,events=bootstrap()
    sel_gw=request.args.get('gw',type=int) or request.form.get('gw',type=int)
    cur_ev=next((e for e in events if e.get('is_current')), None)
    nxt_ev=next((e for e in events if e.get('is_next')), None)
    selected_gw = sel_gw or (cur_ev['id'] if cur_ev else (nxt_ev['id'] if nxt_ev else 1))
    users=all_users()
    conn=db(); cur=conn.cursor()
    for u in users:
        gwp=gw_stats_for_user(u['id'], selected_gw); lp=league_points_from_total(gwp)
        cur.execute("""
            INSERT INTO results (user_id, gameweek_id, gw_points, league_points)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id, gameweek_id)
            DO UPDATE SET gw_points = EXCLUDED.gw_points,
                          league_points = EXCLUDED.league_points
        """, (u['id'], selected_gw, gwp, lp))
    conn.commit(); conn.close()
    flash(f'Finalized GW {selected_gw} results.','success')
    return redirect(url_for('league', gw=selected_gw))

if __name__ == '__main__':
    app.run(debug=True)
