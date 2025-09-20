import os, requests, json, time, uuid, smtplib, math
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

def send_email(to_email, subject, body):
    api_key = os.environ.get("BREVO_API_KEY")
    url = "https://api.brevo.com/v3/smtp/email"

    payload = {
        "sender": {"email": "goe@fatzone.co.uk", "name": "FBJ Game"},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": body
    }
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if r.status_code >= 400:
        print("❌ Email failed:", r.text)
    else:
        print("✅ Email sent:", r.json())


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
            email TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            password TEXT NOT NULL,
            is_confirmed BOOLEAN DEFAULT FALSE,
            confirmation_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            display_name TEXT NOT NULL
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

def next_opponents_by_team(teams, events):
    data = load_fpl_from_gist()
    fixtures = data.get("fixtures", [])

    # find the next GW id
    nxt = next((e for e in events if e.get('is_next')), None)
    if not nxt:
        return {}
    gw_id = nxt['id']

    choice = {}
    for f in fixtures:
        if f.get("event") != gw_id:  # only look at fixtures in the next GW
            continue
        h,a = f['team_h'], f['team_a']
        choice[h] = teams[a]['short_name']+' (H)'
        choice[a] = teams[h]['short_name']+' (A)'
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

def get_user_id(email):
    conn=db(); cur=conn.cursor()
    cur.execute('SELECT id FROM users WHERE email=%s', (email,))
    r=cur.fetchone()
    conn.close()
    return r[0] if r else None

def get_display_name(user_id):
    conn=db(); cur=conn.cursor()
    cur.execute('SELECT display_name FROM users WHERE id=%s', (user_id,))
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
    cur.execute('SELECT id, email, display_name FROM users ORDER BY display_name ASC')
    rows=cur.fetchall(); conn.close()
    return [{'id':r[0],'email':r[1], 'display_name':r[2]} for r in rows]

def calc_penalty(n, total_users):
    """
    n = number of managers who picked this player
    total_users = number of managers with valid picks this GW
    Returns penalty per manager (0 if unique pick).
    """
    if n <= 1:
        return 0

    if 1 <= total_users <= 6:
        return 2 * n - 2
    elif 7 <= total_users <= 12:
        return n - 1
    else:  # 13+
        return math.ceil(0.5 * n - 0.5)

def get_player_pick_counts(gw_id):
    """
    Returns a dict mapping player_id -> number of managers
    who picked that player in the given gameweek.
    """
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT player_id, COUNT(*) 
        FROM picks 
        WHERE gameweek_id = %s
        GROUP BY player_id
    """, (gw_id,))
    rows = cur.fetchall()
    conn.close()
    return {player_id: count for player_id, count in rows}

def get_valid_user_count(gw_id):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM picks
        WHERE gameweek_id = %s
    """, (gw_id,))
    count = cur.fetchone()[0] or 0
    conn.close()
    return count

def league_penalty_rule(total_users):
    if 1 <= total_users <= 6:
        return "Small league (1–6 users): penalty = -2 per player"
    elif 7 <= total_users <= 12:
        return "Medium league (7–12 users): penalty = -1 per player"
    else:
        return "Large league (13+ users): penalty = -0.5 per player (rounded up)"

def gw_stats_for_user(uid, gw_id):
    conn = db(); cur = conn.cursor()
    cur.execute(
        'SELECT position, player_id FROM picks WHERE user_id=%s AND gameweek_id=%s',
        (uid, gw_id)
    )
    rows = cur.fetchall()
    conn.close()
    if not rows:
        return 0

    pick_counts = get_player_pick_counts(gw_id)
    total_users = get_valid_user_count(gw_id)

    total = 0
    for _, pid in rows:
        hist = gw_stats_for_player(pid, gw_id)
        pts = hist.get('total_points', 0) if hist else 0

        count = pick_counts.get(pid, 1)
        penalty = calc_penalty(count, total_users)
        pts -= penalty

        total += pts
    return total

def get_gw_lineup_for_users(events, data):
    cur_ev = next((e for e in events if e.get('is_current')), None)
    if not cur_ev:
        return [], None
    gw_id = cur_ev['id']

    team_map = {t['id']: t for t in data['teams']}
    player_map = {p['id']: p for p in data['elements']}
    users = all_users()

    pick_counts = get_player_pick_counts(gw_id)
    total_users = get_valid_user_count(gw_id)
    rule_text = league_penalty_rule(total_users)

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
                if p.get('photo'):
                  photo_id = p.get('photo', '').split('.')[0]
                  photo_url = f'https://resources.premierleague.com/premierleague/photos/players/40x40/p{photo_id}.png'
                else:
                  photo_url = url_for('static', filename='question.png')
                    
                hist = gw_stats_for_player(pid, gw_id) or {}
                base_pts = hist.get('total_points', 0)

                count = pick_counts.get(pid, 1)
                penalty = calc_penalty(count, total_users)
                pts = base_pts - penalty

                user_total += pts
                lineup[pos] = {
                    "name": p.get("web_name", "").strip(),
                    "photo_url": photo_url,
                    "base_points": base_pts,
                    "points": pts,
                    "penalty": penalty,
                    "pick_count": count,
                    "rule_text": rule_text
                }
            else:
                lineup[pos] = {
                    "name": None,
                    "photo_url": url_for('static', filename='question.png'),
                    "base_points": 0,
                    "points": 0,
                    "penalty": 0,
                    "pick_count": 0,
                    "rule_text": rule_text
                }

        results.append({
            "username": u['display_name'],
            "lineup": lineup,
            "total": user_total
        })
    return results, gw_id


# ----------------- ROUTES -----------------
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"].strip()
        last_name = request.form["last_name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not (first_name and last_name and email and password):
            flash("⚠️ All fields are required.", "warning")
            return render_template("register.html", title="Register")

        hashed_pw = generate_password_hash(password)
        token = uuid.uuid4().hex

        try:
            conn = db(); cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (email, first_name, last_name, password, confirmation_token)
                VALUES (%s, %s, %s, %s, %s)
            """, (email, first_name, last_name, hashed_pw, token))
            conn.commit()
            conn.close()

            # Confirmation email
            confirm_link = url_for("confirm_email", token=token, _external=True)
            send_email(
                email,
                "Confirm your FBJ Game account",
                f"""
                <p>Hi {first_name},</p>
                <p>Thanks for registering! Please confirm your account by clicking below:</p>
                <p><a href="{confirm_link}">Confirm my account</a></p>
                """
            )

            flash("✅ Registration successful! Check your email to confirm your account.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            conn.rollback(); conn.close()
            print("Registration error:", e)
            flash("❌ That email is already registered.", "danger")

    return render_template("register.html", title="Register")

@app.route("/confirm/<token>")
def confirm_email(token):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE confirmation_token=%s", (token,))
    user = cur.fetchone()

    if user:
        cur.execute("UPDATE users SET is_confirmed=TRUE, confirmation_token=NULL WHERE id=%s", (user[0],))
        conn.commit()
        flash("✅ Email confirmed! You can now log in.", "success")
    else:
        flash("⚠️ Invalid or expired confirmation link.", "danger")

    conn.close()
    return redirect(url_for("login"))
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]

        conn = db(); cur = conn.cursor()
        cur.execute("SELECT id, password, is_confirmed FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            uid, hashed_pw, confirmed = user
            if not confirmed:
                flash("⚠️ Please confirm your email before logging in.", "warning")
            elif check_password_hash(hashed_pw, password):
                session["user_id"] = uid
                session["email"] = email
                return redirect(url_for("welcome"))
            else:
                flash("❌ Incorrect password.", "danger")
        else:
            flash("❌ No account found with that email.", "danger")

    return render_template("login.html", title="Login")

@app.route('/reset_request')
def reset_request():
    flash("Password reset not implemented yet.", "info")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('welcome.html', title='Welcome')

@app.route("/rules")
def rules():
    return render_template("rules.html", title="Game Rules")

@app.route('/live')
def live():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    display_name = get_display_name(uid)

    data, teams, positions, events = bootstrap()
    locked, gw_id = get_locked_picks(uid, events)

    total_points = 0
    picks = {'GK': None, 'DEF': None, 'MID': None, 'FWD': None}

    if locked and gw_id:
        team_map = {t['id']: t for t in data['teams']}
        player_map = {p['id']: p for p in data['elements']}
        pick_counts = get_player_pick_counts(gw_id)
        total_users = get_valid_user_count(gw_id)
        rule_text = league_penalty_rule(total_users)

        for pos in picks.keys():
            pid = locked.get(pos)
            if not pid:
                continue
            p = player_map.get(pid)
            if not p:
                continue

            photo_id = p.get('photo', '').split('.')[0]
            photo_url = f'https://resources.premierleague.com/premierleague/photos/players/110x140/p{photo_id}.png'
            hist = gw_stats_for_player(pid, gw_id) or {}
            base_pts = hist.get('total_points', 0)

            count = pick_counts.get(pid, 1)
            penalty = calc_penalty(count, total_users)
            gw_pts = base_pts - penalty

            total_points += gw_pts
            picks[pos] = {
                'name': f"{p.get('first_name','')} {p.get('second_name','')}".strip(),
                'team_name': teams[p['team']]['name'],
                'photo_url': photo_url,
                'base_points' : base_pts,
                'gw_points': gw_pts,
                'penalty': penalty,
                'pick_count': count,
                'rule_text': rule_text,
                'stats': ({
                    'position': positions[p['element_type']],
                    'minutes': hist.get('minutes', 0),
                    'saves': hist.get('saves', 0),
                    'goals_conceded': hist.get('goals_conceded', 0),
                    'assists': hist.get('assists', 0),
                    'goals_scored': hist.get('goals_scored', 0),
                    'bonus': hist.get('bonus', 0),
                    'def_contrib': hist.get('defensive_contribution', 0),
                    'yellow_cards': hist.get('yellow_cards', 0),
                    'red_cards': hist.get('red_cards', 0),
                    'penalties_missed': hist.get('penalties_missed', 0),
                    'own_goals': hist.get('own_goals', 0),
                } if hist else None)
            }

    league_lineups, gw_id_all = get_gw_lineup_for_users(events, data)

    return render_template(
        'live.html',
        title='Live GW',
        username=display_name,
        total_points=total_points,
        squad=picks,
        league_lineups=league_lineups,
        gw_id_all=gw_id_all
    )

@app.route('/picks')
def picks():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid=session['user_id']; email=session['email']
    club=request.args.get('club'); position=request.args.get('position'); page=int(request.args.get('page',1))
    data,teams,positions,events=bootstrap()
    team_map={t['id']:t for t in data['teams']}
    opp_map=next_opponents_by_team(team_map, events)
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
    return render_template('picks.html',title='Pick Team',players=subset,selected=selected,selected_clubs=selected_clubs,clubs=clubs,current_page=page,total_pages=total_pages)

@app.route('/pick_player', methods=['POST'])
def pick_player():
    if 'user_id' not in session: return ('',401)
    data_json = request.get_json(force=True)
    position=data_json['position']; player_id=int(data_json['player_id'])
    uid=session['user_id']; email=session['email']
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
    if 'user_id' not in session: return ('',401)
    position=request.get_json(force=True)['position']
    uid=session['user_id']; email=session['email']
    data,teams,positions,events=bootstrap()
    pending, gw_next = get_pending_picks(uid, events)
    conn=db(); cur=conn.cursor()
    cur.execute('DELETE FROM picks WHERE user_id=%s AND gameweek_id=%s AND position=%s', (uid, gw_next, position))
    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/clear_team', methods=['POST'])
def clear_team():
    if 'user_id' not in session: return ('',401)
    uid=session['user_id']; email=session['email']
    data,teams,positions,events=bootstrap()
    pending, gw_next = get_pending_picks(uid, events)
    conn=db(); cur=conn.cursor()
    cur.execute('DELETE FROM picks WHERE user_id=%s AND gameweek_id=%s', (uid, gw_next))
    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/league', methods=['GET'])
def league():
    if 'user_id' not in session: return redirect(url_for('login'))
    data,teams,positions,events=bootstrap()
    users=all_users()
    conn=db(); cur=conn.cursor()
    cur.execute("""
        SELECT u.display_name,
               COALESCE(SUM(r.league_points),0) as total_lp,
               CASE WHEN COUNT(r.gw_points)>0
                    THEN AVG(CASE WHEN r.gw_points BETWEEN 0 AND 21 THEN r.gw_points ELSE 0 END)
                    ELSE 0 END as avg_gw
        FROM users u
        LEFT JOIN results r ON r.user_id=u.id
        GROUP BY u.id, u.display_name
        ORDER BY total_lp DESC, avg_gw DESC, u.display_name ASC
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
        history_rows.append({'username':u['display_name'],'gw_points':gwp,'display_points':display_points,'league_points':lp})
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
    if 'user_id' not in session: return redirect(url_for('login'))
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
