import os, requests, json, time, uuid, smtplib, math
import psycopg2, psycopg2.extras
from datetime import datetime, timezone, timedelta
import pytz
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'devsecret')

app.permanent_session_lifetime = timedelta(days=30)

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

    # Users table (unchanged)
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

    # Leagues table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS leagues (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            created_by INT REFERENCES users(id),
            created_at TIMESTAMP DEFAULT now()
        );
    """)

    # League memberships
    cur.execute("""
        CREATE TABLE IF NOT EXISTS league_members (
            id SERIAL PRIMARY KEY,
            league_id INT NOT NULL REFERENCES leagues(id) ON DELETE CASCADE,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            joined_at TIMESTAMP DEFAULT now(),
            UNIQUE (league_id, user_id)
        );
    """)

    # Picks (now linked to league_id)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS picks (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id),
            league_id INT NOT NULL REFERENCES leagues(id),
            gameweek_id INT NOT NULL,
            position TEXT NOT NULL,
            player_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, league_id, gameweek_id, position)
        );
    """)

    # Results (also linked to league_id)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id),
            league_id INT NOT NULL REFERENCES leagues(id),
            gameweek_id INT NOT NULL,
            gw_points INT NOT NULL,
            league_points INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, league_id, gameweek_id)
        );
    """)

    conn.commit()
    conn.close()

init_db()

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

# ----- League helpers -----
def get_league(league_id):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id, name, created_by FROM leagues WHERE id=%s", (league_id,))
    row = cur.fetchone(); conn.close()
    if not row: return None
    return {"id": row[0], "name": row[1], "created_by": row[2]}

def is_member(user_id, league_id):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT 1 FROM league_members
        WHERE user_id=%s AND league_id=%s
        LIMIT 1
    """, (user_id, league_id))
    ok = cur.fetchone() is not None
    conn.close()
    return ok

def user_leagues(user_id):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT l.id, l.name
        FROM leagues l
        JOIN league_members m ON m.league_id = l.id
        WHERE m.user_id=%s
        ORDER BY l.name ASC
    """, (user_id,))
    rows = cur.fetchall(); conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]

# Decorator to enforce membership and load league
def league_required(view):
    @wraps(view)
    def wrapper(league_id, *args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('new_login'))
        league = get_league(league_id)
        if not league: abort(404)
        if not is_member(session['user_id'], league_id):
            flash("You’re not a member of that league.", "warning")
            return redirect(url_for('fbj_home'))  # or your FBJ welcome page
        g.league = league  # makes league available in view/templates
        return view(league_id, *args, **kwargs)
    return wrapper

def league_users(league_id):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.display_name, u.email
        FROM users u
        JOIN league_members m ON m.user_id = u.id
        WHERE m.league_id = %s
        ORDER BY u.display_name ASC
    """, (league_id,))
    users = [{'id': r[0], 'display_name': r[1], 'email': r[2]} for r in cur.fetchall()]
    conn.close()
    return users

# League-scoped variants of your helpers
def get_pending_picks_league(user_id, league_id, events):
    nxt = next((e for e in events if e.get('is_next')), None)
    if not nxt: nxt = next((e for e in events if not e.get('finished')), None)
    if not nxt: return {}, None
    gw_id = nxt['id']
    conn=db(); cur=conn.cursor()
    cur.execute("""
        SELECT position, player_id
        FROM picks
        WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
    """, (user_id, league_id, gw_id))
    rows=cur.fetchall(); conn.close()
    return ({pos:pid for pos,pid in rows}, gw_id)

def get_locked_picks_league(user_id, league_id, events):
    now = datetime.now(timezone.utc)
    cur_ev = next((e for e in events if e.get('is_current')), None)
    if not cur_ev: return {}, None
    deadline = datetime.fromisoformat(cur_ev['deadline_time'].replace('Z','+00:00'))
    # ensure deadline is parsed as UTC
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    else:
        deadline = deadline.astimezone(timezone.utc)
    if now < deadline: return {}, None
    gw_id = cur_ev['id']
    conn=db(); cur=conn.cursor()
    cur.execute("""
        SELECT position, player_id
        FROM picks
        WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
    """, (user_id, league_id, gw_id))
    rows=cur.fetchall(); conn.close()
    return ({pos: pid for pos, pid in rows}, gw_id)

def get_player_pick_counts(gw_id, league_id):
    conn=db(); cur=conn.cursor()
    cur.execute("""
        SELECT player_id, COUNT(*)::int
        FROM picks
        WHERE gameweek_id=%s AND league_id=%s
        GROUP BY player_id
    """, (gw_id, league_id))
    counts = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()
    return counts

def get_valid_user_count(gw_id, league_id):
    conn=db(); cur=db().cursor()
    cur.execute("""
        SELECT COUNT(*)::int
        FROM (
          SELECT user_id
          FROM picks
          WHERE gameweek_id=%s AND league_id=%s
          GROUP BY user_id
          HAVING COUNT(*) = 4
        ) t
    """, (gw_id, league_id))
    n = cur.fetchone()[0] or 0
    conn.close()
    return n

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

def decorate_players(players, teams, positions, opp_map):
    badge_template = load_fpl_from_gist().get("badge_template")

    out = []
    for p in players:
        d = dict(p)
        d['team_name'] = teams[p['team']]['name']
        d['position_name'] = positions[p['element_type']]
        d['next_opp'] = opp_map.get(p['team'], '-')
        d['kit_url'] = badge_template.format(teams[p['team']]['code'])

        # 🔹 extra stats (come directly from bootstrap player data)
        d['minutes'] = p.get('minutes', 0)
        d['goals_scored'] = p.get('goals_scored', 0)
        d['assists'] = p.get('assists', 0)
        d['clean_sheets'] = p.get('clean_sheets', 0)
        d['bonus'] = p.get('bonus', 0)
        d['def_contrib'] = p.get('defensive_contribution', 0)
        d['total_points'] = p.get('total_points', 0)

        # 🔹 last gameweek points (pulled from gw_stats)
        # careful: need to figure out last completed gw
        data = load_fpl_from_gist()
        events = data.get("bootstrap", {}).get("events", [])
        last_gw = next((e for e in reversed(events) if e.get("finished")), None)
        if last_gw:
            last_stats = data.get("stats", {}).get(str(last_gw["id"]), {})
            d['last_gw_points'] = last_stats.get(str(p['id']), {}).get("total_points", 0)
        else:
            d['last_gw_points'] = 0

        out.append(d)

    return out


def gw_stats_for_player(player_id, gw_round):
    data = load_fpl_from_gist()
    return data.get("stats", {}).get(str(gw_round), {}).get(str(player_id), {})

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

def league_penalty_rule(total_users):
    if 1 <= total_users <= 6:
        return "Small league (1–6 users): penalty = -2 per player"
    elif 7 <= total_users <= 12:
        return "Medium league (7–12 users): penalty = -1 per player"
    else:
        return "Large league (13+ users): penalty = -0.5 per player (rounded up)"

def gw_stats_for_user(uid, gw_id, league_id):
    conn = db(); cur = conn.cursor()

    # 1. Try cached results first
    cur.execute("""
        SELECT gw_points 
        FROM results 
        WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
    """, (uid, league_id, gw_id))
    row = cur.fetchone()
    if row:
        conn.close()
        return row[0]  # ✅ return cached value immediately

    # 2. Otherwise, calculate on the fly
    cur.execute("""
        SELECT position, player_id 
        FROM picks 
        WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
    """, (uid, league_id, gw_id))
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return 0

    pick_counts = get_player_pick_counts(gw_id, league_id)
    total_users = get_valid_user_count(gw_id, league_id)

    total = 0
    for _, pid in rows:
        hist = gw_stats_for_player(pid, gw_id) or {}
        pts = hist.get("total_points", 0)
        count = pick_counts.get(pid, 1)
        penalty = calc_penalty(count, total_users)
        total += pts - penalty

    return total


def get_gw_lineup_for_users(events, data, league_id):
    cur_ev = next((e for e in events if e.get('is_current')), None)
    if not cur_ev:
        return [], None
    gw_id = cur_ev['id']

    team_map = {t['id']: t for t in data['teams']}
    player_map = {p['id']: p for p in data['elements']}
    users = league_users(league_id)  # 🔑 only members of this league

    pick_counts = get_player_pick_counts(gw_id, league_id)
    total_users = get_valid_user_count(gw_id, league_id)
    rule_text = league_penalty_rule(total_users)

    results = []
    for u in users:
        uid = u['id']
        conn = db(); cur = conn.cursor()
        cur.execute("""
            SELECT position, player_id
            FROM picks
            WHERE user_id=%s AND gameweek_id=%s AND league_id=%s
        """, (uid, gw_id, league_id))
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
                    photo_id = p['photo'].split('.')[0]
                    photo_url = f'https://resources.premierleague.com/premierleague25/photos/players/110x140/{photo_id}.png'
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
    if "user_id" in session:
        return redirect(url_for("welcome"))
    else:
        return redirect(url_for("login"))

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
                session.permanent = True
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
    return render_template('welcome.html', title='FatZone')

@app.route("/fbj/rules")
def rules():
    return render_template("rules.html", title="Game Rules")

@app.route('/fbj/create_league', methods=['GET', 'POST'])
def create_league():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        uid = session['user_id']
        if not name:
            flash("League name required", "danger")
            return redirect(url_for('create_league'))

        conn = db(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO leagues (name, created_by)
            VALUES (%s, %s)
            RETURNING id
        """, (name, uid))
        league_id = cur.fetchone()[0]

        cur.execute("""
            INSERT INTO league_members (league_id, user_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (league_id, uid))
        conn.commit(); conn.close()

        flash(f"Created league {name}", "success")
        return redirect(url_for('league', league_id=league_id))

    return render_template("create_league.html", title="Create League")

@app.route('/fbj/join_league', methods=['GET', 'POST'])
def join_league():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    conn = db(); cur = conn.cursor()

    # leagues user is already in
    cur.execute("SELECT league_id FROM league_members WHERE user_id=%s", (uid,))
    joined_ids = {row[0] for row in cur.fetchall()}

    # list leagues not joined yet
    cur.execute("""
        SELECT l.id, l.name, u.display_name AS creator
        FROM leagues l
        JOIN users u ON u.id = l.created_by
        WHERE l.id <> ALL(%s)
        ORDER BY l.name ASC
    """, (list(joined_ids) or [0],))  # fallback to avoid empty array error
    leagues = [{'id': r[0], 'name': r[1], 'creator': r[2]} for r in cur.fetchall()]
    conn.close()

    if request.method == 'POST':
        league_id = int(request.form.get('league_id'))
        conn = db(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO league_members (league_id, user_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (league_id, uid))
        conn.commit(); conn.close()
        flash("Joined league successfully!", "success")
        return redirect(url_for('my_leagues'))

    return render_template("join_league.html", title="Join League", leagues=leagues)
    
@app.route('/fbj/my_leagues')
def my_leagues():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT l.id, l.name, COUNT(m2.user_id) AS member_count
        FROM leagues l
        JOIN league_members m ON m.league_id = l.id
        JOIN league_members m2 ON m2.league_id = l.id
        WHERE m.user_id = %s
        GROUP BY l.id, l.name
        ORDER BY l.name ASC
    """, (uid,))
    leagues = [{'id': r[0], 'name': r[1], 'member_count': r[2]} for r in cur.fetchall()]
    conn.close()

    return render_template("my_leagues.html", title="FBJ", leagues=leagues)

@app.route('/fbj/league/<int:league_id>/live')
@league_required
def live(league_id):
    uid = session['user_id']
    display_name = get_display_name(uid)

    data, teams, positions, events = bootstrap()
    locked, gw_id = get_locked_picks_league(uid, league_id, events)

    total_points = 0
    picks = {'GK': None, 'DEF': None, 'MID': None, 'FWD': None}

    if locked and gw_id:
        team_map = {t['id']: t for t in data['teams']}
        player_map = {p['id']: p for p in data['elements']}
        pick_counts = get_player_pick_counts(gw_id, league_id)
        total_users = get_valid_user_count(gw_id, league_id)
        rule_text = league_penalty_rule(total_users)

        for pos in picks.keys():
            pid = locked.get(pos)
            if not pid:
                continue
            p = player_map.get(pid)
            if not p:
                continue

            photo_id = p.get('photo', '').split('.')[0]
            photo_url = f'https://resources.premierleague.com/premierleague25/photos/players/110x140/{photo_id}.png'
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
                'base_points': base_pts,
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

    league_lineups, gw_id_all = get_gw_lineup_for_users(events, data, league_id)

    return render_template(
        'live.html',
        title=f"Live GW – {g.league['name']}",
        username=display_name,
        total_points=total_points,
        squad=picks,
        league_lineups=league_lineups,
        gw_id_all=gw_id_all,
        league_id=league_id,      # 🔑 pass to template for nav links
        league_name=g.league['name']
    )
    
@app.route('/fbj/league/<int:league_id>/picks')
@league_required
def picks(league_id):
    uid = session['user_id']
    email = session['email']

    # filters
    club = request.args.get('club')
    position = request.args.get('position')
    page = int(request.args.get('page', 1))

    # bootstrap data
    data, teams, positions, events = bootstrap()
    team_map = {t['id']: t for t in data['teams']}
    opp_map = next_opponents_by_team(team_map, events)
    players = decorate_players(data['elements'], team_map, positions, opp_map)
    players.sort(key=lambda x: x.get('total_points', 0), reverse=True)

    # apply filters
    if club:
        players = [p for p in players if p['team_name'] == club]
    if position:
        players = [p for p in players if p['position_name'] == position]

    # pagination
    page_size = 20
    start = (page - 1) * page_size
    end = start + page_size
    subset = players[start:end]
    total_pages = (len(players) + page_size - 1) // page_size

    # current selections (league-aware)
    pending, gw_next = get_pending_picks_league(uid, league_id, events)
    selected = {'GK': None, 'DEF': None, 'MID': None, 'FWD': None}
    player_map = {p['id']: p for p in data['elements']}
    badge_template = load_fpl_from_gist().get("badge_template")
    for pos, pid in pending.items():
        p = player_map.get(pid)
        if not p:
            continue
        team = team_map[p['team']]
        badge_url = badge_template.format(team['code'])
        selected[pos] = {
            'first_name': p['first_name'],
            'second_name': p['second_name'],
            'team_name': team['name'],
            'kit_url': badge_url
        }
    selected_clubs = {selected[pos]['team_name'] for pos in selected if selected[pos]}

    # wrap subset for easier attribute access
    class O(dict):
        __getattr__ = dict.get
    subset = [O(p) for p in subset]

    # list of clubs
    clubs = sorted({team_map[p['team']]['name'] for p in data['elements']})

    # find next gw and deadline
    next_event = next((e for e in events if e.get("is_next")), None)
    next_gw = next_event['id'] if next_event else None
    next_deadline_fmt = None
    if next_event and next_event.get('deadline_time'):
        deadline_utc = datetime.fromisoformat(next_event['deadline_time'].replace("Z", "+00:00"))
        uk_tz = pytz.timezone("Europe/London")
        deadline_local = deadline_utc.astimezone(uk_tz)
        next_deadline_fmt = deadline_local.strftime("%a %d %b, %H:%M UK")

    return render_template(
        'picks.html',
        title=f'Pick Team – {g.league["name"]}',
        players=subset,
        selected=selected,
        selected_clubs=selected_clubs,
        clubs=clubs,
        current_page=page,
        total_pages=total_pages,
        next_gw=next_gw,
        next_deadline=next_deadline_fmt,
        league_id=league_id,
        league_name=g.league["name"]
    )
    
@app.route('/fbj/league/<int:league_id>/pick_player', methods=['POST'])
@league_required
def pick_player(league_id):
    if 'user_id' not in session:
        return ('', 401)

    data_json = request.get_json(force=True)
    position = data_json['position']
    player_id = int(data_json['player_id'])
    apply_all = data_json.get('apply_all', False)
    uid = session['user_id']

    # bootstrap etc...
    data, teams, positions, events = bootstrap()
    player = next((p for p in data['elements'] if p['id'] == player_id), None)
    if not player: return jsonify({'status': 'error'}), 400
    pos_name = positions[player['element_type']]
    if pos_name != position: return jsonify({'status': 'error'}), 400

    pending, gw_next = get_pending_picks_league(uid, league_id, events)
    team_map = {t['id']: t for t in data['teams']}

    # enforce unique club (for current league only)
    chosen_clubs = set()
    for pos, pid in pending.items():
        pp = next((e for e in data['elements'] if e['id'] == pid), None)
        if pp: chosen_clubs.add(team_map[pp['team']]['name'])
    if team_map[player['team']]['name'] in chosen_clubs:
        return jsonify({'status':'error','msg':'Club already selected'}),400

    # insert for this league
    conn=db(); cur=conn.cursor()
    cur.execute("""
        INSERT INTO picks (user_id, league_id, gameweek_id, position, player_id)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (user_id, league_id, gameweek_id, position)
        DO UPDATE SET player_id = EXCLUDED.player_id
    """, (uid, league_id, gw_next, position, player_id))

    # also insert for all leagues (if checkbox ticked)
    if apply_all:
        leagues = user_leagues(uid)
        for l in leagues:
            if l['id'] == league_id: 
                continue
            cur.execute("""
                INSERT INTO picks (user_id, league_id, gameweek_id, position, player_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id, league_id, gameweek_id, position)
                DO UPDATE SET player_id = EXCLUDED.player_id
            """, (uid, l['id'], gw_next, position, player_id))

    conn.commit(); conn.close()
    return jsonify({'status': 'ok'})
    
@app.route('/fbj/league/<int:league_id>/sync_team_to_all', methods=['POST'])
@league_required
def sync_team_to_all(league_id):
    if 'user_id' not in session:
        return ('', 401)

    uid = session['user_id']
    data, teams, positions, events = bootstrap()
    pending, gw_id = get_pending_picks_league(uid, league_id, events)

    if not gw_id:
        return jsonify({'status': 'error', 'msg': 'No active gameweek'}), 400

    # Get all leagues in the SAME connection
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT l.id
        FROM leagues l
        JOIN league_members m ON m.league_id = l.id
        WHERE m.user_id = %s
    """, (uid,))
    leagues = [row[0] for row in cur.fetchall()]

    # Replace picks in every league with this league's current picks
    for lid in leagues:
        cur.execute("""
            DELETE FROM picks
            WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
        """, (uid, lid, gw_id))
        for pos, pid in pending.items():
            cur.execute("""
                INSERT INTO picks (user_id, league_id, gameweek_id, position, player_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (uid, lid, gw_id, pos, pid))

    conn.commit(); conn.close()

    flash("✅ Your current picks have been synced to all leagues.", "success")
    return jsonify({'status': 'ok'})

@app.route('/fbj/league/<int:league_id>/remove_player', methods=['POST'])
@league_required
def remove_player(league_id):
    if 'user_id' not in session: return ('',401)
    data_json = request.get_json(force=True)
    position = data_json['position']
    apply_all = data_json.get('apply_all', False)
    uid = session['user_id']

    data,teams,positions,events=bootstrap()
    pending, gw_next = get_pending_picks_league(uid, league_id, events)
    conn=db(); cur=conn.cursor()
    cur.execute("""
        DELETE FROM picks
        WHERE user_id=%s AND league_id=%s AND gameweek_id=%s AND position=%s
    """, (uid, league_id, gw_next, position))

    if apply_all:
        leagues = user_leagues(uid)
        for l in leagues:
            if l['id'] == league_id: continue
            cur.execute("""
                DELETE FROM picks
                WHERE user_id=%s AND league_id=%s AND gameweek_id=%s AND position=%s
            """, (uid, l['id'], gw_next, position))

    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/fbj/league/<int:league_id>/clear_team', methods=['POST'])
@league_required
def clear_team(league_id):
    if 'user_id' not in session: return ('',401)
    data_json = request.get_json(force=True) or {}
    apply_all = data_json.get('apply_all', False)
    uid = session['user_id']

    data,teams,positions,events=bootstrap()
    pending, gw_next = get_pending_picks_league(uid, league_id, events)
    conn=db(); cur=conn.cursor()
    cur.execute("""
        DELETE FROM picks
        WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
    """, (uid, league_id, gw_next))

    if apply_all:
        leagues = user_leagues(uid)
        for l in leagues:
            if l['id'] == league_id: continue
            cur.execute("""
                DELETE FROM picks
                WHERE user_id=%s AND league_id=%s AND gameweek_id=%s
            """, (uid, l['id'], gw_next))

    conn.commit(); conn.close()
    return jsonify({'status':'ok'})

@app.route('/fbj/league/<int:league_id>/league', methods=['GET'])
@league_required
def league(league_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    data, teams, positions, events = bootstrap()
    users = league_users(league_id)  # ✅ only members of this league

    conn = db(); cur = conn.cursor()

    # --- League standings (total LP + avg GW) ---
    cur.execute("""
        SELECT u.id, u.display_name,
               COALESCE(SUM(r.league_points), 0) AS total_lp,
               CASE WHEN COUNT(r.gw_points) > 0
                    THEN AVG(CASE WHEN r.gw_points BETWEEN 0 AND 21 THEN r.gw_points ELSE 0 END)
                    ELSE 0 END AS avg_gw
        FROM users u
        JOIN league_members m ON m.user_id = u.id
        LEFT JOIN results r ON r.user_id = u.id AND r.league_id = %s
        WHERE m.league_id = %s
        GROUP BY u.id, u.display_name
        ORDER BY total_lp DESC, avg_gw DESC, u.display_name ASC
    """, (league_id, league_id))
    league_rows = [
        {'user_id': r[0], 'username': r[1], 'total_lp': int(r[2]), 'avg_gw': float(r[3])}
        for r in cur.fetchall()
    ]

    # --- Pick GW ---
    sel_gw = request.args.get('gw', type=int)
    cur_ev = next((e for e in events if e.get('is_current')), None)
    nxt_ev = next((e for e in events if e.get('is_next')), None)
    default_gw = cur_ev['id'] if cur_ev else (nxt_ev['id'] if nxt_ev else 1)
    selected_gw = sel_gw or default_gw

    # --- Batch fetch results for this GW ---
    cur.execute("""
        SELECT user_id, gw_points, league_points
        FROM results
        WHERE gameweek_id=%s AND league_id=%s
    """, (selected_gw, league_id))
    resmap = {row[0]: {'gw_points': row[1], 'league_points': row[2]} for row in cur.fetchall()}

    # --- Batch fetch picks for all users (only if needed) ---
    missing_ids = [u['id'] for u in users if u['id'] not in resmap]
    picks_by_user = {}
    if missing_ids:
        cur.execute("""
            SELECT user_id, position, player_id
            FROM picks
            WHERE league_id=%s AND gameweek_id=%s
              AND user_id = ANY(%s)
        """, (league_id, selected_gw, missing_ids))
        rows = cur.fetchall()
        from collections import defaultdict
        picks_by_user = defaultdict(dict)
        for uid, pos, pid in rows:
            picks_by_user[uid][pos] = pid

    conn.close()

    # --- Build history rows ---
    history_rows = []
    for u in users:
        if u['id'] in resmap:
            gwp = resmap[u['id']]['gw_points']
            lp = resmap[u['id']]['league_points']
        else:
            # Only calculate if absolutely missing
            user_picks = picks_by_user.get(u['id'], {})
            if not user_picks:
                gwp, lp = 0, 0
            else:
                gwp = gw_stats_for_user(u['id'], selected_gw, league_id)
                lp = league_points_from_total(gwp)
        display_points = f"{gwp}" if gwp <= 21 else f"Bust ({gwp})"
        history_rows.append({
            'username': u['display_name'],
            'gw_points': gwp,
            'display_points': display_points,
            'league_points': lp
        })

    history_rows.sort(key=lambda r: (r['league_points'], r['gw_points']), reverse=True)

    # --- Fixtures: check if this GW can be finalized ---
    fixtures = load_fpl_from_gist().get("fixtures", [])
    relevant = [f for f in fixtures if f.get('event') == selected_gw]
    can_finalize = bool(relevant) and all(f.get('finished') for f in relevant)

    all_gws = [{'id': e['id']} for e in events]
    return render_template(
        'league.html',
        title=f'League & History – {g.league["name"]}',
        league_rows=league_rows,
        history_rows=history_rows,
        all_gws=all_gws,
        selected_gw=selected_gw,
        can_finalize=can_finalize,
        league_id=league_id,
        league_name=g.league['name']
    )


@app.route('/fbj/league/<int:league_id>/finalize_gw', methods=['POST'])
@league_required
def finalize_gw(league_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    data, teams, positions, events = bootstrap()
    sel_gw = request.args.get('gw', type=int) or request.form.get('gw', type=int)
    cur_ev = next((e for e in events if e.get('is_current')), None)
    nxt_ev = next((e for e in events if e.get('is_next')), None)
    selected_gw = sel_gw or (cur_ev['id'] if cur_ev else (nxt_ev['id'] if nxt_ev else 1))

    users = league_users(league_id)

    conn = db(); cur = conn.cursor()
    for u in users:
        gwp = gw_stats_for_user(u['id'], selected_gw, league_id)
        lp = league_points_from_total(gwp)
        cur.execute("""
            INSERT INTO results (user_id, league_id, gameweek_id, gw_points, league_points)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id, league_id, gameweek_id)
            DO UPDATE SET gw_points = EXCLUDED.gw_points,
                          league_points = EXCLUDED.league_points
        """, (u['id'], league_id, selected_gw, gwp, lp))
    conn.commit(); conn.close()

    flash(f'Finalized GW {selected_gw} results for {g.league["name"]}.', 'success')
    return redirect(url_for('league', league_id=league_id, gw=selected_gw))

@app.route("/draft_pyramid")
def draft_pyramid_home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("draft_pyramid_home.html", title="Draft Pyramid")

@app.route("/draft_playoffs")
def draft_playoffs_home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("draft_playoffs_home.html", title="Draft Playoffs")

# Health check route
@app.route("/healthz")
def healthz():
    return jsonify(status="ok"), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
