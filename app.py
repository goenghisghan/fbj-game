import os, sqlite3, requests
from flask import Flask, render_template, request, redirect, url_for, session as flask_session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')

DB_PATH = 'users.db'

# --- FPL API setup ---
LOGIN_URL = "https://users.premierleague.com/accounts/login/"
FPL_BOOTSTRAP = "https://fantasy.premierleague.com/api/bootstrap-static/"
FPL_FIXTURES = "https://fantasy.premierleague.com/api/fixtures/"

BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/118.0.0.0 Safari/537.36",
    "accept-language": "en-GB,en;q=0.9",
}

session = requests.session()

def fpl_login():
    """Login to FPL API using CSRF token like a real browser."""
    email = os.environ.get("FPL_EMAIL", "")
    password = os.environ.get("FPL_PASSWORD", "")
    if not email or not password:
        print("⚠️ No FPL_EMAIL/FPL_PASSWORD set, skipping login")
        return

    # Step 1: GET login page for CSRF token
    r1 = session.get(LOGIN_URL, headers=BASE_HEADERS)
    r1.raise_for_status()
    csrf_token = session.cookies.get_dict().get("csrftoken", "")
    print("Fetched CSRF token:", csrf_token)

    # Step 2: POST credentials with CSRF
    payload = {
        "login": email,
        "password": password,
        "csrfmiddlewaretoken": csrf_token,
        "app": "plfpl-web",
        "redirect_uri": "https://fantasy.premierleague.com/"
    }
    headers = BASE_HEADERS.copy()
    headers["Referer"] = LOGIN_URL
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token

    r2 = session.post(LOGIN_URL, data=payload, headers=headers)
    r2.raise_for_status()

    print("✅ Login POST done. Cookies now:", session.cookies.get_dict())
    print("Login response snippet:", r2.text[:300])

def safe_get_json(url, timeout=20):
    """Fetch JSON from FPL API with current session."""
    try:
        r = session.get(url, headers=BASE_HEADERS, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"FPL API fetch failed for {url}: {e}")
        try:
            flash("⚠️ Unable to fetch FPL data", "warning")
        except:
            pass
        return {}

# Try login on startup
try:
    fpl_login()
except Exception as e:
    print("⚠️ Login failed:", e)

# --- Database setup ---
def db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
    conn.commit()
    conn.close()

init_db()

def get_user_id(username):
    conn = db()
    cur = conn.cursor()
    cur.execute('SELECT id FROM users WHERE username=?', (username,))
    r = cur.fetchone()
    conn.close()
    return r[0] if r else None

# --- Routes ---
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        try:
            conn = db()
            cur = conn.cursor()
            cur.execute('INSERT INTO users(username,password) VALUES (?,?)',
                        (u, generate_password_hash(p)))
            conn.commit()
            conn.close()
            flash('Registered, please login.')
            return redirect(url_for('login'))
        except:
            flash('User exists')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        conn = db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username=?', (u,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[2], p):
            flask_session['username'] = u
            return redirect(url_for('welcome'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    if 'username' not in flask_session:
        return redirect(url_for('login'))
    return render_template('welcome.html')

@app.route('/squad')
def squad():
    if 'username' not in flask_session:
        return redirect(url_for('login'))
    data = safe_get_json(FPL_BOOTSTRAP)
    teams = {t['id']: t for t in data.get('teams', [])}
    positions = {1: 'GK', 2: 'DEF', 3: 'MID', 4: 'FWD'}
    players = []
    for p in data.get('elements', []):
        players.append({
            'first_name': p['first_name'],
            'second_name': p['second_name'],
            'team_name': teams.get(p['team'], {}).get('name', ''),
            'position_name': positions.get(p['element_type'], ''),
            'total_points': p['total_points'],
            'next_opp': '-'
        })
    return render_template('squad.html', players=players)

@app.route('/my_squad')
def my_squad():
    if 'username' not in flask_session:
        return redirect(url_for('login'))
    username = flask_session['username']
    squad = {'GK': None, 'DEF': None, 'MID': None, 'FWD': None}
    return render_template('my_squad.html', username=username, squad=squad)

@app.route('/league')
def league():
    if 'username' not in flask_session:
        return redirect(url_for('login'))
    league_rows = [{'username': 'demo', 'total_lp': 0, 'avg_gw': 0.0}]
    return render_template('league.html', league_rows=league_rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
