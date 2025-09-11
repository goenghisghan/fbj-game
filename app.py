import os, sqlite3, requests, base64, hashlib, uuid, re
from flask import Flask, render_template, request, redirect, url_for, session as flask_session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')

DB_PATH = 'users.db'

# --- FPL API setup ---
URLS = {
    "auth": "https://login.premierleague.com/api/v1/auth",
    "start": "https://login.premierleague.com/api/v1/auth/start",
    "login": "https://login.premierleague.com/api/v1/auth/continue",
    "resume": "https://login.premierleague.com/api/v1/auth/resume",
    "token": "https://login.premierleague.com/api/v1/token",
}
FPL_BOOTSTRAP = "https://fantasy.premierleague.com/api/bootstrap-static/"
FPL_FIXTURES = "https://fantasy.premierleague.com/api/fixtures/"

session = requests.Session()
HEADERS = {
    "User-Agent": "plfpl-mobile/2.0.9 (Android; 11)",
    "Accept": "application/json",
    "accept-language": "en-GB,en;q=0.9"
}

ACCESS_TOKEN = None
REFRESH_TOKEN = None


# --- PKCE helpers ---
def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')


# --- FPL login flow ---
def fpl_login():
    """Perform full PKCE OAuth2 login to FPL."""
    global ACCESS_TOKEN, REFRESH_TOKEN

    email = os.environ.get("FPL_EMAIL", "")
    password = os.environ.get("FPL_PASSWORD", "")
    if not email or not password:
        print("⚠️ No FPL_EMAIL/FPL_PASSWORD set, skipping login")
        return

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    initial_state = uuid.uuid4().hex

    # Step 1: Request authorization page
    params = {
        "client_id": "bfcbaf69-aade-4c1b-8f00-c1cb8a193030",
        "redirect_uri": "https://fantasy.premierleague.com/",
        "response_type": "code",
        "scope": "openid profile email offline_access",
        "state": initial_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    r1 = session.get(URLS["auth"], params=params, headers=HEADERS)
    r1.raise_for_status()
    login_html = r1.text

    access_token = re.search(r'"accessToken":"([^"]+)"', login_html).group(1)
    new_state = re.search(r'<input[^>]+name="state"[^>]+value="([^"]+)"', login_html).group(1)

    # Step 2: Use accessToken to get interaction id and token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    r2 = session.post(URLS["start"], headers=headers).json()
    interaction_id = r2["interactionId"]
    interaction_token = r2["interactionToken"]

    # Step 3: log in with interaction tokens (2 POST requests)
    r3 = session.post(
        URLS["login"],
        headers={"interactionId": interaction_id, "interactionToken": interaction_token},
        json={
            "id": r2["id"],
            "eventName": "continue",
            "parameters": {"eventType": "polling"},
            "pollProps": {"status": "continue", "delayInMs": 10, "retriesAllowed": 1, "pollChallengeStatus": False},
        },
    )
    r4 = session.post(
        URLS["login"],
        headers={"interactionId": interaction_id, "interactionToken": interaction_token},
        json={
            "id": r3.json()["id"],
            "nextEvent": {
                "constructType": "skEvent",
                "eventName": "continue",
                "params": [],
                "eventType": "post",
                "postProcess": {},
            },
            "parameters": {
                "buttonType": "form-submit",
                "buttonValue": "SIGNON",
                "username": email,
                "password": password,
            },
            "eventName": "continue",
        },
    )
    dv_response = r4.json()["dvResponse"]

    # Step 4: Resume login and handle redirect
    r5 = session.post(
        URLS["resume"],
        data={"dvResponse": dv_response, "state": new_state},
        allow_redirects=False,
    )
    location = r5.headers["Location"]
    auth_code = re.search(r"[?&]code=([^&]+)", location).group(1)

    # Step 5: Exchange auth code for access token
    r6 = session.post(
        URLS["token"],
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://fantasy.premierleague.com/",
            "code": auth_code,
            "code_verifier": code_verifier,
            "client_id": "bfcbaf69-aade-4c1b-8f00-c1cb8a193030",
        },
    )
    r6.raise_for_status()
    token_response = r6.json()

    REFRESH_TOKEN = token_response.get("refresh_token")
    ACCESS_TOKEN = token_response.get("access_token")

    if ACCESS_TOKEN:
        HEADERS["X-API-Authorization"] = f"Bearer {ACCESS_TOKEN}"
        print("✅ Logged in, access token acquired")
    else:
        print("⚠️ Login succeeded but no access token:", token_response)


def safe_get_json(url, timeout=20):
    """Fetch JSON from FPL API with access token headers."""
    try:
        r = session.get(url, headers=HEADERS, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"FPL API fetch failed for {url}: {e}")
        try:
            flash("⚠️ Unable to fetch FPL data", "warning")
        except:
            pass
        return {}

# Run login on startup
try:
    fpl_login()
except Exception as e:
    print("⚠️ Startup login failed:", e)


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


# --- Routes (same as before) ---
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
