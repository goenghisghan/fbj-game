import os, re, uuid, base64, hashlib, secrets, requests, sqlite3
from flask import Flask, render_template, request, redirect, url_for, session as flask_session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')

DB_PATH = 'users.db'

# ----------------- AUTH + API -----------------
URLS = {
    "auth": "https://account.premierleague.com/as/authorize",
    "start": "https://account.premierleague.com/davinci/policy/262ce4b01d19dd9d385d26bddb4297b6/start",
    "login": "https://account.premierleague.com/davinci/connections/0d8c928e4970386733ce110b9dda8412/capabilities/customHTMLTemplate",
    "resume": "https://account.premierleague.com/as/resume",
    "token": "https://account.premierleague.com/as/token",
}
FPL_BOOTSTRAP = "https://fantasy.premierleague.com/api/bootstrap-static/"

session = requests.Session()
HEADERS = {
    "User-Agent": "plfpl-mobile/2.0.9 (Android; 11)",
    "Accept": "application/json",
    "accept-language": "en-GB,en;q=0.9"
}
ACCESS_TOKEN = None


def generate_code_verifier():
    return secrets.token_urlsafe(64)[:128]


def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def fpl_login():
    """Perform OAuth2 PKCE login flow and set ACCESS_TOKEN"""
    global ACCESS_TOKEN
    email = os.environ.get("FPL_EMAIL")
    password = os.environ.get("FPL_PASSWORD")
    if not email or not password:
        print("⚠️ EMAIL/PASSWORD not set in environment")
        return

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    initial_state = uuid.uuid4().hex

    # Step 1: Authorize
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
    login_html = r1.text

    access_token = re.search(r'"accessToken":"([^"]+)"', login_html).group(1)
    new_state = re.search(r'<input[^>]+name="state"[^>]+value="([^"]+)"', login_html).group(1)

    # Step 2: Interaction
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    r2 = session.post(URLS["start"], headers=headers).json()
    interaction_id = r2["interactionId"]
    interaction_token = r2["interactionToken"]

    # Step 3: Polling + Login
    session.post(
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
            "id": r2["id"],
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

    # Step 4: Resume
    r5 = session.post(
        URLS["resume"], data={"dvResponse": dv_response, "state": new_state}, allow_redirects=False
    )
    location = r5.headers["Location"]
    auth_code = re.search(r"[?&]code=([^&]+)", location).group(1)

    # Step 5: Exchange token
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
    token_response = r6.json()
    ACCESS_TOKEN = token_response.get("access_token")

    if ACCESS_TOKEN:
        HEADERS["X-API-Authorization"] = f"Bearer {ACCESS_TOKEN}"
        print("✅ Logged in, token acquired")
    else:
        print("⚠️ Login response missing token", token_response)


def safe_get_json(url):
    try:
        r = session.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"⚠️ FPL fetch failed {url}: {e}")
        return {}

# Run login at startup
fpl_login()


# ----------------- DB + ROUTES (unchanged) -----------------
def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    conn.commit()
    conn.close()


init_db()


@app.route("/")
def root():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (u,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[2], p):
            flask_session["username"] = u
            return redirect(url_for("welcome"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/welcome")
def welcome():
    if "username" not in flask_session:
        return redirect(url_for("login"))
    return render_template("welcome.html")


@app.route("/squad")
def squad():
    if "username" not in flask_session:
        return redirect(url_for("login"))
    data = safe_get_json(FPL_BOOTSTRAP)
    return {"keys": list(data.keys())}  # just show API response keys for test


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
