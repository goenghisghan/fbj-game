import os, requests, json, sqlite3
from flask import Flask, render_template, request, redirect, url_for, session as flask_session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")

DB_PATH = "users.db"

# ----------------- TOKEN HANDLING -----------------
def get_tokens_from_gist():
    gist_id = os.getenv("GIST_ID")
    github_token = os.getenv("GITHUB_TOKEN")
    if not gist_id or not github_token:
        print("⚠️ Missing GIST_ID or GITHUB_TOKEN in environment")
        return None, None

    url = f"https://api.github.com/gists/{gist_id}"
    headers = {"Authorization": f"Bearer {github_token}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    gist_data = r.json()

    # Take the first file in the gist
    file_content = list(gist_data["files"].values())[0]["content"]
    tokens = json.loads(file_content)

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if access_token:
        print("✅ Loaded access token from Gist")
    else:
        print("⚠️ No access token found in Gist")
    return access_token, refresh_token


ACCESS_TOKEN, REFRESH_TOKEN = get_tokens_from_gist()

HEADERS = {
    "User-Agent": "plfpl-mobile/2.0.9 (Android; 11)",
    "Accept": "application/json",
    "accept-language": "en-GB,en;q=0.9",
    "X-API-Authorization": f"Bearer {ACCESS_TOKEN}" if ACCESS_TOKEN else "",
}

FPL_BOOTSTRAP = "https://fantasy.premierleague.com/api/bootstrap-static/"

# ----------------- DB HANDLING -----------------
def db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    conn.commit()
    conn.close()

init_db()

# ----------------- ROUTES -----------------
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
    try:
        r = requests.get(FPL_BOOTSTRAP, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()
        # Just show the keys of the response for now
        return {"keys": list(data.keys())}
    except Exception as e:
        return {"error": str(e)}

# ----------------- MAIN -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
