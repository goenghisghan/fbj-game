import os, json, sqlite3, requests
from flask import Flask, render_template, request, redirect, url_for, session as flask_session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev")

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

    file_content = list(gist_data["files"].values())[0]["content"]
    tokens = json.loads(file_content)

    return tokens.get("access_token"), tokens.get("refresh_token")


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
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
    )
    conn.commit()
    conn.close()

init_db()

# ----------------- HELPERS -----------------
def bootstrap():
    """Fetch base FPL data (players, teams, positions, events)."""
    try:
        r = requests.get(FPL_BOOTSTRAP, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()
        teams = data["teams"]
        positions = data["element_types"]
        events = data["events"]
        return data, teams, positions, events
    except Exception as e:
        print(f"⚠️ FPL API fetch failed: {e}")
        return None, [], [], []

# ----------------- ROUTES -----------------
@app.route("/")
def root():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        conn = db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users(username, password) VALUES(?, ?)", 
                        (u, generate_password_hash(p)))
            conn.commit()
            flash("✅ Registration successful, please log in")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("⚠️ Username already taken")
        finally:
            conn.close()
    return render_template("register.html")

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

@app.route("/my_squad")
def my_squad():
    if "username" not in flask_session:
        return redirect(url_for("login"))
    data, teams, positions, events = bootstrap()
    if not data:
        return render_template("error.html", message="Unable to fetch FPL data")
    # You can expand this with real squad logic
    return render_template("my_squad.html", data=data)

@app.route("/squad")
def squad():
    if "username" not in flask_session:
        return redirect(url_for("login"))
    data, teams, positions, events = bootstrap()
    if not data:
        return render_template("error.html", message="Unable to fetch FPL data")
    # Example: show teams and positions
    return render_template("squad.html", teams=teams, positions=positions)

@app.route("/league")
def league():
    if "username" not in flask_session:
        return redirect(url_for("login"))
    data, teams, positions, events = bootstrap()
    if not data:
        return render_template("error.html", message="Unable to fetch FPL data")
    return render_template("league.html", events=events, teams=teams)

# ----------------- MAIN -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
