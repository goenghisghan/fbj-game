import os, sqlite3, requests
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY','dev')

DB_PATH = 'users.db'

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/118.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Referer": "https://fantasy.premierleague.com/",
}

def safe_get_json(url, timeout=20):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"FPL API fetch failed for {url}: {e}")
        try: flash("⚠️ Unable to fetch FPL data","warning")
        except: pass
        return {}

FPL_BOOTSTRAP='https://fantasy.premierleague.com/api/bootstrap-static/'
FPL_FIXTURES='https://fantasy.premierleague.com/api/fixtures/'

def db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn=db(); cur=conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
    conn.commit(); conn.close()
init_db()

def get_user_id(username):
    conn=db(); cur=conn.cursor(); cur.execute('SELECT id FROM users WHERE username=?',(username,)); r=cur.fetchone(); conn.close()
    return r[0] if r else None

@app.route('/')
def root(): return redirect(url_for('login'))

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        u=request.form['username']; p=request.form['password']
        try:
            conn=db(); cur=conn.cursor(); cur.execute('INSERT INTO users(username,password) VALUES (?,?)',(u,generate_password_hash(p))); conn.commit(); conn.close()
            flash('Registered, please login.'); return redirect(url_for('login'))
        except: flash('User exists')
    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form['username']; p=request.form['password']
        conn=db(); cur=conn.cursor(); cur.execute('SELECT * FROM users WHERE username=?',(u,)); user=cur.fetchone(); conn.close()
        if user and check_password_hash(user[2],p):
            session['username']=u; return redirect(url_for('welcome'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    if 'username' not in session: return redirect(url_for('login'))
    return render_template('welcome.html')

@app.route('/squad')
def squad():
    if 'username' not in session: return redirect(url_for('login'))
    data = safe_get_json(FPL_BOOTSTRAP)
    teams={t['id']:t for t in data.get('teams',[])}; positions={1:'GK',2:'DEF',3:'MID',4:'FWD'}
    players=[]
    for p in data.get('elements',[]):
        players.append({
            'first_name':p['first_name'],'second_name':p['second_name'],
            'team_name':teams.get(p['team'],{}).get('name',''),
            'position_name':positions.get(p['element_type'],''),
            'total_points':p['total_points'],'next_opp':'-'
        })
    return render_template('squad.html',players=players)

@app.route('/my_squad')
def my_squad():
    if 'username' not in session: return redirect(url_for('login'))
    username=session['username']
    squad={'GK':None,'DEF':None,'MID':None,'FWD':None}
    return render_template('my_squad.html',username=username,squad=squad)

@app.route('/league')
def league():
    if 'username' not in session: return redirect(url_for('login'))
    league_rows=[{'username':'demo','total_lp':0,'avg_gw':0.0}]
    return render_template('league.html',league_rows=league_rows)
