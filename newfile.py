from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import sqlite3
from datetime import datetime
import random
import os
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------
# Config
# --------------------
app = Flask(__name__)
app.secret_key = "secret123"  # session secret (change for production)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB

DATABASE = BASE_DIR / "users.db"

# --------------------
# Database helpers
# --------------------
def get_conn():
    return sqlite3.connect(DATABASE)

def query_db(query, args=(), one=False):
    conn = get_conn()
    c = conn.cursor()
    c.execute(query, args)
    rv = c.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# --------------------
# Initialize DB (drop old and create fresh as requested)
# --------------------
def init_db():
    conn = get_conn()
    c = conn.cursor()

    # Drop old table if exists (user asked to remove existing table)
    c.execute("DROP TABLE IF EXISTS users;")

    # Create new table with avatar and progress
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            progress INTEGER DEFAULT 0
        )
    ''')

    # Insert demo users (passwords hashed)
    demo = [
        ('Karthik', 'karthik@example.com', generate_password_hash('123'), '', 0),
        ('Lucky', 'lucky@example.com', generate_password_hash('123'), '', 0)
    ]
    c.executemany("INSERT OR IGNORE INTO users (name, email, password, avatar, progress) VALUES (?, ?, ?, ?, ?)", demo)

    conn.commit()
    conn.close()
    print("✅ Database initialized and demo users inserted.")

init_db()

# --------------------
# Context processors (inject now and session user details)
# --------------------
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.context_processor
def inject_user():
    return {
        'session_user_name': session.get('user_name'),
        'session_user_email': session.get('email')
    }

# --------------------
# Utilities
# --------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

# --------------------
# Routes
# --------------------
@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('landing'))

# --------------------
# Register
# --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not email or not password:
            return render_template('registration.html', error="Email and password required!")

        if not name:
            # auto-fill name if empty
            name = email.split('@')[0]

        if password != confirm:
            return render_template('registration.html', error="Passwords do not match!")

        # ensure unique email
        exists = query_db("SELECT id FROM users WHERE email=?", (email,), one=True)
        if exists:
            return render_template('registration.html', error="Email already exists!")

        hashed = generate_password_hash(password)
        query_db("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed))

        user = query_db("SELECT * FROM users WHERE email=?", (email,), one=True)
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        session['email'] = user[2]

        return redirect(url_for('home'))

    return render_template('registration.html')

# --------------------
# Login
# --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = query_db("SELECT * FROM users WHERE email=?", (email,), one=True)
        if not user:
            return render_template('loginpage.html', error="User not found!")

        stored_hash = user[3]
        if not check_password_hash(stored_hash, password):
            return render_template('loginpage.html', error="Incorrect password!")

        # set session
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        session['email'] = user[2]

        return redirect(url_for('home'))

    return render_template('loginpage.html')

# --------------------
# Home
# --------------------
@app.route('/home')
def home():
    if 'user_id' in session:
        now = datetime.now()
        hour = now.hour

        if hour < 12:
            greeting = "Good Morning"
        elif hour < 17:
            greeting = "Good Afternoon"
        else:
            greeting = "Good Evening"

        motivations = [
            "Success is the sum of small efforts, repeated day in and day out.",
            "Believe you can and you're halfway there.",
            "Don’t watch the clock; do what it does. Keep going.",
            "Start where you are. Use what you have. Do what you can."
        ]
        motivation = random.choice(motivations)

        return render_template('homepage.html',
                               name=session.get('user_name'),
                               email=session.get('email'),
                               greeting=greeting,
                               motivation=motivation)
    return redirect(url_for('login'))

# --------------------
# Dashboard (GET shows dashboard; POST updates profile/settings)
# --------------------
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    message = None
    error = None

    if request.method == 'POST':
        # update name/email and optionally change password
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()

        cur_pwd = request.form.get('current_password', '')
        new_pwd = request.form.get('new_password', '')
        confirm_new = request.form.get('confirm_new_password', '')

        if not name or not email:
            error = "Name and email are required."
        else:
            # if changing password
            if new_pwd or confirm_new:
                if not cur_pwd:
                    error = "Enter current password to change password."
                else:
                    user = query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)
                    if not user:
                        error = "User not found."
                    else:
                        if not check_password_hash(user[3], cur_pwd):
                            error = "Current password incorrect."
                        elif new_pwd != confirm_new:
                            error = "New passwords do not match."

        if not error:
            # ensure email not used by another
            ex = query_db("SELECT * FROM users WHERE email=? AND id!=?", (email, user_id), one=True)
            if ex:
                error = "Email already used by another account."

        if not error:
            if new_pwd:
                hashed = generate_password_hash(new_pwd)
                query_db("UPDATE users SET name=?, email=?, password=? WHERE id=?", (name, email, hashed, user_id))
            else:
                query_db("UPDATE users SET name=?, email=? WHERE id=?", (name, email, user_id))

            # refresh session
            session['user_name'] = name
            session['email'] = email
            message = "Profile updated successfully."

    # fetch fresh user data
    user = query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    user_data = {
        'id': user[0],
        'name': user[1],
        'email': user[2],
        'avatar': user[4] or '',
        'progress': user[5] or 0
    }

    return render_template('userdashboard.html', user=user_data, message=message, error=error)

# --------------------
# Avatar upload endpoint
# --------------------
@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'avatar' not in request.files:
        flash("No file part")
        return redirect(url_for('dashboard'))

    file = request.files['avatar']
    if file.filename == '':
        flash("No selected file")
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        _, ext = os.path.splitext(filename)
        uid = session['user_id']
        out_name = f"user_{uid}_{int(datetime.now().timestamp())}{ext}"
        save_path = UPLOAD_DIR / out_name
        file.save(str(save_path))

        # store relative path to static folder (templates use url_for('static', filename=...))
        avatar_db_path = f"uploads/{out_name}"
        query_db("UPDATE users SET avatar=? WHERE id=?", (avatar_db_path, uid))

        # no session refresh needed for avatar (dashboard reads from DB), but you can refresh if you store in session
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid file type. Allowed: png,jpg,jpeg,gif")
        return redirect(url_for('dashboard'))

# --------------------
# Serve uploaded files (Flask already serves static, but keeping route optional)
# --------------------
@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(str(UPLOAD_DIR), filename)

# --------------------
# Set progress (demo helper)
# --------------------
@app.route('/set_progress/<int:val>')
def set_progress(val):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    v = max(0, min(100, val))
    query_db("UPDATE users SET progress=? WHERE id=?", (v, session['user_id']))
    return redirect(url_for('dashboard'))

# --------------------
# Logout
# --------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --------------------
# Other pages (ensure templates exist)
# --------------------
@app.route('/about')
def about():
    return render_template('aboutecet.html')

@app.route('/afterecet')
def after_ecet():
    return render_template('afterecet.html')

@app.route('/alerts')
def alerts():
    return render_template('ecetalerts.html')

@app.route('/doubts')
def chatbox():
    return render_template('doubtchatbox.html')

@app.route('/strategy')
def strategy():
    return render_template('preparationstrategy.html')

@app.route('/goaltracker')
def goal_tracker():
    return render_template('goaltracker.html')

@app.route('/notes')
def notes():
    return render_template('importantnotes.html')

@app.route('/landing')
def landing():
    return render_template('landingpage.html')

# --------------------
# Run
# --------------------
if __name__ == '__main__':
    app.run(debug=True)