from flask import Flask, request, render_template, g, abort, redirect, session, url_for
import sqlite3
import requests
import os

app = Flask(__name__)
app.secret_key = "super_vulnerable_secret"
app.config['SESSION_COOKIE_NAME'] = 'todo_session' # ป้องกัน Cookie ชนกับ app.py

# รองรับการรันบน Serverless และตั้งค่า URL ชี้ไปที่ Render หรือ Localhost
DATABASE = '/tmp/todo_test.db' if os.environ.get('VERCEL') == '1' else 'todo_test.db'
IDS_URL = os.environ.get('IDS_URL', "http://127.0.0.1:5000/detect")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, task_name TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
        
        cur = db.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            # เพิ่มบัญชีจำลอง
            db.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
            db.execute("INSERT INTO tasks (task_name) VALUES ('ประชุมทีมงาน 10.00 น.')")
            db.commit()

# ==========================================
# 🛡️ WAF Middleware (ด่านหน้าตรวจจับการโจมตี)
# ==========================================
@app.before_request
def waf_middleware():
    payloads_to_check = []
    
    if request.method == 'GET':
        for key, value in request.args.items():
            payloads_to_check.append(value)
    elif request.method == 'POST':
        for key, value in request.form.items():
            payloads_to_check.append(value)
            
    for payload in payloads_to_check:
        try:
            res = requests.post(IDS_URL, json={"payload": payload}, timeout=2)
            if res.status_code == 200:
                data = res.json()
                if data.get("prediction") == "Attack":
                    abort(403, description="Access Denied: Malicious Request Blocked by Web Application Firewall.")
        except Exception as e:
            pass

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html', description=e.description), 403

# ==========================================
# 📝 โค้ดของเว็บ Todo List
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        db = get_db()
        cur = db.cursor()
        
        # 🚨 VULNERABLE SQL INJECTION: ไม่มีการใช้ Parameterized Query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cur.execute(query)
            user = cur.fetchone()
            if user:
                session['user'] = user[1]
                return redirect(url_for('index'))
            else:
                error = "รหัสผ่านไม่ถูกต้อง"
        except Exception as e:
            # แสดง Error ให้เห็นชัดเจนเวลาเจาะระบบ
            error = f"Database Error: {e}"
            
    return render_template('todo_login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, task_name FROM tasks")
    tasks = cur.fetchall()
        
    return render_template('todo.html', tasks=tasks, username=session['user'])

@app.route('/add', methods=['POST'])
def add_task():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    task_name = request.form.get('task_name', '')
    
    if task_name:
        # 🚨 VULNERABLE XSS: บันทึกข้อมูลลงไปตรงๆ (Stored XSS)
        db = get_db()
        db.execute("INSERT INTO tasks (task_name) VALUES (?)", (task_name,))
        db.commit()
        
    return redirect('/')

@app.route('/clear', methods=['POST'])
def clear_tasks():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    db.execute("DELETE FROM tasks")
    db.commit()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(port=5001, debug=True)
