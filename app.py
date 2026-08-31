import joblib
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import sqlite3
from datetime import datetime
import requests
import urllib.parse
import math
import html as html_lib
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "super_secret_ids_key"
app.config['SESSION_COOKIE_NAME'] = 'ids_session'

DB_PATH = '/tmp/logs.db' if os.environ.get('VERCEL') == '1' else 'logs.db'

# ==============================
# Load ML model
# ==============================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from transformers import pipeline
    import torch
    model_path = os.path.join(BASE_DIR, "models", "hf_model")
    # Use GPU if available, else CPU
    device = 0 if torch.cuda.is_available() else -1
    hf_pipeline = pipeline("text-classification", model=model_path, tokenizer=model_path, device=device)
    model_error = None
except Exception as e:
    print("Warning: Could not load Hugging Face model.", e)
    hf_pipeline = None
    model_error = str(e)

# ==============================
# Discord Webhook
# ==============================

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1480176307965792399/BpllTJGok1w55SLCh_abFjGCiFg0K9kI2zOlipTtTE5wu9Z1BhzR1iZ9JarYjEfBAJcQ"

def send_discord_alert(payload, ip):
    message = {
        "content": f"""
⚠ Web IDS Alert

Attack Detected

Payload:
{payload}

IP:
{ip}

Time:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    }
    try:
        if DISCORD_WEBHOOK.startswith("http"):
            requests.post(DISCORD_WEBHOOK, json=message, timeout=3)
    except Exception as e:
        print("⚠ Discord alert failed:", e)

# ==============================
# Database Init
# ==============================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            payload TEXT,
            prediction TEXT,
            confidence REAL,
            ip TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    c.execute("SELECT * FROM admins WHERE username = 'admin'")
    if not c.fetchone():
        hashed_pw = generate_password_hash("admin123")
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", hashed_pw))
    conn.commit()
    conn.close()

init_db()

# ==============================
# Authentication
# ==============================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM admins WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row and check_password_hash(row[0], password):
            session['logged_in'] = True
            session['username'] = username
            next_url = request.args.get("next")
            return redirect(next_url or url_for('dashboard'))
        else:
            error = "Invalid username or password"

    return render_template('login.html', error=error)

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/")
def home():
    if 'logged_in' in session:
        return render_template('index.html')
    return render_template('index.html') # allow home page to be public

# ==============================
# Detect / Analyze
# ==============================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.json
    if not data:
        return jsonify({"error": "No payload"}), 400

    body = (data.get("body") or "").strip()
    query = (data.get("query_string") or "").strip()
    path = (data.get("path") or "").strip()
    
    parts = []
    if path: parts.append(path)
    if query: parts.append(query)
    if body: parts.append(body)
    
    payload = " ".join(parts)
    payload = urllib.parse.unquote(payload)

    if not payload:
        return jsonify({"prediction": "safe", "confidence": 1.0, "attack_type": "N/A"})

    if hf_pipeline:
        try:
            result = hf_pipeline(payload, truncation=True, max_length=512)[0]
            prediction = "malicious" if result['label'] == "Attack" else "safe"
            confidence = float(result['score'])
            rf_prob = confidence if prediction == "malicious" else (1.0 - confidence)
        except Exception as e:
            prediction = "safe"
            confidence = 1.0
            rf_prob = 0.0
    else:
        # Fallback if no models loaded
        prediction = "safe"
        confidence = 1.0
        rf_prob = 0.0

    ip = request.remote_addr

    # Log to DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO request_log (timestamp, payload, prediction, confidence, ip) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), payload, "Attack" if prediction == "malicious" else "Normal", confidence, ip)
    )
    conn.commit()
    conn.close()

    if prediction == "malicious":
        send_discord_alert(payload, ip)

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "attack_type": f"Model Load Error: {model_error}" if model_error else ("Unknown Threat" if prediction == "malicious" else "N/A"),
        "model_probabilities": {
            "Detection Engine": rf_prob
        }
    })

# API detect (Legacy endpoint for external use)
@app.route("/detect", methods=["POST"])
def detect():
    data = request.json
    if not data or "payload" not in data:
        return jsonify({"error": "No payload provided"}), 400
    payload = urllib.parse.unquote(data.get("payload", "").strip())
    
    if hf_pipeline:
        try:
            result = hf_pipeline(payload, truncation=True, max_length=512)[0]
            prediction = result['label']
            confidence = float(result['score'])
        except:
            prediction = "Normal"
            confidence = 1.0
    else:
        prediction = "Normal"
        confidence = 1.0

    ip = request.remote_addr
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO request_log (timestamp, payload, prediction, confidence, ip) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), payload, prediction, confidence, ip))
    conn.commit()
    conn.close()

    if prediction == "Attack":
        send_discord_alert(payload, ip)

    return jsonify({"prediction": prediction, "confidence": confidence, "ip": ip})

# ==============================
# Dashboard Views
# ==============================

@app.route("/dashboard")
@login_required
def dashboard():
    filter_type = request.args.get('filter', 'all')
    page = request.args.get('page', 1, type=int)
    limit = 10
    offset = (page - 1) * limit
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM request_log")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM request_log WHERE prediction='Attack'")
    malicious = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM request_log WHERE prediction='Normal'")
    safe = cursor.fetchone()[0]
    
    # Timeline
    cursor.execute("SELECT substr(timestamp, 1, 10) as dt, prediction, count(*) FROM request_log GROUP BY dt, prediction ORDER BY dt ASC")
    timeline_rows = cursor.fetchall()
    
    labels_set = set()
    safe_dict = {}
    malicious_dict = {}
    for r in timeline_rows:
        dt, pred, count = r[0], r[1], r[2]
        labels_set.add(dt)
        if pred == 'Normal':
            safe_dict[dt] = count
        else:
            malicious_dict[dt] = count
            
    labels = sorted(list(labels_set))
    timeline_data = {
        'labels': labels,
        'safe': [safe_dict.get(l, 0) for l in labels],
        'malicious': [malicious_dict.get(l, 0) for l in labels]
    }
    
    attack_types = {"Injection": malicious} 
    
    cursor.execute("SELECT ip, count(*) as c FROM request_log GROUP BY ip ORDER BY c DESC LIMIT 5")
    top_ips = {r[0]: r[1] for r in cursor.fetchall()}

    query = "SELECT * FROM request_log"
    params = []
    if filter_type == 'safe':
        query += " WHERE prediction='Normal'"
    elif filter_type == 'malicious':
        query += " WHERE prediction='Attack'"
        
    cursor.execute(query, params)
    total_filtered = len(cursor.fetchall())
    
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    cursor.execute(query, params)
    logs_rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for r in logs_rows:
        logs.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'source_ip': r['ip'],
            'method': 'REQ',
            'path': '/',
            'prediction': 'safe' if r['prediction'] == 'Normal' else 'malicious',
            'attack_type': 'N/A' if r['prediction'] == 'Normal' else 'Threat'
        })
        
    stats = {'total': total, 'safe': safe, 'malicious': malicious}
    total_pages = math.ceil(total_filtered / limit) if total_filtered > 0 else 1
    
    return render_template('dashboard.html', 
                          stats=stats, timeline_data=timeline_data,
                          attack_types=attack_types, top_ips=top_ips,
                          logs=logs, page=page, total_pages=total_pages, filter=filter_type)

@app.route("/test")
@login_required
def test_payload():
    return render_template('test_payload.html')

@app.route("/log/<int:id>")
@login_required
def log_detail(id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM request_log WHERE id=?", (id,))
    r = c.fetchone()
    conn.close()
    if not r:
        return "Not found", 404
        
    is_safe = (r['prediction'] == 'Normal')
    log_obj = {
        'id': r['id'],
        'timestamp': r['timestamp'],
        'source_ip': r['ip'],
        'method': 'REQ',
        'path': '/',
        'prediction': 'safe' if is_safe else 'malicious',
        'confidence': r['confidence'],
        'attack_type': 'N/A' if is_safe else 'Threat',
        'body': r['payload'],
        'model_probabilities': {
            'Engine': 1.0 - r['confidence'] if is_safe else r['confidence']
        }
    }
    return render_template('log_detail.html', log=log_obj)

# Keep the old /logs route mapping to dashboard just in case
@app.route("/logs")
@login_required
def logs_redirect():
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)