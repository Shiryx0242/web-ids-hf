import os
import re
import sqlite3
import threading
from datetime import datetime
import requests
import urllib.parse
import math
from flask import Flask, request, jsonify, session, redirect, url_for, render_template

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
    torch.set_num_threads(1)
    torch.set_grad_enabled(False) # Save memory during inference
    model_path = os.path.join(BASE_DIR, "models", "hf_model")
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

def send_discord_alert_task(message):
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=10)
    except:
        pass

def send_discord_alert(payload, ip):
    message = {
        "content": f"⚠ Web IDS Alert\n\nAttack Detected\n\nPayload:\n{payload}\n\nIP:\n{ip}\n\nTime:\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    }
    if DISCORD_WEBHOOK.startswith("http"):
        threading.Thread(target=send_discord_alert_task, args=(message,)).start()
        return "Dispatched to background"
    return "No webhook configured"

# ==============================
# Database Initialization
# ==============================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS request_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  payload TEXT,
                  prediction TEXT,
                  confidence REAL,
                  ip TEXT)''')
    conn.commit()
    conn.close()

# Initialize DB on startup (fixes Hugging Face DB missing error)
init_db()

# ==============================
# Routes
# ==============================
@app.route("/")
def index():
    import os
    todo_url = os.environ.get("TODO_URL", "http://127.0.0.1:5001")
    return render_template('index.html', todo_url=todo_url)

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
    
    raw_payload = " ".join(parts)
    raw_payload = urllib.parse.unquote(raw_payload)

    if not raw_payload:
        return jsonify({"prediction": "safe", "confidence": 1.0, "attack_type": "N/A"})

    # Make AI "Smart" against HTML evasion by stripping HTML tags before analysis
    clean_payload = re.sub(r'<[^>]+>', ' ', raw_payload)
    clean_payload = re.sub(r'\s+', ' ', clean_payload).strip()
    if not clean_payload:
        clean_payload = raw_payload # Fallback if entirely HTML

    if hf_pipeline:
        try:
            words = clean_payload.split()
            chunk_size = 20
            chunks = [' '.join(words[i:i + chunk_size]) for i in range(0, max(1, len(words)), chunk_size)]
            if not chunks: chunks = [clean_payload]
            
            prediction = "safe"
            confidence = 1.0
            
            for chunk in chunks:
                if not chunk: continue
                result = hf_pipeline(chunk, truncation=True, max_length=512)[0]
                if result['label'] == "Attack":
                    prediction = "malicious"
                    confidence = float(result['score'])
                    break
        except Exception as e:
            prediction = "safe"
            confidence = 1.0
    else:
        prediction = "safe"
        confidence = 1.0

    ip = request.remote_addr

    # Log to DB (log the RAW payload so the user can see what was actually sent)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO request_log (timestamp, payload, prediction, confidence, ip) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), raw_payload, "Attack" if prediction == "malicious" else "Normal", confidence, ip)
    )
    conn.commit()
    conn.close()

    discord_status = "Not sent"
    if prediction == "malicious":
        discord_status = send_discord_alert(raw_payload, ip)

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "discord_status": discord_status,
        "attack_type": f"Model Load Error" if model_error else ("Unknown Threat" if prediction == "malicious" else "N/A"),
        "model_probabilities": {
            "Detection Engine": confidence if prediction == "malicious" else (1.0 - confidence)
        }
    })

@app.route("/detect", methods=["POST"])
def detect():
    data = request.json
    if not data or "payload" not in data:
        return jsonify({"error": "No payload provided"}), 400
    
    raw_payload = urllib.parse.unquote(data.get("payload", "").strip())
    
    # Smart HTML stripping
    clean_payload = re.sub(r'<[^>]+>', ' ', raw_payload)
    clean_payload = re.sub(r'\s+', ' ', clean_payload).strip()
    if not clean_payload:
        clean_payload = raw_payload
        
    if hf_pipeline:
        try:
            words = clean_payload.split()
            chunk_size = 20
            chunks = [' '.join(words[i:i + chunk_size]) for i in range(0, max(1, len(words)), chunk_size)]
            if not chunks: chunks = [clean_payload]
            
            prediction = "Normal"
            confidence = 1.0
            
            for chunk in chunks:
                if not chunk: continue
                result = hf_pipeline(chunk, truncation=True, max_length=512)[0]
                if result['label'] == "Attack":
                    prediction = "Attack"
                    confidence = float(result['score'])
                    break
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
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), raw_payload, prediction, confidence, ip))
    conn.commit()
    conn.close()

    discord_status = "Not sent"
    if prediction == "Attack":
        discord_status = send_discord_alert(raw_payload, ip)

    return jsonify({"prediction": prediction, "confidence": confidence, "ip": ip, "discord_status": discord_status})

# ==============================
# Dashboard Views
# ==============================
@app.route("/dashboard")
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
def test_payload():
    return render_template('test_payload.html')

@app.route("/log/<int:id>")
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

@app.route("/logs")
def logs_redirect():
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
