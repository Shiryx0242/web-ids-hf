# Web IDS Project (Hugging Face Edition)

Machine-learning-based Web Intrusion Detection System (Web IDS) powered by Deep Learning (Hugging Face `transformers`). It detects suspicious web payloads such as SQL injection and Cross-Site Scripting (XSS) with high accuracy.

---

## Overview

The project consists of two cooperating Flask applications:

1. **Web IDS (`app.py` - Port 5000)**
   - Receives payloads and processes them using a fine-tuned Hugging Face model (`distilbert-base-uncased`).
   - Acts as a Web Application Firewall (WAF) middleware for protected apps.
   - Stores detection logs in SQLite.
   - Displays a protected dashboard and log pages.
   - Sends alerts to Discord when an attack is detected.

2. **Vulnerable Test Application (`todo_app.py` - Port 5001)**
   - Provides an intentionally vulnerable local test application (SQLi on Login, XSS on Add Task).
   - Routes traffic through the Web IDS on port 5000 to demonstrate attack blocking.
   - Used for authorized security testing and presentation purposes.

---

## Features

- Deep Learning Classification via Hugging Face `pipeline`.
- High accuracy attack detection (SQLi, XSS).
- Custom dataset generation & model evaluation scripts.
- SQLite request logging with Source IP.
- Login-protected dashboard with real-time charts (Chart.js).
- Discord Alert integration.
- Separate intentionally vulnerable Todo test app for demonstration.

---

## High-Level Architecture

```mermaid
flowchart LR
    Attacker[Attacker] -->|Sends Malicious Payload| TodoApp[Vulnerable Todo App (Port 5001)]
    TodoApp -->|Routes traffic to WAF| IDS[Web IDS API (Port 5000)]
    
    IDS --> HF[Hugging Face Model (DistilBERT)]
    HF -->|Predicts 'Attack'| Alert[Discord Alert]
    HF -->|Predicts 'Attack'| Block[Returns 403 Forbidden]
    HF -->|Predicts 'Normal'| Allow[Allows Request]
    
    IDS --> Log[(SQLite Database)]
    Log --> Dashboard[Admin Dashboard]
```

---

## Local Installation

### 1. Create a virtual environment & Install dependencies

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows
source .venv/bin/activate    # macOS/Linux

pip install -r requirements.txt
```

### 2. Train the Hugging Face Model (First Time Setup)

Before running the application, you must generate the dataset and train the model:

```bash
python train_model.py
```
*Note: This will take a few minutes if running on CPU. It generates a 5,000-sample dataset and fine-tunes DistilBERT.*

### 3. Evaluate the Model (Optional)

To see the accuracy percentage and generate a Confusion Matrix:

```bash
python evaluate_model.py
```

### 4. Run the Project (Requires 2 Terminals)

**Terminal 1 (Start the WAF & Dashboard):**
```bash
python app.py
```
*Access the dashboard at `http://127.0.0.1:5000` (Admin credentials: `admin` / `admin123`)*

**Terminal 2 (Start the Vulnerable Target App):**
```bash
python todo_app.py
```
*Access the test application at `http://127.0.0.1:5001`*

---

## How to Test for Presentation

1. **SQL Injection:** Go to `http://127.0.0.1:5001/login` and enter `admin' --` as the username. The IDS will block the request.
2. **Cross-Site Scripting (XSS):** Log into the Todo app normally (`admin`/`admin123`). Add a task with payload `<script>alert(1)</script>`. The IDS will block it.
3. **Long HTML Payload:** Go to `http://127.0.0.1:5000/test`, paste 100 lines of normal HTML code, and hide `' OR 1=1 --` inside it. The model will detect the anomaly.

---

## Important Security Notice

The vulnerable test application (`todo_app.py`) contains intentional security flaws. **DO NOT** deploy `todo_app.py` to a public server without strict network isolation. It is meant for local presentation and testing only.
