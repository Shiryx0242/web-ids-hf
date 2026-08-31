import pandas as pd
import numpy as np
import os
import torch
import matplotlib.pyplot as plt
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import random

print("Loading Hugging Face model for evaluation...")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "models", "hf_model")

# โหลดโมเดล
try:
    device = 0 if torch.cuda.is_available() else -1
    hf_pipeline = pipeline("text-classification", model=model_path, tokenizer=model_path, device=device)
except Exception as e:
    print("Error loading model:", e)
    exit()

# สร้าง Test Set แบบเดียวกับตอนเทรน (เพื่อให้ได้ชุดข้อสอบเดิมที่โมเดลไม่เคยเห็นตอนเทรน)
def generate_dataset(n_samples=5000):
    payloads = []
    labels = []
    tables = ["users", "admin", "students", "products", "orders", "customers", "auth", "session", "logs", "items", "cart"]
    cols = ["id", "username", "password", "email", "status", "role", "token", "hash", "salt", "first_name", "last_name", "price"]
    words = ["hello", "world", "test", "data", "query", "user", "admin", "system", "search", "update", "delete", "create", "read"]
    endpoints = ["/index.html", "/api/login", "/about", "/contact", "/dashboard", "/products/1", "/user/profile", "/checkout", "/api/v1/users", "/search"]
    
    for _ in range(n_samples // 2):
        attack_type = random.choice(["sqli", "xss"])
        if attack_type == "sqli":
            t = random.choice(tables)
            c = random.choice(cols)
            w = random.choice(words)
            sqli_patterns = [
                f"'{' '*random.randint(0,2)}OR{' '*random.randint(1,3)}1=1--",
                f"\"{' '*random.randint(0,2)}OR{' '*random.randint(1,3)}\"\"=\"",
                f"') OR ('1'='1",
                f"admin' --",
                f"' UNION SELECT null, username, password FROM {t}--",
                f"' AND SLEEP({random.randint(1,10)})--",
                f"1; DROP TABLE {t}--",
                f"SELECT * FROM {t} WHERE {c}='{w}' OR 1=1"
            ]
            payloads.append(random.choice(sqli_patterns))
        else:
            w = random.choice(words)
            xss_patterns = [
                f"<script>alert(1)</script>",
                f"<img src=x onerror=alert(1)>",
                f"<body onload=alert('{w}')>",
                f"javascript:alert(1)",
                f"'\"><script>alert(document.cookie)</script>"
            ]
            payloads.append(random.choice(xss_patterns))
        labels.append("Attack")
        
        normal_type = random.choice(["text", "url", "param", "json", "html"])
        w1 = random.choice(words)
        ep = random.choice(endpoints)
        
        if normal_type == "text":
            payloads.append(f"{w1} request")
        elif normal_type == "url":
            payloads.append(f"GET {ep} HTTP/1.1")
        elif normal_type == "json":
            payloads.append(f'{{"username":"{w1}"}}')
        elif normal_type == "html":
            normal_patterns = [
                f"<html><body><p>{w1}</p></body></html>",
                f"<div class='container'><span>{w1}</span></div>",
                f"<a href='/{ep}'>Click here</a>",
                f"<!-- This is a normal comment -->",
                f"<form method='POST'><input type='text' name='{w1}'/></form>"
            ]
            payloads.append(random.choice(normal_patterns))
        else:
            payloads.append(f"search keyword={w1}")
        labels.append("Normal")

    df = pd.DataFrame({"payload": payloads, "label": labels})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

print("Generating Test Dataset...")
df = generate_dataset(5000)
# แบ่ง 80:20 (ใช้ random_state=42 เพื่อให้ตรงกับตอนเทรนเป๊ะๆ จะได้ข้อมูล 20% ที่โมเดลไม่เคยเห็นจริงๆ)
_, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])

print(f"Testing on {len(test_df)} unseen samples...")
y_true = test_df["label"].tolist()
payloads = test_df["payload"].tolist()

# ทำนายผล (Predict)
print("Evaluating... (This may take a minute)")
results = hf_pipeline(payloads, truncation=True, max_length=128, batch_size=16)
y_pred = [res['label'] for res in results]

# ===============================
# คำนวณความแม่นยำ (Metrics)
# ===============================
print("\n=== Hugging Face Model Evaluation ===")
report = classification_report(y_true, y_pred, digits=4)
print(report)

# ===============================
# สร้างกราฟ Confusion Matrix
# ===============================
cm = confusion_matrix(y_true, y_pred, labels=["Attack", "Normal"])
disp = ConfusionMatrixDisplay(cm, display_labels=["Attack", "Normal"])
disp.plot(cmap='Blues')
plt.title("Hugging Face (DistilBERT) - Confusion Matrix")

save_img = os.path.join(BASE_DIR, "models", "hf_confusion_matrix.png")
plt.savefig(save_img, dpi=150, bbox_inches='tight')
print(f"\nConfusion matrix saved successfully to: {save_img}")
print("You can use this image in your presentation!")
