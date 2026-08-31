import pandas as pd
import numpy as np
import os
import random
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset
from sklearn.model_selection import train_test_split

# ===============================
# 1. Generate dataset (Reduced to 5,000 for faster CPU training)
# ===============================
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
        labels.append(1) # 1 = Attack
        
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
        labels.append(0) # 0 = Normal

    df = pd.DataFrame({"payload": payloads, "label": labels})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

print("Generating dataset...")
df = generate_dataset(5000)

print(f"Dataset size : {len(df)} samples")
print(f"Attack       : {len(df[df['label']==1])}")
print(f"Normal       : {len(df[df['label']==0])}")
print()

# ===============================
# 2. Prepare Data for Hugging Face
# ===============================
print("Loading Pre-trained Tokenizer...")
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)

def tokenize_function(examples):
    return tokenizer(examples["payload"], padding="max_length", truncation=True, max_length=128)

train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])

train_dataset = Dataset.from_pandas(train_df)
test_dataset = Dataset.from_pandas(test_df)

print("Tokenizing datasets...")
train_dataset = train_dataset.map(tokenize_function, batched=True)
test_dataset = test_dataset.map(tokenize_function, batched=True)

train_dataset = train_dataset.remove_columns(["payload", "__index_level_0__"])
test_dataset = test_dataset.remove_columns(["payload", "__index_level_0__"])
train_dataset.set_format("torch")
test_dataset.set_format("torch")

# ===============================
# 3. Model Fine-Tuning
# ===============================
print("Loading Pre-trained Model...")
id2label = {0: "Normal", 1: "Attack"}
label2id = {"Normal": 0, "Attack": 1}

model = AutoModelForSequenceClassification.from_pretrained(
    model_name, 
    num_labels=2, 
    id2label=id2label, 
    label2id=label2id
)

training_args = TrainingArguments(
    output_dir="./models/hf_results",
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    num_train_epochs=3,
    weight_decay=0.01,
    eval_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    report_to="none"
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    processing_class=tokenizer,
)

print("Training Hugging Face model...")
trainer.train()

# ===============================
# 4. Save Fine-Tuned Model
# ===============================
save_path = "./models/hf_model"
if not os.path.exists(save_path):
    os.makedirs(save_path)

print(f"\nSaving fine-tuned model to {save_path}...")
trainer.save_model(save_path)
tokenizer.save_pretrained(save_path)

print("Model saved successfully. You can now use it in app.py!")
