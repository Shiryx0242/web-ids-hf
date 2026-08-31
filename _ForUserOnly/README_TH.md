# Web Application Intrusion Detection System (Web IDS)

## ภาพรวมระบบ

ระบบ Web Application IDS เป็นระบบตรวจจับการโจมตีที่เกิดกับ Web Application
โดยใช้ Machine Learning ในการวิเคราะห์ payload ที่ถูกส่งเข้ามา เช่น SQL Injection
และ Cross-Site Scripting (XSS)

เมื่อระบบตรวจพบการโจมตีจะ: - บันทึกข้อมูลลงฐานข้อมูล SQLite - แสดงข้อมูลใน Web
Dashboard - ส่ง Notification ไปยัง Discord

------------------------------------------------------------------------

## โครงสร้างระบบ

Client → Flask API (/detect) → Preprocessing (Vectorizer) → ML Model\
→ บันทึก Log (SQLite) → Dashboard + Discord Notification

------------------------------------------------------------------------

## โฟลเดอร์โปรเจค

    web_ids_project
    │
    ├── app.py
    ├── generate_logs.py
    ├── train_model.py
    ├── logs.db
    │
    ├── models
    │   ├── model.pkl
    │   └── vectorizer.pkl

------------------------------------------------------------------------

## การติดตั้ง

### 1. ติดตั้ง Python

แนะนำ Python 3.10 ขึ้นไป

### 2. ติดตั้ง Library

    pip install flask scikit-learn joblib requests

### 3. รันระบบ

    python app.py

ระบบจะเปิดที่

    http://127.0.0.1:5000

------------------------------------------------------------------------

## หน้าใช้งานระบบ

### Dashboard

    http://127.0.0.1:5000/dashboard

### Logs

    http://127.0.0.1:5000/logs

------------------------------------------------------------------------

## การทดสอบระบบด้วย Postman

Method

    POST

URL

    http://127.0.0.1:5000/detect

Body (JSON)

    {
     "payload": "<script>alert(1)</script>"
    }

หรือ

    {
     "payload": "' OR 1=1 --"
    }

เมื่อกด Send ระบบจะ: 1. วิเคราะห์ payload 2. แสดงผล prediction 3. บันทึก log
4. แจ้งเตือน Discord หากเป็น Attack

------------------------------------------------------------------------

## การแจ้งเตือน Discord

ระบบใช้ Discord Webhook เพื่อแจ้งเตือนเมื่อพบ Attack

ตัวอย่าง Notification

    ⚠ Web IDS Alert
    Attack Detected
    Payload: ' OR 1=1 --
    IP: 127.0.0.1

------------------------------------------------------------------------

## แนวทางการนำเสนอระบบ

1.  เปิด Dashboard
2.  ใช้ Postman ยิง Payload Attack
3.  แสดงผล Prediction
4.  เปิดหน้า Logs
5.  แสดง Discord Notification

จะทำให้เห็นลำดับการทำงานของระบบอย่างชัดเจน

------------------------------------------------------------------------

## หมายเหตุ

ผู้ใช้งานควรทดสอบระบบด้วยตนเองผ่าน Postman เพื่อให้เข้าใจลำดับการทำงานของระบบตั้งแต่

-   การรับ request
-   การตรวจจับด้วย Machine Learning
-   การบันทึก Log
-   การแจ้งเตือน
