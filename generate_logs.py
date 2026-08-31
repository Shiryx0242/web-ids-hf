import requests
import random
import time

url = "http://127.0.0.1:5000/detect"

payloads = [
"hello world",
"login request",
"normal search",
"product id=123",
"test request",
"' OR 1=1 --",
"SELECT * FROM users",
"<script>alert(1)</script>",
"DROP TABLE users",
"<img src=x onerror=alert(1)>"
]

for i in range(30):

    payload = random.choice(payloads)

    r = requests.post(
        url,
        json={"payload": payload}
    )

    print(r.json())

    time.sleep(0.3)