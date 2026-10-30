# test_api.py
import requests
import json

# API 서버 주소
URL = "http://localhost:8000/predict"

# 1. 완벽한 정상 요청 샘플
# CSIC 2010 학습 데이터셋 스타일의 진짜 정상 샘플
normal_sample = {
    "method": "GET",
    "url_path": "/tienda1/index.jsp",
    "query_params": "id=1",
    "body_content": "",
    "user_agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
    "ip_address": "192.168.0.15",
    "timestamp": "2026-06-28T10:00:00"
}

# 2. XSS 및 디렉토리 탈출(Path Traversal) 공격 샘플
attack_sample_1 = {
    "method": "GET",
    "url_path": "/download.php",
    "query_params": "file=../../../etc/passwd&q=<script>alert(1)</script>",
    "body_content": "",
    "user_agent": "curl/7.68.0",
    "ip_address": "172.16.0.8",
    "timestamp": "2026-06-28T10:05:00"
}

# 3. SQL Injection 공격 샘플
attack_sample_2 = {
    "method": "POST",
    "url_path": "/login.jsp",
    "query_params": "",
    "body_content": "user_id=admin'--&password=1=1 union select drop",
    "user_agent": "python-requests/2.25.1",
    "ip_address": "10.0.0.99",
    "timestamp": "2026-06-28T10:10:00"
}

samples = [
    ("✅ [정상 샘플]", normal_sample),
    ("🚨 [공격 샘플 1 - XSS & Path Traversal]", attack_sample_1),
    ("🚨 [공격 샘플 2 - SQL Injection]", attack_sample_2)
]

print("=" * 60)
print("🎯 Security Threat Detection API Test")
print("=" * 60)

for title, payload in samples:
    print(f"\n{title}")
    print(f"👉 Request: {payload['method']} {payload['url_path']}?{payload['query_params']}")
    if payload['body_content']:
        print(f"👉 Body   : {payload['body_content']}")
        
    try:
        response = requests.post(URL, json=payload)
        res_data = response.json()
        
        print(f"   위협 점수(Threat Score): {res_data['threat_score']:.4f}")
        print(f"   차단된 IP Address      : {res_data['ip_address']}")
        print(f"   탐지 사유(Reason)      : {res_data['reason']}")
    except Exception as e:
        print(f"   서버 연결 오류: {e}")