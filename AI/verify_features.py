import requests
import json
from datetime import datetime

URL = "http://localhost:8000/predict"

# 현재 활성화된 모든 피처를 검증하기 위한 타겟 페이로드 모음
test_cases = [
    {
        "scenario": "🟢 1. 정상 요청 (대조군)",
        "expected": "위협 점수 낮음, 사유: '-'",
        "payload": {"method": "POST", "url_path": "/login", "body_content": "userid=hyunwook&password=mysecretpassword", "user_agent": "Mozilla/5.0"}
    },
    {
        "scenario": "🔴 2. 순수 특수문자 과다 (난독화/버퍼오버플로우 의심)",
        "expected": "'특수문자 과다' 출력",
        "payload": {"method": "POST", "url_path": "/search", "body_content": "query=!!!!@@@@####$$$$%%%%^^^^&&&&****()()", "user_agent": "Mozilla/5.0"}
    },
    {
        "scenario": "🔴 3. SQL Injection (키워드 + 주석 패턴)",
        "expected": "'Body 공격 키워드', 'SQL 패턴', 'SQL 주석 패턴' 출력",
        "payload": {"method": "POST", "url_path": "/login", "body_content": "username=admin'--&password=1=1 drop table users", "user_agent": "Mozilla/5.0"}
    },
    {
        "scenario": "🔴 4. SQL Injection (UNION SELECT 패턴)",
        "expected": "'UNION SELECT 패턴' 명시적 출력",
        "payload": {"method": "POST", "url_path": "/item", "body_content": "id=-1 union select 1,2,version()", "user_agent": "Mozilla/5.0"}
    },
    {
        "scenario": "🔴 5. XSS 공격 (<script> 태그 및 키워드)",
        "expected": "'XSS 패턴', '<script> 태그' 출력",
        "payload": {"method": "POST", "url_path": "/board", "body_content": "content=hello <script>alert('xss');</script> onerror=javascript:", "user_agent": "Mozilla/5.0"}
    },
    {
        "scenario": "🔴 6. Path Traversal (디렉토리 탈출)",
        "expected": "'디렉토리 탈출 패턴' 출력",
        "payload": {"method": "POST", "url_path": "/download", "body_content": "file=../../../../etc/passwd", "user_agent": "Mozilla/5.0"}
    },
    {
        "scenario": "👿 7. 끔찍한 혼종 (SQLi + XSS + Path Traversal 종합 세트)",
        "expected": "모든 피처 사유가 종합적으로 출력되어야 함",
        "payload": {"method": "POST", "url_path": "/api/upload", "body_content": "admin'-- union select <script>alert(1)</script> ../../boot.ini", "user_agent": "Mozilla/5.0"}
    }
]

log_filename = "reason_verification.md"

print(f"🚀 총 {len(test_cases)}개의 시나리오를 서버로 전송 중...")

with open(log_filename, "w", encoding="utf-8") as f:
    f.write(f"# 🎯 AI 보안 위협 탐지 피처(Reason) 검증 로그\n")
    f.write(f"**테스트 일시:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n")

    for idx, case in enumerate(test_cases, 1):
        try:
            res = requests.post(URL, json=case["payload"])
            data = res.json()
            
            # 로그 파일에 Markdown 형태로 예쁘게 기록
            f.write(f"### {case['scenario']}\n")
            f.write(f"- **기대 결과:** {case['expected']}\n")
            f.write(f"- **실제 페이로드 (Body):** `{case['payload']['body_content']}`\n")
            f.write(f"- **위협 점수 (Threat Score):** `{data['threat_score']:.4f}`\n")
            f.write(f"- **출력된 탐지 사유 (Reason):** **{data['reason']}**\n\n")
            
        except Exception as e:
            f.write(f"### {case['scenario']} - ❌ 서버 연결 에러: {e}\n\n")

print(f"✅ 검증 완료! 프로젝트 폴더에 생성된 '{log_filename}' 파일을 열어서 결과를 확인하세요.")