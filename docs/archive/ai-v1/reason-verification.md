# 🎯 AI 보안 위협 탐지 피처(Reason) 검증 로그
**테스트 일시:** 2026-07-14 06:52:42

---
### 🟢 1. 정상 요청 (대조군)
- **기대 결과:** 위협 점수 낮음, 사유: '-'
- **실제 페이로드 (Body):** `userid=hyunwook&password=mysecretpassword`
- **위협 점수 (Threat Score):** `0.2453`
- **출력된 탐지 사유 (Reason):** **-**

### 🔴 2. 순수 특수문자 과다 (난독화/버퍼오버플로우 의심)
- **기대 결과:** '특수문자 과다' 출력
- **실제 페이로드 (Body):** `query=!!!!@@@@####$$$$%%%%^^^^&&&&****()()`
- **위협 점수 (Threat Score):** `0.4162`
- **출력된 탐지 사유 (Reason):** **-**

### 🔴 3. SQL Injection (키워드 + 주석 패턴)
- **기대 결과:** 'Body 공격 키워드', 'SQL 패턴', 'SQL 주석 패턴' 출력
- **실제 페이로드 (Body):** `username=admin'--&password=1=1 drop table users`
- **위협 점수 (Threat Score):** `0.9254`
- **출력된 탐지 사유 (Reason):** **Body 공격 키워드, SQL 패턴(1개), SQL 주석 패턴**

### 🔴 4. SQL Injection (UNION SELECT 패턴)
- **기대 결과:** 'UNION SELECT 패턴' 명시적 출력
- **실제 페이로드 (Body):** `id=-1 union select 1,2,version()`
- **위협 점수 (Threat Score):** `0.9563`
- **출력된 탐지 사유 (Reason):** **Body 공격 키워드, SQL 패턴(2개), UNION SELECT 패턴**

### 🔴 5. XSS 공격 (<script> 태그 및 키워드)
- **기대 결과:** 'XSS 패턴', '<script> 태그' 출력
- **실제 페이로드 (Body):** `content=hello <script>alert('xss');</script> onerror=javascript:`
- **위협 점수 (Threat Score):** `0.8873`
- **출력된 탐지 사유 (Reason):** **Body 공격 키워드, XSS 패턴(7개), <script> 태그, 특수문자 과다(11개)**

### 🔴 6. Path Traversal (디렉토리 탈출)
- **기대 결과:** '디렉토리 탈출 패턴' 출력
- **실제 페이로드 (Body):** `file=../../../../etc/passwd`
- **위협 점수 (Threat Score):** `0.1522`
- **출력된 탐지 사유 (Reason):** **-**

### 👿 7. 끔찍한 혼종 (SQLi + XSS + Path Traversal 종합 세트)
- **기대 결과:** 모든 피처 사유가 종합적으로 출력되어야 함
- **실제 페이로드 (Body):** `admin'-- union select <script>alert(1)</script> ../../boot.ini`
- **위협 점수 (Threat Score):** `0.8461`
- **출력된 탐지 사유 (Reason):** **Body 공격 키워드, SQL 패턴(2개), XSS 패턴(4개), 디렉토리 탈출 패턴, UNION SELECT 패턴, <script> 태그, SQL 주석 패턴, 특수문자 과다(8개)**

