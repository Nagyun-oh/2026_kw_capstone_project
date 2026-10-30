# 🎯 7월 AI 개발 파트 목표 달성 보고서

이번 달 AI 개발 파트에서 설정한 4가지 핵심 개발 목표(작업)에 대한 수행 결과 및 달성 내역을 상세히 정리한 문서입니다. 최적화된 4개의 앙상블 모델(`model_bundle_ultimate.pkl`)을 FastAPI 서버에 성공적으로 연동하고, 실시간 탐지 테스트를 완수하여 모든 완료 기준을 100% 충족했습니다.

---

## 1. 모델 번들 실행 확인

* **목표:** FastAPI 서버 시작 시 최적화된 AI 모델이 정상적으로 로드되는지 확인
* **완료 기준:** FastAPI 서버 시작 시 모델 로딩 여부 확인
* **상태:** ✅ **완료**

### 📍 상세 내용 및 달성 결과

서버 기동 시 모델을 메모리에 안정적으로 적재하는 로직을 성공적으로 구현했습니다.

* FastAPI의 `@app.on_event("startup")` 이벤트 훅을 사용하여 서버가 실행될 때 모델 번들 파일(`model_bundle_ultimate.pkl`)이 자동으로 로딩되도록 설정했습니다.
* Optuna를 이용한 10,000회 전수조사를 통해 도출된 **글로벌 최적 가중치(`optimized_weights`)**와 **임계값(`threshold: 0.6321`)**을 시스템에 적용했습니다.
* 4개의 앙상블 모델 객체(RandomForest, ExtraTrees, XGBoost, HistGradientBoosting)가 개별적으로 정상 로드됨을 확인했습니다.

### 🧾 서버 구동 로그 증빙

서버 시작 시 터미널에 아래와 같은 로그가 출력되며 모델과 가중치가 정상적으로 적용되었음을 증명합니다.

```text
Loaded Ultimate model bundle: .../model_bundle_ultimate.pkl
Applied Weights: {'ExtraTrees': 0.3494, 'RandomForest': 0.3434, 'XGBoost': 0.2321, 'HistGradientBoosting': 0.0751}
INFO:     Application startup complete.
```

---

## 2. 입력 피처(Feature) 확정 및 추출 파이프라인

* **목표:** HTTP 요청에서 보안 위협을 판단하기 위한 핵심 데이터(피처) 정의 및 추출 로직 구현
* **완료 기준:** `method`, `path`, `query`, `body`, `user-agent`, 특수문자 수 등 정리
* **상태:** ✅ **완료**

* **목표:** 원본 HTTP 웹 요청 트래픽을 AI 모델이 학습하고 판단할 수 있는 수치형 데이터(피처)로 정제하는 파이프라인 설계
* **완료 기준:** `method`, `path`, `query`, `body`, `user-agent`, 특수문자 수 등 총 23개 피처 정의 및 동작 검증
* **상태:** ✅ **완료**

### 📍 개념 설명: 왜 피처 추출(Feature Extraction)이 필요한가?
AI 모델(머신러닝 알고리즘)은 사람이 읽는 자연어 텍스트(`"SELECT * FROM..."` 등)를 있는 그대로 이해하지 못합니다. 모델이 동작하기 위해서는 모든 입력 트래픽이 **'고정된 크기의 숫자 배열(Vector)'**로 변환되어야 합니다. 

본 프로젝트에서는 외부에서 들어오는 날것의 `HttpRequest`를 분석하여, 보안 위협의 결정적 증거가 되는 **총 23개의 핵심 보안 지표(피처)**를 정밀하게 짜내는 `build_feature_row()` 파이프라인을 구축했습니다.

---

### 📋 23개 핵심 입력 피처 명세서 (Deep Dive)

추출된 23개의 피처는 탐지 목적과 데이터의 성격에 따라 총 4개의 카테고리로 엄격하게 분류됩니다. 각 피처의 정의와 보안 관점에서의 판단 근거는 다음과 같습니다.

#### 카테고리 A. 기본 범주형 정보 (Categorical Features - 4개)
텍스트 형태의 데이터로, AI 모델이 수치로 계산할 수 있도록 고유한 숫자 ID로 변환(Label Encoding)되어 입력됩니다.

| 번호 | 피처명 (Variable Name) | 피처 설명 (Description) | 보안 관점의 의의 (Security Significance) |
| :--- | :--- | :--- | :--- |
| 1 | `method` | HTTP 요청 메서드 (GET, POST, PUT, DELETE 등) | 공격의 형태에 따라 데이터를 전송하는 방식(메서드)이 달라집니다. 대량의 악성 페이로드는 주로 POST 바디에 실려 오며, 자동화된 스캐너는 GET 요청을 남발하는 경향이 있습니다. |
| 2 | `user_agent` | 클라이언트가 보낸 브라우저 및 OS 정보 (User-Agent) | 일반적인 사용자는 Chrome, Safari 등을 쓰지만, 해킹 툴(sqlmap, nmap 등)이나 자동화 스크립트는 고유한 흔적을 남기거나 아예 비어있어(`UNKNOWN`) 정상 사용자와 쉽게 구별됩니다. |
| 3 | `url_path` | 접속을 시도한 웹 서버의 경로 및 스크립트 파일명 | 공격자들은 주로 관리자 페이지(`/admin`), 로그인 엔드포인트(`/login.jsp`), 파일 다운로드 취약점이 존재하는 웹 페이지(`/download.php`)를 집중 타격하므로 주요 탐지 지표가 됩니다. |
| 4 | `file_extension` | 요청한 파일의 확장자 (jsp, php, html, none 등) | 웹 서버의 권한을 탈취하는 '웹쉘(WebShell)' 공격이나 악성 스크립트 실행을 위해 특정 백엔드 확장자(.php, .jsp)를 강제로 호출하는 행위를 포착합니다. |

#### 카테고리 B. 길이 및 구조 통계 (Structural Features - 6개)
요청 데이터의 물리적인 크기와 구조적 깊이를 측정하여, 비정상적으로 대대적인 입력이 들어오는 변칙 행위를 잡아냅니다.

| 번호 | 피처명 (Variable Name) | 피처 설명 (Description) | 보안 관점의 의의 (Security Significance) |
| :--- | :--- | :--- | :--- |
| 5 | `url_len` | 쿼리 파라미터를 포함한 전체 URL의 글자 수 | 정상적인 웹 서핑에서는 URL이 수백 자를 넘지 않습니다. URL이 기하급수적으로 길다면 시스템 마비를 노리는 버퍼 오버플로우 공격이나 복잡한 Injection 구문이 포함되었을 가능성이 큽니다. |
| 6 | `query_len` | 주소창 뒤(`?`)에 붙는 인자(Query Parameter)의 길이 | GET 방식의 악성 스크립트 주입 공격이 발생하면 쿼리 스트링의 길이가 비정상적으로 길어집니다. |
| 7 | `body_len` | HTTP 요청 본문(POST Body) 데이터의 길이 | 사용자의 일반적인 폼 입력 값에 비해 데이터 전송량이 비정상적으로 많다면, 대량의 SQL Injection 구문이나 파일 탈취 코드가 바디에 숨겨져 들어오는 신호입니다. |
| 8 | `total_len` | URL 길이와 Body 길이를 합산한 총 글자 수 | 전체 트래픽의 규모를 거시적으로 파악하여 단일 피처 왜곡에 따른 모델의 혼선을 방지합니다. |
| 9 | `path_depth` | URL 경로의 슬래시(`/`) 개수를 기준으로 측정한 디렉토리 깊이 | 시스템 내부 깊숙한 설정 파일에 접근하려는 시도(예: 디렉토리 탐색)는 평소보다 주소 깊이가 깊어지거나 복잡한 계층을 형성하게 됩니다. |
| 10 | `param_count` | 요청에 포함된 인자 변수의 개수 (`=` 기호의 개수) | 자동화된 웹 취약점 스캐닝 장비가 수많은 변수값을 무작위로 대입(Parameter Pollution)하며 서버를 찌르는 행위를 식별합니다. |

#### 카테고리 C. 특수문자 및 인코딩 통계 (Character Analysis Features - 5개)
공격 구문 조립을 위해 필수적으로 사용되는 기호들의 밀도와 난독화(암호화) 시도를 계량화합니다.

| 번호 | 피처명 (Variable Name) | 피처 설명 (Description) | 보안 관점의 의의 (Security Significance) |
| :--- | :--- | :--- | :--- |
| 11 | `special_char_count` | 위험 특수문자(`'`, `"`, `<`, `>`, `--`, `;`, `%`, `(`, `)`, `=`)의 총 개수 | 해킹 공격 구문(SQL 연산자, HTML 태그 등)을 완성하려면 문법 구조상 특수문자가 무조건 많이 쓰입니다. 정상 트래픽과 악성 트래픽을 가르는 가장 원초적이고 강력한 지표입니다. |
| 12 | `special_char_ratio` | 전체 글자 수 대비 위험 특수문자가 차지하는 비율 (밀도) | 글자 수가 아주 긴 정상 본문 글과, 글자 수는 짧지만 특수문자로 빽빽한 악성 코드 페이로드를 정밀하게 변별하기 위한 조화 지표입니다. |
| 13 | `encoded_char_count` | URL 인코딩 기호(`%`)의 등장 횟수 | 웹 방화벽(WAF)의 단순 키워드 필터링 시스템을 우회하기 위해 공격 구문을 16진수(`%20`, `%2e` 등)로 숨겨서 보내는 난독화 공격 패턴을 탐지합니다. |
| 14 | `digit_ratio` | 전체 요청 본문에서 숫자(0~9)가 차지하는 비율 | 데이터베이스 내용을 강제로 덤프하거나 시스템 ID 값을 무작위로 대입할 때 발생하는 숫자 밀도의 급증 현상을 추적합니다. |
| 15 | `alpha_ratio` | 전체 요청 본문에서 영문자(A-Z, a-z)가 차지하는 비율 | 전체적인 텍스트 구조의 균형도를 측정하여 알파벳과 기호의 비정상적인 배치 상태를 모델에게 학습시킵니다. |

#### 카테고리 D. 보안 위협 패턴 및 시그니처 (Signature Matching Features - 8개)
알려진 웹 해킹 기법들의 고유한 특징적 문자열과 제어 구문 패턴이 포함되어 있는지 직접 검증합니다.

| 번호 | 피처명 (Variable Name) | 피처 설명 (Description) | 보안 관점의 의의 (Security Significance) |
| :--- | :--- | :--- | :--- |
| 16 | `has_keywords_query` | 주소창 쿼리에 주요 공격 키워드가 포함되어 있는지 여부 (0 또는 1) | 주소창을 통해 전송되는 값에 데이터베이스 명령어나 스크립트 예약어가 단 하나라도 존재하는지 1차 필터링합니다. |
| 17 | `has_keywords_body` | POST 본문에 주요 공격 키워드가 포함되어 있는지 여부 (0 또는 1) | 사용자가 입력하는 폼 내부나 API 전송 바디 영역에 숨겨진 악성 명령 키워드를 격리 분석합니다. |
| 18 | `sql_keyword_count` | SQL 주요 문법 키워드(`select`, `union`, `where`, `drop`, `sleep` 등)의 등장 횟수 | 숫자가 높을수록 데이터베이스를 조작하고 파괴하려는 'SQL Injection' 공격일 확률이 비약적으로 상승합니다. |
| 19 | `xss_keyword_count` | 악성 스크립트 키워드(`script`, `alert`, `onerror`, `javascript:` 등)의 등장 횟수 | 타 사용자의 브라우저에서 쿠키나 세션을 탈취하려는 'XSS(Cross-Site Scripting)' 공격을 정밀 캡처합니다. |
| 20 | `path_traversal_count` | 상위 디렉토리 이동 패턴(`../`, `..\`, `etc/passwd` 등)의 발견 횟수 | 웹 서버 경로를 탈취하여 운영체제 핵심 시스템 파일(`boot.ini`, 리눅스 계정 정보 등)을 무단으로 열람하려는 'Path Traversal' 공격을 완벽히 차단합니다. |
| 21 | `has_script_tag` | `<script` 라는 문자열이 명시적으로 포함되었는지 여부 (0 또는 1) | 브라우저 원격 제어 및 악성코드 유포 공격인 XSS의 확실한 명타(Signature)를 즉시 잡아내는 핵심 스위치입니다. |
| 22 | `has_union_select` | 한 문장 안에 `union`과 `select`가 동시에 나타났는지 여부 (0 또는 1) | 데이터베이스의 다른 테이블 정보를 강제로 결합하여 회원 정보나 비밀번호를 통째로 빼내 가는 고난도 SQL 인젝션 기법을 저격합니다. |
| 23 | `has_comment_pattern` | SQL 주석 기호(`--`, `/*`, `*/`)가 포함되어 있는지 여부 (0 또는 1) | 개발자가 짜놓은 정상 뒤쪽 쿼리 문법을 무력화시키고 인증을 우회하려는 해커들의 주석 처리 꼼수를 잡아냅니다. |

---

### ⚙️ 데이터 변환 흐름도 (Data Flow)
1. **클라이언트 요청 발생:** 웹 서비스 사용자 또는 해커가 웹 서버로 HTTP 패킷 전송
2. **FastAPI 수신:** `main.py` 서버가 데이터를 받아 `HttpRequest` 스키마 객체로 변환
3. **특징 추출:** `build_feature_row()` 작동 ➡️ 날것의 텍스트 분석 ➡️ **23개의 숫자로 매핑된 한 줄의 행(Row)** 생성
4. **인코딩 적용:** 범주형 문자열 데이터에 `LabelEncoder`를 씌워 최종 수치 행렬로 정제
5. **AI 추론 엔진 전송:** 최종 가공된 **23차원의 수치형 데이터 1행**이 최적화된 4대장 앙상블 모델로 전달되어 위험 확률(`threat_score`) 연산 시작

### 📍 상세 내용 및 달성 결과

HTTP 요청을 파싱하여 모델에 입력할 총 23개의 파생 피처(Feature)를 확정하고, 이를 추출하는 파이프라인을 구축했습니다.

* 클라이언트 요청 데이터를 받기 위해 `HttpRequest` 데이터 스키마를 정의했습니다.
* `build_feature_row()` 함수를 통해 가공되지 않은 HTTP 요청 데이터로부터 모델 학습에 사용된 23개의 핵심 피처를 계산하고 추출합니다.

### 📋 핵심 추출 피처 리스트

모델이 악의적인 패턴을 식별하기 위해 사용하는 주요 피처는 다음과 같이 4가지 카테고리로 나뉩니다.

1. **기본 정보 (Categorical):** `method`, `url_path`, `query_params`, `body_content`, `user_agent` (모델 입력을 위해 Label Encoding 적용)
2. **길이 및 통계 (Numerical):** URL 길이, Query 길이, Body 길이, 파라미터 개수(`param_count`), 디렉토리 깊이(`path_depth`)
3. **보안 위협 특화 (Character Analysis):** 특수문자 총개수(`special_char_count`), URL 인코딩 문자 개수, 영문/숫자 비율
4. **공격 시그니처 (Keyword Matching):** SQL Injection 관련 키워드 개수, XSS 관련 키워드 개수, 디렉토리 탈출(Path Traversal) 패턴 매칭 여부, `<script>` 태그 유무, SQL 주석(`--`, `/*`) 패턴 유무 등

---

## 3. 정상/공격 샘플 예측 결과 확인

* **목표:** 실제 API 서버에 트래픽을 전송하여 모델의 실시간 위협 탐지 능력을 검증
* **완료 기준:** 샘플별 `threat score` 기록
* **상태:** ✅ **완료**

### 📍 상세 내용 및 달성 결과

테스트 자동화 스크립트(`test_api.py`)를 작성하여 API 서버(`/predict` 엔드포인트)에 가상의 트래픽 샘플을 전송했습니다. 수제 Soft Voting 로직이 산출한 위협 점수(`threat_score`)와 탐지 사유가 정확히 반환되는 것을 확인했습니다. (적용된 탐지 임계값: 0.6321)

### 📊 샘플 테스트 결과 기록

#### 🟢 [정상 샘플] (CSIC 2010 도메인 트래픽 기반)

학습 데이터의 분포와 유사한 정상적인 요청을 전송했을 때의 결과입니다.

* **Request:** `GET /tienda1/index.jsp?id=1`
* **결과 분석:** 위협 점수가 임계값(0.6321) 미만이므로 **정상 통과**로 판정합니다.
* **위협 점수 (Threat Score):** `0.4263`
* **차단 여부:** IP 차단 없음 (`0.0.0.0` 반환)
* **탐지 사유:** `-`

#### 🔴 [공격 샘플 1 - XSS & Path Traversal]

악성 스크립트 실행 및 상위 디렉토리 접근을 시도하는 복합 공격 샘플입니다.

* **Request:** `GET /download.php?file=../../../etc/passwd&q=<script>alert(1)</script>`
* **결과 분석:** 위협 점수가 매우 높아 **공격으로 탐지**되었습니다.
* **위협 점수 (Threat Score):** `0.7950`
* **차단 여부:** 실제 IP 차단 대상 지정 및 백엔드에 정보 전달 (`172.16.0.8`)
* **탐지 사유:** URL 공격 키워드, XSS 패턴(4개), 디렉토리 탈출 패턴, `<script>` 태그, 특수문자 과다(8개)

#### 🔴 [공격 샘플 2 - SQL Injection]

데이터베이스 쿼리를 조작하려는 전형적인 공격 샘플입니다.

* **Request:** `POST /login.jsp?` / **Body:** `user_id=admin'--&password=1=1 union select drop`
* **결과 분석:** 명확한 악성 패턴이 다수 발견되어 **공격으로 탐지**되었습니다.
* **위협 점수 (Threat Score):** `0.9645`
* **차단 여부:** 실제 IP 차단 대상 지정 및 백엔드에 정보 전달 (`10.0.0.99`)
* **탐지 사유:** Body 공격 키워드, SQL 패턴(3개), UNION SELECT 패턴, SQL 주석 패턴

### 🧾 테스트 실행 로그 증빙

`test_api.py` 실행 결과 터미널에 출력된 실제 로그는 다음과 같습니다.

```text
(capstone) C:\capstone_project\2026-KW-Capstone-Project\AI>python test_api.py
🎯 Security Threat Detection API Test

✅ [정상 샘플]
👉 Request: GET /tienda1/index.jsp?id=1
   위협 점수(Threat Score): 0.4263
   차단된 IP Address : 0.0.0.0
   탐지 사유(Reason) : -

🚨 [공격 샘플 1 - XSS & Path Traversal]
👉 Request: GET /download.php?file=../../../etc/passwd&q=<script>alert(1)</script>
   위협 점수(Threat Score): 0.7950
   차단된 IP Address : 172.16.0.8
   탐지 사유(Reason) : URL 공격 키워드, XSS 패턴(4개), 디렉토리 탈출 패턴, <script> 태그, 특수문자 과다(8개)

🚨 [공격 샘플 2 - SQL Injection]
👉 Request: POST /login.jsp?
👉 Body : user_id=admin'--&password=1=1 union select drop
   위협 점수(Threat Score): 0.9645
   차단된 IP Address : 10.0.0.99
   탐지 사유(Reason) : Body 공격 키워드, SQL 패턴(3개), UNION SELECT 패턴, SQL 주석 패턴
```

---

## 4. 모델 없음/오류 처리

* **목표:** 모델 파일 누락 등 시스템 장애 발생 시 안정적인 예외 처리 구현
* **완료 기준:** 모델 로딩 실패 시 명확한 에러 반환
* **상태:** ✅ **완료**

### 📍 상세 내용 및 달성 결과

AI 모델 파일(`model_bundle_ultimate.pkl`)이 시스템에 존재하지 않거나, 메모리에 정상적으로 로드되지 않은 상태에서 추론 API 호출이 발생할 경우를 대비해 철저한 예외 방어 로직을 구축했습니다.

* `/predict` 및 `/predict/batch` 엔드포인트의 최상단에 검증 로직을 배치했습니다.
* 모델이 로드되지 않은 상태로 확인되면, 즉각적으로 HTTP `503 Service Unavailable` 상태 코드와 에러 메시지를 반환합니다.
* **구현된 오류 처리 코드 예시:**

```python
if model is None:
    raise HTTPException(status_code=503, detail="Model is not loaded.")
```

## 💾 훈련 데이터셋 (Dataset)

본 프로젝트의 훈련 데이터(`txt`, `csv`)는 용량 문제로 Kaggle에 호스팅되어 있습니다. 아래 링크에서 다운로드하실 수 있습니다.

* [데이터셋 다운로드 페이지로 이동 (Kaggle)]
(https://www.kaggle.com/datasets/hyunwook23/26-kw-capstone-project)

* API keys:
"""
# Install dependencies as needed:
# pip install kagglehub[pandas-datasets]
import kagglehub
from kagglehub import KaggleDatasetAdapter

# Set the path to the file you'd like to load
file_path = ""

# Load the latest version
df = kagglehub.load_dataset(
  KaggleDatasetAdapter.PANDAS,
  "hyunwook23/26-kw-capstone-project",
  file_path,
  # Provide any additional arguments like 
  # sql_query or pandas_kwargs. See the 
  # documenation for more information:
  # https://github.com/Kaggle/kagglehub/blob/main/README.md#kaggledatasetadapterpandas
)

print("First 5 records:", df.head())
"""

# Web Attack Multi-Label Dataset Analysis

## Dataset Overview

본 프로젝트에서는 웹 공격 탐지(Web Attack Detection)를 위해 다음과 같은 데이터셋들을 사용한다.

### Dataset Structure

```text
dataset/
├── cisc_normalTraffic_train.txt
├── cisc_normalTraffic_test.txt
├── cisc_anomalousTraffic_test.txt
└── data_capec_multilabel.csv
```

---

# 1. CSIC Normal Traffic Dataset

## 1.1 `cisc_normalTraffic_train.txt`

### Description

웹 애플리케이션의 정상적인 HTTP 요청(HTTP Request)만을 포함하는 학습 데이터셋이다.

### Purpose

* 정상 트래픽 패턴 학습
* 이상 탐지(Anomaly Detection) 모델 학습
* 정상 사용자 행동 모델링

### Example

```http
Start - Id: 7704
class: Valid
GET http://localhost:8080/tienda1/imagenes/nuestratierra.jpg HTTP/1.1
User-Agent: Mozilla/5.0
Pragma: no-cache
```

### Characteristics

* Class: `Valid`
* HTTP Header 포함
* GET/POST Request 포함
* Cookie, User-Agent, Referer 등 다양한 Header 정보 제공

### Applications

* One-Class SVM
* AutoEncoder
* Isolation Forest
* Normal Behavior Modeling

---

## 1.2 `cisc_normalTraffic_test.txt`

### Description

정상 트래픽에 대한 테스트 데이터셋이다.

### Purpose

모델이 정상 요청을 공격으로 오인하는지(False Positive)를 평가하기 위해 사용한다.

### Evaluation

```text
Normal → Normal : True Negative
Normal → Attack : False Positive
```

---

## 1.3 `cisc_anomalousTraffic_test.txt`

### Description

다양한 웹 공격이 포함된 테스트 데이터셋이다.

### Purpose

모델의 공격 탐지 성능을 평가한다.

### Evaluation

```text
Attack → Attack : True Positive
Attack → Normal : False Negative
```

### Included Attacks

* SQL Injection
* Cross Site Scripting (XSS)
* Path Traversal
* Command Injection
* Protocol Manipulation
* HTTP Verb Tampering

---

# 2. CAPEC Multi-Label Dataset

## File

```text
data_capec_multilabel.csv
```

### Dataset Size

| Item               | Value   |
| ------------------ | ------- |
| Number of Samples  | 907,815 |
| Number of Features | 24      |
| Number of Labels   | 14      |

---

# 2.1 Features

## Network Information

| Feature   |
| --------- |
| timestamp |
| src_ip    |
| src_port  |
| dst_ip    |
| dst_port  |

---

## HTTP Request Information

| Feature                 |
| ----------------------- |
| request_http_method     |
| request_http_request    |
| request_http_protocol   |
| request_user_agent      |
| request_referer         |
| request_host            |
| request_origin          |
| request_cookie          |
| request_content_type    |
| request_accept          |
| request_accept_language |
| request_accept_encoding |
| request_do_not_track    |
| request_connection      |
| request_body            |

---

## HTTP Response Information

| Feature                      |
| ---------------------------- |
| response_http_protocol       |
| response_http_status_code    |
| response_http_status_message |
| response_content_length      |

---

# 2.2 Multi-Label Classes

| Label | Attack Type                      |
| ----- | -------------------------------- |
| 000   | Normal                           |
| 272   | Protocol Manipulation            |
| 242   | Code Injection                   |
| 88    | OS Command Injection             |
| 126   | Path Traversal                   |
| 66    | SQL Injection                    |
| 16    | Dictionary-based Password Attack |
| 310   | Scanning for Vulnerable Software |
| 153   | Input Data Manipulation          |
| 248   | Command Injection                |
| 274   | HTTP Verb Tampering              |
| 194   | Fake the Source of Data          |
| 34    | HTTP Response Splitting          |
| 33    | HTTP Request Smuggling           |

---

# 3. Class Distribution Analysis

Total Samples:

```text
907,815
```

## Class Distribution

| Attack Class                     | Samples | Percentage |
| -------------------------------- | ------: | ---------: |
| Normal                           | 525,195 |     57.85% |
| SQL Injection                    | 250,311 |     27.57% |
| Fake the Source of Data          |  56,145 |      6.18% |
| Path Traversal                   |  20,992 |      2.31% |
| HTTP Response Splitting          |  19,738 |      2.17% |
| Code Injection                   |  15,827 |      1.74% |
| Protocol Manipulation            |   9,153 |      1.01% |
| OS Command Injection             |   7,482 |      0.82% |
| HTTP Verb Tampering              |   5,437 |      0.60% |
| Scanning for Vulnerable Software |   2,718 |      0.30% |
| Input Data Manipulation          |   2,272 |      0.25% |
| Dictionary-based Password Attack |   1,847 |      0.20% |
| HTTP Request Smuggling           |   1,059 |      0.12% |
| Command Injection                |       1 |   0.00011% |

---

# 4. Class Imbalance Analysis

## Severe Long-Tail Distribution

```text
Normal                         ████████████████████████████████
SQL Injection                  ███████████████
Fake Source of Data            ███
Path Traversal                 █
HTTP Response Splitting        █
Code Injection                 █
Protocol Manipulation          ▌
OS Command Injection           ▌
HTTP Verb Tampering            ▍
Vulnerable Software Scan       ▏
Input Data Manipulation        ▏
Dictionary Attack              ▏
HTTP Request Smuggling         ▏
Command Injection              .
```

---

## Dominant Classes

```text
Normal + SQL Injection
= 775,506 samples
= 85.42%
```

즉, 전체 데이터의 약 85%가 두 개의 클래스에 집중되어 있다.

---

## Rare Classes

```text
HTTP Request Smuggling : 1,059
Dictionary Attack      : 1,847
Command Injection      : 1
```

극단적인 데이터 불균형이 존재한다.

---

# 📦 최종 산출물 명세서: `model_bundle_ultimate.pkl` 내부 구조 분석

본 문서는 극한의 하이퍼파라미터 튜닝과 1만 번의 글로벌 가중치 전수조사를 통해 생성된 최종 AI 탐지 엔진 파일인 **`model_bundle_ultimate.pkl`**의 내부 저장 데이터 구조와 바이너리 명세를 상세히 기록한 부속 문서입니다.

이 파일은 Python의 `joblib` 라이브러리를 통해 압축 저장된 객체(Serialized Object)로, 웹 보안 위협을 실시간으로 판별하기 위한 **모델, 인코더, 최적 가중치, 탐지 임계값 등 모든 핵심 지표가 단 하나의 꾸러미로 통합된 마크다운 마스터피스**입니다.

---

## 🏗️ 1. 전체 아키텍처 개요 (Conceptual Architecture)

`main.py` 서버가 구동될 때 이 `.pkl` 파일을 로드하면 메모리상에 다음과 같은 딕셔너리(Dictionary) 구조의 데이터 맵이 펼쳐지며 실시간 탐지 엔진이 활성화됩니다.

```text
model_bundle_ultimate.pkl (Dict)
 ├── ["models"] (Dict) ───────────────► 4대장 최적화 ML 모델 객체 (RF, ET, XGB, HGB)
 ├── ["optimized_weights"] (Dict) ────► 9 : 9 : 6 : 2 수학적 가중치 비율
 ├── ["threshold"] (Float) ───────────► 0.6321 철벽 탐지 기준선
 ├── ["encoders"] (Dict) ─────────────► 웹 트래픽 변환용 LabelEncoder 객체 4개
 └── ["features"] (List) ─────────────► 23차원 입력 피처 변수명 배열
```

## 🔍 2. 세부 데이터 객체 명세 (Data Component Details)
* 1️⃣ bundle["models"] : 극한 튜닝된 4대장 독립 인공지능 (AI Models)
파이썬의 머신러닝 라이브러리(scikit-learn, xgboost)로 학습이 완벽히 끝난 4개의 모델 바이너리 객체가 딕셔너리 형태로 들어있습니다. 서버가 요청을 받으면 이 4개의 두뇌가 동시에 굴러가며 확률을 계산합니다.

* models["RandomForest"]: 44층 깊이로 깊고 꼼꼼하게 해킹 로그를 분석하는 심층 나무 모델 객체.

* models["ExtraTrees"]: 무작위 분할 방식을 채택하여 신종/변칙 공격(Zero-Day)을 유연하게 잡아내는 창의적 나무 모델 객체.

* models["XGBoost"]: 941개의 얕은 나무를 연속으로 배열하여 남들이 놓친 미세한 오답을 초고속으로 정밀 타격하는 부스팅 모델 객체.

* models["HistGradientBoosting"]: 데이터를 구간별 히스토그램으로 뭉뚱그려 분석함으로써 극단적인 오탐을 부드럽게 방지해 주는 방패 모델 객체.

* 2️⃣ bundle["optimized_weights"] : 1만 번 조사를 통해 찾은 황금 가중치 (Weights)
* 각 모델의 의견을 최종 결과에 얼마나 반영할지 결정하는 수학적 가중치 맵입니다. 10,000번의 시뮬레이션을 통해 F1-Score가 최고점을 찍은 시점의 확률 분배 비율이 저장되어 있습니다.

* "ExtraTrees": 0.3494 (약 35%) ➡️ 정수 환산 비중: 9

* "RandomForest": 0.3434 (약 34%) ➡️ 정수 환산 비중: 9

* "XGBoost": 0.2321 (약 23%) ➡️ 정수 환산 비중: 6

* "HistGradientBoosting": 0.0751 (약 8%) ➡️ 정수 환산 비중: 2

* 의의: 이 비율 데이터를 파일에 함께 내장함으로써, 추후 코드를 수정하지 않고도 파일 로드만으로 9:9:6:2 소프트 보팅 결합 수식이 즉시 작동합니다.

* 3️⃣ bundle["threshold"] : 철벽의 탐지 임계값 (Optimal Threshold)
* 저장된 값: 0.6321 (Float)

* 의의: 4대장 모델의 확률을 가중치 비율로 결합한 최종 위협 점수(Threat Score)가 정확히 0.6321 이상일 때만 실제 해킹 공격(High/Medium 위협)으로 간주하도록 방어벽을 세운 기준선입니다. 50%라는 일반적인 기준 대신 이 수치를 파일에 박아둠으로써 오탐률을 0%에 가깝게 낮추는 보안 튜닝이 완성되었습니다.

* 4️⃣ bundle["encoders"] : 문자열 변환용 범주형 데이터 변환기 (Label Encoders)
* 텍스트로 구성된 실시간 웹 로그 파라미터를 AI가 처리할 수 있는 정수(Integer) 데이터로 변환해 주는 LabelEncoder 객체 4개가 딕셔너리로 내장되어 있습니다.

* encoders["method"]: GET ➡️ 1, POST ➡️ 2 형태로 변환

* encoders["user_agent"]: 수만 가지의 브라우저 문자열을 고유 숫자 ID로 매핑

* encoders["url_path"]: 웹 서버 요청 URI 경로를 수치화

* encoders["file_extension"]: .jsp, .php, .html 등의 확장자를 숫자로 인코딩

* 특징: 학습 시 본 적 없는 완전히 새로운 브라우저나 경로가 들어오면 에러를 내는 대신 안전하게 UNKNOWN이라는 예약된 숫자 코드로 자동 변환하는 방어 로직이 인코더 객체 내부에 심어져 있습니다.

* 5️⃣ bundle["features"] : 23차원 입력 피처 배열 (Features List)
* 저장된 값: ['method_encoded', 'user_agent_encoded', ..., 'has_comment_pattern']

* 의의: 모델이 학습했던 23개 피처의 정확한 순서와 명칭이 저장된 리스트입니다. 실시간으로 웹 트래픽 피처를 추출할 때, 데이터의 순서가 뒤바뀌어 AI가 엉뚱한 판단을 내리지 않도록 순서를 강제하고 통제하는 정렬 가이드 역할을 합니다.

### 🛡️ 아키텍처 관점의 효과

이러한 예외 처리를 통해 백엔드(Spring) 서버는 AI 서버의 상태(장애 또는 로딩 실패)를 명확히 인지할 수 있습니다. 이를 바탕으로 트래픽을 일시적으로 우회시키거나 관리자에게 알림을 보내는 등의 후속 폴백(Fallback) 조치를 안전하게 취할 수 있는 견고한 아키텍처를 완성했습니다.
