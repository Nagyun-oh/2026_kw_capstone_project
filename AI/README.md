# AI 보안 위협 탐지 서버

> LightGBM · RandomForest · ExtraTrees 기반 Soft Voting 앙상블 모델을 활용한  
> HTTP 요청 실시간 공격 탐지 FastAPI 서버

---

## 📁 디렉토리 구조

```
AI/
├── main.py                        # FastAPI 서버 본체
├── train_and_save_model.py        # 앙상블 모델 학습 및 저장 스크립트
├── requirements.txt               # 패키지 목록
├── model_bundle.pkl               # 학습된 모델 번들 (학습 후 자동 생성, Git 제외)
├── data_capec_multilabel.csv      # CAPEC Multilabel 데이터셋 (Git 제외)
├── cisc_normalTraffic_train.txt   # CSIC 2010 정상 요청 학습용
├── cisc_normalTraffic_test.txt    # CSIC 2010 정상 요청 검증용
└── cisc_anomalousTraffic_test.txt # CSIC 2010 공격 요청
```

---

## ⚙️ 개발 환경

| 항목 | 버전 |
|---|---|
| Python | 3.11 |
| FastAPI | 0.111.0 |
| scikit-learn | 1.5.0 |
| LightGBM | 4.3.0 |
| imbalanced-learn | 0.12.3 |
| OS | Windows 10/11 |

---

## 실행 방법 (처음 설정)

### STEP 1. 가상환경 생성 및 활성화
git clone https://github.com/Nagyun-oh/2026-KW-Capstone-Project.git

① 기존 capstone 폴더 삭제
Remove-Item -Recurse -Force capstone
② 새 가상환경 생성
python -m venv capstone

* cmd로 전환해서 실행:
VSCode 터미널 오른쪽 위에 + 옆 ∨ 버튼 클릭 → Command Prompt 선택

```bash
cd AI
python -m venv capstone
capstone\Scripts\activate
```

터미널 앞에 `(capstone)` 이 붙으면 활성화 성공.

* (capstone) 해제하는 방법 : deactivate

> PowerShell에서 스크립트 실행 오류가 나는 경우 아래 명령어 실행 후 재시도:
> ```bash
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

---

### STEP 2. 패키지 설치

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

설치 확인:

```bash
python -c "import fastapi; import lightgbm; import imblearn; print('OK')"
```

`OK` 출력되면 정상.

---

### STEP 3. 모델 학습(ver1 기준.)

> ⚠️ `model_bundle.pkl` 파일이 없을 때만 실행. 이미 있으면 STEP 4로 바로 이동.

```bash
python train_and_save_model.py
```

학습이 완료되면 아래 메시지가 출력되고 `model_bundle.pkl` 파일이 생성된다.

```
✅ 번들 저장 완료: ...model_bundle.pkl
   포함 항목: model / encoders / features / threshold / metadata
```

> ⏱️ CAPEC 데이터셋(90만 건) 포함 학습 시 30분~1시간 소요될 수 있음.

---

* 현재 버전에서는 kaggle에 업로드한 데이터셋+model_bundle_ultimate.pkl 다운받아서 실행할 것.

### STEP 4. FastAPI 서버 실행

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

아래처럼 출력되면 서버 실행 성공:

```
Loaded model bundle: ...model_bundle.pkl
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

서버 종료: **Ctrl + C**

---

### STEP 5. 동작 확인

브라우저에서 Swagger UI 접속:

```
http://localhost:8000/docs
```

`/predict` 엔드포인트에서 **Try it out** → 아래 JSON 입력 → **Execute**:

```json
{
  "method": "POST",
  "url_path": "/login.jsp",
  "query_params": "",
  "body_content": "id=admin'-- select union drop",
  "user_agent": "Mozilla/5.0",
  "ip_address": "192.168.0.55",
  "timestamp": "2026-05-18T14:00:00"
}
```

정상 응답 예시:

```json
{
  "threat_score": 0.9113,
  "ip_address": "192.168.0.55",
  "reason": "Body 공격 키워드, SQL 패턴(3개), UNION SELECT 패턴, SQL 주석 패턴"
}
```

---

## 📡 API 명세

### 기본 URL

```
http://localhost:8000
```

### 엔드포인트 목록

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/` | 서버 상태 확인 |
| GET | `/health` | 모델 로드 여부 및 서버 상태 확인 |
| POST | `/predict` | HTTP 요청 단건 분석 |
| POST | `/predict/batch` | HTTP 요청 다건 일괄 분석 |

---

### POST `/predict`

**요청 스키마 (Spring → FastAPI)**

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `method` | string | ✅ | GET / POST / PUT / DELETE |
| `url_path` | string | ✅ | URL 경로 (예: `/login.jsp`) |
| `query_params` | string | 없으면 `""` | `?` 뒤 파라미터 |
| `body_content` | string | 없으면 `""` | POST body 내용 |
| `user_agent` | string | 없으면 `""` | User-Agent 헤더 |
| `ip_address` | string | 없으면 `""` | 요청자 IP |
| `timestamp` | string | 없으면 `""` | 요청 시각 |

**응답 스키마 (FastAPI → Spring)**

| 필드 | 타입 | 설명 |
|---|---|---|
| `threat_score` | float | 공격 확률 (0.0 ~ 1.0) |
| `ip_address` | string | 공격이면 실제 IP, 정상이면 `"0.0.0.0"` |
| `reason` | string | 공격 이유, 정상이면 `"-"` |

---

## 🤖 AI 모델 구성

### 앙상블 구조

```
LightGBM (가중치 ×2)
    +
Random Forest (가중치 ×1)     →  Soft Voting  →  threat_score
    +
Extra Trees (가중치 ×1)
```

### 학습 데이터셋

| 데이터셋 | 샘플 수 | 분할 | 증강 |
|---|---|---|---|
| CSIC 2010 | 97,065건 | Train 70% / Val 10% / Test 20% | SMOTE-ENN (Train만) |
| CAPEC Multilabel | 907,815건 | Train 70% / Val 10% / Test 20% | 없음 |

### 최종 성능 (Test 기준 실측값)

| 지표 | 값 |
|---|---|
| Accuracy | 0.9598 |
| F1-Score | 0.9500 |
| AUC-ROC | 0.9931 |
| FNR (미탐률) | 5.86% |

---

## ❗ 에러 대처

| 에러 메시지 | 원인 | 해결 |
|---|---|---|
| `No module named 'imblearn'` | imbalanced-learn 미설치 | `pip install imbalanced-learn==0.12.3` |
| `cannot import name '_is_pandas_df'` | scikit-learn 버전 충돌 | `pip install scikit-learn==1.5.0 imbalanced-learn==0.12.3` |
| `KeyError: 'le_method'` | 구버전 main.py 사용 중 | 최신 main.py 로 교체 |
| `503 Model is not loaded` | model_bundle.pkl 없음 | STEP 3 (모델 학습) 먼저 실행 |
| `FileNotFoundError: cisc_*.txt` | 데이터 파일 위치 오류 | AI 폴더 안에 데이터 파일 이동 |
| 스크립트 실행 오류 (PowerShell) | 실행 정책 제한 | `Set-ExecutionPolicy RemoteSigned` |
