# AI_new — 3모델 소프트보팅 앙상블 위협 탐지 서버

Spring 백엔드 ↔ Kafka ↔ AI 서버 통신 규격은 레포 루트의 `main (1).py`(GitHub 기준 최신)를
그대로 유지하면서, AI 판정 로직만 **트랜스포머 + 트리 + 스키마 전문가** 3모델 소프트보팅
앙상블로 교체한 서버입니다. `AI_v0/main.py`, `AI_v0/main_v2.py`, 레포 루트 `main (1).py`는
전혀 건드리지 않았습니다 — 이 디렉토리는 완전히 새로운 통합 지점입니다.

## 1. 왜 이게 필요한가

- 목표1(앙상블): 트랜스포머(바이트 단위) + 트리(HistGradientBoosting) + 스키마 전문가
  (HistGradientBoosting, 애플리케이션 구조 기반) 3개를 로짓 공간 소프트보팅으로 결합합니다.
- 목표2(경량화): 예전 4모델(RF/ET/XGB/HGB) 앙상블은 pkl 하나가 3GB를 넘었습니다. 지금은
  HistGradientBoosting 단일 모델 조합으로 대체해서 트리+스키마 결합 pkl이 13.75MB입니다.
- 목표3(오탐 해결): `user_agent_encoded` 같은 출처 식별 지름길 피처를 제거하고, 규칙 게이트 +
  3모델 통계 판정을 병행해서 오탐을 줄였습니다.

## 2. 모델 구성

| 모델 | 알고리즘 | 피처 수 | 최종 하이퍼파라미터 | 역할 |
|---|---|---|---|---|
| 트랜스포머 | 바이트 단위 Transformer (hidden=96, layer=3) | 바이트 시퀀스 + 구조 피처 19개 | `AI/` 학습 파이프라인 산출물 | 내용 기반 판단 |
| 트리 | HistGradientBoostingClassifier | 28개 (`features_v2.py`) | `trial_36` | 내용+통계 기반 판단 |
| 스키마 전문가 | HistGradientBoostingClassifier | 12개 (`schema_expert.py`) | `trial_18` | 구조 기반 판단 (positive security model) |

**결합 방식**: 확률이 아니라 **로짓 공간**에서 가중평균 후 다시 확률로 변환합니다
(`soft_vote()`, `schema_expert.py`와 동일 공식).

```
weights = [transformer: 0.05, tree: 0.85, schema: 0.10]   # validation 심플렉스 그리드서치로 확정
threshold = 0.9650                                         # source_robust_score 기준 확정
```

**규칙 게이트가 먼저 온다**: `features_v2.py`의 `rule_hits()`가 SQL 논리우회, 스캐너 UA 등
결정적 공격 패턴을 임계값과 무관하게 먼저 잡습니다. 3모델 통계 판정만으로는 학습 데이터에 거의
없는 공격 패턴(예: `admin' OR '1'='1'` + `sqlmap` UA)을 결합 임계값(0.965) 미만으로 놓칠 수 있음을
실측으로 확인해서 유지합니다.

## 3. 파일 구조

```
AI_new/
├── main.py                    # FastAPI + Kafka 서버 (실제 배포 진입점)
├── schema_expert.py           # 스키마 전문가 피처 계산 + soft_vote()
├── features_v2.py             # 트리 피처 계산 + 규칙 게이트(rule_hits) + explain()
├── requirements.txt
├── models/
│   ├── model_bundle_tree_schema.pkl   # 트리(trial_36)+스키마(trial_18) 결합 배포 번들
│   ├── attack_taxonomy.json           # 트랜스포머 XAI용 공격 분류표
│   └── transformer/
│       ├── model_bundle.pkl               # 트랜스포머 원본 (파일명 변경 금지, 아래 4장 참고)
│       └── model_bundle.pkl.manifest.json # 위 pkl의 SHA-256 무결성 매니페스트
├── security_ai/                # AI/src/security_ai에서 트랜스포머 추론에 필요한 부분만 vendoring
│   ├── data/                   # HttpRecord, sanitize_record (train/serve skew 방지용)
│   ├── model/                  # HttpByteTransformer, ByteHttpTokenizer
│   ├── serving/                # ModelRuntime, model_artifact(무결성 검증), schemas
│   └── xai/                    # TransformerExplainer
```

`security_ai/serving/app.py`, `serving/kafka_worker.py`는 **의도적으로 제외**했습니다. 이유는
4장 참고.

## 4. 왜 pkl이 3개가 아니라 2개인가 / 왜 트랜스포머는 따로인가

트리와 스키마는 하나의 `model_bundle_tree_schema.pkl`로 결합했지만,
트랜스포머는 원본 파일명(`model_bundle.pkl`)과 매니페스트(`model_bundle.pkl.manifest.json`)를
그대로 유지해야 합니다.

이유: `security_ai/serving/model_artifact.py`가 트랜스포머 pkl을 로드할 때
"실제 파일명이 매니페스트의 `bundle_filename`과 정확히 일치 + 파일 바이트의 SHA-256이
매니페스트와 일치 + torch major.minor 버전 일치"를 전부 검증합니다. 이건 트랜스포머 개발
쪽에서 만든 공급망 무결성 보호 장치라, 다른 파일 안에 재포장하면 이 검증을 그대로 재사용할 수
없습니다. 3모델을 한 파일에 재포장한 비교용 산출물도 실험했지만 원본과 같은 파일 기반 무결성
검증을 그대로 적용할 수 없어 실제 배포에는 사용하지 않습니다.

## 5. Kafka/API 통신 규격 (변경 없음, `main (1).py`와 동일)

```
토픽:        ai-request-topic  (Spring → AI)
             ai-result-topic   (AI → Spring)
컨슈머 그룹: ai-service-group
```

**⚠️ 중요**: `AI_v0/main_v2.py`, 레포 루트 `main (1).py`와 토픽·컨슈머그룹이 완전히 동일합니다.
이 서버를 띄울 때 그 두 서버가 동시에 실행 중이면 안 됩니다 — 같은 컨슈머 그룹에 여러 프로세스가
붙으면 카프카가 파티션을 나눠 배정해서, 앙상블이 되는 게 아니라 요청마다 트래픽이 조용히
반씩(또는 셋 중 하나로) 분할됩니다. **셋 중 하나만 실행하세요.**

요청/응답 필드 (Spring 쪽 스키마 변경 없음):

```
Request  (Spring → FastAPI): method, url_path, query_params, body_content, user_agent,
                              ip_address, timestamp, log_id
Response (FastAPI → Spring): threat_score, ip_address, reason, log_id
```

## 6. 학습에 사용한 데이터셋

`AI_v0/data/`, `AI/data/`에 여러 공개 데이터셋 원본이 있지만, 실제로 학습(train/validation/test)에
쓴 건 4개뿐입니다 (`features_v2_dataset.parquet`, `schema_features.parquet`의 `source` 컬럼 기준,
전체 1,527,243행):

| source 값 | 데이터셋 | 행 수 | 용도 |
|---|---|---|---|
| `wcp` | WAF_Comparison | 1,012,893 | 정상 트래픽 대량 확보 (정상 93.9만/공격 7.4만) |
| `capec` | CAPEC 공격 패턴 기반 | 397,468 | 공격 다양성 (정상 14.8만/공격 25.0만) |
| `ecml` | ECML/PKDD 2007 챌린지 | 50,116 | 공격 유형 라벨 보강 |
| `csic` | CSIC 2010 (WAAD 내 사본) | 34,593 | 표준 HTTP 공격 탐지 벤치마크 |
| `httpparams` | HttpParams | 32,173 | **학습 미사용, external_eval 전용** (파라미터 값 조각만 있어 method/URL 복원 불가) |

**의도적으로 제외한 데이터셋**:
- `WEB-IDS23` (1,200만행) — 네트워크 flow 통계만 있고 HTTP 텍스트가 없어서 이 모델들과 체계가 다름
- `BAC-ML-1M` (100만행) — 라벨이 요청 내용이 아니라 서버의 인가 판정 결과라 텍스트 기반 모델
  학습에 넣으면 라벨 노이즈가 됨 (별도 context_holdout 평가 전용으로 격리)
- 최상위 `cisc/` 폴더 — WAAD 안의 CSIC 2010과 내용이 완전히 중복
- `Zenodo`(ModSecurity 실 운영 로그) — 명시적 라벨이 없어(WAF 룰 태그로만 유추 가능) 아직 미반영

데이터 포맷: `JSONL(정본, 트랜스포머용) → SQLite(색인) → Parquet(트리·스키마 전용 파생)` 3층
구조. 트리·스키마는 숫자 피처 14~28개만 필요해서, 매번 JSONL을 파싱하는 대신 컬럼형 Parquet으로
한 번 뽑아두면 학습 반복 속도가 크게 빨라집니다. 셋 다 같은 JSONL 정본에서 파생돼서 라벨/split
정의가 한 곳에서만 결정되고, 트리와 트랜스포머 모델 간 비교가 공정해집니다.

실제 최종 분할은 다음과 같습니다.

| split | 정상 | 공격 | 합계 | 용도 |
|---|---:|---:|---:|---|
| train | 795,763 | 248,117 | 1,043,880 | 모델 학습 |
| validation | 171,499 | 53,869 | 225,368 | 모델/가중치/임계값 선택 |
| test | 172,937 | 52,885 | 225,822 | 최종 내부 평가 |
| external_eval | 20,304 | 11,869 | 32,173 | HTTPParams 외부 평가 |

`features_v2_dataset.parquet`은 1,527,243행 × 60컬럼, ZSTD 압축, 약 33.50MiB입니다.
`split`, `source`, `label`, `families` 네 메타 컬럼과 body 포함 `b_` 피처 28개, body 제거 `u_`
피처 28개로 구성됩니다. 학습에서는 train의 두 변형을 함께 사용하고, 현재 모델 선택·배포 조건은
body를 제거한 `u_`를 사용합니다.

`schema_features.parquet`은 같은 1,527,243행 × 9컬럼, ZSTD 압축, 약 26.82MiB입니다. `path`,
`param_names`, 파라미터 수, 값 길이, 숫자/URL 인코딩 값 통계를 저장합니다. 라벨은
`features_v2_dataset.parquet`의 같은 행에서 가져오기 때문에 두 파일의 행 순서를 변경하면 안 됩니다.

Parquet을 선택한 이유는 열 단위 압축, 숫자 자료형 보존, 필요한 컬럼만 선택해서 읽는 기능,
Pandas/PyArrow 기반 반복 학습 속도 때문입니다. 공격 페이로드에 흔한 쉼표·따옴표·줄바꿈 때문에
생기는 CSV escaping 문제도 피할 수 있습니다.

**용량 문제로 데이터셋 원본과 대용량 pkl은 이 저장소에 포함하지 않습니다.**
Kaggle에 업로드 후 아래에 링크를 남길 예정입니다.

- 데이터셋: `(Kaggle 링크 채울 예정)`
- 운영 모델 pkl: `(Kaggle 고정 버전 링크 채울 예정)`

## 7. 설치 및 실행 방법

Windows PowerShell과 Python 3.12 기준:

```powershell
cd C:\capstone_project\2026-KW-Capstone-Project\AI_new
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**⚠️ torch==2.8.0 고정 필수** — 트랜스포머 pkl이 로드 시점에 정확히 이 major.minor 버전인지
검증합니다(다르면 `ModelArtifactError` 발생). `AI/requirements.txt`와 동일한 이유로 고정되어
있습니다 (Windows torch 2.9+ 환경에서 발생하는 `c10.dll` 회귀 회피).

모델 파일 배치 (Kaggle에서 받은 경우):
```
models/model_bundle_tree_schema.pkl        ← Kaggle에서 다운로드
models/transformer/model_bundle.pkl        ← Kaggle에서 다운로드 (파일명 절대 변경 금지)
models/transformer/model_bundle.pkl.manifest.json  ← 이미 이 저장소에 포함되어 있음
models/attack_taxonomy.json                ← 이미 이 저장소에 포함되어 있음
```

운영용 두 pkl의 현재 체크섬은 다음과 같습니다. 신뢰할 수 없는 출처의 pickle은 임의 코드를 실행할
수 있으므로 로드하지 마세요.

| 파일 | 크기 | SHA-256 |
|---|---:|---|
| `model_bundle_tree_schema.pkl` | 13.75MiB | `9A4DDDB016831B92378CB393BBA6FAE12274BBB03D3CB44E07E5C004F9BD396D` |
| `transformer/model_bundle.pkl` | 1.58MiB | `FD062264EF61B7CEF149D3B3802FFDE0B08C17EA9102463A8931D174C8FF19A3` |

Windows PowerShell에서 확인:

```powershell
Get-FileHash models\model_bundle_tree_schema.pkl -Algorithm SHA256
Get-FileHash models\transformer\model_bundle.pkl -Algorithm SHA256
```

실행:
```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

`AI_new` 밖(저장소 루트)에서 실행하려면:
```bash
python -m uvicorn AI_new.main:app --host 0.0.0.0 --port 8000 --workers 1
```
(둘 다 동작하도록 `main.py`가 자기 디렉터리를 `sys.path`에 자동으로 추가합니다.)

Kafka consumer와 모델 상태가 프로세스 안에 있으므로 운영 서버는 worker 1개를 유지합니다.

카프카 브로커 주소는 `main.py` 상단의 `KAFKA_BOOTSTRAP_SERVERS`에서 바꿀 수 있습니다
(기본값 `localhost:9092`).

## 8. API

- `GET /` — 헬스체크(간단)
- `GET /health` — 모델 로딩 상태, 앙상블 가중치/임계값, 트랜스포머 배포 계약 검증 여부
- `POST /predict` — 요청 1건 판정 (`HttpRequest` → `ThreatResponse`)
- `POST /predict/batch` — 요청 여러 건 일괄 판정

모델 로딩 확인:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

정상이라면 `model_loaded=true`, `transformer_deployment_contract_valid=true`여야 합니다. Swagger
문서는 `http://localhost:8000/docs`에서 확인할 수 있습니다.

단건 예측 예시:

```powershell
$body = @{
    log_id = 1001
    method = "GET"
    url_path = "/rest/products/search"
    query_params = "q=apple"
    body_content = ""
    user_agent = "Mozilla/5.0"
    ip_address = "127.0.0.1"
    timestamp = "2026-09-22T12:00:00+09:00"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://localhost:8000/predict `
    -ContentType "application/json" -Body $body
```

응답 예시:

```json
{
  "log_id": 1001,
  "threat_score": 0.0312,
  "ip_address": "0.0.0.0",
  "reason": "-"
}
```

공격이면 입력 IP와 탐지 근거가 반환되고, 정상이면 `ip_address="0.0.0.0"`, `reason="-"`가
반환됩니다. `/predict/batch`는 같은 요청 객체의 JSON 배열을 받습니다.

카프카가 연결되면 `ai-request-topic`을 컨슈밍해서 자동으로 판정 후 `ai-result-topic`에
결과를 보냅니다(HTTP API와 동일한 판정 로직 공유).

기본 Kafka 설정은 다음과 같습니다.

| 항목 | 값 |
|---|---|
| bootstrap server | `localhost:9092` |
| request topic | `ai-request-topic` |
| result topic | `ai-result-topic` |
| consumer group | `ai-service-group` |

## 9. 내부 평가 결과

최종 구성(Transformer 0.05 + Tree trial 36 0.85 + Schema trial 18 0.10)의 공통 test split 결과:

| 지표 | 값 |
|---|---:|
| source robust score | 0.9141 |
| ROC-AUC | 0.9947 |
| Average Precision | 0.9847 |
| F1 | 0.9015 |
| CSIC AP / FPR | 0.7702 / 0.205% |
| CAPEC FPR | 0.866% |

이 test split은 과거 평가에서도 사용된 적이 있으므로 완전히 새로운 독립 holdout 성능으로 주장하면
안 됩니다. CAPEC FPR도 출처별 목표 0.5%를 초과합니다. 최종 일반화·오탐 검증은 새로 수집한
Juice Shop holdout에서 수행해야 합니다.

## 10. 알려진 제약 사항 / 남은 작업

- **실제 카프카 왕복 테스트 미완료** — 지금까지는 카프카 브로커 없는 환경에서 `run_predict()`
  직접 호출 + FastAPI `TestClient`로만 검증했습니다. 실제 브로커 붙여서 최종 확인 필요.
- **스키마 사전(dictionary)이 잠정안** — 지금은 학습셋 혼합 코퍼스 기준(경로 29만여 개)이라
  `schema_expert.py` 설계 의도(보호 대상 앱 전용 positive security model)와 다릅니다. Juice Shop
  정상 트래픽 확보되면 사전만 교체하면 됩니다(모델 재학습 불필요).
- **트랜스포머 body 처리 조건 미확인** — production 조건(body 제거)으로 export된 확률이 맞는지
  트랜스포머 쪽 확인 대기 중.
- **트랜스포머 추론 지연시간 미측정** — 목표2(경량화) 관점에서 아직 실측 안 함.
- Codex 코드리뷰로 발견된 정확성 문제 4건(스키마 `path_depth` 학습·서빙 불일치, 트리 body 입력
  조건 불일치, 트랜스포머 동시성 락 우회, 모듈 경로 의존성)은 전부 수정 완료했습니다
  (`ai_team_sync/STATUS_tree_schema.md` 아홉 번째 업데이트 참고).

## 11. Git/Kaggle 배포 구분

Git에 포함할 파일:

- `README.md`, `main.py`, `features_v2.py`, `schema_expert.py`, `requirements.txt`
- `security_ai/**/*.py` 전체 (`security_ai/data/`도 실행 코드이므로 포함)
- `models/attack_taxonomy.json`
- `models/transformer/model_bundle.pkl.manifest.json`

Git에 포함하지 않을 파일:

- 모든 `*.pkl`
- 원본/가공 데이터셋, CSV, JSONL, Parquet, SQLite
- `_to_delete/`, 실험용 모델 바이너리, 가상환경, 캐시, 학습 중간 산출물

모델과 재학습 데이터는 Kaggle 고정 버전 링크로 배포하고 이 README의 링크·배치 경로·체크섬을
함께 갱신합니다. `build_ensemble_bundle.py`와 `experimental/`은 운영에 필요하지 않은 제작·비교
스크립트이므로 일반 배포 커밋에서는 제외할 수 있습니다.
