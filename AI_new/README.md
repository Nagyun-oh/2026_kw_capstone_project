# AI_new — 3모델 소프트보팅 앙상블 위협 탐지 서버

Spring 백엔드가 Kafka(`ai-request-topic`)로 보낸 HTTP 요청을 **트랜스포머 + 트리 + 스키마 전문가**
3모델 소프트보팅 앙상블로 판정하고, 결과(공격이면 판정 근거 포함)를 `ai-result-topic`으로 돌려주는
서버입니다. Compose·CI·EC2 배포가 모두 이 디렉터리를 AI 서비스로 사용합니다.

## 1. 왜 이게 필요한가

- 목표1(앙상블): 트랜스포머(바이트 단위) + 트리(HistGradientBoosting) + 스키마 전문가
  (HistGradientBoosting, 애플리케이션 구조 기반) 3개를 로짓 공간 소프트보팅으로 결합합니다.
- 목표2(경량화): 예전 4모델(RF/ET/XGB/HGB) 앙상블([이전 모델 기록](../docs/archive/ai-v1/))은 pkl 하나가 3GB를 넘었습니다. 지금은
  HistGradientBoosting 단일 모델 조합으로 대체해서 트리+스키마 결합 pkl이 13.75MB입니다.
- 목표3(오탐 해결): `user_agent_encoded` 같은 출처 식별 지름길 피처를 제거하고, 규칙 게이트 +
  3모델 통계 판정을 병행해서 오탐을 줄였습니다.

## 2. 모델 구성

| 모델 | 알고리즘 | 피처 수 | 최종 하이퍼파라미터 | 역할 |
|---|---|---|---|---|
| 트랜스포머 | 바이트 단위 Transformer (hidden=96, layer=3) | 바이트 시퀀스 + 구조 피처 19개 | 학습 파이프라인 산출물 (저장소 외부) | 내용 기반 판단 |
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
├── features_v2.py             # 트리 피처 계산 + 규칙 게이트(rule_hits) + explain() + 근거 문자열(feature_evidence)
├── ensemble_explainer.py      # 판정 근거 분해 (TreeSHAP + 로짓 분해 → reason·explanation, 9장)
├── tests/                     # 판정 설명 테스트 (pytest)
├── requirements.txt
├── models/
│   ├── model_bundle_tree_schema.pkl   # 트리(trial_36)+스키마(trial_18) 결합 배포 번들
│   ├── attack_taxonomy.json           # 트랜스포머 XAI용 공격 분류표
│   └── transformer/
│       ├── model_bundle.pkl               # 트랜스포머 원본 (파일명 변경 금지, 아래 4장 참고)
│       └── model_bundle.pkl.manifest.json # 위 pkl의 SHA-256 무결성 매니페스트
├── security_ai/                # 학습 파이프라인의 security_ai 패키지에서 트랜스포머 추론에 필요한 부분만 vendoring
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

## 5. Kafka/API 통신 규격 (응답에 설명 필드 추가)

```
토픽:        ai-request-topic  (Spring → AI)
             ai-result-topic   (AI → Spring)
컨슈머 그룹: ai-service-group
```

**⚠️ 중요**: 같은 컨슈머 그룹(`ai-service-group`)에 **다른 모델 서버**를 함께 붙이면 카프카가
파티션을 나눠 배정해서, 앙상블이 되는 게 아니라 요청이 서버별로 조용히 나뉩니다.
**이 그룹으로는 이 서버만 실행하세요.**

요청/응답 필드 (Spring 쪽 스키마 변경 없음):

```
Request  (Spring → FastAPI): method, url_path, query_params, body_content, user_agent,
                              ip_address, timestamp, log_id
Response (FastAPI → Spring): threat_score, ip_address, reason, log_id
                             + decision_source, explanation (판정 근거 설명, 9장)
```

`decision_source`·`explanation`은 필드를 추가한 것이라 기존 소비자는 무시해도 됩니다(Spring의 기본
ObjectMapper는 모르는 필드를 무시). `reason`의 형식만 바뀌었습니다(`[규칙] …` / `[모델] …`).

입력 처리 규칙:

- 트랜스포머 입력 상한(`security_ai/serving/schemas.py`의 `PredictRequest`)을 넘는 필드는 상한까지 잘라 판정합니다.
  예전에는 검증 오류로 판정 전체가 버려져 결과가 발행되지 않았습니다. 트리·스키마 모델과 규칙 게이트는 원본 값을 씁니다.
- User-Agent가 상한(4,096자)을 넘으면 그 자체를 공격 사유(`비정상적으로 긴 User-Agent`)로 판정합니다.
- 형식이 잘못된 `ip_address`는 트랜스포머에 빈 값으로 넘기고 판정을 계속합니다.
- `ai-request-topic`에서 JSON이 아니거나 값이 비어 있는 메시지는 로그(`[Kafka AI Error] JSON이 아닌 메시지 건너뜀`)를 남기고 건너뜁니다.
  예전에는 이런 메시지 한 건이 같은 메시지를 무한히 다시 읽게 만들어 소비 전체가 멈췄습니다.

## 6. 학습에 사용한 데이터셋

여러 공개 데이터셋을 검토했지만, 실제로 학습(train/validation/test)에
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

- 데이터셋: https://www.kaggle.com/datasets/hyunwook23/capstone-new2026/settings
- 운영 모델 pkl: https://www.kaggle.com/datasets/hyunwook23/capstone-new2026/settings

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
검증합니다(다르면 `ModelArtifactError` 발생). 학습 환경과 같은 버전으로 고정되어
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

테스트 (판정 설명, Kafka 워커는 띄우지 않음):
```powershell
python -m pip install pytest
python -m pytest tests
```
모델 파일(`models/*.pkl`)이 없으면 모델이 필요한 테스트는 건너뜁니다.

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
  "reason": "-",
  "decision_source": null,
  "explanation": null
}
```

공격이면 입력 IP와 탐지 근거가 반환되고, 정상이면 `ip_address="0.0.0.0"`, `reason="-"`가
반환됩니다. `/predict/batch`는 같은 요청 객체의 JSON 배열을 받습니다.

공격 응답 예시 (`explanation`은 일부 생략, 필드 설명은 9장):

```json
{
  "log_id": 1002,
  "threat_score": 0.9991,
  "ip_address": "203.0.113.7",
  "reason": "[모델] URL 인코딩 문자 5개 [%22×4, %3D] +3.0 · 문자 비율 0.46 +1.8 · 처음 보는 경로·파라미터 조합 +1.6 · 검토 권장: 구조 특성 위주 판정",
  "decision_source": "model",
  "explanation": {
    "method": "tree_shap+logit_decomposition",
    "model_score": 0.9991,
    "logit": 7.0656,
    "threshold_logit": 3.3168,
    "base_logit": -3.595,
    "transformer_logit": 0.374,
    "adjustment": 0.0,
    "model_probabilities": {"transformer": 0.9994, "tree": 0.9982, "schema": 1.0},
    "toward_attack": [
      {"model": "tree", "feature": "encoded_char_count", "label": "URL 인코딩 문자", "value": 5,
       "display": "URL 인코딩 문자 5개", "contribution": 2.9943,
       "evidence": [{"text": "%22", "count": 4}, {"text": "%3D", "count": 1}]}
    ],
    "toward_normal": [
      {"model": "tree", "feature": "sql_keyword_count", "label": "SQL 키워드", "value": 0,
       "display": "SQL 키워드 0개", "contribution": -0.4093, "evidence": []}
    ],
    "rules": [],
    "pattern_share": 0.397,
    "review_recommended": true,
    "note": "기여도는 모델이 공격 쪽으로 기운 정도이며 공격 성공이나 피해의 증거가 아닙니다."
  }
}
```

규칙 게이트만 판정하면 `reason`은 `[규칙] UNION SELECT 구문 [union select] · 공격 도구 User-Agent [sqlmap]`처럼
걸린 규칙과 매칭된 문자열이 되고, `explanation.rules`에 같은 내용이, `toward_attack`·`toward_normal`에는
같은 요청을 3모델이 어떻게 봤는지가 들어갑니다. 규칙에 걸렸어도 3모델 점수가 임계값 이상이면
`[모델] SQL 키워드 … · 규칙도 일치: UNION SELECT 구문`처럼 모델 근거를 먼저 보여 줍니다.

카프카가 연결되면 `ai-request-topic`을 컨슈밍해서 자동으로 판정 후 `ai-result-topic`에
결과를 보냅니다(HTTP API와 동일한 판정 로직 공유).

기본 Kafka 설정은 다음과 같습니다.

| 항목 | 값 |
|---|---|
| bootstrap server | `localhost:9092` |
| request topic | `ai-request-topic` |
| result topic | `ai-result-topic` |
| consumer group | `ai-service-group` |

## 9. 판정 근거 설명 (XAI)

판정(점수·임계값·규칙)은 그대로 두고 **공격으로 판정한 요청에만** 근거를 붙입니다
(`ensemble_explainer.py`, 탐지 1건당 약 6ms). 정상 요청에는 계산하지 않습니다.

**판정 출처** (`decision_source`)

- `rule`: 규칙 게이트만 판정(3모델 점수는 임계값 미만). `reason`은 걸린 규칙과 매칭된 문자열이며, 규칙이 곧 판정 근거입니다.
- `model`: 3모델 점수가 임계값 이상. `reason`은 아래 기여도 상위 3개와 근거 문자열이고, 규칙도 함께 걸렸다면
  끝에 `규칙도 일치: …`를 붙입니다. 이때는 패턴 근거가 규칙으로 확인됐으므로 `검토 권장` 표시는 붙이지 않습니다.
- 어느 쪽이든 탐지 여부와 점수는 같습니다. 바뀌는 것은 근거를 무엇으로 보여 주느냐뿐입니다.

**기여도 분해 (TreeSHAP)** — 최종 판정 로짓은 세 모델 로짓의 가중합이고, 트리·스키마 모델
(HistGradientBoosting)의 로짓은 TreeSHAP으로 '기준값 + 피처별 기여'로 정확히 나뉩니다.

```
최종 로짓 = base_logit + Σ contribution(트리 28개 + 스키마 12개) + transformer_logit + adjustment
공격 판정: 최종 로짓 ≥ threshold_logit (= logit(0.965) ≈ 3.32)
```

- `contribution`은 최종 로짓 단위입니다(트리는 0.85×SHAP, 스키마는 0.10×SHAP). 양수면 공격 쪽입니다.
- 트랜스포머(가중치 0.05)는 바이트 입력이라 피처로 나누지 않고 `transformer_logit` 한 항목으로 둡니다.
- `adjustment`는 확률 클리핑(±13.8)으로 생긴 차이이며 보통 0입니다.
- 서버 시작 시 '기준값 + SHAP 합 = 모델 로짓'을 확인하고, 맞지 않으면(shap·sklearn 버전 불일치 등)
  설명을 끄고 기존 reason을 씁니다. 설명 중 오류가 나도 탐지 결과는 기존 reason으로 그대로 보냅니다.
- 근거 문자열(`evidence`)은 피처를 계산한 정규식을 같은 입력에 다시 적용해서 찾습니다
  (`features_v2.feature_evidence`). 트리는 body 없이 판정하므로 트리 피처의 근거도 body를 뺀 입력에서 찾습니다.

**검토 권장 표시** (`review_recommended`) — 모델 판정 중, 트리 기여에서 시그니처형 피처(기존 `explain()`이
근거로 쓰던 SQL·XSS·경로 탈출·명령어·NoSQL·템플릿 패턴, 봇 UA, URL 인코딩·특수문자 수)의 비율
(`pattern_share`)이 0.5 미만이면 표시합니다. 경로 깊이·확장자·길이·비율처럼 요청의 '모양'이 주도한 판정은
데이터셋 지름길일 수 있어서입니다. 기준 0.5는 평가 전에 정한 값입니다.

| `explanation` 필드 | 의미 |
|---|---|
| `model_score` | 3모델 결합 확률. 규칙 판정이면 `threat_score`(최소 0.90)와 다를 수 있음 |
| `logit`, `threshold_logit`, `base_logit` | 최종 로짓, 판정 기준 로짓, 기준값 |
| `transformer_logit`, `adjustment` | 트랜스포머 항목, 클리핑 보정 |
| `model_probabilities` | 모델별 단독 공격 확률 |
| `toward_attack` / `toward_normal` | 공격 쪽 상위 5개 / 정상 쪽 상위 3개 피처 (`model`, `feature`, `label`, `value`, `display`, `contribution`, `evidence`) |
| `rules` | 걸린 규칙과 매칭 문자열 (규칙 판정일 때) |
| `pattern_share`, `review_recommended` | 시그니처형 근거 비율, 검토 권장 여부 |

**census 평가** (2026-10-23, 테스트셋 `test.jsonl`의 층화 표본 86,067건 · 평가 스크립트는 저장소 미포함) — 모델 판정 탐지 35,263건
(그중 정상 라벨 2,261건). 규칙 판정 8,341건은 규칙이 곧 근거라 제외했습니다.

| 항목 | 결과 |
|---|---|
| 충실도: 지목한 피처를 정상 기준값으로 바꿨을 때 판정이 정상으로 뒤집히는 비율 | SHAP 상위 1/2/3개 65.8% / 94.5% / 97.4% (무작위 6.2% / 11.8% / 17.3%) |
| 같은 개수로 비교 (기존 reason이 피처를 언급한 27,964건, 평균 2.1개) | 기존 reason 65.4% / SHAP 83.4% / 무작위 12.6% |
| 기존 reason이 '통계적 이상'(근거 없음)이던 7,299건 | SHAP 상위 3개를 바꾸면 99.8%가 뒤집힘 |
| 커버리지 (모델 근거가 있는 설명) | 기존 79.3% → 100% |
| 검토 권장 표시 | 모델 판정의 64.8%에 표시. 표시된 쪽 오탐 9.8% vs 표시 안 된 쪽 0.3%, 오탐의 98.6%가 표시된 쪽 |
| 계산 시간 (탐지 1건) | p50 6.0ms, p95 6.6ms |

**독립 공개셋 재평가** (2026-10-25, 학습과 출처가 다른 `open_testset_v1` 304,027건) — 모델 판정 탐지 8,478건에서
충실도 SHAP 상위 1/3개 99.3% / 100% (무작위 8.9% / 24.3%). 오탐이 2건뿐이라 검토 권장의 오탐 분리 효과는 측정하지 못했습니다.

**한계**

- 기여도는 모델이 공격 쪽으로 기운 정도이지 공격 성공이나 피해의 증거가 아닙니다.
- 모델의 지름길도 그대로 드러납니다. census에서 1순위 근거가 '경로 깊이'인 모델 판정이 21.8%였고, 표본
  4,000건으로 확인하니 전부 루트 `/` 요청(WCP 출처)이었습니다. POST `/`는 트리가 body를 보지 않는데도
  경로 깊이만으로 공격 판정이 났습니다. 재학습 전까지 이런 판정은 검토 권장으로 표시됩니다.
- 검토 권장은 표시 범위가 넓습니다(모델 판정의 65%). 기준을 census로 다시 맞추면 평가 데이터에 맞춘 셈이
  되므로 Juice Shop holdout 같은 별도 데이터에서 조정하세요.
- 트랜스포머의 바이트 구간 하이라이트(`security_ai/xai/explainer.py`, Integrated Gradients)는 요청당 약
  65ms라 운영 경로에서는 켜지 않았습니다.

## 10. 내부 평가 결과

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

## 11. 알려진 제약 사항 / 남은 작업

- **카프카 왕복 확인 완료** (2026-11-01, 로컬 Compose 전체 스택) — WAF → Fluent Bit → Kafka → 백엔드 → AI →
  Kafka → 백엔드 → DB 경로로 정상·규칙 판정·모델 판정 요청 3건을 보내, 판정 결과와 설명(`reason`)이
  `detected_threats.description`에 저장되는 것을 확인했습니다. EC2는 배포 후 같은 방식으로 따로 확인해야 합니다.
- **스키마 사전(dictionary)이 잠정안** — 지금은 학습셋 혼합 코퍼스 기준(경로 29만여 개)이라
  `schema_expert.py` 설계 의도(보호 대상 앱 전용 positive security model)와 다릅니다. Juice Shop
  정상 트래픽 확보되면 사전만 교체하면 됩니다(모델 재학습 불필요).
- **트랜스포머 body 처리 조건 미확인** — production 조건(body 제거)으로 export된 확률이 맞는지
  트랜스포머 쪽 확인 대기 중.
- **트랜스포머 추론 지연시간 미측정** — 목표2(경량화) 관점에서 아직 실측 안 함.
- **판정 설명이 드러낸 지름길** — 경로 깊이 0(루트 요청), 확장자, URL 인코딩 여부(인코딩 없는 SQLi는 정상 쪽으로
  기움)가 큰 근거로 쓰입니다(9장). 재학습 때 데이터 출처 편향을 함께 확인해야 합니다.
- **규칙 게이트가 `+`를 공백으로 풀지 않음** — `features_v2.py`가 `unquote`로 디코딩해서 `"+OR+"1"="1` 같은
  SQLi를 규칙이 놓치고 모델 판정으로 넘어갑니다(census '통계적 이상' 7,299건 중 5,160건). 고치면 판정이
  바뀌므로 실험 결과와 분리해 처리하고, 모델 피처에는 적용하지 않아야 합니다(학습·서빙 분포 불일치).
- Codex 코드리뷰로 발견된 정확성 문제 4건(스키마 `path_depth` 학습·서빙 불일치, 트리 body 입력
  조건 불일치, 트랜스포머 동시성 락 우회, 모듈 경로 의존성)은 전부 수정 완료했습니다
  (`ai_team_sync/STATUS_tree_schema.md` 아홉 번째 업데이트 참고).

## 12. Git/Kaggle 배포 구분

Git에 포함할 파일:

- `README.md`, `main.py`, `features_v2.py`, `schema_expert.py`, `ensemble_explainer.py`, `requirements.txt`
- `tests/*.py`
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
