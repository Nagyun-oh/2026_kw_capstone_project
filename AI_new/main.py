"""
FastAPI Server for Real-Time Web Attack Detection (3-Model Soft-Voting Ensemble)

카프카/FastAPI 통신 규격은 기존 `main (1).py`(레포 루트, GitHub 기준 최신)를 그대로 유지한다.
바뀐 건 AI 내부 판정 로직뿐이다: 4대장(RF/ET/XGB/HGB) 고정가중 앙상블 대신,
트랜스포머(바이트 단위) + 트리(HistGB, 28피처) + 스키마 전문가(HistGB, 12피처) 3모델을
로짓 공간 소프트보팅으로 결합한다 (ai_team_sync/05-3모델-앙상블-최종결과.md 참고).

■ 파이프라인 통신 규격 (변경 없음):
  - Spring → FastAPI (Request): method, url_path, query_params, body_content, user_agent,
    ip_address, timestamp, log_id
  - FastAPI → Spring (Response): threat_score, ip_address, reason, log_id
  - Kafka 토픽/컨슈머그룹: ai-request-topic / ai-result-topic / ai-service-group (변경 없음)

■ 실행 전제 조건:
  - models/model_bundle_tree_schema.pkl (트리 trial_36 + 스키마 trial_18 결합 배포 번들,
    build_ensemble_bundle.py 산출물. joblib(lzma) 압축, 단일 파일)
  - models/transformer/model_bundle.pkl (트랜스포머, AI/08_export_model_bundle.py 산출물)
  - models/attack_taxonomy.json         (트랜스포머 XAI용 공격 분류표)

■ 왜 트랜스포머는 트리/스키마와 한 파일로 합치지 않았나:
  `security_ai/serving/model_artifact.py`가 트랜스포머 .pkl을 "파일명이 매니페스트와 정확히
  일치 + SHA-256 일치 + torch 버전 일치"를 전제로 검증하는 독립 무결성 검증 대상으로 설계해뒀다
  (공급망 보호 목적, 트랜스포머 쪽 팀이 만든 장치). 다른 파일 안에 재포장하면 이 검증이 깨지거나
  검증 로직을 우회해야 해서, 트랜스포머만 원본 파일명 그대로 별도 유지한다. 트리+스키마는 원래
  이런 무결성 검증 장치가 없는 순수 sklearn 객체라 하나로 합쳐도 문제없다.

■ 중요 — 카프카 운영 주의사항:
  이 서버는 `AI_v0/main_v2.py`, `main (1).py`와 **동일한 토픽/컨슈머그룹**을 쓴다. 이 서버를
  띄울 때는 그 두 서버가 동시에 실행 중이지 않은지 반드시 확인할 것 — 같은 컨슈머 그룹에 여러
  프로세스가 붙으면 카프카가 파티션을 나눠 배정해서 메시지가 서버들 사이에 무작위로 쪼개진다
  (앙상블이 아니라 트래픽이 조용히 분할되는 결과가 된다). 상세: ai_team_sync/DECISIONS_LOG.md.
"""

from pathlib import Path
import json
import os
import sys
import threading
import time

# 저장소 루트에서 `import AI_new.main` / `uvicorn AI_new.main:app`으로 실행하거나, 다른 cwd에서
# 임포트되는 경우에도 features_v2/schema_expert/security_ai를 항상 찾도록 이 파일 위치를
# sys.path에 명시적으로 추가한다 (원래는 `cd AI_new && uvicorn main:app`로만 실행 가능했음).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────
# Kafka 설정 부분 (main (1).py와 완전히 동일 — 바꾸지 않음)
from kafka import KafkaConsumer, KafkaProducer

kafka_stop_event = threading.Event()
kafka_consumer = None
kafka_producer = None

# AI 서버 로컬 실행 -> localhost:9092 (현재)
# AI 서버 Docker 실행 -> kafka:29092 (compose에서 KAFKA_BOOTSTRAP_SERVERS 환경변수로 전달)
KAFKA_BOOTSTRAP_SERVERS = [
    server.strip()
    for server in os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092").split(",")
    if server.strip()
]
AI_REQUEST_TOPIC = "ai-request-topic"
AI_RESULT_TOPIC = "ai-result-topic"
AI_CONSUMER_GROUP = "ai-service-group"
# ─────────────────────────────────────────────────────────

# AI 내부 로직 — 여기서부터 3모델 앙상블로 교체됨
from features_v2 import FEATURES, CATEGORICAL, build_feature_row, rule_hits, explain
import schema_expert as se
from security_ai.serving.predictor import ModelRuntime
from security_ai.serving.schemas import PredictRequest

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
TREE_SCHEMA_BUNDLE_PATH = MODELS_DIR / "model_bundle_tree_schema.pkl"
TRANSFORMER_BUNDLE_PATH = MODELS_DIR / "transformer" / "model_bundle.pkl"
TRANSFORMER_MANIFEST_PATH = MODELS_DIR / "transformer" / "model_bundle.pkl.manifest.json"
TRANSFORMER_TAXONOMY_PATH = MODELS_DIR / "attack_taxonomy.json"

# 3모델 소프트보팅 가중치 + 결합 임계값
# (ai_team_sync/05-3모델-앙상블-최종결과.md — validation 심플렉스 그리드서치로 확정)
ENSEMBLE_WEIGHTS = np.array([0.05, 0.85, 0.10])  # [transformer, tree, schema]
ENSEMBLE_THRESHOLD = 0.9650

app = FastAPI(
    title="보안 위협 탐지 API",
    description="Spring 서버로부터 HTTP 요청 데이터를 받아 위협 여부를 판별합니다 (3모델 앙상블).",
    version="5.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 전역 모델 상태
tree_model = None
tree_vocab = None
schema_model = None
schema_dict = None
transformer_runtime: ModelRuntime | None = None
models_ready = False


class HttpRequest(BaseModel):
    log_id: int | None = None       # 추가된 데이터 컬럼 (Spring <-> Kafka <-> AI Server 통신을 위해 필요함)
    method: str
    url_path: str
    query_params: str = ""
    body_content: str = ""
    user_agent: str = ""
    ip_address: str = ""    # 요청 IP
    timestamp: str = ""     # 요청 시각


class ThreatResponse(BaseModel):
    log_id: int | None = None  # 추가된 데이터 컬럼 (Spring <-> Kafka <-> AI Server 통신을 위해 필요함)
    threat_score: float   # 3모델 소프트보팅 결합 확률 (0.0 ~ 1.0)
    ip_address:   str     # 공격이면 실제 IP, 정상이면 "0.0.0.0"
    reason:       str     # 왜 위협인지 (정상이면 "-")


# ─────────────────────────────────────────────────────────
# 트리용 인코딩 (main_v2.py의 to_vector와 동일한 방식)
def tree_to_vector(row: dict) -> np.ndarray:
    v = []
    for f in FEATURES:
        if f == "method_encoded":
            m = tree_vocab["method"]
            v.append(m.get(row["method"], m["__OTHER__"]))
        elif f == "file_extension_encoded":
            m = tree_vocab["file_extension"]
            v.append(m.get(row["file_extension"], m["__OTHER__"]))
        else:
            v.append(row[f])
    return np.array([v], dtype=np.float32)


def _logit(p, eps=1e-6):
    p = np.clip(p, eps, 1 - eps)
    return np.log(p / (1 - p))


def soft_vote(probas, weights):
    """schema_expert.py의 soft_vote()와 완전히 동일한 로짓공간 가중평균."""
    probas = np.asarray(probas, dtype=np.float64)
    w = np.asarray(weights, dtype=np.float64)
    w = w / w.sum()
    z = np.tensordot(w, _logit(probas), axes=1)
    return 1.0 / (1.0 + np.exp(-z))


@app.on_event("startup")
def load_model() -> None:
    global tree_model, tree_vocab, schema_model, schema_dict, transformer_runtime, models_ready

    missing = [p for p in (TREE_SCHEMA_BUNDLE_PATH, TRANSFORMER_BUNDLE_PATH,
                            TRANSFORMER_MANIFEST_PATH, TRANSFORMER_TAXONOMY_PATH) if not p.exists()]
    if missing:
        print(f"[AI] 모델 파일 누락: {missing}")
        return

    # 트리 + 스키마 결합 배포 번들 (build_ensemble_bundle.py 산출물, 단일 파일)
    ts_bundle = joblib.load(TREE_SCHEMA_BUNDLE_PATH)
    tree_bundle = ts_bundle["tree"]
    schema_bundle = ts_bundle["schema"]

    tree_model = tree_bundle["model"]
    tree_vocab = tree_bundle["vocab"]
    try:
        tree_model.n_jobs = 1
    except Exception:
        pass
    print(f"[AI] 트리 모델 로드 완료 ({tree_bundle.get('model_type')})")

    schema_model = schema_bundle["model"]
    schema_dict = schema_bundle["dictionary"]
    try:
        schema_model.n_jobs = 1
    except Exception:
        pass
    print(f"[AI] 스키마 전문가 로드 완료 ({schema_bundle.get('model_type')}) "
          f"| 사전 경로수={len(schema_dict['path_cnt']):,} ({schema_bundle.get('dictionary_note', '')})")

    bundled_weights = ts_bundle.get("ensemble", {}).get("weights")
    bundled_threshold = ts_bundle.get("ensemble", {}).get("threshold")
    if bundled_weights is not None and bundled_threshold is not None:
        expected = {"transformer": ENSEMBLE_WEIGHTS[0], "tree": ENSEMBLE_WEIGHTS[1], "schema": ENSEMBLE_WEIGHTS[2]}
        if bundled_weights != expected or bundled_threshold != ENSEMBLE_THRESHOLD:
            print(f"[AI][경고] 번들 내 앙상블 메타데이터가 main.py 상수와 다름! "
                  f"번들={bundled_weights}/{bundled_threshold} vs 코드={expected}/{ENSEMBLE_THRESHOLD}")

    manifest = json.loads(TRANSFORMER_MANIFEST_PATH.read_text(encoding="utf-8"))
    transformer_runtime = ModelRuntime(
        TRANSFORMER_BUNDLE_PATH,
        taxonomy_path=TRANSFORMER_TAXONOMY_PATH,
        require_deployment=True,
        expected_artifact_sha256=manifest["bundle_sha256"],
    )
    print(f"[AI] 트랜스포머 로드 완료 ({transformer_runtime.model_version}) "
          f"| deployment_contract_valid={transformer_runtime.provenance.deployment_contract_valid}")

    models_ready = True
    print(f"[AI] 3모델 준비 완료 | 가중치(transformer/tree/schema)={ENSEMBLE_WEIGHTS.tolist()} "
          f"| 결합 임계값={ENSEMBLE_THRESHOLD}")

    # ─────────────────────────────────────────────────────────
    # Kafka worker thread
    # -> FastAPI 서버가 켜지면, Kafka consumer도 백그라운드에서 같이 켜짐.
    thread = threading.Thread(target=kafka_worker, daemon=True)
    thread.start()
    print("[Kafka AI] background worker started")
    # ─────────────────────────────────────────────────────────


@app.get("/")
def root():
    return {"status": "running", "message": "Security threat detection API is running."}


@app.get("/health")
def health_check():
    return {
        "status": "healthy" if models_ready else "loading",
        "model_loaded": models_ready,
        "ensemble_weights": {"transformer": ENSEMBLE_WEIGHTS[0], "tree": ENSEMBLE_WEIGHTS[1],
                              "schema": ENSEMBLE_WEIGHTS[2]},
        "threshold": ENSEMBLE_THRESHOLD,
        "transformer_model_version": transformer_runtime.model_version if transformer_runtime else None,
        "transformer_deployment_contract_valid": (
            transformer_runtime.provenance.deployment_contract_valid if transformer_runtime else None
        ),
    }


def run_predict(req: HttpRequest) -> ThreatResponse:
    if not models_ready:
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    # 규칙 게이트/설명(reason)용 row는 실제 body를 그대로 포함해서 만든다 — POST body 안의
    # SQLi/XSS 등을 규칙 게이트가 여전히 잡아야 하기 때문(features_v2.py는 body 포함/미포함
    # 어느 쪽으로 호출해도 동작하도록 설계돼 있음).
    row = build_feature_row(req.method, req.url_path, req.query_params,
                             req.body_content, req.user_agent)

    # 1단계 — 규칙 게이트 (결정적). 학습 데이터에 거의 없어 모델이 배우지 못한
    # 정의상 공격(SQL 논리우회, Log4Shell 등)을 임계값과 무관하게 잡는다.
    # -> 3모델을 합쳐도 결합 임계값(0.965)이 보수적이라 이런 명백한 공격을 놓칠 수 있음이
    #    실측으로 확인돼서 유지한다 (features_v2.py, main_v2.py와 동일한 설계).
    hits = rule_hits(row)

    # 2단계 — 3모델 통계적 판정
    #
    # 트리 모델은 앙상블 가중치(0.05/0.85/0.10)와 결합 임계값(0.9650)을 탐색할 때
    # body를 강제로 제거한 "u_" 조건(ai_team_sync/ensemble_results/build_ensemble_probs.py,
    # extract_v2.py -- u_ = build_feature_row(..., body="", ...))으로 검증됐다. 여기서
    # req.body_content를 그대로 트리 입력에 넣으면 검증 때와 다른 분포를 넣는 셈이 돼서
    # 임계값 0.9650의 근거가 깨진다 -- 그래서 트리 전용 row는 body=""로 별도로 만든다.
    # (스키마 모델은 애초에 하나의 고정 조건으로만 학습돼서 이 문제가 없다 -- 아래 그대로 유지.)
    tree_row = build_feature_row(req.method, req.url_path, req.query_params,
                                  "", req.user_agent)
    tree_p = float(tree_model.predict_proba(tree_to_vector(tree_row))[0][1])

    schema_row = se.build_row(req.url_path, req.query_params, req.body_content, schema_dict)
    schema_p = float(schema_model.predict_proba(se.to_vector(schema_row))[0][1])

    # ModelRuntime.predict()를 통해서 호출한다 -- 내부적으로 self._lock(RLock)으로 감싸고
    # 점수 유효성(0<=score<=1, finite)까지 검증한다. explainer.score()를 직접 부르면 이
    # 보호를 우회하게 되고, Kafka 워커 스레드와 HTTP 요청이 동시에 들어올 때 안전하지 않다.
    predict_request = PredictRequest(
        log_id=req.log_id, method=req.method or "GET", url_path=req.url_path or "/",
        query_params=req.query_params, body_content=req.body_content,
        user_agent=req.user_agent, ip_address=req.ip_address, timestamp=req.timestamp,
    )
    transformer_p = float(transformer_runtime.predict(predict_request).threat_score)

    combined = float(soft_vote([transformer_p, tree_p, schema_p], ENSEMBLE_WEIGHTS))

    if hits:
        is_attack = True
        score = max(combined, 0.90)
        reason = ", ".join(desc for _, desc in hits)
    elif combined >= ENSEMBLE_THRESHOLD:
        is_attack = True
        score = combined
        reason = explain(row, combined, ENSEMBLE_THRESHOLD)
    else:
        is_attack = False
        score = combined
        reason = "-"

    return ThreatResponse(
        log_id=req.log_id,
        threat_score=round(score, 4),
        ip_address=req.ip_address if is_attack else "0.0.0.0",
        reason=reason,
    )


@app.post("/predict", response_model=ThreatResponse)
def predict(request: HttpRequest):
    return run_predict(request)


@app.post("/predict/batch")
def predict_batch(requests: list[HttpRequest]):
    if not models_ready:
        raise HTTPException(status_code=503, detail="Model is not loaded.")
    results = [run_predict(r).dict() for r in requests]
    return {"total": len(results), "results": results}


# ─────────────────────────────────────────────────────────
# Kafka에서 받은 JSON dict를 HttpRequest로 검증하고, 예측한 다음 dict로 바꿔 반환합니다.
# 즉, Kafka 메시지 하나를 처리하는 최소 단위.
def handle_kafka_message(message: dict) -> dict:
    request = HttpRequest(**message)
    result = run_predict(request)
    return result.dict()
# ─────────────────────────────────────────────────────────


@app.on_event("shutdown")
def stop_kafka_worker():
    kafka_stop_event.set()
    if kafka_consumer is not None:
        try:
            kafka_consumer.close()
        except Exception:
            pass
    if kafka_producer is not None:
        try:
            kafka_producer.close()
        except Exception:
            pass
    print("[Kafka AI] background worker stopping")


def kafka_worker():
    global kafka_consumer, kafka_producer

    while not models_ready and not kafka_stop_event.is_set():
        print("[Kafka AI] 모델 로딩 대기 중 ...")
        time.sleep(1)

    while not kafka_stop_event.is_set():
        try:
            # 1) Kafka Consumer 생성
            kafka_consumer = KafkaConsumer(
                AI_REQUEST_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id=AI_CONSUMER_GROUP,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
            # 2) Kafka Producer 생성
            kafka_producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
            )

            print(f"[Kafka AI] consume start: {AI_REQUEST_TOPIC}")

            # 3) 메시지를 하나씩 처리
            for record in kafka_consumer:
                if kafka_stop_event.is_set():
                    break

                try:
                    # ai-request-topic 메시지 수신
                    # -> 예측
                    # -> ai-result-topic으로 결과 전송
                    request_message = record.value
                    result_message = handle_kafka_message(request_message)

                    kafka_producer.send(
                        AI_RESULT_TOPIC,
                        key=str(result_message.get("log_id", "")).encode("utf-8"),
                        value=result_message,
                    )
                    kafka_producer.flush()

                    print(
                        f"[Kafka AI] result sent. "
                        f"log_id={result_message.get('log_id')} "
                        f"score={result_message.get('threat_score')}"
                    )
                except Exception as e:
                    print(f"[Kafka AI Error] message 처리 실패: {e}")

        except Exception as e:
            print(f"[Kafka AI Error] Kafka worker exception: {e}")

        finally:
            if kafka_consumer is not None:
                try:
                    kafka_consumer.close()
                except Exception:
                    pass
                kafka_consumer = None
            if kafka_producer is not None:
                try:
                    kafka_producer.close()
                except Exception:
                    pass
                kafka_producer = None

        if kafka_stop_event.is_set():
            break

        time.sleep(2)
