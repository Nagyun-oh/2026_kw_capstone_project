"""

FastAPI Server for Real-Time Web Attack Detection (Ultimate Ensemble v3.0.0)

■ 파이프라인 통신 규격:
  - Spring → FastAPI (Request):
    * HTTP 요청 기본 정보: method, url_path, query_params, body_content, user_agent
    * 메타데이터 정보: ip_address, timestamp
    * 내부 파이프라인: 수신된 데이터를 바탕으로 보안 특화 피처 총 23개를 정밀 추출하여 앙상블 모델에 입력
  
  - FastAPI → Spring (Response):
    * threat_score (float): 4대장 앙상블 모델(RandomForest, ExtraTrees, XGBoost, HistGradientBoosting)의 
                           황금 가중치(9:9:6:2)를 반영하여 산출한 최종 공격 확률 지수 (0.0 ~ 1.0)
    * ip_address (str): 위협 점수가 최적 임계값(0.6321) 이상일 경우 실제 차단 대상 IP 반환,
                        정상 요청(안전)일 경우 "0.0.0.0" 반환
    * reason (str): 탐지된 공격 유형 및 사유 상세 분석 텍스트 (예: URL 공격 키워드, SQL 패턴, XSS 패턴 등),
                    정상 요청일 경우 "-" 반환
    * 예외 처리: 모델 파일(model_bundle_ultimate.pkl)이 누락되거나 로딩 실패 시 HTTP 503 Service Unavailable 반환

■ 실행 전제 조건:
  - weight_optimizer.py를 먼저 실행하여 AI/model_bundle_ultimate.pkl 파일을 생성해야 서버가 정상 기동됩니다.

FastAPI server for the web-attack detection ensemble model.

Run weight_optimizer.py first to create AI/model_bundle_ultimate.pkl.
"""

from pathlib import Path
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────
# Kafka 설정 부분
import json
import threading
import time
from kafka import KafkaConsumer, KafkaProducer

# ──────── AI 컨테이너화 ────────
import os
# ──────────────────────────────

kafka_stop_event = threading.Event()
kafka_consumer = None
kafka_producer = None


# 로컬 기본값은 localhost:9092.
# Docker 실행 시 KAFKA-BOOTSTRAP_SERVERS = kafka:29092를 전달한다.
KAFKA_BOOTSTRAP_SERVERS = [
    server.strip()
    for server in os.getenv(
        "KAFKA_BOOTSTRAP_SERVERS",
        "localhost:9092",
    ).split(",")
    if server.strip()
]
AI_REQUEST_TOPIC = "ai-request-topic"
AI_RESULT_TOPIC = "ai-result-topic"
AI_CONSUMER_GROUP = "ai-service-group"
# ─────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
# 1. 최종 글로벌 최적화 번들 파일명 적용 완료!
BUNDLE_PATH = BASE_DIR / "model_bundle_ultimate.pkl"

ATTACK_KEYWORDS = [
    "select",   "insert",   "update",   "delete",   "drop",
    "union",    "exec",    "script",    "alert",    "../",
]
SQL_KEYWORDS = [
    "select",    "insert",    "update",    "delete",    "drop",
    "union",    "where",    "from",    "exec",    "sleep",    "benchmark",
]
XSS_KEYWORDS = [
    "<script",    "script",    "alert",    "onerror",
    "onload",    "javascript:",    "<img",    "<svg",
]
PATH_TRAVERSAL_PATTERNS = ["../", "..\\", "%2e%2e", "etc/passwd", "boot.ini"]
SPECIAL_CHARS = ["'", '"', "<", ">", "--", ";", "%", "(", ")", "="]

app = FastAPI(
    title="보안 위협 탐지 API",
    description="Spring 서버로부터 HTTP 요청 데이터를 받아 위협 여부를 판별합니다.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = None
encoders = {}
features = []
threshold = 0.5
model_type = "unknown"
# 2. 최적 가중치를 동적으로 할당받을 전역 변수
optimized_weights = None


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
    threat_score: float   # 공격일 확률 그대로 (0.0 ~ 1.0)
    ip_address:   str     # 공격이면 실제 IP, 정상이면 "0.0.0.0"
    reason:       str     # 왜 위협인지 (정상이면 "-")


def count_matches(text: str, patterns: list[str]) -> int:
    text_lower = (text or "").lower()
    return sum(text_lower.count(pattern.lower()) for pattern in patterns)


def has_any(text: str, patterns: list[str]) -> int:
    return int(count_matches(text, patterns) > 0)


def safe_ratio(part: int, total: int) -> float:
    return part / total if total else 0.0


def safe_encode(column: str, value: str) -> int:
    encoder = encoders[column]
    value = value if value in encoder.classes_ else "UNKNOWN"
    return int(encoder.transform([value])[0])


def build_feature_row(req: HttpRequest) -> dict[str, object]:
    method = (req.method or "UNKNOWN").upper()
    url_path = req.url_path or ""
    query_params = req.query_params or ""
    body_content = req.body_content or ""
    user_agent = req.user_agent or ""

    full_url = url_path + (f"?{query_params}" if query_params else "")
    decoded_query = unquote(query_params)
    decoded_body = unquote(body_content)
    decoded_url = unquote(full_url)
    combined = f"{decoded_url} {decoded_body}"

    url_len = len(full_url)
    query_len = len(query_params)
    body_len = len(body_content)
    total_len = url_len + body_len
    special_char_count = sum(full_url.count(c) for c in SPECIAL_CHARS) + sum(
        body_content.count(c) for c in SPECIAL_CHARS
    )
    encoded_char_count = full_url.count("%") + body_content.count("%")
    digit_count = sum(ch.isdigit() for ch in full_url + body_content)
    alpha_count = sum(ch.isalpha() for ch in full_url + body_content)
    param_count = query_params.count("=") + body_content.count("=")
    path_depth = len([part for part in url_path.split("/") if part])
    file_extension = Path(url_path).suffix.lower().lstrip(".") or "NONE"

    return {
        "method": method,
        "user_agent": user_agent,
        "url_path": url_path,
        "file_extension": file_extension,
        "url_len": url_len,
        "query_len": query_len,
        "body_len": body_len,
        "total_len": total_len,
        "path_depth": path_depth,
        "param_count": param_count,
        "special_char_count": special_char_count,
        "special_char_ratio": safe_ratio(special_char_count, total_len),
        "encoded_char_count": encoded_char_count,
        "digit_ratio": safe_ratio(digit_count, total_len),
        "alpha_ratio": safe_ratio(alpha_count, total_len),
        "has_keywords_query": has_any(decoded_query, ATTACK_KEYWORDS),
        "has_keywords_body": has_any(decoded_body, ATTACK_KEYWORDS),
        "sql_keyword_count": count_matches(combined, SQL_KEYWORDS),
        "xss_keyword_count": count_matches(combined, XSS_KEYWORDS),
        "path_traversal_count": count_matches(combined, PATH_TRAVERSAL_PATTERNS),
        "has_script_tag": int("<script" in combined.lower()),
        "has_union_select": int("union" in combined.lower() and "select" in combined.lower()),
        "has_comment_pattern": int("--" in combined or "/*" in combined or "*/" in combined),
    }


def extract_features(req: HttpRequest) -> pd.DataFrame:
    row = build_feature_row(req)
    if "method" in encoders:
        row["method_encoded"] = safe_encode("method", row["method"])
    if "user_agent" in encoders:
        row["user_agent_encoded"] = safe_encode("user_agent", row["user_agent"])
    if "url_path" in encoders:
        row["url_path_encoded"] = safe_encode("url_path", row["url_path"])
    if "file_extension" in encoders:
        row["file_extension_encoded"] = safe_encode("file_extension", row["file_extension"])
    return pd.DataFrame([{feature: row[feature] for feature in features}], columns=features)


def get_risk_level(probability: float) -> str:
    if probability >= 0.7:
        return "HIGH"
    if probability >= 0.4:
        return "MEDIUM"
    return "LOW"


def get_attack_reason(probability: float, row: dict) -> str:
    if probability < threshold:
        return "-"

    reasons = []

    if row.get("has_keywords_query"):
        reasons.append("URL 공격 키워드")
    if row["has_keywords_body"]:
        reasons.append("Body 공격 키워드")
    if row["sql_keyword_count"] > 0:
        reasons.append(f"SQL 패턴({row['sql_keyword_count']}개)")
    if row["xss_keyword_count"] > 0:
        reasons.append(f"XSS 패턴({row['xss_keyword_count']}개)")
    if row["path_traversal_count"] > 0:
        reasons.append("디렉토리 탈출 패턴")
    if row["has_union_select"]:
        reasons.append("UNION SELECT 패턴")
    if row["has_script_tag"]:
        reasons.append("<script> 태그")
    if row["has_comment_pattern"]:
        reasons.append("SQL 주석 패턴")
    if row["special_char_count"] > 5:
        reasons.append(f"특수문자 과다({row['special_char_count']}개)")

    if not reasons:
        reasons.append("복합적인 패턴 이상 (Path/Method/UA)")

    return ", ".join(reasons)


@app.on_event("startup")
def load_model() -> None:
    global model, encoders, features, threshold, model_type, optimized_weights

    if not BUNDLE_PATH.exists():
        print(f"Model bundle not found: {BUNDLE_PATH}")
        return

    bundle = joblib.load(BUNDLE_PATH)
    
    # 3. Ultimate 번들 구조(모델 딕셔너리 + 가중치) 파싱
    if "optimized_weights" in bundle:
        model = bundle["models"]  
        optimized_weights = bundle["optimized_weights"] 
    else:
        model = bundle.get("model")
        optimized_weights = None

    encoders = bundle.get("encoders")
    if encoders is None:
        encoders = {
            "method": bundle["le_method"],
            "user_agent": bundle["le_ua"],
            "url_path": bundle["le_path"],
        }
    features = bundle["features"]
    threshold = float(bundle.get("threshold", 0.5))
    model_type = bundle.get("model_type", "unknown")
    print(f"Loaded Ultimate model bundle: {BUNDLE_PATH}")
    print(f"Applied Weights: {optimized_weights}")

    # ─────────────────────────────────────────────────────────
    # Kafka worker thread
    # -> FastAPI 서버가 켜지면, Kafka consumer도 백그라운드에서 같이 켜짐.
    thread = threading.Thread(target=kafka_worker,daemon=True)
    thread.start()
    print("[Kafka AI] background worker started")
    # ─────────────────────────────────────────────────────────


@app.get("/")
def root():
    return {"status": "running", "message": "Security threat detection API is running."}


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_type": model_type,
        "threshold": threshold,
        "feature_count": len(features),
    }


def run_predict(req: HttpRequest) -> ThreatResponse:
    if model is None:
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    feature_frame = extract_features(req)

    # 4. 수제 Soft Voting 확률 결합 알고리즘 구현
    if optimized_weights:
        probability = sum(
            weight * m.predict_proba(feature_frame)[0][1]
            for name, m in model.items()
            for weight in [optimized_weights[name]]
        )
    else:
        probability = float(model.predict_proba(feature_frame)[0][1])

    is_attack = probability >= threshold
    row = build_feature_row(req)

    return ThreatResponse(
        log_id       = req.log_id,  # 추가된 부분 (Spring <-> Kafka <-> AI Server 통신을 위해 필요함)
        threat_score = round(probability, 4),
        ip_address   = req.ip_address if is_attack else "0.0.0.0",
        reason       = get_attack_reason(probability, row),
    )


@app.post("/predict", response_model=ThreatResponse)
def predict(request: HttpRequest):
    return run_predict(request)


@app.post("/predict/batch")
def predict_batch(requests: list[HttpRequest]):
    if model is None:
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    results = []
    for req in requests:
        feature_frame = extract_features(req)
        
        if optimized_weights:
            probability = sum(
                weight * m.predict_proba(feature_frame)[0][1]
                for name, m in model.items()
                for weight in [optimized_weights[name]]
            )
        else:
            probability = float(model.predict_proba(feature_frame)[0][1])
            
        is_attack = probability >= threshold
        row = build_feature_row(req)
        results.append(
            ThreatResponse(
                threat_score = round(probability, 4),
                ip_address   = req.ip_address if is_attack else "0.0.0.0",
                reason       = get_attack_reason(probability, row),
            ).dict()
        )

    return {"total": len(results), "results": results}

# ─────────────────────────────────────────────────────────
# Kafka에서 받은 JSON dict를 HttpRequestData로 검증합고, 예측한 다음 dict로 바꿔 반환합니다.
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

    while model is None and not kafka_stop_event.is_set():
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


# ─────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────
# API 엔드포인트
# ─────────────────────────────────────────────────────────