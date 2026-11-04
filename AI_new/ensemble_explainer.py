# -*- coding: utf-8 -*-
"""
ensemble_explainer.py — 3모델 앙상블 판정의 근거를 분해한다 (판정 결과는 바꾸지 않음)

main.py의 최종 판정 로짓은 z = Σ w_i·logit(p_i)이다. 트리·스키마 모델(HistGradientBoosting)의
로짓은 TreeSHAP으로 '기준값 + 피처별 기여'로 정확히 나뉘므로, z도 피처 단위 기여의 합이 된다.

  z = w_tree·기준값_tree + w_schema·기준값_schema       (base_logit)
    + Σ w_tree·SHAP_tree_j + Σ w_schema·SHAP_schema_k   (피처별 contribution)
    + w_transformer·logit(p_transformer)                (트랜스포머는 한 항목)
    + 보정                                              (확률 클리핑 ±13.8로 생긴 차이, 보통 0)

기여는 '모델이 공격 쪽으로 기운 정도'이지 공격 성공이나 피해의 증거가 아니다. 근거 문자열은
features_v2.feature_evidence()가 피처를 계산한 정규식을 같은 입력에 다시 적용해서 찾는다.
"""
import math
import threading

import numpy as np
import shap

import features_v2 as fv
import schema_expert as se

TOP_K_REASON = 3            # reason 문자열에 넣는 공격 쪽 상위 피처 수
TOP_K_ATTACK = 5            # explanation에 넣는 공격 쪽 피처 수
TOP_K_NORMAL = 3            # explanation에 넣는 정상 쪽 피처 수
TOP_K_EVIDENCE = 3          # 피처 하나당 보여줄 근거 조각 수
REASON_LIMIT = 240          # ip_blacklist.reason이 VARCHAR(255)라 그보다 짧게 자른다
EVIDENCE_TEXT_LIMIT = 30    # 근거 조각 하나의 최대 길이
ADDITIVITY_TOLERANCE = 1e-6

# features_v2.explain()이 공격 근거로 삼던 시그니처형 피처. 나머지(길이·비율·경로 구조·확장자 등)는
# 요청의 '모양'이라 데이터셋 출처를 배운 지름길일 수 있다. 트리 기여 중 시그니처 비율이 낮은 모델
# 판정에는 검토 권장 표시를 붙인다(기준 0.5는 미리 정한 값이며 평가 데이터로 맞추지 않았다).
PATTERN_FEATURES = frozenset({
    "sql_tautology", "sql_keyword_count", "sql_comment_count", "xss_keyword_count",
    "xss_event_handler", "path_traversal_count", "cmd_keyword_count", "cmd_metachar",
    "template_injection", "nosql_count", "ua_is_bot", "encoded_char_count", "special_char_count",
})
REVIEW_PATTERN_SHARE = 0.5

# 피처 → (표시 이름, 표시 형식). flag는 (값이 1일 때, 0일 때) 문구. 순서는 모델 입력 순서와 같다.
TREE_FEATURES = {
    "method_encoded": ("메서드", "category"),
    "file_extension_encoded": ("확장자", "category"),
    "url_len": ("URL 길이", "length"),
    "query_len": ("쿼리 길이", "length"),
    "body_len": ("본문 길이", "length"),
    "total_len": ("전체 길이", "length"),
    "path_depth": ("경로 깊이", "number"),
    "param_count": ("파라미터", "count"),
    "max_param_value_len": ("가장 긴 파라미터 값", "length"),
    "special_char_count": ("특수문자", "count"),
    "special_char_ratio": ("특수문자 비율", "ratio"),
    "digit_ratio": ("숫자 비율", "ratio"),
    "alpha_ratio": ("문자 비율", "ratio"),
    "encoded_char_count": ("URL 인코딩 문자", "count"),
    "non_ascii_count": ("비ASCII 문자", "count"),
    "sql_keyword_count": ("SQL 키워드", "count"),
    "sql_tautology": (("SQL 논리우회 패턴", "SQL 논리우회 패턴 없음"), "flag"),
    "sql_comment_count": ("SQL 주석 패턴", "count"),
    "xss_keyword_count": ("XSS 패턴", "count"),
    "xss_event_handler": (("XSS 이벤트 핸들러", "XSS 이벤트 핸들러 없음"), "flag"),
    "path_traversal_count": ("디렉터리 탈출 패턴", "count"),
    "cmd_keyword_count": ("시스템 명령어", "count"),
    "cmd_metachar": (("쉘 메타문자", "쉘 메타문자 없음"), "flag"),
    "template_injection": (("템플릿/JNDI 인젝션 패턴", "템플릿/JNDI 인젝션 패턴 없음"), "flag"),
    "nosql_count": ("NoSQL 연산자", "count"),
    "ua_is_bot": (("봇/스캐너 User-Agent", "일반 User-Agent"), "flag"),
    "ua_empty": (("User-Agent 없음", "User-Agent 있음"), "flag"),
    "has_body": (("본문 있음", "본문 없음"), "flag"),
}
SCHEMA_FEATURES = {
    "path_known": (("정상 트래픽에서 본 경로", "처음 보는 경로"), "flag"),
    "paramset_known": (("정상 트래픽에서 본 경로·파라미터 조합", "처음 보는 경로·파라미터 조합"), "flag"),
    "log_path_freq": ("정상 트래픽 경로 출현", "freq"),
    "log_paramset_freq": ("정상 트래픽 경로·파라미터 조합 출현", "freq"),
    "n_unknown_params": ("처음 보는 파라미터", "count"),
    "frac_unknown": ("처음 보는 파라미터 비율", "ratio"),
    "n_params": ("파라미터(본문 포함)", "count"),
    "max_val_len": ("가장 긴 값", "length"),
    "mean_val_len": ("평균 값 길이", "length"),
    "n_numeric_vals": ("숫자 값", "count"),
    "n_encoded_vals": ("인코딩된 값", "count"),
    "path_depth": ("경로 깊이(스키마 기준)", "number"),
}
if list(TREE_FEATURES) != fv.FEATURES or list(SCHEMA_FEATURES) != se.FEATURES:
    raise RuntimeError("설명용 피처 목록이 모델 입력 피처 순서와 다릅니다")

PATTERN_INDEX = np.array([i for i, name in enumerate(fv.FEATURES) if name in PATTERN_FEATURES])


def _logit(p, eps=1e-6):
    """main.soft_vote()와 같은 클리핑."""
    p = np.clip(p, eps, 1 - eps)
    return np.log(p / (1 - p))


def _single_row(values):
    """shap 버전에 따라 (1, n) 또는 (1, n, 2)로 오는 SHAP 값을 공격 클래스 1행으로 맞춘다."""
    values = np.asarray(values, dtype=np.float64)
    if values.ndim == 3:
        values = values[..., -1]
    return values[0]


def _scalar(value):
    return float(np.ravel(value)[-1])


def _display(label, kind, value):
    if kind == "flag":
        return label[0] if value else label[1]
    if kind == "category":
        return f"{label} 없음" if value == "NONE" else f"{label} {_safe_text(value)}"
    if kind == "count":
        return f"{label} {int(value)}개"
    if kind == "length":
        return f"{label} {int(round(value))}자"
    if kind == "ratio":
        return f"{label} {value:.2f}"
    if kind == "freq":
        return f"{label} {int(round(math.expm1(value)))}회"
    return f"{label} {int(value)}"


def _safe_text(text):
    """요청에서 온 문자열을 한 줄로 만들고 길이를 자른다 (로그·DB·화면 표시용)."""
    text = "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in text)
    return text if len(text) <= EVIDENCE_TEXT_LIMIT else text[:EVIDENCE_TEXT_LIMIT - 1] + "…"


def _evidence(pairs):
    return [{"text": _safe_text(text), "count": count} for text, count in pairs[:TOP_K_EVIDENCE]]


def _evidence_text(evidence):
    return ", ".join(f"{e['text']}×{e['count']}" if e["count"] > 1 else e["text"] for e in evidence)


def _clip(text):
    return text if len(text) <= REASON_LIMIT else text[:REASON_LIMIT - 1] + "…"


def _number(value):
    if isinstance(value, str):
        return _safe_text(value)
    value = float(value)
    return int(value) if value.is_integer() else round(value, 4)


def describe(model, name, tree_row, schema_row):
    """피처 하나의 (표시 이름, 값, 표시 문구). model은 "tree" 또는 "schema"."""
    label, kind = (TREE_FEATURES if model == "tree" else SCHEMA_FEATURES)[name]
    if model == "tree":
        value = tree_row[name.removesuffix("_encoded")] if kind == "category" else tree_row[name]
    else:
        value = schema_row[name]
    return (label[0] if kind == "flag" else label), _number(value), _display(label, kind, value)


def pattern_share(tree_shap):
    """트리 모델이 공격 쪽으로 기운 기여 중 시그니처형 피처의 비율 (공격 쪽 기여가 없으면 None)."""
    positive = np.clip(tree_shap, 0.0, None)
    total = float(positive.sum())
    if total <= 0.0:
        return None
    return float(positive[PATTERN_INDEX].sum() / total)


class EnsembleExplainer:
    """트리·스키마 TreeSHAP + 트랜스포머 항목으로 최종 판정 로짓을 분해한다.

    FastAPI 요청 스레드와 Kafka 워커가 함께 부르므로 SHAP 계산은 락으로 감싼다(탐지 1건당 수 ms).
    """

    def __init__(self, tree_model, schema_model, schema_dictionary, weights, threshold):
        self._tree = shap.TreeExplainer(tree_model)
        self._schema = shap.TreeExplainer(schema_model)
        self._tree_base = _scalar(self._tree.expected_value)
        self._schema_base = _scalar(self._schema.expected_value)
        self._tree_model = tree_model
        self._schema_model = schema_model
        self._schema_dictionary = schema_dictionary
        weights = np.asarray(weights, dtype=np.float64)
        self._weights = weights / weights.sum()          # [transformer, tree, schema]
        self.threshold = float(threshold)
        self.threshold_logit = float(_logit(np.float64(self.threshold)))
        self._lock = threading.Lock()

    def check_additivity(self, tree_x, schema_x):
        """기준값 + SHAP 합이 모델 출력(로짓)과 같은지 확인한다 (shap·sklearn 버전 불일치 감지용)."""
        with self._lock:
            tree_shap = _single_row(self._tree.shap_values(tree_x, check_additivity=False))
            schema_shap = _single_row(self._schema.shap_values(schema_x, check_additivity=False))
        tree_gap = abs(self._tree_base + tree_shap.sum() - float(self._tree_model.decision_function(tree_x)[0]))
        schema_gap = abs(self._schema_base + schema_shap.sum()
                         - float(self._schema_model.decision_function(schema_x)[0]))
        return max(tree_gap, schema_gap) <= ADDITIVITY_TOLERANCE, max(tree_gap, schema_gap)

    def decompose(self, tree_x, schema_x, probas):
        """최종 로짓 = base_logit + Σ tree + Σ schema + transformer + adjustment 를 이루는 값들."""
        with self._lock:
            tree_shap = _single_row(self._tree.shap_values(tree_x, check_additivity=False))
            schema_shap = _single_row(self._schema.shap_values(schema_x, check_additivity=False))
        w_transformer, w_tree, w_schema = self._weights
        z = _logit(np.asarray(probas, dtype=np.float64))
        tree_raw = self._tree_base + tree_shap.sum()
        schema_raw = self._schema_base + schema_shap.sum()
        return {
            "logit": float(self._weights @ z),
            "base_logit": float(w_tree * self._tree_base + w_schema * self._schema_base),
            "tree": w_tree * tree_shap,
            "schema": w_schema * schema_shap,
            "transformer": float(w_transformer * z[0]),
            "adjustment": float(w_tree * (z[1] - tree_raw) + w_schema * (z[2] - schema_raw)),
            "tree_shap": tree_shap,
        }

    def explain(self, request, tree_row, tree_x, schema_row, schema_x, probas, hits):
        """공격 판정 1건 → (decision_source, reason, explanation). hits가 있으면 규칙 게이트가 판정한 것.

        request: method/url_path/query_params/body_content/user_agent 속성을 가진 요청 객체.
        tree_row·schema_row: 모델 입력을 만든 피처 dict (트리는 body 없이 만든 row).
        probas: [transformer, tree, schema] 단독 공격 확률.
        """
        parts = self.decompose(tree_x, schema_x, probas)
        candidates = (
            [("tree", name, float(c)) for name, c in zip(TREE_FEATURES, parts["tree"])]
            + [("schema", name, float(c)) for name, c in zip(SCHEMA_FEATURES, parts["schema"])]
        )
        attack = sorted((c for c in candidates if c[2] > 0), key=lambda c: -c[2])[:TOP_K_ATTACK]
        normal = sorted((c for c in candidates if c[2] < 0), key=lambda c: c[2])[:TOP_K_NORMAL]
        toward_attack = [self._item(request, tree_row, schema_row, *c) for c in attack]
        toward_normal = [self._item(request, tree_row, schema_row, *c) for c in normal]

        source = "rule" if hits else "model"
        share = pattern_share(parts["tree_shap"])
        review = source == "model" and share is not None and share < REVIEW_PATTERN_SHARE
        rules = [self._rule(request, name, description) for name, description in hits]

        model_score = 1.0 / (1.0 + math.exp(-parts["logit"]))
        explanation = {
            "method": "tree_shap+logit_decomposition",
            "model_score": round(model_score, 4),
            "logit": round(parts["logit"], 4),
            "threshold_logit": round(self.threshold_logit, 4),
            "base_logit": round(parts["base_logit"], 4),
            "transformer_logit": round(parts["transformer"], 4),
            "adjustment": round(parts["adjustment"], 6) + 0.0,   # -0.0 표시 방지
            "model_probabilities": {name: round(float(p), 4)
                                    for name, p in zip(("transformer", "tree", "schema"), probas)},
            "toward_attack": toward_attack,
            "toward_normal": toward_normal,
            "rules": rules,
            "pattern_share": None if share is None else round(share, 4),
            "review_recommended": review,
            "note": "기여도는 모델이 공격 쪽으로 기운 정도이며 공격 성공이나 피해의 증거가 아닙니다.",
        }
        return source, self._reason(source, rules, toward_attack, review), explanation

    def _item(self, request, tree_row, schema_row, model, name, contribution):
        label, value, display = describe(model, name, tree_row, schema_row)
        if model == "tree":
            # 트리는 body 없이 판정하므로 근거도 body를 뺀 입력에서 찾는다
            evidence = fv.feature_evidence(name, request.url_path, request.query_params, "",
                                           request.user_agent)
        else:
            evidence = []
            if name in ("n_unknown_params", "frac_unknown"):
                evidence = [(param, 1) for param in se.unknown_param_names(
                    request.url_path, request.query_params, request.body_content, self._schema_dictionary)]
        return {
            "model": model,
            "feature": name,
            "label": label,
            "value": value,
            "display": display,
            "contribution": round(contribution, 4),
            "evidence": _evidence(evidence),
        }

    @staticmethod
    def _rule(request, name, description):
        pairs = [pair for feature in fv.RULE_EVIDENCE.get(name, [])
                 for pair in fv.feature_evidence(feature, request.url_path, request.query_params,
                                                 request.body_content, request.user_agent)]
        return {"rule": name, "description": description, "evidence": _evidence(pairs)}

    @staticmethod
    def _reason(source, rules, toward_attack, review):
        # 근거 조각에 괄호가 들어 있을 수 있어(예: "alert(") 대괄호로 감싼다
        if source == "rule":
            parts = [r["description"] + (f" [{_evidence_text(r['evidence'])}]" if r["evidence"] else "")
                     for r in rules]
            return _clip("[규칙] " + " · ".join(parts))
        parts = [item["display"] + (f" [{_evidence_text(item['evidence'])}]" if item["evidence"] else "")
                 + f" {item['contribution']:+.1f}" for item in toward_attack[:TOP_K_REASON]]
        text = "[모델] " + (" · ".join(parts) if parts else "단일 피처로 설명되지 않는 판정")
        if review:
            text += " · 검토 권장: 구조 특성 위주 판정"
        return _clip(text)
