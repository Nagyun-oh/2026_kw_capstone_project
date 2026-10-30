from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import unquote

import numpy as np

from security_ai.data.schema import HttpRecord


ATTACK_KEYWORDS = ("select", "insert", "update", "delete", "drop", "union", "exec", "script", "alert", "../")
SQL_KEYWORDS = ("select", "insert", "update", "delete", "drop", "union", "where", "from", "exec", "sleep", "benchmark")
XSS_KEYWORDS = ("<script", "script", "alert", "onerror", "onload", "javascript:", "<img", "<svg")
PATH_TRAVERSAL_PATTERNS = ("../", "..\\", "%2e%2e", "etc/passwd", "boot.ini")
SPECIAL_CHARS = ("'", '"', "<", ">", "--", ";", "%", "(", ")", "=")

NUMERIC_FEATURES = (
    "url_len",
    "query_len",
    "body_len",
    "total_len",
    "path_depth",
    "param_count",
    "special_char_count",
    "special_char_ratio",
    "encoded_char_count",
    "digit_ratio",
    "alpha_ratio",
    "has_keywords_query",
    "has_keywords_body",
    "sql_keyword_count",
    "xss_keyword_count",
    "path_traversal_count",
    "has_script_tag",
    "has_union_select",
    "has_comment_pattern",
)

VARIANT_CATEGORICAL_FEATURES = {
    # 과거 학습 코드의 23개 피처를 그대로 재구성한다. 정확한 URL path와
    # User-Agent 값은 출처 식별자가 될 수 있으므로 비교용으로만 사용한다.
    "legacy_full": ("method", "user_agent", "url_path", "file_extension"),
    # 값 자체가 데이터 출처를 암기하기 쉬운 두 필드를 제외한 대조군이다.
    "content_reduced": ("method", "file_extension"),
}


def _count_matches(text: str, patterns: Iterable[str]) -> int:
    lowered = (text or "").lower()
    return sum(lowered.count(pattern.lower()) for pattern in patterns)


def _safe_ratio(part: int, total: int) -> float:
    return part / total if total else 0.0


def _user_agent(record: HttpRecord) -> str:
    for name, value in record.headers:
        if name.lower() == "user-agent":
            return value
    return ""


def build_legacy_feature_row(record: HttpRecord) -> dict[str, str | float | int]:
    """Reproduce the legacy hand-crafted feature contract on an HttpRecord.

    Provenance fields such as source, source label, IP and timestamp are never
    included. Percent-decoding mirrors AI_v0/train_and_save_model.py.
    """

    method = (record.method or "UNKNOWN").upper()
    path = record.path or ""
    query = record.query or ""
    body = "" if record.body in (None, "null") else record.body
    visible_url = path + (f"?{query}" if query else "")
    decoded_query = unquote(query)
    decoded_body = unquote(body)
    combined = f"{unquote(visible_url)} {decoded_body}"
    total_len = len(visible_url) + len(body)
    special_char_count = sum(visible_url.count(char) + body.count(char) for char in SPECIAL_CHARS)
    characters = visible_url + body

    return {
        "method": method,
        "user_agent": _user_agent(record),
        "url_path": path,
        "file_extension": Path(path).suffix.lower().lstrip(".") or "NONE",
        "url_len": len(visible_url),
        "query_len": len(query),
        "body_len": len(body),
        "total_len": total_len,
        "path_depth": len([part for part in path.split("/") if part]),
        "param_count": query.count("=") + body.count("="),
        "special_char_count": special_char_count,
        "special_char_ratio": _safe_ratio(special_char_count, total_len),
        "encoded_char_count": visible_url.count("%") + body.count("%"),
        "digit_ratio": _safe_ratio(sum(char.isdigit() for char in characters), total_len),
        "alpha_ratio": _safe_ratio(sum(char.isalpha() for char in characters), total_len),
        "has_keywords_query": int(_count_matches(decoded_query, ATTACK_KEYWORDS) > 0),
        "has_keywords_body": int(_count_matches(decoded_body, ATTACK_KEYWORDS) > 0),
        "sql_keyword_count": _count_matches(combined, SQL_KEYWORDS),
        "xss_keyword_count": _count_matches(combined, XSS_KEYWORDS),
        "path_traversal_count": _count_matches(combined, PATH_TRAVERSAL_PATTERNS),
        "has_script_tag": int("<script" in combined.lower()),
        "has_union_select": int("union" in combined.lower() and "select" in combined.lower()),
        "has_comment_pattern": int("--" in combined or "/*" in combined or "*/" in combined),
    }


class LegacyFeatureEncoder:
    """Train-only ordinal encoder plus legacy numeric HTTP features.

    The ordinal representation intentionally follows the old tree pipeline.
    Validation-only values are mapped to -1 and are never used while fitting.
    """

    def __init__(self, variant: str = "legacy_full") -> None:
        if variant not in VARIANT_CATEGORICAL_FEATURES:
            raise ValueError(f"unknown feature variant: {variant}")
        self.variant = variant
        self.categorical_features = VARIANT_CATEGORICAL_FEATURES[variant]
        self.categories_: dict[str, dict[str, int]] = {}

    @property
    def feature_names(self) -> tuple[str, ...]:
        categorical = tuple(f"{name}_encoded" for name in self.categorical_features)
        return categorical + NUMERIC_FEATURES

    def fit(self, records: Sequence[HttpRecord]) -> "LegacyFeatureEncoder":
        rows = [build_legacy_feature_row(record) for record in records]
        self.categories_ = {
            name: {value: index for index, value in enumerate(sorted({str(row[name]) for row in rows}))}
            for name in self.categorical_features
        }
        return self

    def transform(self, records: Sequence[HttpRecord]) -> np.ndarray:
        if not self.categories_:
            raise RuntimeError("LegacyFeatureEncoder must be fit before transform")
        matrix: list[list[float]] = []
        for record in records:
            row = build_legacy_feature_row(record)
            encoded = [
                float(self.categories_[name].get(str(row[name]), -1))
                for name in self.categorical_features
            ]
            encoded.extend(float(row[name]) for name in NUMERIC_FEATURES)
            matrix.append(encoded)
        return np.asarray(matrix, dtype=np.float64)

    def fit_transform(self, records: Sequence[HttpRecord]) -> np.ndarray:
        return self.fit(records).transform(records)

    def unknown_category_report(self, records: Sequence[HttpRecord]) -> dict[str, dict[str, float | int]]:
        if not self.categories_:
            raise RuntimeError("LegacyFeatureEncoder must be fit before reporting unknowns")
        rows = [build_legacy_feature_row(record) for record in records]
        result: dict[str, dict[str, float | int]] = {}
        for name in self.categorical_features:
            counts = Counter(str(row[name]) not in self.categories_[name] for row in rows)
            unknown = counts[True]
            result[name] = {
                "unknown": unknown,
                "total": len(rows),
                "unknown_rate": unknown / len(rows) if rows else 0.0,
                "train_cardinality": len(self.categories_[name]),
            }
        return result
