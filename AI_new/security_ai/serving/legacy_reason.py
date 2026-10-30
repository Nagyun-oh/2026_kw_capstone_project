from __future__ import annotations

from typing import Any, TypedDict

from security_ai.baseline.legacy_features import build_legacy_feature_row
from security_ai.data.schema import HttpRecord


LEGACY_REASON_METHOD = "legacy_signature_compatibility"


class LegacyReasonCode(TypedDict):
    """One machine-readable observation behind the compatibility message.

    These codes describe deterministic signature/shape rules.  They are not
    presented as Transformer attribution or as proof that an attack succeeded.
    """

    code: str
    message: str
    feature: str
    field: str
    observed_value: int
    classification_method: str


class LegacyReasonResult(TypedDict):
    reason: str
    reason_method: str
    reason_codes: list[LegacyReasonCode]


def _code(
    code: str,
    message: str,
    feature: str,
    field: str,
    observed_value: int,
) -> LegacyReasonCode:
    return {
        "code": code,
        "message": message,
        "feature": feature,
        "field": field,
        "observed_value": int(observed_value),
        "classification_method": "legacy_signature_rule",
    }


def build_legacy_reason(
    record: HttpRecord,
    *,
    is_malicious: bool,
) -> LegacyReasonResult:
    """Reproduce the AI_v0 reason text without claiming it is model XAI.

    The model's already-frozen threshold decision is authoritative.  Rules are
    evaluated and disclosed only for a malicious decision, matching AI_v0's
    normal ``"-"`` response while avoiding its stale ``has_keywords_query``
    dictionary-key bug.  Human-readable messages deliberately keep the legacy
    Korean wording and order so existing Spring/UI consumers remain compatible.
    """

    if not is_malicious:
        return {
            "reason": "-",
            "reason_method": LEGACY_REASON_METHOD,
            "reason_codes": [],
        }

    row: dict[str, Any] = build_legacy_feature_row(record)
    codes: list[LegacyReasonCode] = []

    if int(row["has_keywords_query"]) > 0:
        codes.append(
            _code(
                "legacy.url_attack_keyword",
                "URL 공격 키워드",
                "has_keywords_query",
                "query",
                int(row["has_keywords_query"]),
            )
        )
    if int(row["has_keywords_body"]) > 0:
        codes.append(
            _code(
                "legacy.body_attack_keyword",
                "Body 공격 키워드",
                "has_keywords_body",
                "body",
                int(row["has_keywords_body"]),
            )
        )

    sql_count = int(row["sql_keyword_count"])
    if sql_count > 0:
        codes.append(
            _code(
                "legacy.sql_pattern",
                f"SQL 패턴({sql_count}개)",
                "sql_keyword_count",
                "path_query_body",
                sql_count,
            )
        )

    xss_count = int(row["xss_keyword_count"])
    if xss_count > 0:
        codes.append(
            _code(
                "legacy.xss_pattern",
                f"XSS 패턴({xss_count}개)",
                "xss_keyword_count",
                "path_query_body",
                xss_count,
            )
        )

    traversal_count = int(row["path_traversal_count"])
    if traversal_count > 0:
        codes.append(
            _code(
                "legacy.path_traversal_pattern",
                "디렉토리 탈출 패턴",
                "path_traversal_count",
                "path_query_body",
                traversal_count,
            )
        )
    if int(row["has_union_select"]) > 0:
        codes.append(
            _code(
                "legacy.union_select_pattern",
                "UNION SELECT 패턴",
                "has_union_select",
                "path_query_body",
                int(row["has_union_select"]),
            )
        )
    if int(row["has_script_tag"]) > 0:
        codes.append(
            _code(
                "legacy.script_tag",
                "<script> 태그",
                "has_script_tag",
                "path_query_body",
                int(row["has_script_tag"]),
            )
        )
    if int(row["has_comment_pattern"]) > 0:
        codes.append(
            _code(
                "legacy.sql_comment_pattern",
                "SQL 주석 패턴",
                "has_comment_pattern",
                "path_query_body",
                int(row["has_comment_pattern"]),
            )
        )

    special_count = int(row["special_char_count"])
    if special_count > 5:
        codes.append(
            _code(
                "legacy.excessive_special_characters",
                f"특수문자 과다({special_count}개)",
                "special_char_count",
                "path_query_body",
                special_count,
            )
        )

    if not codes:
        codes.append(
            _code(
                "legacy.composite_pattern_anomaly",
                "복합적인 패턴 이상 (Path/Method/UA)",
                "fallback",
                "request",
                1,
            )
        )

    return {
        "reason": ", ".join(item["message"] for item in codes),
        "reason_method": LEGACY_REASON_METHOD,
        "reason_codes": codes,
    }
