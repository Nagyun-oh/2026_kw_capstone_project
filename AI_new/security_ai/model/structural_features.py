from __future__ import annotations

import math

from security_ai.baseline.legacy_features import NUMERIC_FEATURES, build_legacy_feature_row
from security_ai.data.schema import HttpRecord


STRUCTURAL_FEATURE_NAMES = NUMERIC_FEATURES
STRUCTURAL_FEATURE_SIZE = len(STRUCTURAL_FEATURE_NAMES)

_RATIO_FEATURES = {"special_char_ratio", "digit_ratio", "alpha_ratio"}
_BINARY_FEATURES = {
    "has_keywords_query",
    "has_keywords_body",
    "has_script_tag",
    "has_union_select",
    "has_comment_pattern",
}


def structural_feature_vector(record: HttpRecord) -> tuple[float, ...]:
    """Return bounded HTTP shape/signature features for the neural side branch.

    The values contain no source, IP, timestamp, response, or label metadata.
    Log scaling prevents long requests from dominating the Transformer CLS
    representation solely because of their numeric magnitude.
    """

    row = build_legacy_feature_row(record)
    values: list[float] = []
    for name in STRUCTURAL_FEATURE_NAMES:
        value = max(0.0, float(row[name]))
        if name in _RATIO_FEATURES or name in _BINARY_FEATURES:
            normalized = min(value, 1.0)
        else:
            normalized = min(math.log1p(value) / 10.0, 1.0)
        values.append(normalized)
    return tuple(values)
