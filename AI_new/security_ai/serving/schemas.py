from __future__ import annotations

import math
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


_MAX_DEPLOYMENT_THRESHOLD = math.nextafter(1.0, math.inf)


def _validate_deployment_threshold(value: float) -> float:
    """Accept probabilities plus the stage-04 reject-all sentinel.

    Threshold selection deliberately uses the smallest representable value
    above 1.0 when no validation example should be classified as malicious.
    That value is a decision boundary, not a probability, and is therefore
    valid for ``threshold`` even though ``threat_score`` remains in [0, 1].
    """

    numeric = float(value)
    if not math.isfinite(numeric) or not (
        0.0 <= numeric <= _MAX_DEPLOYMENT_THRESHOLD
    ):
        raise ValueError("threshold is outside the serving contract")
    return numeric


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=False)

    schema_version: str = "2.0"
    # Spring/JPA correlation key.  Reject bool/string coercion and values that
    # cannot round-trip through Java's signed Long.
    log_id: int | None = Field(
        default=None,
        ge=1,
        le=9_223_372_036_854_775_807,
        strict=True,
    )
    method: str = Field(min_length=1, max_length=32)
    url_path: str = Field(min_length=1, max_length=8192)
    query_params: str = Field(default="", max_length=65536)
    body_content: str = Field(default="", max_length=262144)
    body_observed: bool = False
    user_agent: str = Field(default="", max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    ip_address: str = Field(default="", max_length=128)
    timestamp: str = Field(default="", max_length=128)

    # Legacy engineered values are accepted for Spring compatibility but are
    # deliberately excluded from the Transformer input.
    url_len: int = 0
    special_char_count: int = 0

    @field_validator("headers")
    @classmethod
    def limit_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 100:
            raise ValueError("at most 100 headers are accepted")
        if sum(len(name) + len(item) for name, item in value.items()) > 32768:
            raise ValueError("combined header size exceeds 32768 characters")
        return value

    @field_validator("ip_address")
    @classmethod
    def normalize_ip_address(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            return ""
        # Zone identifiers are host-local routing metadata, not stable client
        # identities for a cross-service Kafka contract.
        if "%" in stripped:
            raise ValueError("scoped IPv6 addresses are not accepted")
        try:
            return str(ip_address(stripped))
        except ValueError as exc:
            raise ValueError("ip_address must be a valid IPv4 or IPv6 address") from exc


class ModelProvenance(BaseModel):
    """Identity of the exact model/preprocessing/threshold contract in use."""

    checkpoint_sha256: str
    artifact_role: str
    deployment_contract_valid: bool
    decision_rule: str
    threshold: float
    threshold_selection_scope: str
    threshold_selection_policy: str | None = None
    validation_predictions_sha256: str | None = None
    source_checkpoint_sha256: str | None = None
    training_signature: str | None = None
    best_epoch: int | None = None
    inference_precision: str
    tokenizer_type: str
    tokenizer_version: int
    tokenizer_field_budgets: dict[str, int]
    artifact_format: str = "pytorch_checkpoint"
    artifact_sha256: str | None = None
    bundle_schema_version: int | None = None
    source_deployment_checkpoint_sha256: str | None = None
    taxonomy_sha256: str | None = None

    @field_validator("threshold")
    @classmethod
    def validate_threshold(cls, value: float) -> float:
        return _validate_deployment_threshold(value)


class PredictionResponse(BaseModel):
    schema_version: str = "2.0"
    log_id: int | None
    threat_score: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    is_malicious: bool
    threshold: float
    ip_address: str
    reason: str
    # ``reason`` preserves the four-field AI_v0/Kafka contract.  It is a
    # deterministic request-signature summary, not a claim about the neural
    # network's internal reasoning.  ``model_reason`` is populated only when
    # the optional, slower masking-confirmed XAI pass is requested.
    reason_method: str = "legacy_signature_compatibility"
    reason_codes: list[dict[str, Any]] = Field(default_factory=list)
    model_reason: str | None = None
    attack_types: list[dict[str, Any]]
    model_version: str
    model_provenance: ModelProvenance | None = None
    explanation: dict[str, Any]
    warnings: list[str] = Field(default_factory=list)

    @field_validator("threshold")
    @classmethod
    def validate_threshold(cls, value: float) -> float:
        return _validate_deployment_threshold(value)
