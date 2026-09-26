from __future__ import annotations

import math
import threading
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Mapping

import torch

from security_ai.data.canonical import first_header, normalize_headers
from security_ai.data.pipeline import sanitize_record
from security_ai.data.schema import HttpRecord
from security_ai.model.byte_tokenizer import ByteHttpTokenizer
from security_ai.model.structural_features import STRUCTURAL_FEATURE_SIZE
from security_ai.model.transformer import HttpByteTransformer, HttpTransformerConfig
from security_ai.xai.explainer import TransformerExplainer

from .legacy_reason import build_legacy_reason
from .model_artifact import (
    BUNDLE_SCHEMA_VERSION,
    DEPLOYMENT_DECISION_RULE,
    DEPLOYMENT_THRESHOLD_POLICIES,
    DeploymentContractError,
    load_model_artifact,
)
from .schemas import ModelProvenance, PredictRequest, PredictionResponse


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value.lower())


class ModelRuntime:
    """One loaded checkpoint shared by FastAPI and the Kafka worker."""

    def __init__(
        self,
        checkpoint_path: Path,
        taxonomy_path: Path | None = None,
        *,
        ig_steps: int = 16,
        require_deployment: bool = False,
        expected_artifact_sha256: str | None = None,
    ) -> None:
        checkpoint_path = checkpoint_path.resolve()
        if (
            checkpoint_path.suffix.lower() == ".pkl"
            and expected_artifact_sha256 is None
        ):
            raise ValueError(
                "a PKL deployment requires SECURITY_AI_MODEL_SHA256 (or "
                "expected_artifact_sha256) from a trusted channel before unpickling"
            )
        # A PKL carries its frozen taxonomy.  Do not make it depend on a second
        # machine's mutable config file; PT compatibility still uses the
        # explicit taxonomy path.
        artifact_taxonomy_path = (
            None if checkpoint_path.suffix.lower() == ".pkl" else taxonomy_path
        )
        try:
            artifact = load_model_artifact(
                checkpoint_path,
                taxonomy_path=artifact_taxonomy_path,
                expected_sha256=expected_artifact_sha256,
                require_deployment=require_deployment,
            )
        except DeploymentContractError as exc:
            raise ValueError(
                "checkpoint is not a valid stage-04 deployment artifact; "
                "set SECURITY_AI_REQUIRE_DEPLOYMENT=false only for an explicit legacy pilot"
            ) from exc
        checkpoint = artifact.checkpoint
        config = HttpTransformerConfig(**checkpoint["model_config"])
        if config.structural_feature_size not in (0, STRUCTURAL_FEATURE_SIZE):
            raise ValueError(
                "serving supports structural_feature_size 0 or "
                f"{STRUCTURAL_FEATURE_SIZE}, got {config.structural_feature_size}"
            )
        self.model = HttpByteTransformer(config)
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()

        tokenizer_spec = checkpoint.get("tokenizer")
        if tokenizer_spec is None:
            if require_deployment:
                raise ValueError("deployment checkpoint is missing tokenizer specification")
            tokenizer_spec = {}
        if not isinstance(tokenizer_spec, Mapping):
            raise ValueError("checkpoint tokenizer specification must be a mapping")
        if tokenizer_spec:
            try:
                tokenizer_version = int(tokenizer_spec.get("version", -1))
                tokenizer_max_length = int(tokenizer_spec.get("max_length", -1))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "checkpoint tokenizer version/max_length must be integers"
                ) from exc
            if tokenizer_spec.get("type") != "utf8_byte" or tokenizer_version != 1:
                raise ValueError("unsupported checkpoint tokenizer type or version")
            if tokenizer_max_length != config.max_length:
                raise ValueError(
                    "checkpoint tokenizer max_length does not match model_config"
                )
        field_budgets = tokenizer_spec.get("field_budgets")
        if require_deployment and not isinstance(field_budgets, Mapping):
            raise ValueError("deployment checkpoint tokenizer is missing field_budgets")
        normalized_budgets: dict[str, int] | None = None
        if isinstance(field_budgets, Mapping):
            if any(
                not isinstance(name, str)
                or isinstance(value, bool)
                or not isinstance(value, int)
                for name, value in field_budgets.items()
            ):
                raise ValueError("checkpoint tokenizer field_budgets must be integer values")
            normalized_budgets = {
                str(name): int(value) for name, value in field_budgets.items()
            }
        self.tokenizer = ByteHttpTokenizer(
            max_length=config.max_length,
            field_budgets=normalized_budgets,
        )

        self.threshold = float(checkpoint["threshold"])
        if (
            not math.isfinite(self.threshold)
            or self.threshold < 0.0
            or self.threshold > math.nextafter(1.0, math.inf)
        ):
            raise ValueError("checkpoint threshold is outside the serving contract")
        self.model_version = str(
            checkpoint.get("model_version", "http-byte-transformer-unknown")
        )
        self.checkpoint_path = checkpoint_path
        self.checkpoint_sha256 = artifact.artifact_sha256
        self.artifact_format = artifact.artifact_format

        selection = checkpoint.get("threshold_selection")
        selection = selection if isinstance(selection, Mapping) else {}
        deployment_contract_valid = self._deployment_contract_valid(checkpoint, selection)
        if require_deployment and not deployment_contract_valid:
            raise ValueError(
                "checkpoint is not a valid stage-04 deployment artifact; "
                "set SECURITY_AI_REQUIRE_DEPLOYMENT=false only for an explicit legacy pilot"
            )
        tokenizer = self.tokenizer.specification()
        bundle_metadata = artifact.bundle_metadata or {}
        bundle_provenance = bundle_metadata.get("provenance")
        bundle_provenance = (
            bundle_provenance if isinstance(bundle_provenance, Mapping) else {}
        )
        bundle_integrity = bundle_metadata.get("integrity")
        bundle_integrity = (
            bundle_integrity if isinstance(bundle_integrity, Mapping) else {}
        )
        self.provenance = ModelProvenance(
            checkpoint_sha256=self.checkpoint_sha256,
            artifact_role=str(checkpoint.get("artifact_role", "legacy_checkpoint")),
            deployment_contract_valid=deployment_contract_valid,
            decision_rule=str(
                checkpoint.get("decision_rule", DEPLOYMENT_DECISION_RULE)
            ),
            threshold=self.threshold,
            threshold_selection_scope=str(
                selection.get("scope", "legacy_checkpoint_threshold")
            ),
            threshold_selection_policy=(
                str(selection["policy"]) if selection.get("policy") is not None else None
            ),
            validation_predictions_sha256=(
                str(selection["validation_predictions_sha256"])
                if selection.get("validation_predictions_sha256") is not None
                else None
            ),
            source_checkpoint_sha256=(
                str(selection["source_checkpoint_sha256"])
                if selection.get("source_checkpoint_sha256") is not None
                else None
            ),
            training_signature=(
                str(checkpoint["training_signature"])
                if checkpoint.get("training_signature") is not None
                else None
            ),
            best_epoch=(
                int(checkpoint["best_epoch"])
                if checkpoint.get("best_epoch") is not None
                else None
            ),
            inference_precision=str(
                checkpoint.get("inference_precision", "legacy_unspecified")
            ),
            tokenizer_type=str(tokenizer["type"]),
            tokenizer_version=int(tokenizer["version"]),
            tokenizer_field_budgets={
                str(name): int(value)
                for name, value in self.tokenizer.field_budgets.items()
            },
            artifact_format=artifact.artifact_format,
            artifact_sha256=artifact.artifact_sha256,
            bundle_schema_version=(
                int(bundle_metadata.get("bundle_schema_version", BUNDLE_SCHEMA_VERSION))
                if artifact.artifact_format == "pickle_deployment_bundle"
                else None
            ),
            source_deployment_checkpoint_sha256=(
                str(bundle_provenance["source_deployment_checkpoint_sha256"])
                if bundle_provenance.get("source_deployment_checkpoint_sha256") is not None
                else None
            ),
            taxonomy_sha256=(
                str(bundle_integrity["taxonomy_sha256"])
                if bundle_integrity.get("taxonomy_sha256") is not None
                else None
            ),
        )
        taxonomy_source: Path | Mapping[str, Any]
        if artifact.taxonomy is not None:
            taxonomy_source = artifact.taxonomy
        elif taxonomy_path is not None:
            taxonomy_source = taxonomy_path
        else:
            raise ValueError("a PT checkpoint requires an external taxonomy path")
        self.explainer = TransformerExplainer(
            self.model, self.tokenizer, taxonomy_source, ig_steps=ig_steps
        )
        self._lock = threading.RLock()

    def _deployment_contract_valid(
        self,
        checkpoint: Mapping[str, Any],
        selection: Mapping[str, Any],
    ) -> bool:
        try:
            return bool(
                checkpoint.get("artifact_role") == "deployment_checkpoint"
                and checkpoint.get("decision_rule") == DEPLOYMENT_DECISION_RULE
                and selection.get("decision_rule") == DEPLOYMENT_DECISION_RULE
                and selection.get("scope") == "full_validation_only"
                and selection.get("policy") in DEPLOYMENT_THRESHOLD_POLICIES
                and selection.get("test_accessed") is False
                and checkpoint.get("test_accessed") is False
                and checkpoint.get("inference_precision") == "float32"
                and selection.get("inference_precision") == "float32"
                and float(selection["threshold"]) == self.threshold
                and _is_sha256(checkpoint.get("training_signature"))
                and _is_sha256(selection.get("training_signature"))
                and _is_sha256(selection.get("validation_predictions_sha256"))
                and _is_sha256(selection.get("source_checkpoint_sha256"))
                and str(selection["training_signature"])
                == str(checkpoint["training_signature"])
                and int(selection["best_epoch"]) == int(checkpoint["best_epoch"])
                and int(checkpoint["best_epoch"]) > 0
            )
        except (KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def to_record(request: PredictRequest) -> HttpRecord:
        headers = normalize_headers(list(request.headers.items()))
        if request.user_agent and not first_header(headers, "user-agent"):
            headers = headers + (("user-agent", request.user_agent),)
        content_type = first_header(headers, "content-type")
        body_observed = bool(request.body_observed or request.body_content)
        record = HttpRecord(
            record_id=str(request.log_id or "online-request"),
            source="online",
            source_version=request.schema_version,
            dataset_role="external_eval",
            method=request.method.strip().upper(),
            path=request.url_path,
            query=request.query_params,
            headers=headers,
            body=request.body_content,
            body_observed=body_observed,
            content_type=content_type,
            label_binary=None,
        )
        return sanitize_record(record)

    def predict(self, request: PredictRequest, *, explain: bool = False) -> PredictionResponse:
        record = self.to_record(request)
        with self._lock:
            score = self.explainer.score(record)
            if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                raise RuntimeError(
                    "model produced a non-finite or out-of-range threat score"
                )
            malicious = score >= self.threshold
            legacy_reason = build_legacy_reason(
                record, is_malicious=malicious
            )
            if explain:
                explained = self.explainer.explain(
                    record, threshold=self.threshold, top_k=3
                )
                attack_types = explained["attack_types"]
                model_reason = explained["reason"]
                explanation = explained["explanation"]
            else:
                attack_types = []
                model_reason = None
                explanation = {
                    "status": "not_requested",
                    "method": (
                        "token_integrated_gradients+text_span_and_structural_feature_masking"
                        if self.model.config.structural_feature_size
                        else "token_embedding_integrated_gradients+span_masking"
                    ),
                }
            explanation = {
                **explanation,
                "legacy_reason_method": legacy_reason["reason_method"],
                "legacy_reason_is_model_attribution": False,
            }
        warnings = [
            "모델 점수는 공격 성공 또는 실제 피해의 증명이 아닙니다.",
            "reason은 AI_v0 호환 서명 규칙 요약이며 모델 내부 기여도는 model_reason/explanation을 확인해야 합니다.",
        ]
        if not self.provenance.deployment_contract_valid:
            warnings.append(
                "stage-04 deployment 계약이 없는 legacy checkpoint입니다. 운영 자동 차단에 사용하지 마세요."
            )
        if malicious and (
            not request.ip_address or ip_address(request.ip_address).is_unspecified
        ):
            warnings.append(
                "악성으로 판정됐지만 실제 요청 IP가 없어 기존 Backend의 정상 sentinel과 충돌할 수 있습니다."
            )
        return PredictionResponse(
            log_id=request.log_id,
            threat_score=score,
            is_malicious=malicious,
            threshold=self.threshold,
            # The existing Spring ThreatService does not inspect
            # ``is_malicious``.  It uses this exact sentinel as its only normal
            # decision, so echoing a normal client's IP would create a false
            # threat record.
            ip_address=request.ip_address if malicious else "0.0.0.0",
            reason=legacy_reason["reason"],
            reason_method=legacy_reason["reason_method"],
            reason_codes=list(legacy_reason["reason_codes"]),
            model_reason=model_reason,
            attack_types=attack_types,
            model_version=self.model_version,
            model_provenance=self.provenance,
            explanation=explanation,
            warnings=warnings,
        )

    def health(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "model_loaded": True,
            "model_version": self.model_version,
            "threshold": self.threshold,
            "checkpoint": str(self.checkpoint_path),
            "artifact_format": self.artifact_format,
            "model_provenance": self.provenance.model_dump(mode="json"),
            "device": "cpu",
        }
