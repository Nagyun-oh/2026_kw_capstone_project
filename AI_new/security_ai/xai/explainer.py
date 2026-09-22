from __future__ import annotations

import json
import math
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote_plus

import torch

from security_ai.data.schema import HttpRecord
from security_ai.model.byte_tokenizer import ByteHttpTokenizer, ByteOffset
from security_ai.model.structural_features import (
    STRUCTURAL_FEATURE_NAMES,
    structural_feature_vector,
)
from security_ai.model.transformer import HttpByteTransformer


_SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|token|api[_-]?key|authorization|cookie)(\s*[:=]\s*)([^&\s;]+)"
)


def _finite_number(value: object, name: str) -> float:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise RuntimeError(f"XAI produced a non-finite {name}")
    return numeric


def _require_finite_tensor(value: torch.Tensor, name: str) -> None:
    if not bool(torch.isfinite(value).all().item()):
        raise RuntimeError(f"XAI produced non-finite values in {name}")


def _redact(value: str, limit: int = 120) -> str:
    value = _SECRET_PATTERN.sub(r"\1\2<redacted>", value)
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return value[:limit] + ("…" if len(value) > limit else "")


def _field_bytes(record: HttpRecord, field: str) -> bytes:
    if field == "headers":
        value = "\n".join(f"{name}: {header_value}" for name, header_value in record.headers)
    else:
        value = str(getattr(record, field))
    return value.encode("utf-8", errors="surrogatepass")


def _redacted_span_text(record: HttpRecord, field: str, start: int, end: int) -> str:
    """Return a safe preview, even when attribution selects only a secret value."""

    complete = _field_bytes(record, field)
    raw_text = complete[start:end].decode("utf-8", errors="replace")
    if field in {"query", "body", "headers"}:
        complete_text = complete.decode("utf-8", errors="replace")
        for match in _SECRET_PATTERN.finditer(complete_text):
            secret_start_char, secret_end_char = match.span(3)
            secret_start = len(complete_text[:secret_start_char].encode("utf-8"))
            secret_end = len(complete_text[:secret_end_char].encode("utf-8"))
            if start < secret_end and secret_start < end:
                return "<redacted>"
    return _redact(raw_text)


def _mask_byte_span(record: HttpRecord, field: str, start: int, end: int) -> HttpRecord:
    """Occlude a span without shifting every following token position."""

    if field == "headers":
        # Header byte offsets are based on newline-joined fields. Removing the
        # entire overlapping header avoids creating malformed partial headers.
        cursor = 0
        kept: list[tuple[str, str]] = []
        for index, (name, value) in enumerate(record.headers):
            line = f"{name}: {value}".encode("utf-8", errors="surrogatepass")
            line_start = cursor
            line_end = cursor + len(line)
            if line_end <= start or line_start >= end:
                kept.append((name, value))
            cursor = line_end + (1 if index < len(record.headers) - 1 else 0)
        return replace(record, headers=tuple(kept))
    original = _field_bytes(record, field)
    start = min(max(start, 0), len(original))
    end = min(max(end, start), len(original))
    # Expand to UTF-8 character boundaries so masking never leaves an invalid
    # leading/continuation byte around a multibyte character.
    while start > 0 and start < len(original) and original[start] & 0xC0 == 0x80:
        start -= 1
    while end < len(original) and original[end] & 0xC0 == 0x80:
        end += 1
    changed = original[:start] + (b" " * (end - start)) + original[end:]
    value = changed.decode("utf-8", errors="strict")
    if field == "body":
        return replace(record, body=value, body_observed=True)
    return replace(record, **{field: value})


class TransformerExplainer:
    """Integrated Gradients explanations confirmed by feature masking.

    Raw request bytes are grouped back into readable HTTP spans.  Hybrid
    checkpoints additionally explain their bounded structural side input.
    Neither attribution is presented as proof that an attack succeeded.
    """

    def __init__(
        self,
        model: HttpByteTransformer,
        tokenizer: ByteHttpTokenizer,
        taxonomy_source: Path | Mapping[str, Any],
        *,
        ig_steps: int = 16,
        span_radius_bytes: int = 8,
    ) -> None:
        if ig_steps < 2:
            raise ValueError("ig_steps must be at least 2")
        self.model = model.eval()
        self.device = next(self.model.parameters()).device
        self.tokenizer = tokenizer
        self.ig_steps = ig_steps
        self.span_radius_bytes = span_radius_bytes
        if isinstance(taxonomy_source, Mapping):
            taxonomy = dict(taxonomy_source)
        else:
            taxonomy = json.loads(taxonomy_source.read_text(encoding="utf-8"))
        if not isinstance(taxonomy.get("families"), Mapping):
            raise ValueError("attack taxonomy must contain a families mapping")
        self.families: dict[str, dict[str, Any]] = taxonomy["families"]

    def _tensors(
        self, record: HttpRecord
    ) -> tuple[object, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor | None]:
        encoded = self.tokenizer.encode(record)
        input_ids = torch.tensor(
            [encoded.input_ids], dtype=torch.long, device=self.device
        )
        field_ids = torch.tensor(
            [encoded.field_ids], dtype=torch.long, device=self.device
        )
        attention_mask = torch.tensor(
            [encoded.attention_mask], dtype=torch.bool, device=self.device
        )
        structural_features = (
            torch.tensor(
                [structural_feature_vector(record)],
                dtype=torch.float32,
                device=self.device,
            )
            if self.model.config.structural_feature_size
            else None
        )
        if structural_features is not None:
            _require_finite_tensor(structural_features, "structural features")
        return encoded, input_ids, field_ids, attention_mask, structural_features

    def score(self, record: HttpRecord) -> float:
        return float(torch.sigmoid(torch.tensor(self.logit(record))))

    def logit(self, record: HttpRecord) -> float:
        _, input_ids, field_ids, attention_mask, structural_features = self._tensors(record)
        with torch.inference_mode():
            output = self.model(
                input_ids, field_ids, attention_mask, structural_features
            )
        _require_finite_tensor(output, "model logit")
        return float(output[0])

    def _integrated_gradients(
        self,
        input_ids: torch.Tensor,
        field_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        structural_features: torch.Tensor | None,
    ) -> tuple[list[float], float, float, float]:
        token_embeddings = self.model.token_embedding(input_ids).detach()
        token_baseline = torch.zeros_like(token_embeddings)
        alphas = torch.linspace(
            0.0, 1.0, self.ig_steps, device=token_embeddings.device
        ).view(self.ig_steps, 1, 1)
        interpolated_tokens = token_baseline + alphas * (token_embeddings - token_baseline)
        interpolated_tokens.requires_grad_(True)
        repeated_fields = field_ids.expand(self.ig_steps, -1)
        repeated_mask = attention_mask.expand(self.ig_steps, -1)
        # Hold the structural branch fixed while explaining request bytes. A
        # joint all-zero path is numerically unstable around LayerNorm and also
        # answers a less useful question: it changes two input modalities at
        # once. Structural features are validated separately by exact masking.
        repeated_structural = (
            structural_features.expand(self.ig_steps, -1)
            if structural_features is not None
            else None
        )
        logits = self.model.forward_from_token_embeddings(
            interpolated_tokens,
            repeated_fields,
            repeated_mask,
            repeated_structural,
        )
        _require_finite_tensor(logits, "integrated-gradients path logits")
        gradients = torch.autograd.grad(logits.sum(), interpolated_tokens)[0]
        _require_finite_tensor(gradients, "integrated-gradients gradients")
        token_trapezoids = (gradients[:-1] + gradients[1:]) / 2
        token_average_gradient = token_trapezoids.mean(dim=0, keepdim=True)
        token_attribution = (
            (token_embeddings - token_baseline) * token_average_gradient
        ).sum(dim=-1)[0]
        _require_finite_tensor(token_attribution, "token attributions")
        with torch.inference_mode():
            input_output = self.model(
                input_ids, field_ids, attention_mask, structural_features
            )
            baseline_output = self.model.forward_from_token_embeddings(
                token_baseline,
                field_ids,
                attention_mask,
                structural_features,
            )
        _require_finite_tensor(input_output, "input logit")
        _require_finite_tensor(baseline_output, "baseline logit")
        input_logit = float(input_output[0])
        baseline_logit = float(baseline_output[0])
        attribution_sum = _finite_number(token_attribution.sum(), "attribution sum")
        completeness_delta = _finite_number(
            (input_logit - baseline_logit) - attribution_sum,
            "completeness delta",
        )
        return (
            token_attribution.tolist(),
            input_logit,
            baseline_logit,
            completeness_delta,
        )

    def _candidate_spans(
        self, offsets: tuple[ByteOffset | None, ...], attributions: list[float], top_k: int
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        selected_intervals: list[tuple[str, int, int]] = []
        ranked = sorted(
            (
                (score, offset.field, offset.byte_index)
                for offset, score in zip(offsets, attributions)
                if offset is not None and score > 0
            ),
            reverse=True,
        )
        available = {(offset.field, offset.byte_index) for offset in offsets if offset is not None}
        for _, field, centre in ranked:
            start = centre
            end = centre + 1
            for byte_index in range(centre - 1, centre - self.span_radius_bytes - 1, -1):
                if (field, byte_index) not in available:
                    break
                start = byte_index
            for byte_index in range(centre + 1, centre + self.span_radius_bytes + 1):
                if (field, byte_index) not in available:
                    break
                end = byte_index + 1
            # A centre outside an earlier span can still expand back into that
            # span.  Check the *final intervals*, not only centre bytes, so the
            # returned candidates are genuinely disjoint and masking one
            # candidate never also masks part of another candidate.
            if any(
                field == selected_field
                and start < selected_end
                and selected_start < end
                for selected_field, selected_start, selected_end in selected_intervals
            ):
                continue
            token_scores = [
                score
                for offset, score in zip(offsets, attributions)
                if offset is not None and offset.field == field and start <= offset.byte_index < end
            ]
            candidates.append({
                "field": field,
                "start_byte": start,
                "end_byte": end,
                "attribution": sum(token_scores),
            })
            selected_intervals.append((field, start, end))
            if len(candidates) >= top_k:
                break
        return candidates

    def _risk_hints(self, text: str) -> list[dict[str, str]]:
        decoded = unquote_plus(text).lower()
        hints: list[dict[str, str]] = []
        for family, definition in self.families.items():
            signatures = definition.get("legacy_signatures", [])
            matched = [signature for signature in signatures if signature.lower() in decoded]
            if matched:
                hints.append({
                    "type": family,
                    "display_name": definition["display_name_ko"],
                    "risk_summary": definition["risk_summary_ko"],
                    "matched_signature": matched[0],
                    "classification_method": "attributed_span_signature_hint",
                })
        return hints

    def explain(self, record: HttpRecord, *, threshold: float, top_k: int = 3) -> dict[str, Any]:
        threshold = float(threshold)
        if not math.isfinite(threshold) or not (
            0.0 <= threshold <= math.nextafter(1.0, math.inf)
        ):
            raise ValueError("threshold is outside the XAI serving contract")
        encoded, input_ids, field_ids, attention_mask, structural_features = self._tensors(record)
        (
            attributions,
            input_logit,
            baseline_logit,
            completeness_delta,
        ) = self._integrated_gradients(
            input_ids, field_ids, attention_mask, structural_features
        )
        for name, value in (
            ("input logit", input_logit),
            ("baseline logit", baseline_logit),
            ("completeness delta", completeness_delta),
        ):
            _finite_number(value, name)
        if any(not math.isfinite(float(value)) for value in attributions):
            raise RuntimeError("XAI produced non-finite token attributions")
        probability = float(torch.sigmoid(torch.tensor(input_logit)))
        _finite_number(probability, "threat probability")
        candidate_attributions: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        all_hints: dict[str, dict[str, str]] = {}
        for candidate in self._candidate_spans(encoded.offsets, attributions, top_k):
            field = candidate["field"]
            start = int(candidate["start_byte"])
            end = int(candidate["end_byte"])
            raw_text = _field_bytes(record, field)[start:end].decode("utf-8", errors="replace")
            changed = _mask_byte_span(record, field, start, end)
            logit_without = self.logit(changed)
            score_without = float(torch.sigmoid(torch.tensor(logit_without)))
            logit_drop = input_logit - logit_without
            probability_drop = probability - score_without
            hints = self._risk_hints(raw_text) if logit_drop > 0 else []
            for hint in hints:
                all_hints[hint["type"]] = hint
            evaluated_candidate = {
                **candidate,
                "text_redacted": _redacted_span_text(record, field, start, end),
                "direction": "malicious",
                "attribution_direction": "malicious",
                "occlusion": (
                    "whole_overlapping_header_removed"
                    if field == "headers"
                    else "same_length_space_mask"
                ),
                "logit_without_span": logit_without,
                "logit_drop": logit_drop,
                "score_without_span": score_without,
                "probability_drop": probability_drop,
                "masking_confirmed_malicious": logit_drop > 0,
                "risk_hints": hints,
            }
            candidate_attributions.append(evaluated_candidate)
            # Positive IG proposes a candidate, but only the counterfactual
            # masking check can promote it to malicious evidence.  A negative
            # or zero logit drop means removing the span did not reduce the
            # model's malicious belief, so it must not appear in evidence,
            # attack hints, or annotation-overlap scoring.
            if logit_drop > 0:
                evidence.append(evaluated_candidate)
        candidate_attributions.sort(
            key=lambda item: float(item["attribution"]), reverse=True
        )
        evidence.sort(key=lambda item: float(item["logit_drop"]), reverse=True)
        structural_values = structural_feature_vector(record)
        structural_logit_without: list[float] = []
        if structural_features is not None:
            feature_count = structural_features.shape[1]
            masked_structural = structural_features.repeat(feature_count, 1)
            indices = torch.arange(feature_count)
            masked_structural[indices, indices] = 0.0
            with torch.inference_mode():
                masked_logits = self.model(
                    input_ids.expand(feature_count, -1),
                    field_ids.expand(feature_count, -1),
                    attention_mask.expand(feature_count, -1),
                    masked_structural,
                )
            _require_finite_tensor(masked_logits, "structural masking logits")
            structural_logit_without = [float(value) for value in masked_logits]
        structural_attributions = sorted(
            (
                {
                    "feature": name,
                    "normalized_value": value,
                    "importance_method": "single_feature_zero_masking",
                    "direction": (
                        "malicious"
                        if input_logit - logit_without > 0
                        else "benign"
                    ),
                    "logit_without_feature": logit_without,
                    "logit_drop": input_logit - logit_without,
                    "score_without_feature": float(
                        torch.sigmoid(torch.tensor(logit_without))
                    ),
                    "probability_drop": probability
                    - float(torch.sigmoid(torch.tensor(logit_without))),
                }
                for name, value, logit_without in zip(
                    STRUCTURAL_FEATURE_NAMES,
                    structural_values,
                    structural_logit_without,
                )
            ),
            key=lambda item: abs(float(item["logit_drop"])),
            reverse=True,
        )
        # Keep the full signed sensitivity list for audit, but call an item
        # malicious "evidence" only when removing it actually lowers the
        # malicious logit.  This mirrors the text-span promotion rule above.
        structural_evidence = [
            item
            for item in structural_attributions
            if float(item["logit_drop"]) > 0.0
        ]
        strongest_text = evidence[0] if evidence else None
        strongest_structural = (
            max(
                structural_evidence,
                key=lambda item: float(item["probability_drop"]),
            )
            if structural_evidence
            else None
        )
        text_drop = (
            float(strongest_text["probability_drop"]) if strongest_text else 0.0
        )
        structural_drop = (
            float(strongest_structural["probability_drop"])
            if strongest_structural
            else 0.0
        )
        if strongest_text and text_drop > 0 and text_drop >= structural_drop:
            reason = (
                f"{strongest_text['field']}의 표시 구간을 제거했을 때 악성 점수가 "
                f"{text_drop:.3f} 감소했습니다."
            )
        elif strongest_structural and structural_drop > 0:
            reason = (
                f"구조 피처 {strongest_structural['feature']}를 0으로 가렸을 때 악성 점수가 "
                f"{structural_drop:.3f} 감소했습니다."
            )
        else:
            reason = "안정적으로 확인된 단일 의심 구간이 없습니다."
        return {
            "threat_score": probability,
            "is_malicious": probability >= threshold,
            "threshold": threshold,
            "attack_types": list(all_hints.values()),
            "reason": reason + " 모델 기여도 기반 참고 정보이며 공격 성공의 증명은 아닙니다.",
            "explanation": {
                "method": (
                    "token_integrated_gradients+text_span_and_structural_feature_masking"
                    if structural_features is not None
                    else "token_embedding_integrated_gradients+span_masking"
                ),
                "status": (
                    "complete"
                    if evidence or structural_evidence
                    else "insufficient_evidence"
                ),
                "ig_steps": self.ig_steps,
                "baseline": (
                    "zero_token_embedding_with_structural_features_held_constant_"
                    "plus_position_and_field_context"
                    if structural_features is not None
                    else "zero_token_embedding_with_position_and_field_context"
                ),
                "input_logit": input_logit,
                "baseline_logit": baseline_logit,
                "completeness_delta": completeness_delta,
                "candidate_attributions": candidate_attributions,
                "evidence": evidence,
                "structural_attributions": structural_attributions,
                "structural_evidence": structural_evidence,
                "truncated_fields": list(encoded.truncated_fields),
                "warning": (
                    "Attribution and masking describe model sensitivity, not causal proof "
                    "of an attack or its success."
                ),
            },
        }
