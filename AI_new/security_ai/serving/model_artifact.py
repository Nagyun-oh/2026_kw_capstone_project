"""Versioned deployment artifacts for the HTTP Transformer.

Training checkpoints remain PyTorch ``.pt`` files because they are also used
for experiment provenance and resume workflows.  A deployment bundle is a
smaller, inference-only ``.pkl`` derived *only* from the validation-selected
stage-04 checkpoint.  It contains primitive metadata and a CPU ``state_dict``;
it deliberately does not pickle a live model instance.

Security warning
----------------
Python pickle can execute code while it is loaded.  A manifest SHA-256 is
checked before ``pickle.load`` so accidental corruption and a mismatch with a
trusted digest are caught early, but a sidecar hash is not a digital
signature.  Never load a bundle obtained from an untrusted source.  Distribute
the expected SHA-256 through a trusted channel when authenticity matters.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import pickle
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import torch

from security_ai.model.byte_tokenizer import ByteHttpTokenizer
from security_ai.model.structural_features import STRUCTURAL_FEATURE_SIZE
from security_ai.model.transformer import HttpByteTransformer, HttpTransformerConfig


BUNDLE_FORMAT = "security_ai_http_transformer_deployment"
BUNDLE_SCHEMA_VERSION = 1
MANIFEST_FORMAT = "security_ai_model_bundle_manifest"
MANIFEST_SCHEMA_VERSION = 1
DEPLOYMENT_DECISION_RULE = (
    "malicious_if_probability_greater_than_or_equal_threshold"
)
DEPLOYMENT_THRESHOLD_POLICIES = frozenset(
    ("max_f1", "fpr_ceiling", "precision_floor", "cost_sensitive", "source_guard")
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ModelArtifactError(ValueError):
    """Base class for malformed or incompatible model artifacts."""


class DeploymentContractError(ModelArtifactError):
    """The model is not a validation-selected stage-04 deployment artifact."""


class ArtifactIntegrityError(ModelArtifactError):
    """An artifact or one of its components failed an integrity check."""


@dataclass(frozen=True)
class LoadedModelArtifact:
    """Normalized result returned for either a ``.pt`` or ``.pkl`` input."""

    checkpoint: dict[str, Any]
    taxonomy: dict[str, Any] | None
    artifact_format: str
    artifact_sha256: str
    manifest: dict[str, Any] | None = None
    bundle_metadata: dict[str, Any] | None = None


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _read_file_snapshot(path: Path) -> tuple[bytes, str]:
    """Read once and bind the digest to the exact bytes later deserialized.

    Hashing a path and reopening that path leaves a time-of-check/time-of-use
    window in which a same-sized file can be substituted.  Keeping one byte
    snapshot makes the hash, size check and deserializer operate on identical
    input even if the directory entry changes concurrently.
    """

    try:
        with path.open("rb") as handle:
            content = handle.read()
    except OSError as exc:
        raise ModelArtifactError(f"could not read model artifact snapshot: {path}") from exc
    return content, hashlib.sha256(content).hexdigest()


def _json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ModelArtifactError("artifact metadata is not stable-JSON serializable") from exc


def stable_json_sha256(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value.lower()):
        raise DeploymentContractError(f"{field} must be a SHA-256 hexadecimal string")
    return value.lower()


def _require_plain_mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ModelArtifactError(f"{field} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise ModelArtifactError(f"{field} keys must be strings")
    return dict(value)


def _validate_taxonomy(value: object) -> dict[str, Any]:
    taxonomy = _require_plain_mapping(value, "taxonomy")
    try:
        schema_version = int(taxonomy["schema_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelArtifactError("taxonomy.schema_version must be a positive integer") from exc
    if schema_version < 1:
        raise ModelArtifactError("taxonomy.schema_version must be a positive integer")
    families = taxonomy.get("families")
    if not isinstance(families, Mapping) or not families:
        raise ModelArtifactError("taxonomy.families must be a non-empty mapping")
    for name, definition in families.items():
        if not isinstance(name, str) or not name:
            raise ModelArtifactError("taxonomy family names must be non-empty strings")
        if not isinstance(definition, Mapping):
            raise ModelArtifactError(f"taxonomy family {name!r} must be a mapping")
    # Round-trip through JSON to detach custom mapping implementations and to
    # prove that the value can be reproduced outside the source machine.
    return json.loads(_json_bytes(taxonomy).decode("utf-8"))


def _validate_tokenizer(
    value: object, model_config: HttpTransformerConfig
) -> dict[str, Any]:
    tokenizer = _require_plain_mapping(value, "checkpoint.tokenizer")
    try:
        version = int(tokenizer["version"])
        max_length = int(tokenizer["max_length"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DeploymentContractError(
            "checkpoint tokenizer version/max_length are invalid"
        ) from exc
    if tokenizer.get("type") != "utf8_byte" or version != 1:
        raise DeploymentContractError("unsupported checkpoint tokenizer type or version")
    if max_length != model_config.max_length:
        raise DeploymentContractError(
            "checkpoint tokenizer max_length does not match model_config"
        )
    budgets = tokenizer.get("field_budgets")
    if not isinstance(budgets, Mapping):
        raise DeploymentContractError("checkpoint tokenizer is missing field_budgets")
    if any(
        not isinstance(name, str)
        or isinstance(amount, bool)
        or not isinstance(amount, int)
        for name, amount in budgets.items()
    ):
        raise DeploymentContractError(
            "checkpoint tokenizer field_budgets must contain integer values"
        )
    # The constructor enforces the exact field set and positive budgets.
    try:
        ByteHttpTokenizer(max_length=max_length, field_budgets=budgets)
    except (TypeError, ValueError) as exc:
        raise DeploymentContractError("invalid checkpoint tokenizer field_budgets") from exc
    return tokenizer


def _validate_state_dict(
    value: object, model_config: HttpTransformerConfig
) -> dict[str, torch.Tensor]:
    if not isinstance(value, Mapping) or not value:
        raise DeploymentContractError("checkpoint.state_dict must be a non-empty mapping")
    model = HttpByteTransformer(model_config)
    expected_state = model.state_dict()
    if set(value) != set(expected_state):
        raise DeploymentContractError(
            "checkpoint.state_dict keys do not strictly match model_config"
        )
    state: dict[str, torch.Tensor] = {}
    for name, tensor in value.items():
        if not isinstance(name, str) or not isinstance(tensor, torch.Tensor):
            raise DeploymentContractError(
                "checkpoint.state_dict must map string names to tensors"
            )
        if tensor.layout != torch.strided:
            raise DeploymentContractError("only dense strided state tensors are supported")
        if tensor.device.type == "meta":
            raise DeploymentContractError("meta-device state tensors are not supported")
        expected_tensor = expected_state[name]
        if tensor.dtype != expected_tensor.dtype:
            raise DeploymentContractError(
                f"model tensor {name!r} dtype does not match model_config"
            )
        if tensor.shape != expected_tensor.shape:
            raise DeploymentContractError(
                f"model tensor {name!r} shape does not match model_config"
            )
        if (tensor.is_floating_point() or tensor.is_complex()) and not bool(
            torch.isfinite(tensor).all().item()
        ):
            raise DeploymentContractError(
                f"floating model tensor {name!r} contains NaN or infinity"
            )
        state[name] = tensor
    try:
        model.load_state_dict(state, strict=True)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise DeploymentContractError(
            "checkpoint.state_dict does not strictly match model_config"
        ) from exc
    return state


def validate_deployment_checkpoint(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the immutable stage-04 serving contract.

    The returned dictionary still has the same checkpoint-shaped interface,
    which lets a runtime support both the current ``.pt`` file and the new
    bundle without maintaining two inference implementations.
    """

    result = _require_plain_mapping(checkpoint, "checkpoint")
    required = {
        "model_config",
        "tokenizer",
        "state_dict",
        "threshold",
        "best_epoch",
        "training_signature",
        "inference_precision",
        "test_accessed",
        "artifact_role",
        "decision_rule",
        "threshold_selection",
    }
    missing = sorted(required - set(result))
    if missing:
        raise DeploymentContractError(
            f"deployment checkpoint is missing required fields: {missing}"
        )
    if result.get("artifact_role") != "deployment_checkpoint":
        raise DeploymentContractError("artifact_role is not deployment_checkpoint")
    if result.get("decision_rule") != DEPLOYMENT_DECISION_RULE:
        raise DeploymentContractError("unsupported deployment decision_rule")
    if result.get("test_accessed") is not False:
        raise DeploymentContractError("deployment checkpoint does not prove test_accessed=false")
    if result.get("inference_precision") != "float32":
        raise DeploymentContractError("deployment inference_precision must be float32")

    try:
        threshold = float(result["threshold"])
        best_epoch = int(result["best_epoch"])
    except (TypeError, ValueError) as exc:
        raise DeploymentContractError("threshold or best_epoch is invalid") from exc
    if isinstance(result["best_epoch"], bool) or best_epoch <= 0:
        raise DeploymentContractError("best_epoch must be a positive integer")
    if not math.isfinite(threshold) or not (
        0.0 <= threshold <= math.nextafter(1.0, math.inf)
    ):
        raise DeploymentContractError("threshold is outside the serving contract")
    training_signature = _require_sha256(
        result["training_signature"], "training_signature"
    )

    model_config_raw = _require_plain_mapping(result["model_config"], "model_config")
    try:
        model_config = HttpTransformerConfig(**model_config_raw)
    except (TypeError, ValueError) as exc:
        raise DeploymentContractError("invalid model_config") from exc
    if model_config.structural_feature_size not in (0, STRUCTURAL_FEATURE_SIZE):
        raise DeploymentContractError(
            "deployment model structural_feature_size must be 0 or "
            f"{STRUCTURAL_FEATURE_SIZE}"
        )
    result["model_config"] = model_config_raw
    result["tokenizer"] = _validate_tokenizer(result["tokenizer"], model_config)
    result["state_dict"] = _validate_state_dict(result["state_dict"], model_config)

    selection = _require_plain_mapping(
        result["threshold_selection"], "threshold_selection"
    )
    try:
        selected_threshold = float(selection["threshold"])
        selected_epoch = int(selection["best_epoch"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DeploymentContractError(
            "threshold_selection threshold/best_epoch is invalid"
        ) from exc
    checks = (
        (selection.get("scope") == "full_validation_only", "scope"),
        (selection.get("test_accessed") is False, "test_accessed"),
        (selection.get("policy") in DEPLOYMENT_THRESHOLD_POLICIES, "policy"),
        (selection.get("decision_rule") == DEPLOYMENT_DECISION_RULE, "decision_rule"),
        (selection.get("inference_precision") == "float32", "inference_precision"),
        (selected_threshold == threshold, "threshold"),
        (selected_epoch == best_epoch, "best_epoch"),
        (str(selection.get("training_signature", "")).lower() == training_signature,
         "training_signature"),
    )
    failed = [name for passed, name in checks if not passed]
    if failed:
        raise DeploymentContractError(
            "threshold_selection conflicts with deployment checkpoint: "
            + ", ".join(failed)
        )
    _require_sha256(
        selection.get("training_signature"), "threshold_selection.training_signature"
    )
    _require_sha256(
        selection.get("validation_predictions_sha256"),
        "threshold_selection.validation_predictions_sha256",
    )
    _require_sha256(
        selection.get("source_checkpoint_sha256"),
        "threshold_selection.source_checkpoint_sha256",
    )
    result["threshold"] = threshold
    result["best_epoch"] = best_epoch
    result["training_signature"] = training_signature
    result["threshold_selection"] = selection
    return result


def state_dict_sha256(state_dict: Mapping[str, torch.Tensor]) -> str:
    """Hash tensor names, dtypes, shapes and exact dense CPU bytes."""

    digest = hashlib.sha256()
    for name in sorted(state_dict):
        tensor = state_dict[name]
        if not isinstance(name, str) or not isinstance(tensor, torch.Tensor):
            raise ModelArtifactError("state_dict must map strings to tensors")
        if tensor.layout != torch.strided:
            raise ModelArtifactError("only dense strided state tensors are supported")
        dense = tensor.detach().cpu().contiguous()
        header = _json_bytes(
            {"name": name, "dtype": str(dense.dtype), "shape": list(dense.shape)}
        )
        # Flatten first because reinterpreting a zero-dimensional scalar as
        # bytes is not supported by Tensor.view(dtype).
        raw = dense.reshape(-1).view(torch.uint8).numpy().tobytes(order="C")
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _contract_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "format_version",
        "model_version",
        "artifact_role",
        "decision_rule",
        "threshold",
        "threshold_selection",
        "training_signature",
        "best_epoch",
        "inference_precision",
        "test_accessed",
    )
    return {name: payload.get(name) for name in keys}


def _component_hashes(
    payload: Mapping[str, Any], taxonomy: Mapping[str, Any]
) -> dict[str, str]:
    return {
        "state_dict_sha256": state_dict_sha256(payload["state_dict"]),
        "model_config_sha256": stable_json_sha256(payload["model_config"]),
        "tokenizer_sha256": stable_json_sha256(payload["tokenizer"]),
        "taxonomy_sha256": stable_json_sha256(taxonomy),
        "contract_sha256": stable_json_sha256(_contract_projection(payload)),
    }


def _cpu_state_dict(
    state_dict: Mapping[str, torch.Tensor]
) -> dict[str, torch.Tensor]:
    return {
        name: tensor.detach().cpu().contiguous().clone()
        for name, tensor in state_dict.items()
    }


def _dataset_provenance(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    database_info = checkpoint.get("database_info")
    if not isinstance(database_info, Mapping):
        return {}
    allowed = (
        "schema_version",
        "source_manifest_sha256",
        "import_files_sha256",
        "split_counts",
        "dataset_fingerprint_sha256",
    )
    # Do not leak source-machine absolute paths or mtimes into a shared bundle.
    return {key: database_info[key] for key in allowed if key in database_info}


def _manifest_path(bundle_path: Path) -> Path:
    return bundle_path.with_suffix(bundle_path.suffix + ".manifest.json")


def _atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _atomic_json(path: Path, value: object) -> None:
    _atomic_bytes(path, json.dumps(
        value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    ).encode("utf-8") + b"\n")


def export_deployment_bundle(
    checkpoint_path: Path,
    taxonomy_path: Path,
    output_path: Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Derive an inference-only PKL and pre-unpickle SHA manifest."""

    checkpoint_path = checkpoint_path.resolve()
    taxonomy_path = taxonomy_path.resolve()
    output_path = output_path.resolve()
    manifest_path = _manifest_path(output_path)
    if output_path.suffix.lower() != ".pkl":
        raise ModelArtifactError("deployment bundle output must use the .pkl suffix")
    if not checkpoint_path.is_file():
        raise FileNotFoundError(checkpoint_path)
    if not taxonomy_path.is_file():
        raise FileNotFoundError(taxonomy_path)
    existing = [path for path in (output_path, manifest_path) if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "bundle output already exists; pass overwrite=True to replace the pair"
        )

    source_bytes, source_sha_before = _read_file_snapshot(checkpoint_path)
    try:
        raw_checkpoint = torch.load(
            io.BytesIO(source_bytes), map_location="cpu", weights_only=True
        )
    except Exception as exc:
        raise ModelArtifactError("could not safely load source PyTorch checkpoint") from exc
    checkpoint = validate_deployment_checkpoint(raw_checkpoint)
    taxonomy = _validate_taxonomy(
        json.loads(taxonomy_path.read_text(encoding="utf-8"))
    )

    selection = checkpoint["threshold_selection"]
    payload_keys = (
        "format_version",
        "model_version",
        "model_config",
        "tokenizer",
        "threshold",
        "best_epoch",
        "training_signature",
        "inference_precision",
        "test_accessed",
        "artifact_role",
        "decision_rule",
        "threshold_selection",
    )
    payload = {key: checkpoint[key] for key in payload_keys if key in checkpoint}
    payload["state_dict"] = _cpu_state_dict(checkpoint["state_dict"])
    integrity = _component_hashes(payload, taxonomy)
    bundle: dict[str, Any] = {
        "bundle_format": BUNDLE_FORMAT,
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "payload": payload,
        "taxonomy": taxonomy,
        "explanation_policy": {
            "name": "integrated_gradients_plus_masking_confirmed_v1",
            "taxonomy_schema_version": int(taxonomy["schema_version"]),
        },
        "compatibility": {
            "python_created": sys.version.split()[0],
            "minimum_python": "3.11",
            "torch_created": torch.__version__,
            "required_torch_major_minor": ".".join(torch.__version__.split("+")[0].split(".")[:2]),
            "response_schema_version": "2.0",
        },
        "provenance": {
            "source_deployment_checkpoint_sha256": source_sha_before,
            "source_training_checkpoint_sha256": str(
                selection["source_checkpoint_sha256"]
            ).lower(),
            "validation_predictions_sha256": str(
                selection["validation_predictions_sha256"]
            ).lower(),
            "training_signature": checkpoint["training_signature"],
            "best_epoch": checkpoint["best_epoch"],
            "dataset": _dataset_provenance(checkpoint),
        },
        "integrity": integrity,
    }
    serialized = pickle.dumps(bundle, protocol=pickle.HIGHEST_PROTOCOL)
    bundle_sha = hashlib.sha256(serialized).hexdigest()
    bundle_bytes = len(serialized)
    _atomic_bytes(output_path, serialized)
    written_bytes, written_sha = _read_file_snapshot(output_path)
    if written_sha != bundle_sha or len(written_bytes) != bundle_bytes:
        raise ArtifactIntegrityError(
            "deployment bundle differs from the bytes produced by the exporter"
        )
    manifest: dict[str, Any] = {
        "status": "PASS",
        "manifest_format": MANIFEST_FORMAT,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "bundle_filename": output_path.name,
        "bundle_format": BUNDLE_FORMAT,
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_sha256": bundle_sha,
        "bundle_bytes": bundle_bytes,
        "source_deployment_checkpoint_sha256": source_sha_before,
        "component_hashes": integrity,
    }
    _atomic_json(manifest_path, manifest)
    return {
        "status": "PASS",
        "artifact_role": "inference_only_deployment_bundle",
        "bundle": str(output_path),
        "bundle_sha256": bundle_sha,
        "bundle_bytes": bundle_bytes,
        "manifest": str(manifest_path),
        "source_deployment_checkpoint": str(checkpoint_path),
        "source_deployment_checkpoint_sha256": source_sha_before,
        "threshold": checkpoint["threshold"],
        "threshold_policy": selection["policy"],
        "best_epoch": checkpoint["best_epoch"],
        "test_accessed": False,
    }


def _load_manifest(bundle_path: Path) -> tuple[Path, dict[str, Any]]:
    path = _manifest_path(bundle_path)
    if not path.is_file():
        raise ArtifactIntegrityError(
            f"PKL manifest is required before unpickling: {path}"
        )
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError("PKL manifest is unreadable") from exc
    if not isinstance(manifest, dict):
        raise ArtifactIntegrityError("PKL manifest must contain one object")
    if (
        manifest.get("manifest_format") != MANIFEST_FORMAT
        or manifest.get("manifest_schema_version") != MANIFEST_SCHEMA_VERSION
        or manifest.get("bundle_filename") != bundle_path.name
        or manifest.get("bundle_format") != BUNDLE_FORMAT
        or manifest.get("bundle_schema_version") != BUNDLE_SCHEMA_VERSION
    ):
        raise ArtifactIntegrityError("PKL manifest identity is invalid")
    return path, manifest


def _verify_bundle(
    bundle: object,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    outer = _require_plain_mapping(bundle, "bundle")
    if outer.get("bundle_format") != BUNDLE_FORMAT:
        raise ModelArtifactError("unsupported bundle_format")
    if outer.get("bundle_schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ModelArtifactError("unsupported bundle_schema_version")
    payload = validate_deployment_checkpoint(
        _require_plain_mapping(outer.get("payload"), "bundle.payload")
    )
    taxonomy = _validate_taxonomy(outer.get("taxonomy"))
    integrity = _require_plain_mapping(outer.get("integrity"), "bundle.integrity")
    expected_components = _component_hashes(payload, taxonomy)
    if integrity != expected_components:
        raise ArtifactIntegrityError("bundle component integrity check failed")
    if manifest.get("component_hashes") != expected_components:
        raise ArtifactIntegrityError("manifest component hashes do not match bundle")

    provenance = _require_plain_mapping(outer.get("provenance"), "bundle.provenance")
    source_deployment_sha = _require_sha256(
        provenance.get("source_deployment_checkpoint_sha256"),
        "provenance.source_deployment_checkpoint_sha256",
    )
    if source_deployment_sha != str(
        manifest.get("source_deployment_checkpoint_sha256", "")
    ).lower():
        raise ArtifactIntegrityError("source deployment checkpoint hash mismatch")
    selection = payload["threshold_selection"]
    try:
        provenance_checks = (
            str(provenance.get("source_training_checkpoint_sha256", "")).lower()
            == str(selection["source_checkpoint_sha256"]).lower(),
            str(provenance.get("validation_predictions_sha256", "")).lower()
            == str(selection["validation_predictions_sha256"]).lower(),
            str(provenance.get("training_signature", "")).lower()
            == payload["training_signature"],
            int(provenance.get("best_epoch", -1)) == payload["best_epoch"],
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactIntegrityError("bundle provenance contains invalid values") from exc
    if not all(provenance_checks):
        raise ArtifactIntegrityError("bundle provenance conflicts with payload")

    compatibility = _require_plain_mapping(
        outer.get("compatibility"), "bundle.compatibility"
    )
    running_torch = ".".join(torch.__version__.split("+")[0].split(".")[:2])
    if compatibility.get("required_torch_major_minor") != running_torch:
        raise ModelArtifactError(
            "bundle requires torch major.minor "
            f"{compatibility.get('required_torch_major_minor')}, running {running_torch}"
        )
    metadata = {key: value for key, value in outer.items() if key not in {"payload", "taxonomy"}}
    return payload, taxonomy, metadata


def load_model_artifact(
    path: Path,
    *,
    taxonomy_path: Path | None = None,
    expected_sha256: str | None = None,
    require_deployment: bool = True,
) -> LoadedModelArtifact:
    """Load ``.pt`` or verified ``.pkl`` into one checkpoint-shaped result.

    For a PKL, ``expected_sha256`` is mandatory and must come from a trusted
    channel.  The exact byte snapshot is then checked against that digest and
    its sidecar before the first unpickle operation.  A sidecar delivered with
    the same file is not an authenticity boundary by itself.
    """

    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    suffix = path.suffix.lower()
    if suffix not in {".pt", ".pth", ".pkl"}:
        raise ModelArtifactError("model artifact suffix must be .pt, .pth, or .pkl")
    if suffix == ".pkl" and expected_sha256 is None:
        raise ArtifactIntegrityError(
            "PKL loading requires expected_sha256 from a trusted channel"
        )
    normalized_expected = (
        _require_sha256(expected_sha256, "expected_sha256")
        if expected_sha256 is not None
        else None
    )
    artifact_bytes, actual_sha = _read_file_snapshot(path)
    if normalized_expected is not None:
        if actual_sha != normalized_expected:
            raise ArtifactIntegrityError("model artifact does not match expected_sha256")

    if suffix == ".pkl":
        _, manifest = _load_manifest(path)
        try:
            manifest_sha = _require_sha256(
                manifest.get("bundle_sha256"), "manifest.bundle_sha256"
            )
            manifest_bytes = int(manifest.get("bundle_bytes", -1))
        except (TypeError, ValueError) as exc:
            raise ArtifactIntegrityError("PKL manifest size/hash is invalid") from exc
        if actual_sha != manifest_sha or len(artifact_bytes) != manifest_bytes:
            raise ArtifactIntegrityError(
                "PKL file hash/size does not match manifest; refusing to unpickle"
            )
        try:
            handle = io.BytesIO(artifact_bytes)
            bundle = pickle.load(handle)
            if handle.read(1):
                raise ArtifactIntegrityError("PKL has unexpected trailing bytes")
        except ArtifactIntegrityError:
            raise
        except Exception as exc:
            raise ModelArtifactError("could not deserialize trusted PKL bundle") from exc
        payload, taxonomy, metadata = _verify_bundle(bundle, manifest)
        if taxonomy_path is not None:
            external = _validate_taxonomy(
                json.loads(Path(taxonomy_path).read_text(encoding="utf-8"))
            )
            if stable_json_sha256(external) != stable_json_sha256(taxonomy):
                raise ArtifactIntegrityError(
                    "external taxonomy differs from the taxonomy frozen in the bundle"
                )
        return LoadedModelArtifact(
            checkpoint=payload,
            taxonomy=taxonomy,
            artifact_format="pickle_deployment_bundle",
            artifact_sha256=actual_sha,
            manifest=dict(manifest),
            bundle_metadata=metadata,
        )

    if suffix in {".pt", ".pth"}:
        try:
            raw = torch.load(
                io.BytesIO(artifact_bytes), map_location="cpu", weights_only=True
            )
        except Exception as exc:
            raise ModelArtifactError("could not safely load PyTorch checkpoint") from exc
        if not isinstance(raw, Mapping):
            raise ModelArtifactError("PyTorch checkpoint must contain one mapping")
        checkpoint = (
            validate_deployment_checkpoint(raw)
            if require_deployment
            else _require_plain_mapping(raw, "checkpoint")
        )
        taxonomy = None
        if taxonomy_path is not None:
            taxonomy = _validate_taxonomy(
                json.loads(Path(taxonomy_path).read_text(encoding="utf-8"))
            )
        return LoadedModelArtifact(
            checkpoint=checkpoint,
            taxonomy=taxonomy,
            artifact_format="pytorch_checkpoint",
            artifact_sha256=actual_sha,
        )
    raise AssertionError("validated artifact suffix was not dispatched")


__all__ = [
    "ArtifactIntegrityError",
    "BUNDLE_FORMAT",
    "BUNDLE_SCHEMA_VERSION",
    "DEPLOYMENT_DECISION_RULE",
    "DEPLOYMENT_THRESHOLD_POLICIES",
    "DeploymentContractError",
    "LoadedModelArtifact",
    "ModelArtifactError",
    "export_deployment_bundle",
    "load_model_artifact",
    "sha256_file",
    "stable_json_sha256",
    "state_dict_sha256",
    "validate_deployment_checkpoint",
]
