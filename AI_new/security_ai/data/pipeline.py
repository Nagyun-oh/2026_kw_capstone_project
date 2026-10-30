from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Iterator

from .canonical import canonical_request_hash, safe_record_group
from .parsers import parse_sources
from .schema import HttpRecord, ParseIssue


OUTPUT_FILES = (
    "staging.jsonl", "index.sqlite3", "train.jsonl", "validation.jsonl", "test.jsonl",
    "external_eval.jsonl", "context_holdout.jsonl", "parse_issues.jsonl",
    "label_conflicts.jsonl", "manifest.json",
)


def _json_line(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def _redact_cookie(value: str) -> str:
    names = []
    for part in value.split(";"):
        name = part.partition("=")[0].strip()
        if name:
            names.append(f"{name}=<redacted>")
    return "; ".join(names) if names else "<redacted>"


def sanitize_record(record: HttpRecord) -> HttpRecord:
    """Apply the same non-secret input policy that serving must later use."""

    sanitized: list[tuple[str, str]] = []
    for name, value in record.headers:
        lower = name.lower()
        if lower in {"authorization", "proxy-authorization"}:
            scheme = value.partition(" ")[0]
            sanitized.append((lower, f"{scheme} <redacted>".strip()))
        elif lower in {"cookie", "cookie2", "set-cookie"}:
            sanitized.append((lower, _redact_cookie(value)))
        elif lower == "host":
            sanitized.append((lower, "<host>"))
        elif lower in {"client-ip", "x-forwarded-for", "forwarded"}:
            sanitized.append((lower, "<network-address>"))
        else:
            sanitized.append((lower, value))
    return replace(record, headers=tuple(sanitized))


def _prepare_output(output: Path, overwrite: bool) -> None:
    output.mkdir(parents=True, exist_ok=True)
    existing = [output / name for name in OUTPUT_FILES if (output / name).exists()]
    if existing and not overwrite:
        names = ", ".join(path.name for path in existing)
        raise FileExistsError(f"output already contains generated files ({names}); use --overwrite")
    if overwrite:
        for path in existing:
            if path.is_file() and path.parent.resolve() == output.resolve():
                path.unlink()


def _create_index(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(
        """
        CREATE TABLE fingerprints (
            canonical_hash TEXT PRIMARY KEY,
            first_line INTEGER NOT NULL,
            first_priority INTEGER NOT NULL,
            min_label INTEGER NOT NULL,
            max_label INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE group_stats (
            group_id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            normal_count INTEGER NOT NULL,
            attack_count INTEGER NOT NULL,
            record_count INTEGER NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE TABLE group_assignments (group_id TEXT PRIMARY KEY, split TEXT NOT NULL)"
    )
    return connection


def _role_priority(role: str) -> int:
    return {"context_holdout": 0, "train_candidate": 1, "external_eval": 2}[role]


def _stage_records(
    data_root: Path,
    output: Path,
    sources: Iterable[str],
    limit_per_source: int | None,
) -> tuple[Counter, sqlite3.Connection]:
    stats: Counter = Counter()
    connection = _create_index(output / "index.sqlite3")
    upsert = """
        INSERT INTO fingerprints
            (canonical_hash, first_line, first_priority, min_label, max_label, occurrence_count)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT(canonical_hash) DO UPDATE SET
            occurrence_count = occurrence_count + 1,
            min_label = min(min_label, excluded.min_label),
            max_label = max(max_label, excluded.max_label),
            first_line = CASE WHEN excluded.first_priority > first_priority
                              THEN excluded.first_line ELSE first_line END,
            first_priority = max(first_priority, excluded.first_priority)
    """
    with (output / "staging.jsonl").open("w", encoding="utf-8", newline="\n") as staged, \
            (output / "parse_issues.jsonl").open("w", encoding="utf-8", newline="\n") as issues:
        for item in parse_sources(data_root, sources, limit_per_source):
            if item.issue is not None:
                issues.write(_json_line(item.issue.to_dict()))
                stats[f"parse_issue:{item.issue.source}:{item.issue.reason}"] += 1
                continue
            assert item.record is not None
            record = sanitize_record(item.record)
            if record.label_binary not in (0, 1):
                issue = ParseIssue(record.source, record.record_id, "invalid_binary_label")
                issues.write(_json_line(issue.to_dict()))
                stats[f"parse_issue:{record.source}:invalid_binary_label"] += 1
                continue
            canonical_hash = canonical_request_hash(record)
            group_id = safe_record_group(record)
            line_number = stats["staged_records"]
            envelope = {
                "canonical_hash": canonical_hash,
                "group_id": group_id,
                "record": record.to_dict(),
            }
            staged.write(_json_line(envelope))
            priority = _role_priority(record.dataset_role)
            connection.execute(
                upsert,
                (canonical_hash, line_number, priority, record.label_binary, record.label_binary),
            )
            stats["staged_records"] += 1
            stats[f"source:{record.source}"] += 1
            stats[f"role:{record.dataset_role}"] += 1
            stats[f"binary:{record.label_binary}"] += 1
            if stats["staged_records"] % 25_000 == 0:
                connection.commit()
    connection.commit()
    return stats, connection


def _write_conflicts(connection: sqlite3.Connection, output: Path) -> tuple[int, int]:
    group_count = 0
    occurrence_count = 0
    query = """
        SELECT canonical_hash, occurrence_count, min_label, max_label
        FROM fingerprints WHERE min_label <> max_label ORDER BY canonical_hash
    """
    with (output / "label_conflicts.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for canonical_hash, occurrences, minimum, maximum in connection.execute(query):
            handle.write(_json_line({
                "canonical_hash": canonical_hash,
                "occurrence_count": occurrences,
                "labels": [minimum, maximum],
                "action": "quarantined_all_occurrences",
            }))
            group_count += 1
            occurrence_count += occurrences
    return group_count, occurrence_count


def _index_unique_training_groups(connection: sqlite3.Connection, output: Path) -> None:
    lookup = connection.cursor()
    upsert = """
        INSERT INTO group_stats (group_id, source, normal_count, attack_count, record_count)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(group_id) DO UPDATE SET
            normal_count = normal_count + excluded.normal_count,
            attack_count = attack_count + excluded.attack_count,
            record_count = record_count + 1
    """
    with (output / "staging.jsonl").open(encoding="utf-8") as staged:
        for line_number, line in enumerate(staged):
            envelope = json.loads(line)
            first_line, minimum, maximum = lookup.execute(
                "SELECT first_line, min_label, max_label FROM fingerprints WHERE canonical_hash = ?",
                (envelope["canonical_hash"],),
            ).fetchone()
            if line_number != first_line or minimum != maximum:
                continue
            record = HttpRecord.from_dict(envelope["record"])
            if record.dataset_role != "train_candidate":
                continue
            connection.execute(
                upsert,
                (envelope["group_id"], record.source,
                 int(record.label_binary == 0), int(record.label_binary == 1)),
            )
    connection.commit()


def _assign_training_groups(
    connection: sqlite3.Connection,
    seed: int,
    train_ratio: float,
    validation_ratio: float,
) -> Counter:
    """Deterministic greedy balance within source/label strata."""

    ratios = {"train": train_ratio, "validation": validation_ratio,
              "test": 1 - train_ratio - validation_ratio}
    strata: dict[tuple[str, str], list[tuple[str, int]]] = {}
    for group_id, source, normal, attack, count in connection.execute(
        "SELECT group_id, source, normal_count, attack_count, record_count FROM group_stats"
    ):
        label_shape = "mixed" if normal and attack else "attack" if attack else "normal"
        strata.setdefault((source, label_shape), []).append((group_id, count))

    stats: Counter = Counter()
    for (source, label_shape), groups in sorted(strata.items()):
        groups.sort(key=lambda item: (
            -item[1],
            hashlib.sha256(f"{seed}:{item[0]}".encode("utf-8")).digest(),
        ))
        total = sum(count for _, count in groups)
        assigned = {name: 0 for name in ratios}
        for group_id, count in groups:
            candidates = sorted(
                ratios,
                key=lambda name: (
                    assigned[name] / max(total * ratios[name], 1),
                    hashlib.sha256(f"{seed}:{group_id}:{name}".encode("utf-8")).digest(),
                ),
            )
            split = candidates[0]
            connection.execute(
                "INSERT INTO group_assignments (group_id, split) VALUES (?, ?)",
                (group_id, split),
            )
            assigned[split] += count
            stats[f"stratum:{source}:{label_shape}:{split}"] += count
    connection.commit()
    return stats


def _materialize_splits(
    connection: sqlite3.Connection,
    output: Path,
) -> Counter:
    stats: Counter = Counter()
    destinations = {
        name: (output / f"{name}.jsonl").open("w", encoding="utf-8", newline="\n")
        for name in ("train", "validation", "test", "external_eval", "context_holdout")
    }
    lookup = connection.cursor()
    try:
        with (output / "staging.jsonl").open(encoding="utf-8") as staged:
            for line_number, line in enumerate(staged):
                envelope = json.loads(line)
                row = lookup.execute(
                    "SELECT first_line, min_label, max_label, occurrence_count FROM fingerprints WHERE canonical_hash = ?",
                    (envelope["canonical_hash"],),
                ).fetchone()
                if row is None:
                    raise RuntimeError("staging/index mismatch")
                first_line, minimum, maximum, occurrences = row
                if minimum != maximum:
                    if line_number == first_line:
                        stats["quarantined_conflict_groups"] += 1
                        stats["quarantined_conflict_occurrences"] += occurrences
                    continue
                if line_number != first_line:
                    stats["removed_exact_duplicates"] += 1
                    continue
                record = HttpRecord.from_dict(envelope["record"])
                if record.dataset_role == "external_eval":
                    split = "external_eval"
                elif record.dataset_role == "context_holdout":
                    split = "context_holdout"
                else:
                    assigned = lookup.execute(
                        "SELECT split FROM group_assignments WHERE group_id = ?",
                        (envelope["group_id"],),
                    ).fetchone()
                    if assigned is None:
                        raise RuntimeError(f"missing group assignment: {envelope['group_id']}")
                    split = assigned[0]
                output_value = {
                    "split": split,
                    "canonical_hash": envelope["canonical_hash"],
                    "group_id": envelope["group_id"],
                    "record": envelope["record"],
                }
                destinations[split].write(_json_line(output_value))
                stats[f"split:{split}"] += 1
                stats[f"split:{split}:binary:{record.label_binary}"] += 1
                stats[f"split:{split}:source:{record.source}"] += 1
                for family in record.label_families:
                    stats[f"split:{split}:family:{family}"] += 1
    finally:
        for handle in destinations.values():
            handle.close()
    stats["unique_groups_seen"] = connection.execute(
        "SELECT count(*) FROM group_assignments"
    ).fetchone()[0]
    return stats


def build_dataset(
    data_root: Path,
    output: Path,
    sources: Iterable[str] = ("wcp", "capec", "csic", "ecml", "httpparams", "bac"),
    seed: int = 42,
    train_ratio: float = 0.70,
    validation_ratio: float = 0.15,
    limit_per_source: int | None = None,
    overwrite: bool = False,
) -> dict[str, object]:
    if not 0 < train_ratio < 1 or not 0 < validation_ratio < 1:
        raise ValueError("train and validation ratios must be between 0 and 1")
    if train_ratio + validation_ratio >= 1:
        raise ValueError("train + validation ratio must be less than 1")
    source_list = tuple(sources)
    unknown = sorted(set(source_list) - {"wcp", "capec", "csic", "ecml", "httpparams", "bac"})
    if unknown:
        raise ValueError(f"unknown sources: {', '.join(unknown)}")
    _prepare_output(output, overwrite)
    stage_stats, connection = _stage_records(data_root, output, source_list, limit_per_source)
    try:
        conflict_groups, conflict_occurrences = _write_conflicts(connection, output)
        _index_unique_training_groups(connection, output)
        balance_stats = _assign_training_groups(connection, seed, train_ratio, validation_ratio)
        split_stats = _materialize_splits(connection, output)
        fingerprint_count = connection.execute("SELECT count(*) FROM fingerprints").fetchone()[0]
    finally:
        connection.close()
    manifest: dict[str, object] = {
        "schema_version": 2,
        "seed": seed,
        "ratios": {
            "train": train_ratio,
            "validation": validation_ratio,
            "test": round(1 - train_ratio - validation_ratio, 12),
        },
        "sources": list(source_list),
        "limit_per_source": limit_per_source,
        "staging": dict(sorted(stage_stats.items())),
        "splits": dict(sorted(split_stats.items())),
        "group_balance": dict(sorted(balance_stats.items())),
        "fingerprint_groups": fingerprint_count,
        "label_conflict_groups": conflict_groups,
        "label_conflict_occurrences": conflict_occurrences,
        "policies": {
            "deduplication": "keep one exact canonical request, prefer external_eval over train",
            "label_conflict": "quarantine every occurrence",
            "group_assignment": "deterministic greedy row balance within source/label strata",
            "sensitive_headers": "authorization/cookie/network addresses redacted; host value removed",
            "bac_ml_1m": "context_holdout only; post-request outcomes excluded from model input",
            "web_ids23": "catalogued separately; incompatible network-flow rows are not converted to HTTP requests",
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest
