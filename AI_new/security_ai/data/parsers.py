from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

from .canonical import (
    decoded_payload_group,
    first_header,
    normalize_headers,
    normalized_method,
    parse_header_block,
    split_target,
    structural_template_group,
)
from .schema import AttackSpan, HttpRecord, ParseIssue, ParsedItem, RecordIterator


WCP_FAMILY = {
    "cmdexe": "command_injection",
    "log4shell": "log4shell",
    "shellshock": "shellshock",
    "sqli": "sqli",
    "traversal": "path_traversal",
    "xss": "xss",
    "xxe": "xxe",
}

CAPEC_FAMILY = {
    "272 - Protocol Manipulation": "protocol_manipulation",
    "242 - Code Injection": "code_injection",
    "88 - OS Command Injection": "command_injection",
    "126 - Path Traversal": "path_traversal",
    "66 - SQL Injection": "sqli",
    "16 - Dictionary-based Password Attack": "credential_attack",
    "310 - Scanning for Vulnerable Software": "vulnerability_scanning",
    "153 - Input Data Manipulation": "input_manipulation",
    "248 - Command Injection": "command_injection",
    "274 - HTTP Verb Tampering": "http_verb_tampering",
    "194 - Fake the Source of Data": "source_spoofing",
    "34 - HTTP Response Splitting": "http_response_splitting",
    "33 - HTTP Request Smuggling": "http_request_smuggling",
}
CAPEC_V1_SUPPORTED = {"sqli", "path_traversal", "command_injection"}

ECML_FAMILY = {
    "SqlInjection": "sqli",
    "XSS": "xss",
    "PathTransversal": "path_traversal",
    "OsCommanding": "command_injection",
    "XPathInjection": "xpath_injection",
    "LdapInjection": "ldap_injection",
    "SSI": "ssi",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def iter_json_array(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[Any]:
    """Stream a top-level JSON array without loading the complete file."""

    decoder = json.JSONDecoder()
    with path.open(encoding="utf-8-sig") as handle:
        buffer = ""
        position = 0
        eof = False

        def refill() -> bool:
            nonlocal buffer, position, eof
            if eof:
                return False
            if position:
                buffer = buffer[position:]
                position = 0
            chunk = handle.read(chunk_size)
            if not chunk:
                eof = True
                return False
            buffer += chunk
            return True

        refill()
        while True:
            while position >= len(buffer) and refill():
                pass
            while position < len(buffer) and buffer[position].isspace():
                position += 1
            if position < len(buffer) and buffer[position] == "[":
                position += 1
                break
            raise ValueError(f"top-level JSON value is not an array: {path}")

        while True:
            while True:
                while position >= len(buffer) and refill():
                    pass
                while position < len(buffer) and (buffer[position].isspace() or buffer[position] == ","):
                    position += 1
                if position < len(buffer):
                    break
                if eof:
                    raise ValueError(f"unterminated JSON array: {path}")
            if buffer[position] == "]":
                return
            while True:
                try:
                    value, end = decoder.raw_decode(buffer, position)
                    position = end
                    yield value
                    break
                except json.JSONDecodeError:
                    if not refill():
                        raise ValueError(f"invalid or truncated JSON array: {path}")


def iter_wcp(root: Path, limit: int | None = None) -> RecordIterator:
    base = root / "WAF_Comparison"
    emitted = 0
    for branch, binary in (("legitimate", 0), ("malicious", 1)):
        for path in sorted((base / branch).rglob("*.json")):
            family = WCP_FAMILY.get(path.stem) if binary else None
            try:
                rows = iter_json_array(path)
                for index, row in enumerate(rows, 1):
                    if limit is not None and emitted >= limit:
                        return
                    if not isinstance(row, dict):
                        yield ParsedItem(issue=ParseIssue("wcp", f"{path.name}:{index}", "record_not_object"))
                        continue
                    try:
                        method = normalized_method(_text(row.get("method")))
                        path_part, query = split_target(_text(row.get("url")))
                        raw_headers = row.get("headers") or {}
                        if not isinstance(raw_headers, dict):
                            raise ValueError("headers is not an object")
                        headers = normalize_headers([(str(k), _text(v)) for k, v in raw_headers.items()])
                        body = _text(row.get("data"))
                        content_type = first_header(headers, "content-type")
                        payload = query.partition("=")[2] if method == "GET" else body.partition("=")[2]
                        payload_group = decoded_payload_group(payload, f"wcp-{family}") if binary else ""
                        record = HttpRecord(
                            record_id=f"{path.name}:{index}", source="wcp", source_version="local_snapshot",
                            dataset_role="train_candidate", method=method, path=path_part, query=query,
                            headers=headers, body=body, body_observed="data" in row,
                            content_type=content_type, label_binary=binary,
                            label_families=(family,) if family else (), family_label_complete=True,
                            source_labels=(path.stem if binary else "legitimate",),
                            source_group=f"wcp-site:{path.stem}" if not binary else "",
                            payload_group=payload_group,
                            metadata={"source_file": path.name},
                        )
                        yield ParsedItem(record=record)
                        emitted += 1
                    except (TypeError, ValueError) as exc:
                        yield ParsedItem(issue=ParseIssue("wcp", f"{path.name}:{index}", "invalid_record", str(exc)))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                yield ParsedItem(issue=ParseIssue("wcp", path.name, "file_parse_failed", str(exc)))


def _capec_headers(row: dict[str, str]) -> tuple[tuple[str, str], ...]:
    mapping = (
        ("user-agent", "request_user_agent"), ("referer", "request_referer"),
        ("host", "request_host"), ("origin", "request_origin"),
        ("cookie", "request_cookie"), ("content-type", "request_content_type"),
        ("accept", "request_accept"), ("accept-language", "request_accept_language"),
        ("accept-encoding", "request_accept_encoding"), ("dnt", "request_do_not_track"),
        ("connection", "request_connection"),
    )
    return tuple((name, row.get(column, "")) for name, column in mapping if row.get(column, ""))


def iter_capec(root: Path, limit: int | None = None) -> RecordIterator:
    path = root / "capec" / "data_capec_multilabel.csv"
    csv.field_size_limit(128 * 1024 * 1024)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle), 1):
            if limit is not None and index > limit:
                return
            locator = f"{path.name}:{index + 1}"
            try:
                method = normalized_method(row.get("request_http_method", ""))
                target = row.get("request_http_request", "")
                if not method or not target:
                    yield ParsedItem(issue=ParseIssue("capec", locator, "missing_request_core"))
                    continue
                labels = tuple(column for column in CAPEC_FAMILY if row.get(column) == "1")
                normal = row.get("000 - Normal") == "1"
                if normal and labels:
                    yield ParsedItem(issue=ParseIssue("capec", locator, "row_label_conflict"))
                    continue
                if not normal and not labels:
                    yield ParsedItem(issue=ParseIssue("capec", locator, "missing_label"))
                    continue
                families = tuple(sorted({CAPEC_FAMILY[label] for label in labels}))
                supported = not labels or bool(set(families) & CAPEC_V1_SUPPORTED)
                path_part, query = split_target(target)
                headers = _capec_headers(row)
                record = HttpRecord(
                    record_id=str(index), source="capec", source_version="local_snapshot",
                    dataset_role="train_candidate" if supported else "context_holdout",
                    method=method, path=path_part, query=query, headers=headers,
                    body=row.get("request_body", ""), body_observed=True,
                    content_type=row.get("request_content_type", ""), label_binary=0 if normal else 1,
                    label_families=families, family_label_complete=True,
                    label_confidence="source_reported" if supported else "context_dependent",
                    source_labels=("000 - Normal",) if normal else labels,
                    metadata={"protocol": row.get("request_http_protocol", "")},
                )
                record = HttpRecord(**{**record.__dict__, "source_group": structural_template_group(record)})
                yield ParsedItem(record=record)
            except (TypeError, ValueError) as exc:
                yield ParsedItem(issue=ParseIssue("capec", locator, "invalid_record", str(exc)))


def _read_raw_http(handle: BinaryIO) -> Iterator[tuple[int, str, list[tuple[str, str]], str]]:
    request_number = 0
    while True:
        line = handle.readline()
        while line in (b"\r\n", b"\n"):
            line = handle.readline()
        if not line:
            return
        request_number += 1
        request_line = line.rstrip(b"\r\n").decode("latin-1")
        headers: list[tuple[str, str]] = []
        while True:
            line = handle.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            decoded = line.rstrip(b"\r\n").decode("latin-1")
            if decoded[:1] in " \t" and headers:
                key, old = headers[-1]
                headers[-1] = (key, f"{old} {decoded.strip()}")
                continue
            key, separator, value = decoded.partition(":")
            if separator:
                headers.append((key, value))
        normalized = normalize_headers(headers)
        content_length = first_header(normalized, "content-length")
        if content_length:
            length = int(content_length)
            if length < 0 or length > 128 * 1024 * 1024:
                raise ValueError(f"unsafe Content-Length {length} at request {request_number}")
            body = handle.read(length).decode("latin-1")
        else:
            body = ""
        yield request_number, request_line, list(normalized), body


def iter_csic(root: Path, limit: int | None = None) -> RecordIterator:
    base = root / "WAAD" / "OriginalDataSets" / "csic_2010"
    files = (
        ("normalTrafficTraining.txt", 0, "normal-training"),
        ("normalTrafficTest.txt", 0, "normal-test"),
        ("anomalousTrafficTest.txt", 1, "anomalous-test"),
    )
    emitted = 0
    for filename, binary, source_label in files:
        path = base / filename
        try:
            with path.open("rb") as handle:
                for index, request_line, headers_list, body in _read_raw_http(handle):
                    if limit is not None and emitted >= limit:
                        return
                    locator = f"{filename}:{index}"
                    try:
                        method, target, protocol = request_line.split(" ", 2)
                        path_part, query = split_target(target)
                        headers = tuple(headers_list)
                        record = HttpRecord(
                            record_id=locator, source="csic", source_version="2010",
                            dataset_role="train_candidate", method=normalized_method(method),
                            path=path_part, query=query, headers=headers, body=body,
                            body_observed=True, content_type=first_header(headers, "content-type"),
                            label_binary=binary, label_families=(), family_label_complete=False,
                            label_confidence="source_reported", source_labels=(source_label,),
                            metadata={"protocol": protocol},
                        )
                        record = HttpRecord(**{**record.__dict__, "source_group": structural_template_group(record)})
                        yield ParsedItem(record=record)
                        emitted += 1
                    except ValueError as exc:
                        yield ParsedItem(issue=ParseIssue("csic", locator, "invalid_request_line", str(exc)))
        except (OSError, ValueError) as exc:
            yield ParsedItem(issue=ParseIssue("csic", filename, "file_parse_failed", str(exc)))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(parent: ET.Element, name: str) -> str:
    for child in parent:
        if _local_name(child.tag) == name:
            return child.text or ""
    return ""


def _ecml_spans(sample: ET.Element) -> tuple[AttackSpan, ...]:
    result: list[AttackSpan] = []
    for element in sample.iter():
        if _local_name(element.tag) != "attackIntervall":
            continue
        raw = element.text or ""
        match = re.match(r"([^:]+):.*?(\d+)-(\d+)$", raw)
        result.append(AttackSpan(
            field=raw.partition(":")[0], raw_annotation=raw,
            start=int(match.group(2)) if match else None,
            end=int(match.group(3)) if match else None,
        ))
    return tuple(result)


def iter_ecml(root: Path, limit: int | None = None) -> RecordIterator:
    path = root / "WAAD" / "OriginalDataSets" / "ecml_pkdd" / "learning_dataset_xml.zip"
    emitted = 0
    with zipfile.ZipFile(path) as archive, archive.open("learning_dataset.xml") as handle:
        for _, sample in ET.iterparse(handle, events=("end",)):
            if _local_name(sample.tag) != "sample":
                continue
            if limit is not None and emitted >= limit:
                sample.clear()
                return
            record_id = sample.attrib.get("id", str(emitted + 1))
            try:
                class_element = next(child for child in sample if _local_name(child.tag) == "class")
                labels = tuple((child.text or "") for child in class_element if _local_name(child.tag) == "type")
                normal = labels == ("Valid",)
                if "Valid" in labels and len(labels) > 1:
                    yield ParsedItem(issue=ParseIssue("ecml", record_id, "row_label_conflict"))
                    sample.clear()
                    continue
                request = next(child for child in sample if _local_name(child.tag) == "request")
                method = normalized_method(_child_text(request, "method"))
                uri = _child_text(request, "uri")
                query = _child_text(request, "query")
                if not method or not uri:
                    yield ParsedItem(issue=ParseIssue("ecml", record_id, "missing_request_core"))
                    sample.clear()
                    continue
                headers_block = _child_text(request, "headers")
                headers = parse_header_block(headers_block)
                body_elements = [child for child in request if _local_name(child.tag) == "body"]
                body = body_elements[0].text or "" if body_elements else ""
                families = tuple(sorted({ECML_FAMILY[label] for label in labels if label in ECML_FAMILY}))
                record = HttpRecord(
                    record_id=record_id, source="ecml", source_version="ECML-PKDD-2007",
                    dataset_role="train_candidate", method=method, path=uri, query=query,
                    headers=headers, body=body, body_observed=bool(body_elements),
                    content_type=first_header(headers, "content-type"), label_binary=0 if normal else 1,
                    label_families=families, family_label_complete=True,
                    source_labels=labels, spans=_ecml_spans(sample),
                    metadata={"protocol": _child_text(request, "protocol")},
                )
                record = HttpRecord(**{**record.__dict__, "source_group": structural_template_group(record)})
                yield ParsedItem(record=record)
                emitted += 1
            except (StopIteration, TypeError, ValueError) as exc:
                yield ParsedItem(issue=ParseIssue("ecml", record_id, "invalid_record", str(exc)))
            finally:
                sample.clear()


def iter_httpparams(root: Path, limit: int | None = None) -> RecordIterator:
    base = root / "HttpParams"
    emitted = 0
    for filename in ("payload_full.csv", "payload_test_lexical.csv"):
        path = base / filename
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for index, row in enumerate(csv.DictReader(handle), 1):
                if limit is not None and emitted >= limit:
                    return
                payload = row.get("payload", "")
                anomalous = row.get("label") == "anom"
                attack_type = row.get("attack_type", "")
                family = {
                    "sqli": "sqli", "xss": "xss", "path-traversal": "path_traversal",
                    "cmdi": "command_injection", "sql-syntax": "sqli", "js-syntax": "xss",
                }.get(attack_type)
                yield ParsedItem(record=HttpRecord(
                    record_id=f"{filename}:{index}", source="httpparams", source_version="local_snapshot",
                    dataset_role="external_eval", method="PARAM", path="/", query=payload,
                    body_observed=False, label_binary=int(anomalous),
                    label_families=(family,) if family else (), family_label_complete=True,
                    source_labels=(attack_type,),
                    payload_group=decoded_payload_group(payload, "httpparams"),
                    metadata={"source_file": filename},
                ))
                emitted += 1


def _bac_actor_relation(user_id: str, resource: str, resource_type: str) -> str:
    if resource_type not in {"user", "account"}:
        return "unknown"
    identifiers = re.findall(r"/(\d+)(?:/|$)", resource)
    if not identifiers:
        return "unknown"
    return "same" if identifiers[-1] == user_id else "different"


def iter_bac(root: Path, limit: int | None = None) -> RecordIterator:
    """Parse one verified BAC-ML-1M copy as context-only records."""

    base = root / "BAC-ML-1M"
    preferred = base / "enhanced_bac_results.csv"
    candidates = [preferred] if preferred.exists() else sorted(base.rglob("enhanced_bac_results.csv"))[:1]
    if not candidates:
        yield ParsedItem(issue=ParseIssue("bac_ml_1m", "", "source_file_missing"))
        return
    path = candidates[0]
    csv.field_size_limit(128 * 1024 * 1024)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle), 1):
            if limit is not None and index > limit:
                return
            locator = f"{path.name}:{index + 1}"
            try:
                method = normalized_method(row.get("request_method", ""))
                target = row.get("requested_resource", "")
                label_text = row.get("attack_detected", "")
                if not method or not target:
                    yield ParsedItem(issue=ParseIssue("bac_ml_1m", locator, "missing_request_core"))
                    continue
                if label_text not in {"0", "1"}:
                    yield ParsedItem(issue=ParseIssue("bac_ml_1m", locator, "invalid_binary_label", label_text))
                    continue
                binary = int(label_text)
                vulnerability = row.get("vulnerability_type", "")
                expected_vulnerability = "Yes (IDOR)" if binary else "No"
                if vulnerability != expected_vulnerability:
                    yield ParsedItem(issue=ParseIssue("bac_ml_1m", locator, "label_evidence_mismatch"))
                    continue
                path_part, query = split_target(target)
                headers = normalize_headers([
                    ("referer", row.get("referrer", "")),
                    ("user-agent", row.get("user_agent", "")),
                ])
                actor_relation = _bac_actor_relation(
                    row.get("user_id", ""), target, row.get("resource_type", "")
                )
                context = (
                    ("user_role", row.get("user_role", "")),
                    ("auth_method", row.get("auth_method", "")),
                    ("auth_token_validity", row.get("auth_token_validity", "")),
                    ("login_status", row.get("login_status", "")),
                    ("resource_classification", row.get("resource_classification", "")),
                    ("resource_type", row.get("resource_type", "")),
                    ("expected_access", row.get("expected_access", "")),
                    ("actor_resource_relation", actor_relation),
                    ("attack_payload", row.get("attack_payload", "")),
                )
                yield ParsedItem(record=HttpRecord(
                    record_id=f"row:{index}", source="bac_ml_1m", source_version="2",
                    dataset_role="context_holdout", method=method, path=path_part, query=query,
                    headers=headers, body="", body_observed=False, input_context=context,
                    label_binary=binary,
                    label_families=("broken_access_control",) if binary else (),
                    family_label_complete=True, label_confidence="synthetic_success_label",
                    source_labels=(vulnerability,),
                    metadata={
                        "source_request_id": row.get("request_id", ""),
                        "actual_access_granted": row.get("actual_access_granted", ""),
                        "response_code": row.get("response_code", ""),
                    },
                ))
            except (TypeError, ValueError) as exc:
                yield ParsedItem(issue=ParseIssue("bac_ml_1m", locator, "invalid_record", str(exc)))


PARSERS = {
    "wcp": iter_wcp,
    "capec": iter_capec,
    "csic": iter_csic,
    "ecml": iter_ecml,
    "httpparams": iter_httpparams,
    "bac": iter_bac,
}


def parse_sources(root: Path, sources: Iterable[str], limit_per_source: int | None = None) -> RecordIterator:
    for source in sources:
        parser = PARSERS.get(source)
        if parser is None:
            yield ParsedItem(issue=ParseIssue(source, "", "unknown_source"))
            continue
        yield from parser(root, limit_per_source)
