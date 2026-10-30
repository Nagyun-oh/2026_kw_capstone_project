from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import unquote_plus, urlsplit

from .schema import HttpRecord


_SPACE = re.compile(r"[\t ]+")


def split_target(target: str) -> tuple[str, str]:
    """Return path/query for absolute or origin-form request targets."""

    target = target.strip()
    try:
        parsed = urlsplit(target)
    except ValueError:
        path, separator, query = target.partition("?")
        return path or "/", query if separator else ""
    path = parsed.path or "/"
    return path, parsed.query


def normalize_headers(headers: list[tuple[str, str]] | tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Normalize names only; preserve order, duplicates, and value case."""

    return tuple((name.strip().lower(), value.strip()) for name, value in headers if name.strip())


def parse_header_block(block: str) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = []
    for raw_line in block.replace("\r\n", "\n").split("\n"):
        if not raw_line:
            continue
        if raw_line[:1] in " \t" and headers:
            name, old = headers[-1]
            headers[-1] = (name, f"{old} {raw_line.strip()}")
            continue
        name, separator, value = raw_line.partition(":")
        if separator:
            headers.append((name, value))
    return normalize_headers(headers)


def first_header(headers: tuple[tuple[str, str], ...], name: str) -> str:
    wanted = name.lower()
    return next((value for key, value in headers if key == wanted), "")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def canonical_request_hash(record: HttpRecord) -> str:
    """Exact model-input-equivalence hash; no labels or provenance included."""

    payload = {
        "method": record.method.strip().upper(),
        "path": record.path,
        "query": record.query,
        "headers": sorted(normalize_headers(record.headers)),
        "body": record.body,
        "body_observed": record.body_observed,
        "input_context": sorted(record.input_context),
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return sha256_text(encoded)


def decoded_payload_group(value: str, prefix: str) -> str:
    """Bounded one-pass decoding for grouping only, never model input."""

    decoded = unquote_plus(value)
    return f"{prefix}:{sha256_text(decoded)}"


def structural_template_group(record: HttpRecord) -> str:
    """Conservative request-shape group used before dataset splitting."""

    def normalized_component(value: str) -> str:
        value = unquote_plus(value).lower()
        value = re.sub(r"[0-9a-f]{24,}", "{hex}", value)
        value = re.sub(r"\d+", "{n}", value)
        return "{id}" if len(value) > 32 and value.isalnum() else value

    segments = [normalized_component(segment) for segment in record.path.split("/") if segment]
    query_keys = sorted(
        normalized_component(part.partition("=")[0])
        for part in record.query.split("&") if part
    )
    form_body = "application/x-www-form-urlencoded" in record.content_type.lower()
    body_keys = sorted(
        normalized_component(part.partition("=")[0])
        for part in record.body.split("&") if part
    ) if form_body else []
    shape = json.dumps({
        "method": record.method,
        "path": segments,
        "query_keys": query_keys,
        "content_type": record.content_type.lower().partition(";")[0],
        "body_keys": body_keys,
    }, ensure_ascii=False, separators=(",", ":"))
    return f"{record.source}-template:{sha256_text(shape)}"


def safe_record_group(record: HttpRecord) -> str:
    if record.payload_group:
        return record.payload_group
    if record.source_group:
        return record.source_group
    return f"exact:{canonical_request_hash(record)}"


def normalized_method(value: str) -> str:
    return _SPACE.sub(" ", value.strip()).upper()
