from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from security_ai.data.schema import HttpRecord


PAD_ID = 0
CLS_ID = 1
SEP_ID = 2
TRUNC_ID = 3
MISSING_ID = 9
FIELD_TOKEN_IDS = {
    "method": 4,
    "path": 5,
    "query": 6,
    "headers": 7,
    "body": 8,
}
BYTE_ID_OFFSET = 16
VOCAB_SIZE = BYTE_ID_OFFSET + 256

FIELD_IDS = {
    "special": 0,
    "method": 1,
    "path": 2,
    "query": 3,
    "headers": 4,
    "body": 5,
}
FIELD_VOCAB_SIZE = len(FIELD_IDS)
FIELD_ORDER = ("method", "path", "query", "headers", "body")

# max_length=1024에서 약 1,008 byte를 배분하는 첫 기준이다. 더 짧은
# 실험에서는 같은 비율로 줄이고, 짧아서 남은 몫은 긴 필드에 재분배한다.
DEFAULT_FIELD_BUDGETS = {
    "method": 16,
    "path": 160,
    "query": 256,
    "headers": 192,
    "body": 384,
}


@dataclass(frozen=True)
class ByteOffset:
    field: str
    byte_index: int


@dataclass(frozen=True)
class EncodedRequest:
    input_ids: tuple[int, ...]
    field_ids: tuple[int, ...]
    attention_mask: tuple[int, ...]
    offsets: tuple[ByteOffset | None, ...]
    truncated_fields: tuple[str, ...]


class ByteHttpTokenizer:
    """Lossless UTF-8 byte tokenizer with field markers and byte offsets."""

    def __init__(
        self,
        max_length: int = 1024,
        field_budgets: Mapping[str, int] | None = None,
    ) -> None:
        if max_length < 16:
            raise ValueError("max_length must be at least 16")
        self.max_length = max_length
        self.field_budgets = dict(field_budgets or DEFAULT_FIELD_BUDGETS)
        if set(self.field_budgets) != set(FIELD_ORDER):
            raise ValueError(f"field_budgets must contain exactly: {', '.join(FIELD_ORDER)}")
        if any(value <= 0 for value in self.field_budgets.values()):
            raise ValueError("every field budget must be positive")

    @staticmethod
    def _field_bytes(record: HttpRecord) -> dict[str, bytes]:
        headers = "\n".join(f"{name}: {value}" for name, value in record.headers)
        return {
            "method": record.method.encode("utf-8", errors="surrogatepass"),
            "path": record.path.encode("utf-8", errors="surrogatepass"),
            "query": record.query.encode("utf-8", errors="surrogatepass"),
            "headers": headers.encode("utf-8", errors="surrogatepass"),
            "body": record.body.encode("utf-8", errors="surrogatepass"),
        }

    def _allocate(self, values: Mapping[str, bytes], extra_special_tokens: int = 0) -> dict[str, int]:
        capacity = self.max_length - len(FIELD_ORDER) - 2 - extra_special_tokens
        preferred_total = sum(self.field_budgets.values())
        scale = min(1.0, capacity / preferred_total)
        allocation = {
            name: min(len(values[name]), max(1, int(self.field_budgets[name] * scale)))
            if values[name] else 0
            for name in FIELD_ORDER
        }
        remaining = capacity - sum(allocation.values())

        # 공격 문자열이 많이 위치하는 query/body를 먼저 늘리되, 한 필드가
        # 남은 공간을 전부 독점하지 않도록 round-robin으로 재분배한다.
        priority = ("query", "body", "path", "headers", "method")
        while remaining:
            changed = False
            for name in priority:
                if allocation[name] < len(values[name]):
                    allocation[name] += 1
                    remaining -= 1
                    changed = True
                    if remaining == 0:
                        break
            if not changed:
                break
        return allocation

    @staticmethod
    def _encode_field(value: bytes, budget: int, field: str) -> tuple[list[int], list[ByteOffset | None], bool]:
        if len(value) <= budget:
            return (
                [BYTE_ID_OFFSET + byte for byte in value],
                [ByteOffset(field, index) for index in range(len(value))],
                False,
            )
        if budget <= 0:
            return [], [], bool(value)
        if budget == 1:
            return [TRUNC_ID], [None], True

        kept = budget - 1
        head = (kept + 1) // 2
        tail = kept - head
        head_bytes = value[:head]
        tail_bytes = value[len(value) - tail:] if tail else b""
        tokens = [BYTE_ID_OFFSET + byte for byte in head_bytes]
        offsets: list[ByteOffset | None] = [ByteOffset(field, index) for index in range(head)]
        tokens.append(TRUNC_ID)
        offsets.append(None)
        if tail:
            tail_start = len(value) - tail
            tokens.extend(BYTE_ID_OFFSET + byte for byte in tail_bytes)
            offsets.extend(ByteOffset(field, index) for index in range(tail_start, len(value)))
        return tokens, offsets, True

    def encode(self, record: HttpRecord) -> EncodedRequest:
        values = self._field_bytes(record)
        missing_body = not record.body_observed
        if missing_body:
            values["body"] = b""
        allocation = self._allocate(values, extra_special_tokens=int(missing_body))
        input_ids = [CLS_ID]
        field_ids = [FIELD_IDS["special"]]
        offsets: list[ByteOffset | None] = [None]
        truncated: list[str] = []

        for field in FIELD_ORDER:
            input_ids.append(FIELD_TOKEN_IDS[field])
            field_ids.append(FIELD_IDS[field])
            offsets.append(None)
            if field == "body" and missing_body:
                input_ids.append(MISSING_ID)
                field_ids.append(FIELD_IDS[field])
                offsets.append(None)
                continue
            tokens, token_offsets, was_truncated = self._encode_field(
                values[field], allocation[field], field
            )
            input_ids.extend(tokens)
            field_ids.extend([FIELD_IDS[field]] * len(tokens))
            offsets.extend(token_offsets)
            if was_truncated:
                truncated.append(field)

        input_ids.append(SEP_ID)
        field_ids.append(FIELD_IDS["special"])
        offsets.append(None)
        if len(input_ids) > self.max_length:
            raise AssertionError("token budget exceeded max_length")
        return EncodedRequest(
            input_ids=tuple(input_ids),
            field_ids=tuple(field_ids),
            attention_mask=(1,) * len(input_ids),
            offsets=tuple(offsets),
            truncated_fields=tuple(truncated),
        )

    def specification(self) -> dict[str, object]:
        return {
            "type": "utf8_byte",
            "version": 1,
            "max_length": self.max_length,
            "vocab_size": VOCAB_SIZE,
            "byte_id_offset": BYTE_ID_OFFSET,
            "special_token_ids": {
                "pad": PAD_ID,
                "cls": CLS_ID,
                "sep": SEP_ID,
                "trunc": TRUNC_ID,
                "missing": MISSING_ID,
                **FIELD_TOKEN_IDS,
            },
            "field_ids": FIELD_IDS,
            "field_budgets": self.field_budgets,
            "truncation": "head_tail_with_trunc_token",
        }
