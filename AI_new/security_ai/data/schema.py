from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterator, Literal, Mapping, Sequence


DatasetRole = Literal["train_candidate", "external_eval", "context_holdout"]


@dataclass(frozen=True)
class AttackSpan:
    """An annotation in the source dataset's coordinate system."""

    field: str
    raw_annotation: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class HttpRecord:
    """Source-neutral HTTP request plus labels and provenance.

    Values used only for provenance (IP, time, response, source label) belong in
    metadata and must never be rendered into the model input.
    """

    record_id: str
    source: str
    source_version: str
    dataset_role: DatasetRole
    method: str
    path: str
    query: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""
    body_observed: bool = True
    content_type: str = ""
    input_context: tuple[tuple[str, str], ...] = ()
    label_binary: int | None = None
    label_families: tuple[str, ...] = ()
    family_label_complete: bool = False
    label_confidence: str = "source_reported"
    source_labels: tuple[str, ...] = ()
    source_group: str = ""
    payload_group: str = ""
    spans: tuple[AttackSpan, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["headers"] = [list(item) for item in self.headers]
        value["input_context"] = [list(item) for item in self.input_context]
        value["label_families"] = list(self.label_families)
        value["source_labels"] = list(self.source_labels)
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HttpRecord":
        copied = dict(value)
        copied["headers"] = tuple(tuple(item) for item in value.get("headers", ()))
        copied["input_context"] = tuple(tuple(item) for item in value.get("input_context", ()))
        copied["label_families"] = tuple(value.get("label_families", ()))
        copied["source_labels"] = tuple(value.get("source_labels", ()))
        copied["spans"] = tuple(AttackSpan(**item) for item in value.get("spans", ()))
        return cls(**copied)


@dataclass(frozen=True)
class ParseIssue:
    source: str
    locator: str
    reason: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ParsedItem:
    record: HttpRecord | None = None
    issue: ParseIssue | None = None

    def __post_init__(self) -> None:
        if (self.record is None) == (self.issue is None):
            raise ValueError("ParsedItem requires exactly one of record or issue")


RecordIterator = Iterator[ParsedItem]
HeaderInput = Sequence[tuple[str, str]]
