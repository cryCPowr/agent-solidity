"""Core output data models.

These are intentionally thin, serialization-oriented dataclasses. They carry
no analysis logic. Every field that could be missing is represented
explicitly (``None`` / ``"unknown"``) rather than omitted or guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Valid epistemic statuses for a Fact or a derived relationship.
STATUS_OBSERVED = "observed"   # Directly represented in the AST/source.
STATUS_DERIVED = "derived"     # Deterministically inferred from >=1 observations.
STATUS_UNKNOWN = "unknown"     # Could not be determined reliably.
STATUS_PARTIAL = "partial"     # Partially determined; some sub-parts unknown.

VALID_STATUSES = {STATUS_OBSERVED, STATUS_DERIVED, STATUS_UNKNOWN, STATUS_PARTIAL}


@dataclass
class SourceRef:
    file: str
    start: Optional[int] = None
    end: Optional[int] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    ast_node_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "start": self.start,
            "end": self.end,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "ast_node_id": self.ast_node_id,
        }


@dataclass
class Evidence:
    id: str
    file: str
    start_line: Optional[int]
    end_line: Optional[int]
    start: Optional[int]
    end: Optional[int]
    snippet_path: Optional[str]
    fact_ids: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start": self.start,
            "end": self.end,
            "snippet_path": self.snippet_path,
            "fact_ids": sorted(set(self.fact_ids)),
        }


@dataclass
class Fact:
    id: str
    type: str
    status: str  # one of VALID_STATUSES
    subject: dict           # what the fact is about (contract/function/file refs)
    properties: dict        # atomic observed attributes
    source: Optional[SourceRef]
    evidence: list          # list of evidence ids
    confidence: str         # "high" | "medium" | "low" — extraction confidence, NOT a security rating
    extraction_method: str  # "ast" | "ast+heuristic" | "regex-fallback"

    def to_dict(self) -> dict:
        assert self.status in VALID_STATUSES, f"invalid status {self.status!r} on fact {self.id}"
        return {
            "id": self.id,
            "type": self.type,
            "status": self.status,
            "subject": self.subject,
            "properties": self.properties,
            "source": self.source.to_dict() if self.source else None,
            "evidence": sorted(set(self.evidence)),
            "confidence": self.confidence,
            "extraction_method": self.extraction_method,
        }


@dataclass
class GraphNode:
    id: str
    kind: str
    label: str
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    id: str
    type: str
    source: str
    target: str
    status: str
    properties: dict = field(default_factory=dict)
    fact_ids: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "target": self.target,
            "status": self.status,
            "properties": self.properties,
            "fact_ids": sorted(set(self.fact_ids)),
        }
