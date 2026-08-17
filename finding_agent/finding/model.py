"""Finding data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    finding_id: str
    attack_id: str
    title: str
    severity: str                    # critical | high | medium | low | informational
    severity_rationale: str
    description: str
    impact: str
    attack_path: list[dict[str, Any]]    # ordered steps {order, action, status, location}
    affected_code: list[str]             # root function + step locations
    poc: dict[str, Any]                  # {test_file, workspace, command, meaning}
    mitigation: list[str]
    evidence: list[str]                  # upstream evidence lines (verbatim)
    fact_ids: list[str]
    uncertainty: list[str]               # preserved, never hidden
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "attack_id": self.attack_id,
            "title": self.title,
            "severity": self.severity,
            "severity_rationale": self.severity_rationale,
            "description": self.description,
            "impact": self.impact,
            "attack_path": self.attack_path,
            "affected_code": self.affected_code,
            "poc": self.poc,
            "mitigation": self.mitigation,
            "evidence": self.evidence,
            "fact_ids": self.fact_ids,
            "uncertainty": self.uncertainty,
        }
