"""Validator data model + verdict types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Verdict semantics (strict):
#   CONFIRM      the executed test satisfied the plan's confirm_if
#                conditions -> the exploit path is real as tested
#   REJECT       the executed test disproved the path (confirm condition
#                failed / anti-condition held) -- a RESULT, not an error
#   INCONCLUSIVE no executed decision: compile error, missing harness,
#                infra failure. Never treated as REJECT.
CONFIRM = "CONFIRM"
REJECT = "REJECT"
INCONCLUSIVE = "INCONCLUSIVE"

# Blocking reasons before any code runs.
BLOCKED_NO_HARNESS = "BLOCKED_NO_HARNESS"
READY = "READY"


@dataclass
class Verdict:
    attack_id: str
    verdict: str                    # CONFIRM | REJECT | INCONCLUSIVE
    reason: str
    readiness: str = READY          # READY | BLOCKED_NO_HARNESS
    test_file: str = ""
    forge_output: str = ""
    retry_hint: str = ""            # for the ATTACK/THREAT refinement loop
    evidence: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "readiness": self.readiness,
            "test_file": self.test_file,
            "retry_hint": self.retry_hint,
            "evidence": self.evidence,
            "meta": self.meta,
        }


@dataclass
class ValidationRun:
    attack_id: str
    source_hypothesis_id: str
    strategy: str
    root_function: str
    entry_point: str
    probed_asset: str
    cross_assets: list[str]
    confirm_if: str
    reject_if: str
    exploitability_score: float
    fact_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "source_hypothesis_id": self.source_hypothesis_id,
            "strategy": self.strategy,
            "root_function": self.root_function,
            "entry_point": self.entry_point,
            "probed_asset": self.probed_asset,
            "cross_assets": self.cross_assets,
            "exploitability_score": self.exploitability_score,
        }
