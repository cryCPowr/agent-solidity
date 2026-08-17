"""Attack hypothesis data model.

Evidence discipline (for_attack_agent.md): every derived claim carries an
explicit status from

    PROVEN    fact-level evidence supports the claim
    INFERRED  strong structural evidence, not fact-proven
    POSSIBLE  plausible but unsupported
    UNKNOWN   missing; Validator must verify

Uncertainty is never upgraded into certainty by this agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PROVEN = "PROVEN"
INFERRED = "INFERRED"
POSSIBLE = "POSSIBLE"
UNKNOWN = "UNKNOWN"

STATUS_ORDER = {UNKNOWN: 0, POSSIBLE: 1, INFERRED: 2, PROVEN: 3}


def strongest(*statuses: str) -> str:
    valid = [s for s in statuses if s in STATUS_ORDER]
    return max(valid, key=lambda s: STATUS_ORDER[s]) if valid else UNKNOWN


@dataclass
class AttackStep:
    order: int
    action: str
    status: str = UNKNOWN
    fact_ids: list[str] = field(default_factory=list)
    location: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "action": self.action,
            "status": self.status,
            "fact_ids": self.fact_ids,
            "location": self.location,
        }


@dataclass
class AttackHypothesis:
    attack_id: str
    source_hypothesis_id: str
    root_function: str
    attacker_model: str = ""
    production_relevance: str = ""
    attack_strategy: str = ""
    strategy_status: str = UNKNOWN
    entry_point: dict[str, Any] = field(default_factory=dict)
    controlled_inputs: list[dict[str, Any]] = field(default_factory=list)
    propagation_path: list[dict[str, Any]] = field(default_factory=list)
    sensitive_sink: dict[str, Any] = field(default_factory=dict)
    capability_obtained: str = ""
    affected_assets: list[str] = field(default_factory=list)
    expected_consequence: dict[str, Any] = field(default_factory=dict)
    attack_steps: list[AttackStep] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    fact_ids: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    uncertainty: list[str] = field(default_factory=list)
    validator_plan: dict[str, Any] = field(default_factory=dict)
    exploitability_score: float = 0.0
    exploitability_band: str = "low"
    linked_hypothesis_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "source_hypothesis_id": self.source_hypothesis_id,
            "linked_hypothesis_ids": self.linked_hypothesis_ids,
            "root_function": self.root_function,
            "attacker_model": self.attacker_model,
            "production_relevance": self.production_relevance,
            "attack_strategy": self.attack_strategy,
            "strategy_status": self.strategy_status,
            "entry_point": self.entry_point,
            "controlled_inputs": self.controlled_inputs,
            "propagation_path": self.propagation_path,
            "sensitive_sink": self.sensitive_sink,
            "capability_obtained": self.capability_obtained,
            "affected_assets": self.affected_assets,
            "expected_consequence": self.expected_consequence,
            "attack_steps": [s.to_dict() for s in self.attack_steps],
            "evidence": self.evidence,
            "fact_ids": sorted(set(self.fact_ids)),
            "assumptions": self.assumptions,
            "uncertainty": self.uncertainty,
            "validator_plan": self.validator_plan,
            "exploitability_score": self.exploitability_score,
            "exploitability_band": self.exploitability_band,
        }
