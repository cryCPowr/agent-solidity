"""Exploitability scoring and attack prioritization.

for_attack_agent.md PRIORITIZATION: rank strong security chains, proven
control provenance, attacker-controlled dynamic targets, asset
authorization interactions, asset-flow-linked effects, invariant-linked
effects, privilege boundary violations, concrete consequences.

Deprioritize: structural-only external calls, possible callbacks without
attacker-controlled targets, test-only / dependency-only behavior,
adjacency-only effects, no meaningful consequence.

The score is bounded [0, 10] and maps to bands:
    >= 7.0 high / >= 4.0 medium / else low
"""

from __future__ import annotations

from . import relevance
from .model import PROVEN


def exploitability_score(attack, hypothesis: dict[str, Any]) -> tuple[float, str]:
    score = 0.0

    # Composition strength (upstream quality of the composed evidence)
    strength = hypothesis.get("composition_strength", "")
    if strength == "STRONG_SECURITY_CHAIN":
        score += 3.0
    elif strength == "SECURITY_RELEVANT":
        score += 1.5
    elif strength == "STRUCTURAL":
        score += 0.25
    else:
        # named-lens hypothesis: scale with evidence tier
        tier = hypothesis.get("evidence_tier", "")
        score += {"GRAPH_REACHABILITY": 1.25, "ARGUMENT_DEPENDENCY": 1.0,
                  "RELATIONSHIP_GROUNDED": 0.5, "CO_OCCURRENCE": 0.25}.get(tier, 0.25)

    # Control provenance
    provenance = hypothesis.get("control_provenance", "")
    score += {"PROVEN": 2.0, "INFERRED": 1.0, "UNKNOWN": 0.0, "": 0.0}.get(provenance, 0.0)

    # Attacker-controlled dynamic target (downstream grade)
    grade = _downstream_grade(hypothesis)
    score += {"PROVEN": 1.5, "STRUCTURALLY_INDICATED": 1.0,
              "POSSIBLE": 0.25}.get(grade, 0.0)

    # Asset authorization / asset-flow-linked effects
    stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
    if "asset_authorization" in stages:
        score += 1.0
    linkage = (stages.get("state_value_effect") or {}).get("linkage", "")
    score += {"asset_flow_linked": 1.5, "dataflow_linked": 0.75}.get(linkage, 0.0)

    # Invariant-linked effect
    if hypothesis.get("invariant_candidate_id"):
        score += 0.5
    if "validation_gap" in stages:
        score += 0.5

    # Strategy + consequence quality
    score += {PROVEN: 1.0, "INFERRED": 0.6, "POSSIBLE": 0.2}.get(attack.strategy_status, 0.0)
    if attack.expected_consequence.get("asset_at_risk"):
        score += 0.5

    # Production relevance (test/mock and dependency behavior deprioritized
    # but never discarded)
    score += {
        relevance.PRODUCTION: 1.0,
        relevance.UNKNOWN: 0.4,
        relevance.TEST_MOCK: 0.1,
        relevance.DEPENDENCY: 0.1,
    }.get(attack.production_relevance, 0.4)

    # Attack-gate quality penalty: executable candidates should have very
    # few UNKNOWN gates and zero BLOCKED gates.
    gates = attack.attack_gates or {}
    blocked = sum(1 for g in gates.values() if (g or {}).get("status") == "BLOCKED")
    unknown = sum(1 for g in gates.values() if (g or {}).get("status") == "UNKNOWN")
    score -= blocked * 2.5
    score -= min(unknown * 0.25, 1.0)

    score = round(max(0.0, min(score, 10.0)), 2)
    band = "high" if score >= 7.0 else ("medium" if score >= 4.0 else "low")
    return score, band


def _downstream_grade(hypothesis: dict[str, Any]) -> str:
    for stage in hypothesis.get("chain") or []:
        if stage.get("stage") == "downstream_execution_opportunity":
            return stage.get("grade", "")
    return ""
