"""Prioritization logic.

Assigns investigation priority to threat hypotheses based on:
- Asset impact
- Attacker control level
- Privilege boundary
- Cross-contract reach
- Invariant relevance
- Uncertainty
- Economic exposure
- Exploit-path complexity
- Evidence strength

Priority levels (NOT severity):
  very_high_interest
  high_interest
  medium_interest
  low_interest

Evidence-aware scoring (Bug 3):
  base_score = security-impact signals (asset, actor, cross-contract,
               invariant, category) -- unchanged semantics
  ceiling    = max attainable base_score per evidence tier
  final      = min(base_score, ceiling), mapped to priority bands

The ceilings are strictly ordered so that each tier's maximum attainable
priority is exactly one band above the tier below it:

  GRAPH_REACHABILITY  -> up to very_high_interest
  ARGUMENT_DEPENDENCY -> up to high_interest
  RELATIONSHIP_GROUNDED -> up to medium_interest
  CO_OCCURRENCE       -> up to low_interest

Consequences:
- Under otherwise equivalent security impact, a stronger tier never ranks
  below a weaker tier, and at high impact ranks strictly above it.
- Weak evidence can never become very_high_interest merely because many
  independent signal points are stacked: signal stacking raises base_score,
  which the ceiling clips before band mapping.
- The evidence tier itself contributes NO points; evidence strength acts
  purely as a bound, not as a stackable weight.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import loader
from .evidence import EvidenceTier
from .graph_queries import call_chains, cross_contract_chains
from .hypothesis import ThreatHypothesis

# Evidence-tier ceilings (Bug 3): maximum base score each tier can convert
# into priority. Thresholds for the bands are 7/5/3, so a ceiling of 2 caps
# at low_interest, 4 at medium_interest, 6 at high_interest, and 10 leaves
# very_high_interest reachable only for verified graph reachability.
EVIDENCE_CEILING: dict[str, int] = {
    EvidenceTier.GRAPH_REACHABILITY.value: 10,
    EvidenceTier.ARGUMENT_DEPENDENCY.value: 6,
    EvidenceTier.RELATIONSHIP_GROUNDED.value: 4,
    EvidenceTier.CO_OCCURRENCE.value: 2,
}


def prioritize(
    hypothesis: ThreatHypothesis,
    recon: loader.ReconArtifact,
) -> ThreatHypothesis:
    """Recalculate priority for a single hypothesis."""
    base_score = _score(hypothesis, recon)
    priority, rationale = _map_score(base_score, hypothesis.evidence_tier)
    hypothesis.priority = priority
    hypothesis.priority_rationale = rationale
    return hypothesis


def _score(h: ThreatHypothesis, recon: loader.ReconArtifact) -> int:
    """Return numeric score; higher = more interesting."""
    score = 0
    # Asset impact
    if any(a in h.affected_assets for a in ("ETH", "tokens", "protocol assets", "cross-contract assets")):
        score += 3
    # Attacker control
    if h.actor in ("external_user", "external_contract"):
        score += 2
    if h.actor == "external_contract":
        score += 1  # external contract = less direct control
    # Cross-contract reach
    cross = any(
        c
        for fn in h.affected_functions
        for c in call_chains(recon, fn)
    )
    if cross:
        score += 1
    # Invariant relevance
    if h.invariant_candidate_id:
        score += 2
    # Economic exposure
    if h.category in ("accounting_mismatch", "rounding_allocation", "economic_manipulation"):
        score += 1
    return score


def _map_score(base_score: int, evidence_tier: str | None) -> tuple[str, str]:
    """Map base score to priority, constrained by the evidence ceiling.

    Evidence-aware band maxima:
    - CO_OCCURRENCE: ceiling=2 -> max low_interest
    - RELATIONSHIP_GROUNDED: ceiling=4 -> max medium_interest
    - ARGUMENT_DEPENDENCY: ceiling=6 -> max high_interest
    - GRAPH_REACHABILITY: ceiling=10 -> very_high_interest reachable (7+)
    """
    tier = EvidenceTier.coerce(evidence_tier)
    ceiling = EVIDENCE_CEILING[tier.value]
    score = min(base_score, ceiling)

    if score >= 7:
        return "very_high_interest", f"high-impact combination (score={base_score}, tier={tier.value}, ceiling={ceiling})"
    if score >= 5:
        return "high_interest", f"significant exposure (score={base_score}, tier={tier.value}, ceiling={ceiling})"
    if score >= 3:
        return "medium_interest", f"moderate concern (score={base_score}, tier={tier.value}, ceiling={ceiling})"
    return "low_interest", f"low-impact surface (score={base_score}, tier={tier.value}, ceiling={ceiling})"


def prioritize_all(
    hypotheses: list[ThreatHypothesis],
    recon: loader.ReconArtifact,
) -> list[ThreatHypothesis]:
    return [prioritize(h, recon) for h in hypotheses]