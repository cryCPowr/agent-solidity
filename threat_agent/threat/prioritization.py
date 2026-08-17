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
  + composition quality (bounded +4): proven attacker influence and
    multi-stage relation-backed chains (security_chains.py) rank above
    inferred influence and shallower compositions
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
from .provenance import ControlProvenance

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
    # Composition-strength band caps (threat-perbaikan.md #4/#5): a merely
    # STRUCTURAL composition may exist but must never rank as a
    # high-interest finding, and a SECURITY_RELEVANT (linked but not
    # multi-dimensional) composition stays moderate: only a
    # STRONG_SECURITY_CHAIN with multiple independently supported security
    # dimensions may reach the high-interest bands.
    if hypothesis.composition_strength in ("STRUCTURAL", "SECURITY_RELEVANT") and priority in (
        "high_interest", "very_high_interest",
    ):
        priority = "medium_interest"
        rationale += f" [capped: {hypothesis.composition_strength} composition]"
    hypothesis.priority = priority
    hypothesis.priority_rationale = rationale
    return hypothesis


def _score(h: ThreatHypothesis, recon: loader.ReconArtifact) -> int:
    """Return numeric score; higher = more interesting."""
    score = 0
    # Provenance discipline (threat-perbaikan.md #1/#5): when a hypothesis
    # explicitly declares its control provenance, an UNKNOWN declaration
    # ("we could not tie any caller to this behavior") must not earn the
    # same weight as proven security evidence. Hypotheses that do not
    # declare provenance keep the legacy scoring.
    provenance = ControlProvenance.coerce(h.control_provenance)
    declares_provenance = bool(h.control_provenance)
    # Asset impact -- but only when at least one observed fact grounds the
    # claim: an asset impact asserted with zero fact references (e.g. a
    # bare graph edge) is structural, not security evidence. A declared
    # UNKNOWN provenance further discounts it.
    if h.observed_facts and any(
        a in h.affected_assets
        for a in ("ETH", "tokens", "protocol assets", "cross-contract assets")
    ):
        score += 1 if (declares_provenance and provenance is ControlProvenance.UNKNOWN) else 3
    # Attacker control
    if h.actor in ("external_user", "external_contract"):
        if declares_provenance:
            score += {
                ControlProvenance.PROVEN: 2,
                ControlProvenance.INFERRED: 1,
                ControlProvenance.UNKNOWN: 0,
            }[provenance]
        else:
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
    # Composition quality (security_chains.py): proven attacker influence
    # and deeper multi-stage compositions rank above inferred/shallow ones.
    # Deliberately bounded (+4) and still clipped by the evidence-tier
    # ceilings, so a large volume of weak co-occurring signals can never
    # outweigh a smaller number of high-quality, relation-backed chains.
    # Applies only to actual chain compositions (multi-stage hypotheses),
    # never to single-edge lens hypotheses.
    if h.chain:
        if provenance is ControlProvenance.PROVEN:
            score += 2
        elif provenance is ControlProvenance.INFERRED:
            score += 1
    # Threat-perbaikan.md #1/#5: "uncertain" stages (e.g. the weak
    # downstream-execution-opportunity signal) contribute NO weight; only
    # proven/observed stages count toward chain depth, so chain length
    # alone can never buy high_interest.
    proven_stages = [
        s for s in h.chain
        if s.get("status") in ("proven", "observed")
    ]
    if len(proven_stages) >= 4:
        score += 1
    if len(proven_stages) >= 5:
        score += 1
    # Threat-perbaikan.md #4/#5: composition strength reflects multiple
    # independently supported security dimensions; only a strong chain
    # earns the extra weight (structural earns none).
    if h.composition_strength == "STRONG_SECURITY_CHAIN" and h.chain:
        score += 2
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