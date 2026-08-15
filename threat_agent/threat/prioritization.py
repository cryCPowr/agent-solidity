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

Priority levels (NOT severity):
  very_high_interest
  high_interest
  medium_interest
  low_interest
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import loader
from .graph_queries import call_chains, cross_contract_chains
from .hypothesis import ThreatHypothesis


def prioritize(
    hypothesis: ThreatHypothesis,
    recon: loader.ReconArtifact,
) -> ThreatHypothesis:
    """Recalculate priority for a single hypothesis."""
    score = _score(hypothesis, recon)
    priority, rationale = _map_score(score)
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


def _map_score(score: int) -> tuple[str, str]:
    if score >= 7:
        return "very_high_interest", f"high-impact combination (score={score})"
    if score >= 5:
        return "high_interest", f"significant exposure (score={score})"
    if score >= 3:
        return "medium_interest", f"moderate concern (score={score})"
    return "low_interest", f"low-impact surface (score={score})"


def prioritize_all(
    hypotheses: list[ThreatHypothesis],
    recon: loader.ReconArtifact,
) -> list[ThreatHypothesis]:
    return [prioritize(h, recon) for h in hypotheses]