"""Threat Agent: Security Interpretation Layer.

Consumes Recon artifacts (facts.jsonl, graph.json, summary.json, etc.)
and produces structured security intelligence:

    threat/
    ├── schema.json
    ├── threat_model.json    (actors + trust boundaries)
    ├── surfaces.json        (attack surface clusters)
    ├── invariants.json      (invariant candidates)
    ├── hypotheses.jsonl     (prioritized threat hypotheses)
    ├── relationships.json   (summarized evidence links)
    └── summary.json         (counts & distribution)

Recon = facts. Threat = security interpretation.
Threat does NOT confirm bugs; it generates candidates/hypotheses.

Hypothesis generation (see threat/hypothesis.py) combines two layers:
  - category-specific lenses (named vulnerability patterns)
  - a generic signal-composition layer (threat/composition.py) that finds
    concerning combinations even when no lens has been written for them
"""

from __future__ import annotations

from .loader import ReconArtifact, load_recon
from .actor_model import Actor, build_actors
from .trust_model import TrustBoundary, build_trust_boundaries
from .surface import AttackSurface, build_surfaces
from .invariants import InvariantCandidate, generate_invariants
from .hypothesis import ThreatHypothesis, generate_hypotheses
from .composition import generate_composed_hypotheses, build_function_profiles
from .prioritization import prioritize, prioritize_all
from .graph_queries import reachability_from, call_chains, cross_contract_chains
from .output import write_threat_output

__version__ = "1.0.0"