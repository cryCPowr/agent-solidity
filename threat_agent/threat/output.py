"""Output writer.

Writes Threat Agent artifacts to disk:
  threat/
    ├── schema.json
    ├── threat_model.json
    ├── surfaces.json
    ├── invariants.json
    ├── hypotheses.jsonl
    ├── relationships.json
    └── summary.json
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .actor_model import Actor
    from .trust_model import TrustBoundary
    from .surface import AttackSurface
    from .invariants import InvariantCandidate

from . import loader
from .actor_model import build_actors
from .trust_model import build_trust_boundaries
from .surface import build_surfaces
from .invariants import generate_invariants
from .hypothesis import generate_hypotheses
from .prioritization import prioritize_all


def write_threat_output(
    recon: loader.ReconArtifact,
    output_dir: str,
) -> None:
    """Write all Threat Agent outputs to output_dir."""
    os.makedirs(output_dir, exist_ok=True)

    # Build all threat artifacts
    actors = build_actors(recon)
    boundaries = build_trust_boundaries(recon)
    surfaces = build_surfaces(recon)
    invariants = generate_invariants(recon)
    hypotheses = prioritize_all(generate_hypotheses(recon, invariants), recon)

    # Map invariants for reference
    inv_map = {inv.id: inv for inv in invariants}
    # Link hypotheses to invariants if applicable
    for h in hypotheses:
        if not h.invariant_candidate_id:
            for inv in invariants:
                if any(f in inv.involved_facts for f in h.observed_facts):
                    h.invariant_candidate_id = inv.id
                    break

    # Write schema
    _write_json(os.path.join(output_dir, "schema.json"), _load_schema())

    # Write threat_model.json
    threat_model = {
        "actors": [_actor_to_dict(a) for a in actors],
        "trust_boundaries": [_tb_to_dict(tb) for tb in boundaries],
    }
    _write_json(os.path.join(output_dir, "threat_model.json"), threat_model)

    # Write surfaces.json
    _write_json(os.path.join(output_dir, "surfaces.json"), {
        "count": len(surfaces),
        "surfaces": [_surface_to_dict(s) for s in surfaces],
    })

    # Write invariants.json
    _write_json(os.path.join(output_dir, "invariants.json"), {
        "count": len(invariants),
        "invariants": [_inv_to_dict(inv) for inv in invariants],
    })

    # Write hypotheses.jsonl (one per line)
    with open(os.path.join(output_dir, "hypotheses.jsonl"), "w", encoding="utf-8") as f:
        for h in hypotheses:
            f.write(json.dumps(h.to_dict()) + "\n")

    # Write relationships.json (summarized)
    rels: dict[str, int] = {
        "actor_to_capabilities": sum(len(a.capabilities) for a in actors),
        "trust_boundaries": len(boundaries),
        "high_priority_hypotheses": sum(
            1 for h in hypotheses if h.priority in ("very_high_interest", "high_interest")
        ),
    }
    _write_json(os.path.join(output_dir, "relationships.json"), rels)

    # Write summary.json
    summary = {
        "actor_count": len(actors),
        "trust_boundary_count": len(boundaries),
        "surface_count": len(surfaces),
        "invariant_count": len(invariants),
        "hypothesis_count": len(hypotheses),
        "hypotheses_by_priority": {
            p: sum(1 for h in hypotheses if h.priority == p)
            for p in ("very_high_interest", "high_interest", "medium_interest", "low_interest")
        },
        "hypotheses_by_category": {
            c: sum(1 for h in hypotheses if h.category == c)
            for c in sorted({h.category for h in hypotheses})
        },
    }
    _write_json(os.path.join(output_dir, "summary.json"), summary)


def _write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _actor_to_dict(a: loader.Actor) -> dict[str, Any]:
    return {
        "id": a.id,
        "type": a.type,
        "capabilities": a.capabilities,
        "entrypoints": a.entrypoints,
        "privileged_operations": a.privileged_operations,
        "controlled_parameters": a.controlled_parameters,
        "controlled_assets": a.controlled_assets,
        "reachable_state_transitions": a.reachable_state_transitions,
        "evidence_fact_ids": a.evidence_fact_ids,
        "rationale": a.rationale,
    }


def _tb_to_dict(tb: loader.TrustBoundary) -> dict[str, Any]:
    return {
        "source": tb.source,
        "target": tb.target,
        "relationship": tb.relationship,
        "evidence_fact_ids": tb.evidence_fact_ids,
        "rationale": tb.rationale,
    }


def _surface_to_dict(s: loader.AttackSurface) -> dict[str, Any]:
    return {
        "id": s.id,
        "category": s.category,
        "description": s.description,
        "functions": s.functions,
        "assets": s.assets,
        "capabilities": s.capabilities,
        "entrypoints": s.entrypoints,
        "evidence_fact_ids": s.evidence_fact_ids,
        "cross_contract_reach": s.cross_contract_reach,
    }


def _inv_to_dict(inv: loader.InvariantCandidate) -> dict[str, Any]:
    return {
        "id": inv.id,
        "category": inv.category,
        "statement": inv.statement,
        "rationale": inv.rationale,
        "involved_facts": inv.involved_facts,
        "involved_functions": inv.involved_functions,
        "involved_assets": inv.involved_assets,
        "uncertainty": inv.uncertainty,
        "confidence": inv.confidence,
    }


def _load_schema() -> dict[str, Any]:
    import json
    import os
    schema_path = os.path.join(os.path.dirname(__file__), "schema.py")
    # Inline the schema dict since schema.py contains a JSON schema text
    # Return a minimal schema reference
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Threat Agent Output",
        "version": "1.0",
        "artifacts": [
            "threat_model.json",
            "surfaces.json",
            "invariants.json",
            "hypotheses.jsonl",
            "relationships.json",
            "summary.json",
        ],
    }