"""Trust Boundary Model.

Builds trust relationships between components:
- contract -> external protocol (token, oracle, bridge)
- user -> protocol (caller side)
- operator -> configuration
- contract -> contract (via CALLS edges)

SEPARATES TWO CONCERNS (per hardening requirement):

1. resolution:
   - static      : target/expression resolves to a concrete address
   - dynamic     : target is computed from runtime input (parameter, memory, etc.)
   - unknown     : cannot be determined

2. trust:
   - trusted           : has authorization_check / trusted reference
   - untrusted         : uncontrolled input from external source
   - partially_trusted : controlled but unverified (e.g. function param flowing into call)
   - unknown           : cannot determine

DYNAMIC TARGET != UNTRUSTED TARGET.
A dynamic target may be partially_trusted if the caller validates it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import loader


@dataclass
class TrustBoundary:
    source: str
    target: str
    trust: str = "unknown"        # trusted | untrusted | partially_trusted | unknown
    resolution: str = "unknown"  # static | dynamic | unknown
    evidence_fact_ids: list[str] = field(default_factory=list)
    rationale: str = ""


def build_trust_boundaries(recon: loader.ReconArtifact) -> list[TrustBoundary]:
    """Build trust boundary set from graph and facts.

    Strategy:
    - For each CALLS edge, build a boundary between caller and callee
    - Resolution is determined by call properties (dynamic/static)
    - Trust is determined by authorization evidence, not just resolution
    - Always also add a "user -> protocol" boundary for public entrypoints
    """
    boundaries: dict[tuple[str, str], TrustBoundary] = {}

    def _ensure(src: str, tgt: str) -> TrustBoundary:
        key = (src, tgt)
        if key not in boundaries:
            boundaries[key] = TrustBoundary(source=src, target=tgt, trust="unknown", resolution="unknown", rationale="")
        return boundaries[key]

    # --- From CALLS edges ---
    for edge in recon.graph.edges:
        etype = edge.get("type", "")
        if etype != "CALLS":
            continue
        props = edge.get("properties") or {}
        src_node = recon.graph.nodes_by_id.get(edge.get("source", ""), {})
        tgt_node = recon.graph.nodes_by_id.get(edge.get("target", ""), {})

        if tgt_node.get("kind") == "external_target":
            src_contract = _contract_for_node(src_node.get("id", ""), recon)
            tgt_name = tgt_node.get("name") or edge.get("target", "")
            boundary = _ensure(src_contract, f"external:{tgt_name}")

            # Determine resolution
            if props.get("target_status") == "dynamic":
                boundary.resolution = "dynamic"
            else:
                boundary.resolution = "static"

            # Determine trust - SEPARATE from resolution
            if props.get("call_type") == "delegatecall":
                boundary.trust = "untrusted"
                boundary.resolution = boundary.resolution or "dynamic"
                boundary.rationale = "delegatecall to external target inherits its code and storage context"
            elif boundary.resolution == "dynamic":
                # Dynamic resolution alone does NOT imply untrusted.
                # Trust depends on whether the caller validates the target.
                # We mark as partially_trusted by default (needs validation) and
                # escalate to untrusted only if we can prove lack of validation.
                # Since Recon cannot prove validation, we treat dynamic as
                # partially_trusted with a note about the need for analysis.
                boundary.trust = "partially_trusted"
                boundary.rationale = (
                    "dynamic target: caller validation status unknown; "
                    "requires dataflow verification to establish trust"
                )
            elif boundary.resolution == "static":
                boundary.trust = "partially_trusted"
                boundary.rationale = "static external call to a known address; trust depends on target behavior"
            else:
                boundary.trust = "unknown"
                boundary.rationale = "cannot determine trust level for this external call"

            for fid in edge.get("fact_ids") or []:
                boundary.evidence_fact_ids.append(fid)

    # --- External user -> protocol boundary ---
    for fn_fact in loader.functions(recon):
        fn_key = fn_fact["subject"]["function"]
        fn_facts = loader.facts_for_function(recon, fn_key)
        visibility = next(
            (f for f in fn_facts if f["type"] == "function_visibility"),
            None,
        )
        if visibility and visibility["properties"].get("visibility") in ("external", "public"):
            contract_key = fn_key.split("#")[0]
            boundary = _ensure("external_user", contract_key)
            boundary.trust = "untrusted"
            boundary.resolution = "static"
            boundary.rationale = "any external account can call this public function"
            boundary.evidence_fact_ids.append(visibility.get("id", fn_fact["id"]))

    # --- Operator / governance boundaries from privileged functions ---
    for acf in recon.facts_obj.by_type.get("access_controlled_function", []):
        fn_key = acf["subject"]["function"]
        contract_key = fn_key.split("#")[0]
        for mech in acf["properties"].get("mechanisms", []):
            if mech.get("kind") == "inline":
                actor = "actor:inline_authority"
            elif mech.get("kind") == "modifier":
                mod_name = mech.get("modifier", "")
                actor = f"actor:modifier_authority:{mod_name}"
            else:
                actor = "actor:unknown_authority"
            boundary = _ensure(actor, contract_key)
            # Authority presence implies some level of trust, but resolution
            # depends on the state variable used for authorization
            boundary.trust = "partially_trusted"
            boundary.resolution = "static"
            boundary.rationale = (
                f"authority over {fn_key} gated by {mech.get('kind')} check; "
                f"trust level depends on mutability of referenced state variables"
            )
            boundary.evidence_fact_ids.append(acf["id"])
            for bfid in mech.get("basis_facts", []):
                boundary.evidence_fact_ids.append(bfid)

    # Deduplicate evidence ids
    result = list(boundaries.values())
    for b in result:
        b.evidence_fact_ids = sorted(set(b.evidence_fact_ids))
    return result


def _contract_for_node(node_id: str, recon: loader.ReconArtifact) -> str:
    """Resolve a graph node to its enclosing contract name."""
    node = recon.graph.nodes_by_id.get(node_id, {})
    if not node:
        return ""

    if node.get("contract"):
        return node["contract"]

    if node.get("kind") == "contract":
        return node.get("name", node_id)

    # Fallback: derive from node_id pattern (file#X)
    parts = node_id.split("#")
    return parts[0] if parts else node_id