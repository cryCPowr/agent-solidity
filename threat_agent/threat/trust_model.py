"""Trust Boundary Model.

Builds trust relationships between components:
- contract → external protocol (token, oracle, bridge)
- user → protocol (caller side)
- operator → configuration
- contract → contract (via CALLS edges)

Relationship categories:
  trusted           : has authorization_check / trusted reference
  untrusted         : uncontrolled input from external source
  partially_trusted : controlled but unverified (e.g. function param flowing into call)
  unknown           : cannot determine
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import loader


@dataclass
class TrustBoundary:
    source: str
    target: str
    relationship: str  # trusted | untrusted | partially_trusted | unknown
    evidence_fact_ids: list[str] = field(default_factory=list)
    rationale: str = ""


def build_trust_boundaries(recon: loader.ReconArtifact) -> list[TrustBoundary]:
    """Build trust boundary set from graph and facts.

    Strategy:
    - For each CALLS edge, build a boundary between caller and callee
    - If call target is dynamic / user_controlled -> untrusted (or partially_trusted)
    - If call target is a known protocol/contract -> partially_trusted
    - Always also add a 'user -> protocol' boundary for public entrypoints
    """
    boundaries: dict[tuple[str, str], TrustBoundary] = {}

    def _ensure(src: str, tgt: str) -> TrustBoundary:
        key = (src, tgt)
        if key not in boundaries:
            boundaries[key] = TrustBoundary(source=src, target=tgt, relationship="unknown", rationale="")
        return boundaries[key]

    # --- From CALLS edges ---
    for edge in recon.graph.edges:
        etype = edge.get("type", "")
        if etype != "CALLS":
            continue
        props = edge.get("properties") or {}
        src_node = recon.graph.nodes_by_id.get(edge.get("source", ""), {})
        tgt_node = recon.graph.nodes_by_id.get(edge.get("target", ""), {})
        src_kind = src_node.get("kind", "unknown")
        tgt_kind = tgt_node.get("kind", "unknown")
        # src is usually a function, tgt is usually a function or external_target
        src_name = src_node.get("name") or edge.get("source", "")
        tgt_name = tgt_node.get("name") or edge.get("target", "")
        if tgt_kind == "external_target":
            # The protocol calls an external address -> boundary protocol -> external
            src_contract = _contract_for_node(src_node.get("id", ""), recon)
            boundary = _ensure(src_contract, f"external:{tgt_name}")
            if props.get("target_status") == "dynamic":
                boundary.relationship = "untrusted"
                boundary.rationale = (
                    "external target is dynamically derived; trust depends on caller "
                    "validation"
                )
            elif props.get("call_type") == "delegatecall":
                boundary.relationship = "untrusted"
                boundary.rationale = "delegatecall to external target inherits its code"
            else:
                boundary.relationship = "partially_trusted"
                boundary.rationale = "external call to a specific known target"
            for fid in edge.get("fact_ids") or []:
                boundary.evidence_fact_ids.append(fid)
        else:
            # Internal call between functions/contracts
            src_contract = _contract_for_node(src_node.get("id", ""), recon)
            tgt_contract = _contract_for_node(tgt_node.get("id", ""), recon)
            if src_contract and tgt_contract and src_contract != tgt_contract:
                boundary = _ensure(src_contract, tgt_contract)
                boundary.relationship = "partially_trusted"
                boundary.rationale = "internal cross-contract call"
                for fid in edge.get("fact_ids") or []:
                    boundary.evidence_fact_ids.append(fid)

    # --- External user -> protocol boundary ---
    for fn_fact in loader.functions(recon):
        visibility = next(
            (
                f
                for f in loader.facts_for_function(recon, fn_fact["subject"]["function"])
                if f["type"] == "function_visibility"
            ),
            None,
        )
        if visibility and visibility["properties"].get("visibility") in ("external", "public"):
            fn_key = fn_fact["subject"]["function"]
            contract_key = fn_key.split("#")[0]
            boundary = _ensure("external_user", contract_key)
            boundary.relationship = "untrusted"
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
            boundary.relationship = "partially_trusted"
            boundary.rationale = (
                f"authority over {fn_key} gated by {mech.get('kind')} check"
            )
            boundary.evidence_fact_ids.append(acf["id"])
            for bfid in mech.get("basis_facts", []):
                boundary.evidence_fact_ids.append(bfid)

    # Dedupe evidence ids
    result = list(boundaries.values())
    for b in result:
        b.evidence_fact_ids = sorted(set(b.evidence_fact_ids))
    return result


def _contract_for_node(node_id: str, recon: loader.ReconArtifact) -> str:
    """Resolve a graph node to its enclosing contract (best-effort)."""
    node = recon.graph.nodes_by_id.get(node_id, {})
    if not node:
        return ""
    parent_id = node.get("contract")
    if parent_id:
        return parent_id
    kind = node.get("kind", "")
    if kind == "contract":
        return node.get("name", node_id)
    # Fallback: derive from node_id pattern (file#X)
    return node_id.split("#")[0] if "#" in node_id else node_id