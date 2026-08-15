"""Attack Surface Model.

Clusters security-relevant surfaces:
- external entrypoints
- privileged entrypoints
- asset movement
- approvals/allowances
- external calls
- delegatecall
- callback surfaces
- arithmetic / accounting
- upgradeability / initialization
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import loader


@dataclass
class AttackSurface:
    id: str
    category: str
    description: str
    functions: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    evidence_fact_ids: list[str] = field(default_factory=list)
    cross_contract_reach: bool = False


def build_surfaces(recon: loader.ReconArtifact) -> list[AttackSurface]:
    """Cluster Recon facts into Attack Surfaces."""
    surfaces: dict[str, AttackSurface] = {}

    def _ensure(category: str, desc: str) -> AttackSurface:
        if category not in surfaces:
            surfaces[category] = AttackSurface(
                id=f"surface:{category.lower().replace(' ', '_')}",
                category=category,
                description=desc,
            )
        return surfaces[category]

    # --- 1. Asset Movement Surface ---
    asset_ops = recon.facts_obj.by_type.get("asset_operation", [])
    eth_transfers = recon.facts_obj.by_type.get("eth_transfer", [])
    if asset_ops or eth_transfers:
        s = _ensure("Asset Movement", "Operations that move protocol or user tokens/ETH")
        for f in asset_ops:
            s.functions.append(f["subject"]["function"])
            s.assets.append(f["properties"].get("target_expression", "unknown"))
            s.evidence_fact_ids.append(f["id"])
            if f["properties"].get("operation") in ("approve", "setApprovalForAll"):
                s.capabilities.append("can_approve_spender")
        for f in eth_transfers:
            s.functions.append(f["subject"]["function"])
            s.assets.append("ETH")
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("can_transfer_native_value")

    # --- 2. External Interaction Surface ---
    ext_calls = recon.facts_obj.by_type.get("external_call", [])
    low_level = recon.facts_obj.by_type.get("low_level_call", [])
    if ext_calls or low_level:
        s = _ensure("External Interaction", "Calls to external contracts/targets")
        for f in ext_calls + low_level:
            fn = f["subject"].get("function") or f["subject"].get("caller")
            if fn:
                s.functions.append(fn)
            s.evidence_fact_ids.append(f["id"])
            if f["properties"].get("target_status") == "dynamic":
                s.capabilities.append("can_call_arbitrary_target")
            if f["properties"].get("call_type") == "delegatecall":
                s.capabilities.append("can_delegatecall")

    # --- 3. Privilege / Authorization Surface ---
    acf = recon.facts_obj.by_type.get("access_controlled_function", []),
    if acf[0]:
        s = _ensure("Privileged Entrypoints", "Functions gated by authorization mechanisms")
        for f in acf[0]:
            s.functions.append(f["subject"]["function"])
            s.evidence_fact_ids.append(f["id"])
            for mech in f["properties"].get("mechanisms", []):
                for bfid in mech.get("basis_facts", []):
                    s.evidence_fact_ids.append(bfid)

    # --- 4. Arithmetic / Accounting Surface ---
    arith = recon.facts_obj.by_type.get("arithmetic_operation", [])
    div = recon.facts_obj.by_type.get("division_operation", [])
    if arith or div:
        s = _ensure("Arithmetic and Accounting", "Calculations influencing protocol state or asset allocation")
        for f in arith + div:
            s.functions.append(f["subject"]["function"])
            s.evidence_fact_ids.append(f["id"])
            if f.get("type") == "division_operation":
                s.capabilities.append("rounding_sensitive")

    # --- 5. Lifecycle / Initialization Surface ---
    creations = recon.facts_obj.by_type.get("contract_creation", [])
    selfdestructs = recon.facts_obj.by_type.get("selfdestruct_call", [])
    if creations or selfdestructs:
        s = _ensure("Lifecycle", "Contract creation or destruction events")
        for f in creations:
            s.functions.append(f["subject"]["function"])
            s.evidence_fact_ids.append(f["id"])
        for f in selfdestructs:
            s.functions.append(f["subject"]["function"])
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("can_selfdestruct")

    # --- 6. Upgradeability Surface ---
    # Heuristic: functions named upgradeTo, setImplementation, etc.
    # or using proxy delegatecall patterns.
    for fact in recon.facts_obj.facts:
        if fact["type"] == "function_exists":
            name = fact["properties"].get("name", "").lower()
            if any(x in name for x in ("upgrade", "implementation", "proxy")):
                s = _ensure("Upgradeability", "Components related to contract logic upgrades or proxies")
                s.functions.append(fact["subject"]["function"])
                s.evidence_fact_ids.append(fact["id"])

    # Clean up and dedupe
    result = list(surfaces.values())
    for s in result:
        s.functions = sorted(set(s.functions))
        s.assets = sorted(set(s.assets))
        s.capabilities = sorted(set(s.capabilities))
        s.evidence_fact_ids = sorted(set(s.evidence_fact_ids))
        # Entrypoints are just the functions that are also entrypoints in actor model
        # but for simplicity we list all associated functions here.
        s.entrypoints = s.functions

    return result