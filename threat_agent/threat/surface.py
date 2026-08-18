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
    """Cluster Recon facts into Attack Surfaces.

    Surfaces remain structural: they describe reachable security-relevant
    protocol areas and observed authority boundaries, not exploitability.
    """
    surfaces: dict[str, AttackSurface] = {}

    def _ensure(category: str, desc: str) -> AttackSurface:
        if category not in surfaces:
            surfaces[category] = AttackSurface(
                id=f"surface:{category.lower().replace(' ', '_')}",
                category=category,
                description=desc,
            )
        return surfaces[category]

    def _protocol_contracts() -> list[dict[str, Any]]:
        contracts = recon.protocol.raw.get("contracts")
        return contracts if isinstance(contracts, list) else []

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
    initializer_functions = recon.facts_obj.by_type.get("initializer_function", [])
    initializer_surfaces = recon.facts_obj.by_type.get("initializer_surface", [])
    initializer_lifecycles = recon.facts_obj.by_type.get("initializer_lifecycle", [])
    if creations or selfdestructs or initializer_functions or initializer_surfaces or initializer_lifecycles:
        s = _ensure(
            "Lifecycle",
            "Contract creation, initialization, or destruction surfaces that affect deployment-time state",
        )
        for f in creations:
            s.functions.append(f["subject"]["function"])
            s.evidence_fact_ids.append(f["id"])
        for f in selfdestructs:
            s.functions.append(f["subject"]["function"])
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("can_selfdestruct")
        for f in initializer_functions:
            s.functions.append(f["subject"].get("function", ""))
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("has_initializer")
        for f in initializer_surfaces:
            s.functions.append(f["subject"].get("function", ""))
            s.evidence_fact_ids.append(f["id"])
            props = f.get("properties", {})
            if props.get("authorization_status") == "none_observed":
                s.capabilities.append("initializer_without_observed_authorization")
            if props.get("writes_initialized_flag"):
                s.capabilities.append("initializer_writes_initialized_flag")
        for f in initializer_lifecycles:
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("has_initializer_lifecycle_model")

    # --- 6. Upgradeability Surface ---
    proxy_like = recon.facts_obj.by_type.get("proxy_like_contract", [])
    upgrade_functions = recon.facts_obj.by_type.get("upgrade_function", [])
    upgrade_authorities = recon.facts_obj.by_type.get("upgrade_authority", [])
    delegatecall_paths = recon.facts_obj.by_type.get("proxy_delegatecall_path", [])
    if proxy_like or upgrade_functions or upgrade_authorities or delegatecall_paths:
        s = _ensure(
            "Upgradeability",
            "Components related to proxy patterns, delegatecall-based execution, and logic upgrades",
        )
        for f in proxy_like:
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("proxy_like_contract")
        for f in upgrade_functions:
            s.functions.append(f["subject"].get("function", ""))
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("has_upgrade_function")
        for f in upgrade_authorities:
            s.functions.append(f["subject"].get("function", ""))
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("has_observed_upgrade_authority")
        for f in delegatecall_paths:
            s.functions.append(f["subject"].get("function", ""))
            s.evidence_fact_ids.append(f["id"])
            s.capabilities.append("proxy_delegatecall_path")
            s.cross_contract_reach = True

        # Supplement function inventory from protocol.json when available.
        for contract in _protocol_contracts():
            proxy = (contract.get("proxy_upgradeability") or {})
            if proxy.get("proxy_like"):
                s.capabilities.append("proxy_like_contract")
            for fn in proxy.get("upgrade_functions") or []:
                s.functions.append(fn)
            for fn in proxy.get("initializer_functions") or []:
                s.functions.append(fn)
            if proxy.get("delegatecall_paths"):
                s.cross_contract_reach = True

    # --- 7. Authority / Capability Surface ---
    authority_surfaces = recon.facts_obj.by_type.get("capability_authority_surface", [])
    if authority_surfaces:
        s = _ensure(
            "Authority and Capability",
            "Observed capabilities together with their current authorization surfaces",
        )
        for f in authority_surfaces:
            fn = f["subject"].get("function", "")
            cap = f["subject"].get("capability", "")
            props = f.get("properties", {})
            if fn:
                s.functions.append(fn)
            s.evidence_fact_ids.append(f["id"])
            if cap:
                s.capabilities.append(cap)
            if props.get("authority_status") == "guarded":
                s.capabilities.append("capability_with_observed_authorization")
            else:
                s.capabilities.append("capability_without_observed_authorization")
            if props.get("writes_authorization_state"):
                s.capabilities.append("writes_authorization_state")

    # Clean up and dedupe
    result = list(surfaces.values())
    for s in result:
        s.functions = sorted({fn for fn in s.functions if fn})
        s.assets = sorted({asset for asset in s.assets if asset})
        s.capabilities = sorted({cap for cap in s.capabilities if cap})
        s.evidence_fact_ids = sorted({fid for fid in s.evidence_fact_ids if fid})
        # Entrypoints are just the functions that are also entrypoints in actor model
        # but for simplicity we list all associated functions here.
        s.entrypoints = s.functions

    return result