"""Actor Model.

Builds the actor view of the protocol from Recon facts:
- external_user (caller of public/external functions)
- owner / admin (functions guarded by authorization with state vars)
- protocol (the contract itself)
- external_contract (caller via call options)
- relayer (meta-tx entrypoints)
- governance (functions with timelock/multisig patterns)
- unknown_actor (anything we cannot classify)

Every claim references Recon fact IDs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import loader


SECURITY_RELEVANT_CAPABILITIES = {
    "can_transfer_token",
    "can_approve_spender",
    "can_mint",
    "can_burn",
    "can_modify_authorization_state",
    "can_delegatecall",
    "can_call_arbitrary_target",
    "can_create_contracts",
    "can_selfdestruct",
    "can_transfer_native_value",
    "can_invoke_external_callback",
}


ACTOR_TYPES = {
    "external_user",
    "owner",
    "admin",
    "operator",
    "keeper",
    "guardian",
    "governance",
    "relayer",
    "protocol",
    "external_contract",
    "unknown_actor",
}


@dataclass
class Actor:
    id: str
    type: str
    capabilities: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    privileged_operations: list[str] = field(default_factory=list)
    controlled_parameters: list[str] = field(default_factory=list)
    controlled_assets: list[str] = field(default_factory=list)
    reachable_state_transitions: list[str] = field(default_factory=list)
    evidence_fact_ids: list[str] = field(default_factory=list)
    rationale: str = ""


def build_actors(recon: loader.ReconArtifact) -> list[Actor]:
    """Build actor model from Recon facts.

    Strategy:
    - Identify every public/external function -> external_user entrypoint
    - Identify guarded functions -> owner/admin/operator actor per modifier
    - Identify capability-bearing functions -> grant capability to that actor
    - Identify functions using msg.sender as authority -> owner pattern
    """
    actors: dict[str, Actor] = {}

    def _ensure(actor_id: str, actor_type: str) -> Actor:
        if actor_id not in actors:
            actors[actor_id] = Actor(
                id=actor_id,
                type=actor_type,
                rationale=f"derived from Recon facts",
            )
        return actors[actor_id]

    # --- External user actor: any public/external function ---
    user = _ensure("actor:external_user", "external_user")
    user.rationale = "any caller of public/external functions"
    for fn_fact in loader.functions(recon):
        fn_key = fn_fact["subject"]["function"]
        fn_facts = loader.facts_for_function(recon, fn_key)
        visibility = next(
            (f for f in fn_facts if f["type"] == "function_visibility"),
            None,
        )
        mut = next(
            (f for f in fn_facts if f["type"] == "function_mutability"),
            None,
        )
        if visibility and visibility["properties"].get("visibility") in ("external", "public"):
            user.entrypoints.append(fn_key)
            user.evidence_fact_ids.append(fn_fact["id"])
            if visibility.get("id"):
                user.evidence_fact_ids.append(visibility["id"])
            if mut and mut.get("id"):
                user.evidence_fact_ids.append(mut["id"])
            # Track parameters as user-controlled inputs
            for p in fn_facts:
                if p["type"] == "function_parameter":
                    user.controlled_parameters.append(p["subject"]["parameter"])
                    user.evidence_fact_ids.append(p["id"])
            # Capabilities reachable from this function
            for cap_fact in fn_facts:
                if cap_fact["type"] == "capability":
                    cap_name = cap_fact["subject"]["capability"]
                    if cap_name in SECURITY_RELEVANT_CAPABILITIES:
                        user.capabilities.append(cap_name)
                        user.evidence_fact_ids.append(cap_fact["id"])

    # --- Privileged actors: derived from access_controlled_function facts ---
    for acf in recon.facts_obj.by_type.get("access_controlled_function", []):
        fn_key = acf["subject"]["function"]
        mechanisms = acf["properties"].get("mechanisms", [])
        for mech in mechanisms:
            if mech.get("kind") == "inline":
                actor_type = "owner"
                actor_id = f"actor:inline_authority:{fn_key}"
            elif mech.get("kind") == "modifier":
                mod_name = mech.get("modifier", "")
                actor_id = f"actor:modifier_authority:{mod_name}"
                actor_type = _classify_modifier_actor(mod_name)
            else:
                continue
            actor = _ensure(actor_id, actor_type)
            actor.entrypoints.append(fn_key)
            actor.evidence_fact_ids.append(acf["id"])
            for bfid in mech.get("basis_facts", []):
                actor.evidence_fact_ids.append(bfid)
            for cap_fact in loader.facts_for_function(recon, fn_key):
                if cap_fact["type"] == "capability":
                    cap_name = cap_fact["subject"]["capability"]
                    if cap_name in SECURITY_RELEVANT_CAPABILITIES:
                        actor.privileged_operations.append(f"{cap_name}@{fn_key}")
                        actor.evidence_fact_ids.append(cap_fact["id"])
                        actor.capabilities.append(cap_name)
            actor.rationale = f"authority over {fn_key} via {mech.get('kind')} authorization"

    # --- Protocol actor: the contract itself ---
    protocol = _ensure("actor:protocol", "protocol")
    for contract_fact in loader.contracts(recon):
        contract_key = contract_fact["subject"]["contract"]
        protocol.entrypoints.append(contract_key)
        protocol.evidence_fact_ids.append(contract_fact["id"])
    protocol.rationale = "represents the contracts being analyzed"

    # --- Dedupe evidence_fact_ids ---
    for actor in actors.values():
        actor.evidence_fact_ids = sorted(set(actor.evidence_fact_ids))
        actor.entrypoints = sorted(set(actor.entrypoints))
        actor.capabilities = sorted(set(actor.capabilities))
        actor.privileged_operations = sorted(set(actor.privileged_operations))
        actor.controlled_parameters = sorted(set(actor.controlled_parameters))
        actor.controlled_assets = sorted(set(actor.controlled_assets))
        actor.reachable_state_transitions = sorted(set(actor.reachable_state_transitions))

    return list(actors.values())


def _classify_modifier_actor(modifier_key: str) -> str:
    """Heuristic actor-type from modifier key naming patterns."""
    name = modifier_key.split("::")[-1].lower() if "::" in modifier_key else modifier_key.lower()
    if "owner" in name:
        return "owner"
    if "admin" in name:
        return "admin"
    if "operator" in name:
        return "operator"
    if "keeper" in name:
        return "keeper"
    if "guardian" in name:
        return "guardian"
    if "govern" in name or "timelock" in name:
        return "governance"
    return "unknown_actor"