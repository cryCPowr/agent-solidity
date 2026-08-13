"""Structural capability map.

Capabilities describe what a function can *technically* perform, derived
deterministically from facts already extracted by earlier stages. This module
adds no new source interpretation — it only aggregates existing fact types
into named, evidence-linked capability facts. No capability is framed as
dangerous, exploitable, or a vulnerability; that judgment is explicitly out of
scope (section 26 / 31).
"""

from __future__ import annotations

from collections import defaultdict

from . import ids
from .context import ProjectContext
from .models import Fact

# Maps (fact_type, property_matcher) -> capability name. property_matcher is a
# callable(fact.properties) -> bool.
_RULES = []


def _rule(fact_type, capability, matcher=lambda p: True):
    _RULES.append((fact_type, capability, matcher))


_rule("asset_operation", "can_transfer_token", lambda p: p.get("operation") in
      {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "safeBatchTransferFrom"})
_rule("asset_operation", "can_approve_spender", lambda p: p.get("operation") in
      {"approve", "increaseAllowance", "decreaseAllowance", "setApprovalForAll", "permit"})
_rule("asset_operation", "can_mint", lambda p: p.get("operation") == "mint")
_rule("asset_operation", "can_burn", lambda p: p.get("operation") == "burn")
_rule("eth_transfer", "can_transfer_native_value", lambda p: True)
_rule("function_mutability", "can_receive_native_value", lambda p: p.get("state_mutability") == "payable")
_rule("external_call_surface", "can_call_arbitrary_target",
      lambda p: p.get("call_type") == "low_level" and p.get("target_status") == "dynamic")
_rule("external_call_surface", "can_delegatecall", lambda p: p.get("call_type") == "delegatecall")
_rule("contract_creation", "can_create_contracts", lambda p: True)
_rule("special_evm_feature", "can_create_contracts_deterministically",
      lambda p: p.get("feature") == "create2_salt_option")
_rule("special_evm_feature", "uses_inline_assembly", lambda p: p.get("feature") == "assembly_block")
_rule("callback_capable_call", "can_invoke_external_callback", lambda p: True)
_rule("selfdestruct_call", "can_selfdestruct", lambda p: True)


def derive_capabilities(ctx: ProjectContext) -> None:
    by_function: dict[str, list[Fact]] = defaultdict(list)
    for fact in ctx.facts:
        fn = fact.subject.get("function")
        if fn:
            by_function[fn].append(fact)

    # can_modify_authorization_state: function WRITES a state variable that is
    # also referenced inside some authorization_check condition anywhere in
    # the repository. This is structural (cross-fact), not name-based.
    auth_state_vars: set[str] = set()
    for fact in ctx.facts:
        if fact.type == "authorization_check":
            auth_state_vars.update(fact.properties.get("referenced_state_variables", []))

    emitted = set()
    for func_key, facts in sorted(by_function.items()):
        caps: dict[str, list[str]] = defaultdict(list)
        for fact in facts:
            for fact_type, capability, matcher in _RULES:
                if fact.type == fact_type and matcher(fact.properties):
                    caps[capability].append(fact.id)
            if fact.type == "state_write" and fact.subject.get("state_variable") in auth_state_vars:
                caps["can_modify_authorization_state"].append(fact.id)

        for capability, fact_ids in sorted(caps.items()):
            dedup_key = (func_key, capability)
            if dedup_key in emitted:
                continue
            emitted.add(dedup_key)
            ctx.add_fact(
                Fact(
                    id=ids.fact_id("capability", func_key, capability),
                    type="capability",
                    status="derived",
                    subject={"function": func_key, "capability": capability},
                    properties={"supporting_facts": sorted(set(fact_ids))},
                    source=None,
                    evidence=[],
                    confidence="medium",
                    extraction_method="ast+heuristic",
                )
            )
