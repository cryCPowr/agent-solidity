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


# Enhanced capability rules with evidence attributes
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


def _analyze_capability_attributes(fact, ctx):
    """Analyze and return enriched attributes for a capability.

    Classification vocabulary (driven by EVIDENCE, never by absence):
      - user_controlled : the value derives from a function parameter
      - state_controlled: the value derives from a state variable
      - derived         : the value derives from an expression that is
                          neither a bare parameter nor a bare state var
                          (e.g. arithmetic, type conversion, function call)
      - fixed           : the value is a literal constant (AST Literal) or
                          an immutable/compile-time constant reference
      - unknown         : no AST evidence was found; MUST NOT be upgraded
                          to fixed/derived just because dataflow failed

    Default is ALWAYS "unknown". Only AST evidence moves it.
    """
    attrs = {
        "target": "unknown",
        "amount": "unknown",
        "asset": "unknown",
        "authorization": "unknown",
    }

    def _fn_parameters(fn_key):
        return {
            f.subject.get("parameter")
            for f in ctx.facts
            if f.type == "function_parameter" and f.subject.get("function") == fn_key
        }

    def _classify_value(expr, fn_key):
        """Classify a bare expression string against function parameters."""
        if not expr:
            return "unknown"
        params = _fn_parameters(fn_key)
        if expr in params:
            return "user_controlled"
        return "unknown"

    if fact.type == "asset_operation":
        fn_key = fact.subject.get("function")
        target_expr = fact.properties.get("target_expression", "")
        # Target classification: parameter -> user_controlled; literal address
        # (0x...) -> fixed; otherwise unknown (NOT fixed-by-default).
        if target_expr.startswith("0x") or target_expr.startswith("address("):
            attrs["target"] = "fixed"
        else:
            attrs["target"] = _classify_value(target_expr, fn_key)

        # Amount classification: 2nd argument. Parameter -> user_controlled;
        # literal number -> fixed; otherwise unknown.
        args = fact.properties.get("arguments", [])
        if len(args) >= 2:
            amount_arg = args[1]
            # Literal detection: numbers, hex, strings
            if amount_arg.isdigit() or amount_arg.startswith("0x"):
                attrs["amount"] = "fixed"
            else:
                attrs["amount"] = _classify_value(amount_arg, fn_key)

        # Asset: the token/asset address used. Literal -> fixed;
        # anything else -> unknown.
        if target_expr.startswith("0x") or target_expr.startswith("address("):
            attrs["asset"] = "fixed"
        elif "IERC20" in target_expr or "token" in target_expr.lower():
            # State-deployed token reference (e.g. token.transfer) is
            # state_controlled — the token address is a state variable.
            attrs["asset"] = "state_controlled"
        else:
            attrs["asset"] = "unknown"

        # Authorization
        if fn_key:
            auth_facts = [f for f in ctx.facts
                         if f.type == "access_controlled_function"
                         and f.subject.get("function") == fn_key]
            if auth_facts:
                attrs["authorization"] = "guarded"

    elif fact.type == "eth_transfer":
        fn_key = fact.subject.get("function")
        target_expr = fact.properties.get("target_expression", "")
        amount_expr = fact.properties.get("amount_expression", "")
        # amount_expression can be a string or a list of strings
        if isinstance(amount_expr, list):
            amount_expr = amount_expr[0] if amount_expr else ""
        
        if target_expr.startswith("0x") or target_expr.startswith("address("):
            attrs["target"] = "fixed"
        else:
            attrs["target"] = _classify_value(target_expr, fn_key)
    
        if isinstance(amount_expr, str) and (amount_expr.isdigit() or amount_expr.startswith("0x")):
            attrs["amount"] = "fixed"
        else:
            attrs["amount"] = _classify_value(amount_expr, fn_key) if isinstance(amount_expr, str) else "unknown"

        # Native ETH asset is always the same asset (contract balance)
        attrs["asset"] = "fixed"

        if fn_key:
            auth_facts = [f for f in ctx.facts
                         if f.type == "access_controlled_function"
                         and f.subject.get("function") == fn_key]
            if auth_facts:
                attrs["authorization"] = "guarded"

    elif fact.type == "external_call_surface":
        if fact.properties.get("call_type") == "low_level":
            fn_key = fact.subject.get("function")
            target_expr = fact.properties.get("target_expression", "")
            if target_expr.startswith("0x") or target_expr.startswith("address("):
                attrs["target"] = "fixed"
            else:
                attrs["target"] = _classify_value(target_expr, fn_key)

            if fn_key:
                auth_facts = [f for f in ctx.facts
                             if f.type == "access_controlled_function"
                             and f.subject.get("function") == fn_key]
                if auth_facts:
                    attrs["authorization"] = "guarded"

    return attrs


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
            
            # Analyze capability attributes
            attrs = {}
            for fact_id in fact_ids:
                fact = next((f for f in ctx.facts if f.id == fact_id), None)
                if fact:
                    fact_attrs = _analyze_capability_attributes(fact, ctx)
                    # Merge attributes (take the most specific)
                    for k, v in fact_attrs.items():
                        if v != "unknown":
                            attrs[k] = v
            
            # Fill in unknowns with defaults
            for k in ["target", "amount", "asset", "authorization"]:
                if k not in attrs:
                    attrs[k] = "unknown"
            
            ctx.add_fact(
                Fact(
                    id=ids.fact_id("capability", func_key, capability),
                    type="capability",
                    status="derived",
                    subject={"function": func_key, "capability": capability},
                    properties={
                        "supporting_facts": sorted(set(fact_ids)),
                        "attributes": attrs
                    },
                    source=None,
                    evidence=[],
                    confidence="medium",
                    extraction_method="ast+heuristic",
                )
            )