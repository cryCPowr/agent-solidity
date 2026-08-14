"""Role/privilege map + security-relationship-chain synthesis.

This module performs NO new AST parsing. It is a pure post-processing pass
over facts already emitted by expr_analysis.py / capability.py, combining
them into higher-level, connected relationships — the difference between
"_bridgeFunds performs an external call" and "parameter `data` is passed
into a dynamic-target external call in the same function that also approves
a token to a parameter-controlled spender".

Every fact here carries an explicit epistemic label in its `properties`:

    FACT       — every step is individually backed by an `observed` fact
    INFERENCE  — deterministically combined from multiple observed facts
                 (e.g. "this parameter reaches this call" + "this call's
                 target is dynamic" => "caller influences the call target")
    HYPOTHESIS — a structurally-plausible security-relevant *question* worth
                 a human/next-stage-agent's attention, never a verdict
    UNKNOWN    — could not be determined

This is layered ON TOP OF the existing `status` vocabulary
(observed/derived/partial/unknown), not a replacement for it — the base
`status` field on every Fact is untouched. `certainty` lives inside
`properties` for the two new fact types this module introduces
(`access_controlled_function`, `unguarded_capability_hypothesis`,
`security_relationship_chain`), so nothing about the existing 36 fact types
changes shape.

Nothing here ever asserts "vulnerable", "exploitable", or assigns severity.
"""

from __future__ import annotations

from collections import defaultdict

from . import ids
from .context import ProjectContext
from .models import Fact

# Capabilities that, if exercised without any observed authorization
# mechanism, are worth flagging as a HYPOTHESIS for a later stage to look at
# more closely. This list is itself just a set of existing capability names
# recon/capability.py already produces — no new heuristics are introduced.
_SECURITY_RELEVANT_CAPABILITIES = {
    "can_transfer_token",
    "can_transfer_native_value",
    "can_mint",
    "can_burn",
    "can_modify_authorization_state",
    "can_delegatecall",
    "can_call_arbitrary_target",
    "can_create_contracts",
    "can_selfdestruct",
}

_TOKEN_TRANSFER_OPS = {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "safeBatchTransferFrom"}
_APPROVAL_OPS = {"approve", "increaseAllowance", "setApprovalForAll", "permit"}


# ===========================================================================
# Relationship evidence kinds
# ===========================================================================
# These are the ONLY kinds of inter-operation relationships that recon
# will assert.  They are ordered from strongest (most evidence) to weakest.
#
#   DATA_DEPENDENCY      - one operation's argument/result directly flows into
#                         another via a local variable chain (proven by
#                         local_variable_origin / call_argument_origin_chain facts)
#   ARGUMENT_DEPENDENCY  - two operations share a common argument value
#                         (same parameter or literal used in both)
#   EXECUTION_ORDER      - operations appear in a specific sequential order
#                         within the same block (proven by AST statement order)
#   SAME_BLOCK           - operations appear in the same block
#                         (same basic block / compound statement)
#   SAME_FUNCTION        - operations appear in the same function body
#                         (weakest; implies nothing about dependency)
#
# Certainty mapping:
#   DATA_DEPENDENCY     -> INFERENCE (AST-backed propagation)
#   ARGUMENT_DEPENDENCY -> INFERENCE (shared argument is observable)
#   EXECUTION_ORDER     -> INFERENCE (statement order is observable)
#   SAME_BLOCK          -> HYPOTHESIS  (co-location only)
#   SAME_FUNCTION       -> HYPOTHESIS  (co-location only)


# ===========================================================================
# Role / privilege map
# ===========================================================================

def derive_role_privilege_facts(ctx: ProjectContext) -> None:
    """For every function: is it access-controlled (directly, or via a
    modifier whose own body contains an authorization_check), and does it
    exercise a security-relevant capability without any observed
    authorization mechanism at all?
    """
    auth_by_function: dict[str, list[Fact]] = defaultdict(list)
    auth_by_modifier: dict[str, list[Fact]] = defaultdict(list)
    for f in ctx.facts:
        if f.type != "authorization_check":
            continue
        if "function" in f.subject and f.subject["function"]:
            auth_by_function[f.subject["function"]].append(f)
        if "modifier" in f.subject and f.subject["modifier"]:
            auth_by_modifier[f.subject["modifier"]].append(f)

    capabilities_by_function: dict[str, list[Fact]] = defaultdict(list)
    for f in ctx.facts:
        if f.type == "capability":
            capabilities_by_function[f.subject["function"]].append(f)

    for fu_key, fu in sorted(ctx.function_by_key.items()):
        mechanisms = []

        if fu_key in auth_by_function:
            mechanisms.append({
                "kind": "inline",
                "modifier": None,
                "basis_facts": [f.id for f in auth_by_function[fu_key]],
            })

        for m_name, ref_id in zip(fu.modifiers, fu.modifier_ref_ids):
            decl = ctx.decl_index.get((fu.group, ref_id)) if ref_id is not None else None
            modifier_key = decl.get("modifier_key") if decl and decl.get("kind") == "modifier" else None
            if modifier_key and modifier_key in auth_by_modifier:
                mechanisms.append({
                    "kind": "modifier",
                    "modifier": modifier_key,
                    "basis_facts": [f.id for f in auth_by_modifier[modifier_key]],
                })

        if mechanisms:
            all_basis = sorted({fid for m in mechanisms for fid in m["basis_facts"]})
            ctx.add_fact(
                Fact(
                    id=ids.fact_id("access_controlled_function", fu.file, fu.ast_id),
                    type="access_controlled_function",
                    status="derived",
                    subject={"function": fu_key},
                    properties={
                        "certainty": "FACT",
                        "mechanisms": mechanisms,
                        "basis_facts": all_basis,
                    },
                    source=None,
                    evidence=[],
                    confidence="high",
                    extraction_method="ast+heuristic",
                )
            )

        # Unguarded capability hypothesis: a security-relevant capability
        # with no observed authorization mechanism anywhere in scope
        # (neither inline nor via any used modifier). This is explicitly a
        # HYPOTHESIS, not a finding — plenty of legitimate functions (public
        # mint-to-self faucets, permissionless swap functions, etc.) are
        # correctly unguarded, and recon has no way to know intent.
        if not mechanisms:
            caps = capabilities_by_function.get(fu_key, [])
            relevant = [c for c in caps if c.subject["capability"] in _SECURITY_RELEVANT_CAPABILITIES]
            for cap in relevant:
                ctx.add_fact(
                    Fact(
                        id=ids.fact_id("unguarded_capability_hypothesis", fu.file, f"{fu.ast_id}:{cap.subject['capability']}"),
                        type="unguarded_capability_hypothesis",
                        status="derived",
                        subject={"function": fu_key, "capability": cap.subject["capability"]},
                        properties={
                            "certainty": "HYPOTHESIS",
                            "note": (
                                "no authorization_check was observed for this function, inline "
                                "or via any modifier it uses, while it exercises this capability. "
                                "This is a structural absence-of-evidence signal, not a finding: "
                                "many legitimate functions are intentionally permissionless."
                            ),
                            "basis_facts": [cap.id],
                        },
                        source=None,
                        evidence=[],
                        confidence="low",
                        extraction_method="ast+heuristic",
                    )
                )


# ===========================================================================
# Security relationship chains
# ===========================================================================

def _classify_relationship(call_fact: Fact, asset_fact: Fact, fu, all_facts: list[Fact]) -> tuple[str, str, str]:
    """Determine the strongest evidence-backed relationship kind between
    a dynamic call and an asset operation that co-exist in the same function.

    Returns (relation_kind, certainty, note).

    The ONLY time we escalate beyond co_occurs_with is when we have
    AST-backed evidence of a real dependency:

      - ARGUMENT_DEPENDENCY: both operations use the same parameter or
        literal value as an input.

    If we can't prove dependency, we fall back to co_occurs_with with
    HYPOTHESIS certainty.

    CRITICAL: Same-function co-existence alone is NOT a relationship
    beyond co_occurs_with. We must NEVER mark operations as dependent
    when we only know they're in the same function.
    """
    # Extract AST node IDs involved in the call and asset operation
    call_ast_id = call_fact.source.ast_node_id if call_fact.source else None
    asset_ast_id = asset_fact.source.ast_node_id if asset_fact.source else None

    # --- Try ARGUMENT_DEPENDENCY ---
    # Check if both operations use the same parameter as an input.
    # An 'input' is either the target_expression (for dynamic calls)
    # or one of the arguments (for asset operations).
    call_target = call_fact.properties.get("target_expression", "")
    call_args = call_fact.properties.get("arguments", [])
    asset_op_args = asset_fact.properties.get("arguments", [])
    asset_target = asset_fact.properties.get("target_expression", "")

    # Check for shared parameter usage
    shared_param = None
    for param in fu.parameters:
        param_name = param.name
        if not param_name:
            continue

        # Is the parameter in the call's target or arguments?
        reaches_call = (param_name == call_target) or (param_name in call_args)
        # Is the parameter in the asset operation's target or arguments?
        reaches_asset = (param_name == asset_target) or (param_name in asset_op_args)

        if reaches_call and reaches_asset:
            shared_param = param_name
            break

    if shared_param:
        return (
            "ARGUMENT_DEPENDENCY",
            "INFERENCE",
            f"both operations use parameter '{shared_param}' as input",
        )

    # --- Fall back to co_occurs_with ---
    # We know they're in the same function, but we have NO evidence of
    # any actual dependency between them. This must be HYPOTHESIS,
    # NOT FACT or INFERENCE.
    return (
        "co_occurs_with",
        "HYPOTHESIS",
        "operations coexist in the same function but no data/control dependency was proven",
    )


def derive_relationship_chains(ctx: ProjectContext) -> None:
    """Connect already-extracted per-function facts into short, explicit
    relationship chains, mirroring the shape requested:

        User -> controls -> parameter -> passed_into -> external call
             -> interacts_with -> target -> [relationship] -> asset_operation

    rather than leaving "performs an external call" and "approves a token"
    as two unrelated facts a downstream consumer would have to notice and
    connect themselves.

    CRITICAL: We ONLY add relationship steps when we have evidence for them.
    Same-function co-existence alone gets SAME_FUNCTION with HYPOTHESIS certainty.
    """
    facts_by_function: dict[str, list[Fact]] = defaultdict(list)
    for f in ctx.facts:
        # Most fact types key their subject by "function"; the call-graph
        # fact types (internal_call / external_call / low_level_call) key by
        # "caller" instead — both refer to the same function_key. Bucket by
        # whichever is present so this pass sees the complete per-function
        # fact set rather than silently missing the call-graph facts.
        fn = f.subject.get("function") or f.subject.get("caller")
        if fn:
            facts_by_function[fn].append(f)

    for fu_key, facts in sorted(facts_by_function.items()):
        by_type: dict[str, list[Fact]] = defaultdict(list)
        for f in facts:
            by_type[f.type].append(f)

        dynamic_calls = [
            f for f in by_type.get("external_call", []) + by_type.get("low_level_call", [])
            if f.properties.get("target_status") == "dynamic"
        ]
        param_dataflows = [
            f for f in by_type.get("call_argument_dataflow", [])
            if f.properties.get("origin_kind") == "parameter"
        ]
        approvals = [f for f in by_type.get("asset_operation", []) if f.properties.get("operation") in _APPROVAL_OPS]
        transfers = [f for f in by_type.get("asset_operation", []) if f.properties.get("operation") in _TOKEN_TRANSFER_OPS]
        callbacks = by_type.get("callback_capable_call", [])

        if not dynamic_calls:
            continue

        fu = ctx.function_by_key.get(fu_key)
        if fu is None:
            continue

        for call in dynamic_calls:
            call_ast_id = call.source.ast_node_id if call.source else None
            steps = [
                {
                    "actor": "caller",
                    "relation": "controls",
                    "target": f"parameter(s) of {fu.name}",
                    "certainty": "FACT",
                    "basis_facts": [],
                    "note": "any external account can choose the arguments passed into this public/external function",
                }
            ]

            same_call_dataflows = [d for d in param_dataflows if (d.source.ast_node_id if d.source else None) == call_ast_id]
            for d in same_call_dataflows:
                steps.append({
                    "actor": f"parameter:{d.properties.get('origin_name')}",
                    "relation": "passed_into",
                    "target": f"call({call.properties.get('call_subtype') or call.properties.get('call_type')}) arg#{d.properties.get('argument_index')}",
                    "certainty": "FACT",
                    "basis_facts": [d.id, call.id],
                    "note": "AST-verified: this argument's value is a direct reference to a function parameter",
                })

            target_expr = call.properties.get("target_expression", "")
            target_is_param_named = any(
                target_expr == p.name for p in fu.parameters if p.name
            )
            steps.append({
                "actor": "call target",
                "relation": "resolved_from" if target_is_param_named else "is",
                "target": target_expr or "<unknown expression>",
                "certainty": "INFERENCE" if target_is_param_named else "FACT",
                "basis_facts": [call.id],
                "note": (
                    "call target expression textually matches a function parameter name"
                    if target_is_param_named
                    else "target_status is dynamic (not a compile-time-fixed/immutable address)"
                ),
            })

            if callbacks:
                steps.append({
                    "actor": "call target",
                    "relation": "may_invoke_callback_on",
                    "target": "caller-influenced contract",
                    "certainty": "INFERENCE",
                    "basis_facts": [c.id for c in callbacks],
                    "note": "a callback-compatible interface call was also observed in this function",
                })

            relevant_assets = approvals + transfers
            if relevant_assets:
                for asset_fact in relevant_assets:
                    # Evidence-based relationship classification
                    edge_kind, edge_certainty, edge_note = _classify_relationship(
                        call, asset_fact, fu, facts
                    )
                    steps.append({
                        "actor": "this function",
                        "relation": edge_kind,
                        "target": f"asset_operation({asset_fact.properties.get('operation')} on {asset_fact.properties.get('target_expression')})",
                        "certainty": edge_certainty,
                        "basis_facts": [asset_fact.id, call.id],
                        "note": edge_note,
                    })

            # Overall certainty: the asset-operation relationship is the
            # security-relevant question. If all such relationships are
            # co_occurs_with (HYPOTHESIS), the overall chain certainty is
            # HYPOTHESIS. If ANY asset relationship is proven (ARGUMENT_DEPENDENCY
            # / DATA_DEPENDENCY), the overall is INFERENCE. If there are no
            # asset operations at all, the chain's strength depends on whether
            # a parameter reaches the call directly.
            has_proven_asset_dependency = any(
                s.get("relation") in ("ARGUMENT_DEPENDENCY", "DATA_DEPENDENCY")
                for s in steps
            )
            has_co_occurs_only = any(
                s.get("relation") == "co_occurs_with"
                for s in steps
            )
            has_asset_relationship = any(
                s.get("relation") in ("ARGUMENT_DEPENDENCY", "co_occurs_with", "DATA_DEPENDENCY")
                for s in steps
            )

            if has_asset_relationship and not has_proven_asset_dependency:
                overall = "HYPOTHESIS"
            elif has_proven_asset_dependency:
                overall = "INFERENCE"
            else:
                overall = "INFERENCE" if (same_call_dataflows or target_is_param_named or callbacks) else "FACT"

            ctx.add_fact(
                Fact(
                    id=ids.fact_id("security_relationship_chain", fu.file, f"{fu.ast_id}:{call.id}"),
                    type="security_relationship_chain",
                    status="derived",
                    subject={"function": fu_key, "pattern": "user_influenced_dynamic_call"},
                    properties={
                        "pattern": "user_influenced_dynamic_call",
                        "overall_certainty": overall,
                        "steps": steps,
                    },
                    source=call.source,
                    evidence=list(call.evidence),
                    confidence="medium",
                    extraction_method="ast+heuristic",
                )
            )
