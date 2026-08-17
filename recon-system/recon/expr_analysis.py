"""Per-function body analysis.

Single AST walk over each function's body that emits, with full source
provenance:

  * state reads / writes                       (section 10)
  * call graph edges (internal/external/etc.)   (section 11)
  * external call surface facts                 (section 13)
  * asset / value flow facts                     (section 14)
  * authorization-mechanism facts                 (section 15)
  * control-flow structural facts                  (section 18)
  * event/error emission + revert sites             (section 19)
  * special EVM/Solidity feature facts               (section 20)
  * conservative, evidence-backed data-flow edges     (sections 8-9)

Everything here is either a direct AST observation (`observed`) or a
deterministic, disclosed heuristic (`derived`). Nothing is fabricated; when a
target/value cannot be resolved it is recorded as `unknown`/`partial`.
"""

from __future__ import annotations

from typing import Optional

from . import ast_utils, dataflow, ids
from .context import ProjectContext
from .inventory import ContractUnit, FunctionUnit
from .inventory_facts import function_node_id, state_var_node_id
from .models import Fact, GraphEdge, GraphNode

TOKEN_OP_NAMES = {
    "transfer", "transferFrom", "approve", "increaseAllowance", "decreaseAllowance",
    "safeTransfer", "safeTransferFrom", "safeBatchTransferFrom", "setApprovalForAll",
    "permit", "mint", "burn",
}
LOW_LEVEL_CALL_NAMES = {"call", "delegatecall", "staticcall"}
ETH_TRANSFER_NAMES = {"transfer", "send"}
ENV_ROOTS = {"msg", "block", "tx"}


def _type_string(node: dict) -> Optional[str]:
    return ((node or {}).get("typeDescriptions") or {}).get("typeString")


def _is_address_type(type_string: Optional[str]) -> bool:
    return bool(type_string) and type_string.startswith("address")


def _is_contract_type(type_string: Optional[str]) -> bool:
    return bool(type_string) and (
        type_string.startswith("contract ") or type_string.startswith("interface ")
    )


def _src_text(ctx: ProjectContext, file: str, node: dict) -> str:
    parsed = ast_utils.parse_src(node.get("src")) if node else None
    if not parsed:
        return ""
    start, length, _ = parsed
    text_bytes = ctx.file_bytes.get(file, b"")[start:start + length]
    text = text_bytes.decode("utf-8", errors="replace")
    return text if len(text) <= 200 else text[:200] + "…"


def build_visible_state_vars(ctx: ProjectContext, cu: ContractUnit) -> dict[int, "StateVarUnit"]:
    visible = {}
    for base_ast_id in cu.linearized_base_ast_ids or [cu.ast_id]:
        key = ctx.contract_by_group_ast_id.get((cu.group, base_ast_id))
        base_cu = ctx.contracts.get(key) if key else None
        if not base_cu:
            continue
        for sv in base_cu.state_vars:
            visible.setdefault(sv.ast_id, sv)
    return visible


def _peel_to_root(node: Optional[dict]) -> Optional[dict]:
    while node is not None:
        nt = node.get("nodeType")
        if nt == "MemberAccess":
            node = node.get("expression")
        elif nt == "IndexAccess":
            node = node.get("baseExpression")
        elif nt == "IndexRangeAccess":
            node = node.get("baseExpression")
        elif nt == "TupleExpression" and len(node.get("components") or []) == 1:
            node = (node.get("components") or [None])[0]
        else:
            break
    return node


def analyze_function(ctx: ProjectContext, cu: ContractUnit, fu: FunctionUnit) -> None:
    fnode_id = function_node_id(fu)

    if fu.body_node is None:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("function_body", fu.file, fu.ast_id),
                type="function_body",
                status="observed",
                subject={"function": fu.key},
                properties={"has_body": False, "reason": "declaration_only (interface/abstract/unimplemented)"},
                source=ctx.source_ref(fu.file, fu.node),
                evidence=[],
                confidence="high",
                extraction_method="ast",
            )
        )
        return

    visible_state_vars = build_visible_state_vars(ctx, cu)
    local_scope: dict[int, str] = {}
    for p in fu.parameters:
        local_scope[p.ast_id] = "parameter"
    for r in fu.returns:
        local_scope[r.ast_id] = "return_variable"
    for vd in ast_utils.find_all(fu.body_node, "VariableDeclaration"):
        local_scope.setdefault(vd["id"], "local_variable")

    fu.local_defs, fu.local_defs_ambiguous = dataflow.build_local_defs(fu.body_node)

    write_target_ids: set[int] = set()
    compound_write_ids: set[int] = set()

    for assign in ast_utils.find_all(fu.body_node, "Assignment"):
        lhs = assign.get("leftHandSide")
        targets = lhs.get("components") if (lhs or {}).get("nodeType") == "TupleExpression" else [lhs]
        op = assign.get("operator", "=")
        for t in targets:
            root = _peel_to_root(t)
            if root is not None and root.get("nodeType") == "Identifier":
                write_target_ids.add(root["id"])
                if op != "=":
                    compound_write_ids.add(root["id"])

    for unary in ast_utils.find_all(fu.body_node, "UnaryOperation"):
        op = unary.get("operator")
        if op in ("++", "--", "delete"):
            root = _peel_to_root(unary.get("subExpression"))
            if root is not None and root.get("nodeType") == "Identifier":
                write_target_ids.add(root["id"])
                if op in ("++", "--"):
                    # increment/decrement reads the prior value before writing.
                    compound_write_ids.add(root["id"])

    _emit_state_access(ctx, cu, fu, fnode_id, visible_state_vars, write_target_ids, compound_write_ids)
    _emit_input_origin(ctx, cu, fu, fnode_id)
    _emit_calls(ctx, cu, fu, fnode_id, local_scope, visible_state_vars)
    _emit_control_flow(ctx, cu, fu, fnode_id)
    _emit_events_errors_usage(ctx, cu, fu, fnode_id)
    _emit_special_features(ctx, cu, fu, fnode_id)
    _emit_arithmetic_operations(ctx, cu, fu, fnode_id)
    _emit_loop_complexity(ctx, cu, fu, fnode_id)
    _emit_randomness_patterns(ctx, cu, fu, fnode_id)
    _emit_expression_origin_chains(ctx, cu, fu, fnode_id, local_scope, visible_state_vars)


def _emit_state_access(ctx, cu, fu, fnode_id, visible_state_vars, write_ids, compound_write_ids) -> None:
    seen_pairs: set[tuple[int, str]] = set()  # (node_id, "read"|"write") dedup
    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "Identifier":
            continue
        refid = node.get("referencedDeclaration")
        if refid not in visible_state_vars:
            continue
        sv = visible_state_vars[refid]
        is_write = node["id"] in write_ids
        access_kind = "write" if is_write else "read"
        key = (node["id"], access_kind)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)

        svnode_id = state_var_node_id(sv)
        src_ref = ctx.source_ref(fu.file, node)
        evid = ctx.make_evidence(fu.file, node)
        fact_type = "state_write" if is_write else "state_read"
        fact = Fact(
            id=ids.fact_id(fact_type, fu.file, node["id"]),
            type=fact_type,
            status="observed",
            subject={"function": fu.key, "state_variable": sv.key, "name": sv.name},
            properties={"type": sv.type_string},
            source=src_ref,
            evidence=[evid] if evid else [],
            confidence="high",
            extraction_method="ast",
        )
        ctx.add_fact(fact)
        edge_type = "WRITES" if is_write else "READS"
        ctx.add_edge(
            GraphEdge(
                id=ids.edge_id(edge_type, fnode_id, svnode_id, str(node["id"])),
                type=edge_type,
                source=fnode_id,
                target=svnode_id,
                status="observed",
                fact_ids=[fact.id],
            )
        )
        if node["id"] in compound_write_ids:
            read_fact = Fact(
                id=ids.fact_id("state_read", fu.file, f"{node['id']}:compound"),
                type="state_read",
                status="observed",
                subject={"function": fu.key, "state_variable": sv.key, "name": sv.name},
                properties={"type": sv.type_string, "reason": "compound_assignment_or_increment_implies_read"},
                source=src_ref,
                evidence=[evid] if evid else [],
                confidence="high",
                extraction_method="ast",
            )
            ctx.add_fact(read_fact)
            ctx.add_edge(
                GraphEdge(
                    id=ids.edge_id("READS", fnode_id, svnode_id, f"compound:{node['id']}"),
                    type="READS",
                    source=fnode_id,
                    target=svnode_id,
                    status="observed",
                    fact_ids=[read_fact.id],
                    properties={"reason": "compound_assignment_implies_read"},
                )
            )


def _emit_input_origin(ctx, cu, fu, fnode_id) -> None:
    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "MemberAccess":
            continue
        base = node.get("expression") or {}
        if base.get("nodeType") == "Identifier" and base.get("name") in ENV_ROOTS:
            origin = f"{base['name']}.{node.get('memberName')}"
            src_ref = ctx.source_ref(fu.file, node)
            evid = ctx.make_evidence(fu.file, node)
            ctx.add_fact(
                Fact(
                    id=ids.fact_id("input_origin_env", fu.file, node["id"]),
                    type="input_origin",
                    status="observed",
                    subject={"function": fu.key, "origin": origin},
                    properties={"category": "environment_variable"},
                    source=src_ref,
                    evidence=[evid] if evid else [],
                    confidence="high",
                    extraction_method="ast",
                )
            )


def _unwrap_call_options(expr: dict) -> tuple[dict, dict]:
    """Unwrap a `target.call{value: v, gas: g}` / `new X{salt: s}` style
    FunctionCallOptions node into (underlying_expression, options_by_name).

    `options_by_name` maps option name ("value"/"gas"/"salt") to its AST
    expression node.
    """
    if (expr or {}).get("nodeType") != "FunctionCallOptions":
        return expr, {}
    names = expr.get("names") or []
    options = expr.get("options") or []
    options_by_name = dict(zip(names, options))
    inner = expr.get("expression") or {}
    return inner, options_by_name


def _classify_call(expr: dict, ctx: ProjectContext, group: str) -> str:
    """Classify an (already option-unwrapped) callee expression node.

    Returns one of: internal, external, low_level, delegatecall, staticcall,
    creation, event_call, error_call, require, revert_builtin, assert,
    selfdestruct, other_builtin, unresolved.
    """
    ntype = (expr or {}).get("nodeType")

    if ntype == "NewExpression":
        return "creation"

    if ntype == "Identifier":
        name = expr.get("name")
        if name in ("require",):
            return "require"
        if name in ("revert",):
            return "revert_builtin"
        if name in ("assert",):
            return "assert"
        if name in ("selfdestruct", "suicide"):
            return "selfdestruct"
        if name in ("keccak256", "sha256", "ripemd160", "ecrecover", "addmod", "mulmod", "blockhash"):
            return "other_builtin"
        refid = expr.get("referencedDeclaration")
        if refid is not None:
            decl = ctx.decl_index.get((group, refid))
            decl_kind = decl.get("kind") if decl else None
            if decl_kind == "event":
                return "event_call"
            if decl_kind == "error":
                return "error_call"
            if decl_kind == "function":
                return "internal"
            return "unresolved"
        return "unresolved"

    if ntype == "MemberAccess":
        member = expr.get("memberName")
        base_type = _type_string(expr.get("expression") or {})
        if member in LOW_LEVEL_CALL_NAMES and _is_address_type(base_type):
            return {"call": "low_level", "delegatecall": "delegatecall", "staticcall": "staticcall"}[member]
        if _is_contract_type(base_type):
            return "external"
        if _is_address_type(base_type) and member in ETH_TRANSFER_NAMES:
            return "eth_transfer"
        if member in ("push", "pop"):
            return "array_mutation"
        if expr.get("referencedDeclaration") is not None:
            # e.g. library function call via using-for, or direct library call
            return "external"
        return "unresolved"

    return "unresolved"


def _emit_calls(ctx, cu, fu, fnode_id, local_scope, visible_state_vars) -> None:
    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "FunctionCall":
            continue
        if node.get("kind") in ("typeConversion", "structConstructorCall"):
            continue

        raw_expr = node.get("expression") or {}
        expr, call_options = _unwrap_call_options(raw_expr)
        category = _classify_call(expr, ctx, fu.group)
        src_ref = ctx.source_ref(fu.file, node)
        evid = ctx.make_evidence(fu.file, node)

        if call_options:
            _emit_call_options(ctx, fu, node, call_options, src_ref, evid)

        if category == "array_mutation":
            _emit_array_mutation(ctx, fu, fnode_id, node, expr, visible_state_vars, src_ref, evid)
        elif category == "internal":
            _emit_internal_call(ctx, fu, fnode_id, node, expr, src_ref, evid)
        elif category == "external":
            _emit_external_call(ctx, fu, fnode_id, node, expr, src_ref, evid, "external")
        elif category in ("low_level", "delegatecall", "staticcall"):
            _emit_external_call(ctx, fu, fnode_id, node, expr, src_ref, evid, category)
        elif category == "eth_transfer":
            _emit_eth_transfer(ctx, fu, fnode_id, node, expr, src_ref, evid)
        elif category == "creation":
            _emit_creation(ctx, fu, fnode_id, node, src_ref, evid)
        elif category == "require":
            _emit_require(ctx, fu, fnode_id, node, src_ref, evid, visible_state_vars)
        elif category in ("revert_builtin",):
            _emit_revert(ctx, fu, fnode_id, node, src_ref, evid, "revert_string")
        elif category == "assert":
            _emit_fact(
                ctx, fu, "assert_statement", src_ref, evid,
                {"function": fu.key},
                {"condition": _src_text(ctx, fu.file, node.get("arguments", [{}])[0]) if node.get("arguments") else ""},
                "observed", confidence="high",
            )
        elif category == "other_builtin":
            _emit_builtin_call(ctx, fu, fnode_id, node, expr, src_ref, evid)
            _emit_decode_encode(ctx, fu, fnode_id, node, expr, src_ref, evid)
        elif category == "unresolved":
            _emit_fact(
                ctx, fu, "call_unresolved", src_ref, evid,
                {"function": fu.key},
                {"callee_expression": _src_text(ctx, fu.file, expr)},
                "unknown",
            )
            _emit_decode_encode(ctx, fu, fnode_id, node, expr, src_ref, evid)
        elif category == "selfdestruct":
            _emit_fact(ctx, fu, "selfdestruct_call", src_ref, evid, {"function": fu.key}, {}, "observed")
        # Errors used as `revert CustomError(...)`: represented as FunctionCall
        # whose expression is Identifier referencing an ErrorDefinition.
        if expr.get("nodeType") == "Identifier":
            decl = ctx.decl_index.get((fu.group, expr.get("referencedDeclaration")))
            if decl and decl.get("kind") == "error":
                _emit_revert(ctx, fu, fnode_id, node, src_ref, evid, "custom_error", error_key=decl.get("error_key"))

        # Asset / value flow (token-like operation) — name-pattern based, so
        # always `derived`, never `observed`, and never asserted as a
        # verified ERC20/721/1155 call. Deliberately excludes plain ETH
        # transfers (`address.transfer`/`.send`), which are already recorded
        # as their own `eth_transfer` fact type — an address-typed base is
        # native value movement, not a token-contract call.
        if (
            expr.get("nodeType") == "MemberAccess"
            and expr.get("memberName") in TOKEN_OP_NAMES
            and category not in ("eth_transfer",)
        ):
            _emit_token_operation(ctx, fu, fnode_id, node, expr, src_ref, evid)

        # Callback-compatible interface calls (receiver hooks): a call whose
        # target interface/type name matches known receiver interfaces.
        target_type = _type_string((expr.get("expression") or {})) if expr.get("nodeType") == "MemberAccess" else None
        if target_type and any(
            marker in target_type for marker in ("IERC721Receiver", "IERC1155Receiver", "ERC777")
        ):
            _emit_fact(
                ctx, fu, "callback_capable_call", src_ref, evid,
                {"function": fu.key}, {"target_type": target_type, "member": expr.get("memberName")},
                "derived",
            )

        # Callback relationship via ERC721/1155 safeTransfer/safeBatchTransfer:
        # these token operations trigger callback receivers. We link the call
        # to any onERC721Received/onERC1155Received IMPLEMENTATION in scope.
        #
        # BUGFIX: this previously matched by function name alone across every
        # contract in the project, including bodiless interface declarations
        # (e.g. IERC721Receiver's own abstract `onERC721Received`). An
        # unimplemented interface method can never actually be the function
        # invoked at runtime — Solidity does not allow calling it — so
        # including it was pure noise: a single real call site was reported
        # as having 2 "callback relationships" when only 1 (the concrete
        # implementation) could ever really execute. `other_fu.body_node is
        # not None` restricts this to genuine implementations. We still
        # cannot know WHICH concrete contract's implementation is behind a
        # dynamically-typed interface reference (that's runtime dispatch),
        # so multiple real implementations across different contracts may
        # still all be linked here as structurally-plausible candidates —
        # that part is an intentional, disclosed heuristic (see the `note`
        # below), not a bug.
        member_name = expr.get("memberName")
        if member_name in ("safeTransferFrom", "safeTransfer", "safeBatchTransferFrom"):
            # Check for receiver functions across all contract units in project context
            for other_cu in ctx.contracts.values():
                for other_fu in other_cu.functions:
                    if other_fu.name in ("onERC721Received", "onERC1155Received", "onERC1155BatchReceived") \
                            and other_fu.body_node is not None:
                        callee_target = _src_text(ctx, fu.file, expr.get("expression") or {})
                        _emit_fact(
                            ctx, fu, "callback_relationship", src_ref, evid,
                            {"caller": fu.key, "callee_target_expression": callee_target},
                            {
                                "trigger_operation": member_name,
                                "callback_function": other_fu.key,
                                "callback_name": other_fu.name,
                                "relationship": "external_call → callback_receiver (via safeTransfer)",
                                "note": "structural link only; actual callback dispatch is semantic",
                            },
                            "derived",
                        )
                        break

        # Callback relationship: link external call → receiver interface.
        # This creates the explicit chain:
        #   external call → callback receiver implementation → onERC721Received / onERC1155Received
        # needed by Class-B style reasoning without semantic interpretation.
        if category in ("external", "low_level", "delegatecall", "staticcall"):
            if target_type and any(
                marker in target_type for marker in ("IERC721Receiver", "IERC1155Receiver", "ERC777")
            ):
                callee_target = _src_text(ctx, fu.file, expr.get("expression") or {})
                _emit_fact(
                    ctx, fu, "callback_relationship", src_ref, evid,
                    {"caller": fu.key, "callee_target_expression": callee_target},
                    {
                        "target_type": target_type,
                        "call_type": category,
                        "relationship": "external_call → callback_receiver",
                        "note": "structural link only; actual callback dispatch is semantic",
                    },
                    "derived",
                )

        # Conservative data-flow edges for call arguments (sections 8-9)
        _emit_call_argument_flows(ctx, fu, fnode_id, node, local_scope, visible_state_vars, src_ref, evid)

        # Accounting / value-flow effect (Class D): link an asset-affecting
        # call to the state mutation that immediately follows it.
        # Builds: external data → decoded slot → variable → consumer
        #          value → transformation → balance/liability/share → sink
        member_name = expr.get("memberName") if expr.get("nodeType") == "MemberAccess" else None
        call_path = (
            category in ("external", "low_level", "delegatecall", "staticcall")
            or member_name in TOKEN_OP_NAMES
        )
        if call_path:
            _post_call_state_effect(ctx, fu, fnode_id, node, visible_state_vars)


def _post_call_state_effect(ctx, fu, fnode_id, call_node, visible_state_vars) -> None:
    """Emit a `post_call_state_effect` fact linking an asset-affecting call
    to the next state write in the same function body.

    This creates the structural chain:
      value → transformation → balance/liability/share → sink

    Used by Class D (accounting/value-flow) reasoning. Purely structural:
    records temporal proximity, not semantic causation.
    """
    call_end = call_node.get("src")
    if not call_end:
        return
    parts = call_end.split(":")
    call_end_pos = int(parts[0]) + int(parts[1]) if len(parts) >= 2 else 0
    # Find the closest state write that comes after the call
    # (same source-order heuristic)
    nearest_write = None
    min_gap = 999999
    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "Identifier":
            continue
        refid = node.get("referencedDeclaration")
        if refid not in visible_state_vars:
            continue
        sv = visible_state_vars[refid]
        write_src = node.get("src", "")
        write_parts = write_src.split(":")
        write_start = int(write_parts[0]) if write_parts[0].isdigit() else 0
        if write_start > call_end_pos:
            gap = write_start - call_end_pos
            if gap < min_gap:
                min_gap = gap
                nearest_write = sv
    if nearest_write:
        src_ref = ctx.source_ref(fu.file, call_node)
        evid = ctx.make_evidence(fu.file, call_node)
        _emit_fact(
            ctx, fu, "post_call_state_effect", src_ref, evid,
            {"function": fu.key, "state_variable": nearest_write.key, "name": nearest_write.name},
            {
                "type": nearest_write.type_string,
                "temporal_proximity": "immediate" if min_gap < 50 else "nearby",
                "note": "structural adjacency only; semantic causation requires verification",
            },
            "derived", confidence="medium",
        )


def _emit_call_options(ctx, fu, call_node, call_options: dict, src_ref, evid) -> None:
    """Record `{value: ..., gas: ..., salt: ...}` options on a call/creation
    (e.g. `target.call{value: v}(...)`, `new X{salt: s}(...)`).
    """
    props = {name: _src_text(ctx, fu.file, val) for name, val in call_options.items()}
    _emit_fact(
        ctx, fu, "call_options", src_ref, evid,
        {"function": fu.key}, props, "observed", confidence="high",
    )
    if "value" in call_options:
        _emit_fact(
            ctx, fu, "eth_transfer", src_ref, evid,
            {"function": fu.key},
            {"member": "call{value:}", "amount_expression": [props["value"]]},
            "observed", confidence="high",
        )
    if "salt" in call_options:
        _emit_fact(
            ctx, fu, "special_evm_feature", src_ref, evid,
            {"function": fu.key}, {"feature": "create2_salt_option", "salt_expression": props["salt"]},
            "observed", confidence="high",
        )


def _emit_array_mutation(ctx, fu, fnode_id, node, expr, visible_state_vars, src_ref, evid) -> None:
    """`array.push(...)` / `array.pop()` are state-mutating even though they
    are not Assignment nodes; without this, the root array's WRITE would be
    silently missed by the Assignment/delete-based write detector.
    """
    base = expr.get("expression") or {}
    root = _peel_to_root(base)
    member = expr.get("memberName")
    sv = None
    if root is not None and root.get("nodeType") == "Identifier":
        sv = visible_state_vars.get(root.get("referencedDeclaration"))

    fact = _emit_fact(
        ctx, fu, "array_mutation", src_ref, evid,
        {"function": fu.key},
        {
            "operation": member,
            "target_expression": _src_text(ctx, fu.file, base),
            "state_variable": sv.key if sv else None,
        },
        "observed" if sv else "partial",
        confidence="high" if sv else "medium",
    )
    if sv:
        from .inventory_facts import state_var_node_id
        svnode_id = state_var_node_id(sv)
        write_fact = _emit_fact(
            ctx, fu, "state_write", src_ref, evid,
            {"function": fu.key, "state_variable": sv.key, "name": sv.name},
            {"type": sv.type_string, "via": f"array.{member}()"},
            "observed", confidence="high",
        )
        ctx.add_edge(
            GraphEdge(
                id=ids.edge_id("WRITES", fnode_id, svnode_id, f"{member}:{node['id']}"),
                type="WRITES",
                source=fnode_id,
                target=svnode_id,
                status="observed",
                fact_ids=[write_fact.id],
            )
        )



def _emit_fact(ctx, fu, fact_type, src_ref, evid, subject, properties, status, confidence="medium") -> Fact:
    node_hash = f"{src_ref.start}:{src_ref.end}" if src_ref else "na"
    # Incorporate the full property content (not just its length) so that
    # multiple distinct facts sharing the same AST node/source span (e.g. one
    # call_argument_dataflow fact per argument of the same call) still get
    # distinct, stable ids.
    import json as _json
    props_digest = _json.dumps(properties, sort_keys=True, default=str)
    fact = Fact(
        id=ids.fact_id(fact_type, fu.file, f"{fu.ast_id}:{node_hash}:{props_digest}"),
        type=fact_type,
        status=status,
        subject=subject,
        properties=properties,
        source=src_ref,
        evidence=[evid] if evid else [],
        confidence=confidence,
        extraction_method="ast" if status == "observed" else "ast+heuristic",
    )
    return ctx.add_fact(fact)


def _emit_internal_call(ctx, fu, fnode_id, node, expr, src_ref, evid) -> None:
    decl = ctx.decl_index.get((fu.group, expr.get("referencedDeclaration")))
    callee_key = decl.get("function_key") if decl else None
    status = "observed" if callee_key else "unknown"
    fact = Fact(
        id=ids.fact_id("internal_call", fu.file, node["id"]),
        type="internal_call",
        status=status,
        subject={"caller": fu.key, "callee_name": expr.get("name")},
        properties={"callee_function": callee_key, "static_target": True},
        source=src_ref,
        evidence=[evid] if evid else [],
        confidence="high" if callee_key else "low",
        extraction_method="ast",
    )
    ctx.add_fact(fact)
    if callee_key and callee_key in ctx.function_by_key:
        target_node = function_node_id(ctx.function_by_key[callee_key])
        ctx.add_edge(
            GraphEdge(
                id=ids.edge_id("CALLS", fnode_id, target_node, str(node["id"])),
                type="CALLS",
                source=fnode_id,
                target=target_node,
                status="observed",
                properties={"call_type": "internal"},
                fact_ids=[fact.id],
            )
        )


def _emit_external_call(ctx, fu, fnode_id, node, expr, src_ref, evid, call_type) -> None:
    base_expr = expr.get("expression") or {}
    target_status = "dynamic"
    if base_expr.get("nodeType") == "Identifier":
        decl = ctx.decl_index.get((fu.group, base_expr.get("referencedDeclaration")))
        if decl and decl.get("kind") == "state_variable":
            sv = None
            # immutable state vars have a fixed address after construction
            node_obj = decl.get("node") or {}
            if node_obj.get("mutability") == "immutable":
                target_status = "static_immutable"

    decl = ctx.decl_index.get((fu.group, expr.get("referencedDeclaration")))
    target_function_key = decl.get("function_key") if decl else None

    args_repr = [_src_text(ctx, fu.file, a) for a in node.get("arguments", [])]
    fact = Fact(
        id=ids.fact_id(f"{call_type}_call" if call_type != "external" else "external_call", fu.file, node["id"]),
        type="low_level_call" if call_type in ("low_level", "delegatecall", "staticcall") else "external_call",
        status="observed",
        subject={"caller": fu.key},
        properties={
            "call_subtype": call_type,
            "member": expr.get("memberName"),
            "target_expression": _src_text(ctx, fu.file, base_expr),
            "target_status": target_status,
            "target_function": target_function_key,
            "arguments": args_repr,
        },
        source=src_ref,
        evidence=[evid] if evid else [],
        confidence="medium",
        extraction_method="ast",
    )
    ctx.add_fact(fact)

    external_node = GraphNode(
        id=ids.node_id("external_target", f"{fu.file}:{node['id']}"),
        kind="external_target",
        label=_src_text(ctx, fu.file, base_expr) or "<external>",
        properties={"target_status": target_status, "member": expr.get("memberName")},
    )
    ctx.add_node(external_node)
    edge_type = {"low_level": "CALLS", "delegatecall": "DELEGATES_TO", "staticcall": "CALLS"}.get(call_type, "CALLS")
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id(edge_type, fnode_id, external_node.id, str(node["id"])),
            type=edge_type,
            source=fnode_id,
            target=external_node.id,
            status="observed",
            properties={"call_type": call_type, "target_status": target_status},
            fact_ids=[fact.id],
        )
    )

    ctx.add_fact(
        Fact(
            id=ids.fact_id("external_call_surface", fu.file, node["id"]),
            type="external_call_surface",
            status="observed",
            subject={"function": fu.key},
            properties={
                "call_type": call_type,
                "member": expr.get("memberName"),
                "target_status": target_status,
                "target_expression": _src_text(ctx, fu.file, expr.get("expression") or {}),
            },
            source=src_ref,
            evidence=[evid] if evid else [],
            confidence="high",
            extraction_method="ast",
        )
    )


def _emit_eth_transfer(ctx, fu, fnode_id, node, expr, src_ref, evid) -> None:
    args = node.get("arguments", [])
    amount_expr = _src_text(ctx, fu.file, args[0]) if args else "unknown"
    _emit_fact(
        ctx, fu, "eth_transfer",
        src_ref, evid,
        {"function": fu.key},
        {
            "member": expr.get("memberName"),
            "target_expression": _src_text(ctx, fu.file, expr.get("expression") or {}),
            "amount_expression": amount_expr,
        },
        "observed",
        confidence="high",
    )


def _emit_creation(ctx, fu, fnode_id, node, src_ref, evid) -> None:
    new_expr = node.get("expression") or {}
    type_name = ((new_expr.get("typeName") or {}).get("typeDescriptions") or {}).get("typeString") \
        or (new_expr.get("typeName") or {}).get("name")
    fact = _emit_fact(
        ctx, fu, "contract_creation", src_ref, evid,
        {"function": fu.key}, {"target_type": type_name}, "observed", confidence="high",
    )
    target_node = GraphNode(
        id=ids.node_id("creation_target", f"{fu.file}:{node['id']}"),
        kind="creation_target",
        label=type_name or "<contract>",
        properties={},
    )
    ctx.add_node(target_node)
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id("CREATES", fnode_id, target_node.id, str(node["id"])),
            type="CREATES",
            source=fnode_id,
            target=target_node.id,
            status="observed",
            fact_ids=[fact.id],
        )
    )


_SIGNATURE_BUILTINS = {"ecrecover"}
_DIGEST_BUILTINS = {"keccak256", "sha256", "ripemd160"}


def _emit_builtin_call(ctx, fu, fnode_id, node, expr, src_ref, evid) -> None:
    name = expr.get("name")
    args = [_src_text(ctx, fu.file, a) for a in node.get("arguments", [])]
    _emit_fact(
        ctx, fu, "builtin_call", src_ref, evid,
        {"function": fu.key},
        {"builtin": name, "arguments": args},
        "observed", confidence="high",
    )
    if name in _SIGNATURE_BUILTINS:
        _emit_fact(
            ctx, fu, "signature_recovery_operation", src_ref, evid,
            {"function": fu.key},
            {"builtin": name, "arguments": args},
            "observed", confidence="high",
        )
    elif name in _DIGEST_BUILTINS:
        _emit_fact(
            ctx, fu, "digest_construction_operation", src_ref, evid,
            {"function": fu.key},
            {"builtin": name, "arguments": args},
            "observed", confidence="high",
        )


def _emit_require(ctx, fu, fnode_id, node, src_ref, evid, visible_state_vars, subject_key: str = "function") -> None:
    args = node.get("arguments", [])
    condition_text = _src_text(ctx, fu.file, args[0]) if args else ""
    message = None
    if len(args) > 1:
        message = _src_text(ctx, fu.file, args[1])
    mentions_sender = "msg.sender" in condition_text
    _emit_fact(
        ctx, fu, "require_statement", src_ref, evid,
        {subject_key: fu.key},
        {"condition": condition_text, "message": message},
        "observed", confidence="high",
    )
    if mentions_sender and args:
        referenced_state_vars = []
        for n, _p in ast_utils.walk(args[0]):
            if n.get("nodeType") == "Identifier" and n.get("referencedDeclaration") in visible_state_vars:
                referenced_state_vars.append(visible_state_vars[n["referencedDeclaration"]].key)
        _emit_fact(
            ctx, fu, "authorization_check", src_ref, evid,
            {subject_key: fu.key},
            {
                "mechanism": "require_msg_sender_comparison",
                "condition": condition_text,
                "referenced_state_variables": sorted(set(referenced_state_vars)),
            },
            "derived",
        )


def _emit_revert(ctx, fu, fnode_id, node, src_ref, evid, revert_kind, error_key=None) -> None:
    props = {"revert_kind": revert_kind}
    if error_key:
        props["error"] = error_key
    if node.get("arguments"):
        props["arguments"] = [_src_text(ctx, fu.file, a) for a in node.get("arguments", [])]
    _emit_fact(ctx, fu, "revert_site", src_ref, evid, {"function": fu.key}, props, "observed", confidence="high")


def _emit_token_operation(ctx, fu, fnode_id, node, expr, src_ref, evid) -> None:
    args = node.get("arguments", [])
    arg_texts = [_src_text(ctx, fu.file, a) for a in args]
    _emit_fact(
        ctx, fu, "asset_operation", src_ref, evid,
        {"function": fu.key},
        {
            "operation": expr.get("memberName"),
            "target_expression": _src_text(ctx, fu.file, expr.get("expression") or {}),
            "arguments": arg_texts,
            "note": "classified by function-name pattern match; token-standard conformance not verified",
        },
        "derived",
    )


def _emit_call_argument_flows(ctx, fu, fnode_id, call_node, local_scope, visible_state_vars, src_ref, evid) -> None:
    for idx, arg in enumerate(call_node.get("arguments", [])):
        root = _peel_to_root(arg)
        origin_kind = "unknown"
        origin_name = None
        status = "unknown"
        if root is not None and root.get("nodeType") == "Identifier":
            refid = root.get("referencedDeclaration")
            if refid in visible_state_vars:
                origin_kind, origin_name = "state_variable", visible_state_vars[refid].name
                status = "derived" if root is not arg else "observed"
            elif refid in local_scope:
                origin_kind, origin_name = local_scope[refid], root.get("name")
                status = "derived" if root is not arg else "observed"
            elif root.get("name") in ("msg", "block", "tx"):
                origin_kind, origin_name = "environment", root.get("name")
                status = "observed"
        elif arg.get("nodeType") == "Literal":
            origin_kind, origin_name, status = "literal", _src_text(ctx, fu.file, arg), "observed"

        _emit_fact(
            ctx, fu, "call_argument_dataflow", src_ref, evid,
            {"function": fu.key},
            {
                "argument_index": idx,
                "argument_expression": _src_text(ctx, fu.file, arg),
                "origin_kind": origin_kind,
                "origin_name": origin_name,
            },
            status,
        )


def _emit_expression_origin_chains(ctx, cu, fu, fnode_id, local_scope, visible_state_vars) -> None:
    """Conservative local def-use / expression propagation (extends
    sections 8-9). See recon/dataflow.py's module docstring for the exact
    propagation rules and where resolution deliberately stops.

    Purely additive: does not alter `call_argument_dataflow` (still
    emitted by `_emit_call_argument_flows`, one hop, unchanged) or any
    other existing fact type. Adds two new fact types:

      * `local_variable_origin` -- one fact per local variable that has a
        write site at all, carrying the full hop-by-hop chain back to its
        ultimate origin (parameter / state variable / environment /
        literal), or an explicit `unknown` status with a `reason` when
        propagation could not resolve it (multiple assignments,
        branch-guarded assignment, or an unsupported expression shape such
        as a call result or mapping/array read).
      * `call_argument_origin_chain` -- the same kind of full chain for
        each call argument expression itself, which may pass through zero
        or more local variables before reaching the call site.
    """
    local_defs = fu.local_defs
    ambiguous = getattr(fu, "local_defs_ambiguous", {})
    local_names: dict[int, str] = {}
    for vd in ast_utils.find_all(fu.body_node, "VariableDeclaration"):
        local_names.setdefault(vd["id"], vd.get("name"))
    visible_state_var_names = {refid: sv.name for refid, sv in visible_state_vars.items()}

    def _emit_origin_fact(fact_type, subject, src_ref, evid, extra_subject, name, result, unresolved_extra=None):
        chain = [h.to_dict() for h in result.chain]
        props = {
            **extra_subject,
            "root_kind": result.kind,
            "root_name": result.name,
            "chain": chain,
            "hop_count": len(chain),
        }
        if result.kind == "unresolved" and not chain:
            props["reason"] = (unresolved_extra or {}).get("reason", "unsupported_expression_shape")
            if "expression" in (unresolved_extra or {}):
                props["expression"] = unresolved_extra["expression"]
        confidence = "high" if result.status in ("observed", "derived") else "low"
        _emit_fact(ctx, fu, fact_type, src_ref, evid, subject, props, result.status, confidence=confidence)

    # --- local_variable_origin: one per local var with a known write site ---
    for vid, rhs_node in local_defs.items():
        name = local_names.get(vid)
        result = dataflow.resolve_origin(rhs_node, local_defs, local_scope, visible_state_var_names)
        src_ref = ctx.source_ref(fu.file, rhs_node)
        evid = ctx.make_evidence(fu.file, rhs_node)
        _emit_origin_fact(
            "local_variable_origin", {"function": fu.key, "variable": name}, src_ref, evid,
            {"variable_name": name}, name, result,
            unresolved_extra={"expression": _src_text(ctx, fu.file, rhs_node)},
        )

    for vid, (reason, site_node) in ambiguous.items():
        name = local_names.get(vid)
        src_ref = ctx.source_ref(fu.file, site_node)
        evid = ctx.make_evidence(fu.file, site_node)
        _emit_fact(
            ctx, fu, "local_variable_origin", src_ref, evid,
            {"function": fu.key, "variable": name},
            {"variable_name": name, "reason": reason},
            "unknown", confidence="low",
        )

    # --- call_argument_origin_chain: one per call argument ---
    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "FunctionCall":
            continue
        if node.get("kind") in ("typeConversion", "structConstructorCall"):
            continue
        src_ref = ctx.source_ref(fu.file, node)
        evid = ctx.make_evidence(fu.file, node)
        for idx, arg in enumerate(node.get("arguments", [])):
            result = dataflow.resolve_origin(arg, local_defs, local_scope, visible_state_var_names)
            _emit_origin_fact(
                "call_argument_origin_chain", {"function": fu.key}, src_ref, evid,
                {"argument_index": idx, "argument_expression": _src_text(ctx, fu.file, arg)},
                None, result,
                unresolved_extra={"expression": _src_text(ctx, fu.file, arg)},
            )


_CONTROL_NODE_TYPES = {
    "IfStatement": "if_statement",
    "ForStatement": "loop",
    "WhileStatement": "loop",
    "DoWhileStatement": "loop",
    "TryStatement": "try_catch",
    "UncheckedBlock": "unchecked_block",
    "Conditional": "ternary_expression",
}


def _emit_control_flow(ctx, cu, fu, fnode_id) -> None:
    for node, _parent in ast_utils.walk(fu.body_node):
        ntype = node.get("nodeType")
        if ntype not in _CONTROL_NODE_TYPES:
            continue
        src_ref = ctx.source_ref(fu.file, node)
        evid = ctx.make_evidence(fu.file, node)
        _emit_fact(
            ctx, fu, "control_flow_structure", src_ref, evid,
            {"function": fu.key},
            {"construct": _CONTROL_NODE_TYPES[ntype]},
            "observed", confidence="high",
        )


def _emit_events_errors_usage(ctx, cu, fu, fnode_id) -> None:
    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "EmitStatement":
            continue
        call = node.get("eventCall") or {}
        expr = call.get("expression") or {}
        decl = ctx.decl_index.get((fu.group, expr.get("referencedDeclaration")))
        event_key = decl.get("event_key") if decl else None
        src_ref = ctx.source_ref(fu.file, node)
        evid = ctx.make_evidence(fu.file, node)
        fact = _emit_fact(
            ctx, fu, "event_emission", src_ref, evid,
            {"function": fu.key},
            {
                "event": event_key,
                "event_name": expr.get("name"),
                "arguments": [_src_text(ctx, fu.file, a) for a in call.get("arguments", [])],
            },
            "observed" if event_key else "unknown",
            confidence="high" if event_key else "low",
        )
        if event_key and event_key in ctx.event_by_key:
            from .inventory_facts import event_node_id
            target_node = event_node_id(ctx.event_by_key[event_key])
            ctx.add_edge(
                GraphEdge(
                    id=ids.edge_id("EMITS", fnode_id, target_node, str(node["id"])),
                    type="EMITS",
                    source=fnode_id,
                    target=target_node,
                    status="observed",
                    fact_ids=[fact.id],
                )
            )


_SPECIAL_NODE_TYPES = {
    "InlineAssembly": "assembly_block",
}


def _enclosing_use(node: dict, parent: Optional[dict]) -> Optional[str]:
    """Cheap, structural (non-semantic) classification of what immediately
    consumes an expression's result.
    """
    if parent is None:
        return None
    pt = parent.get("nodeType")
    if pt == "Return":
        return "return_value"
    if pt == "Assignment" and parent.get("rightHandSide") is node:
        return "assignment_rhs"
    if pt == "VariableDeclarationStatement":
        return "variable_initializer"
    if pt == "FunctionCall":
        return "call_argument"
    if pt == "UnaryOperation":
        return f"unary_op:{parent.get('operator')}"
    if pt == "BinaryOperation":
        return f"binary_op:{parent.get('operator')}"
    if pt == "TupleExpression":
        return "tuple_component"
    if pt == "IndexAccess":
        return "index_access_base" if parent.get("baseExpression") is node else "index_access_index"
    if pt == "MemberAccess":
        return "member_access_base"
    return pt.lower() if pt else None


def _emit_arithmetic_operations(ctx, cu, fu, fnode_id) -> None:
    """Structural precursor for Class C (rounding/truncation/precision)
    review: records every division (Solidity integer division always
    truncates towards zero) with its operands and immediate consumer. This
    is deliberately NOT a rounding-bug detector — recon does not know
    whether a given truncation matters; it only makes every division site
    and what directly consumes its result inspectable without re-parsing
    the AST.

    Additionally emits generic `arithmetic_operation` facts for all binary
    operations (/, *, -, +, %, etc.) to provide broader arithmetic context
    for downstream precision/overflow analysis. This is purely structural;
    no vulnerability claims are made.
    """
    for node, parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") != "BinaryOperation":
            continue
        operator = node.get("operator")
        src_ref = ctx.source_ref(fu.file, node)
        evid = ctx.make_evidence(fu.file, node)
        left_text = _src_text(ctx, fu.file, node.get("leftExpression") or {})
        right_text = _src_text(ctx, fu.file, node.get("rightExpression") or {})
        result_type = _type_string(node)
        consumer = _enclosing_use(node, parent)

        # Generic arithmetic operation fact (ALL binary ops)
        _emit_fact(
            ctx, fu, "arithmetic_operation", src_ref, evid,
            {"function": fu.key},
            {
                "operator": operator,
                "left_operand": left_text,
                "right_operand": right_text,
                "result_type": result_type,
                "immediate_consumer": consumer,
            },
            "observed", confidence="high",
        )

        # Specific division operation fact (keeps backward compatibility)
        if operator == "/":
            _emit_fact(
                ctx, fu, "division_operation", src_ref, evid,
                {"function": fu.key},
                {
                    "left_operand": left_text,
                    "right_operand": right_text,
                    "result_type": result_type,
                    "immediate_consumer": consumer,
                    "note": (
                        "Solidity integer division truncates towards zero; recon does not "
                        "evaluate whether this truncation is significant for this value"
                    ),
                },
                "observed", confidence="high",
            )
        
        # Bit-shift operation fact (for arithmetic bound violation detection)
        if operator in ("<<", ">>", ">>>"):
            right_expr = node.get("rightExpression") or {}
            shift_source = _classify_operand_source(right_expr)
            _emit_fact(
                ctx, fu, "bitshift_operation", src_ref, evid,
                {"function": fu.key},
                {
                    "operator": operator,
                    "operand": left_text,
                    "shift_amount": right_text,
                    "shift_amount_source": shift_source,
                    "result_type": result_type,
                    "immediate_consumer": consumer,
                    "note": (
                        "Bit-shift operations can cause panic if shift amount exceeds type bounds (255 for uint256)"
                    ),
                },
                "observed", confidence="high",
            )


def _classify_operand_source(node: dict) -> str:
    """Classify the source of an operand (constant, parameter, state_var, computed)."""
    if node.get("nodeType") == "Literal":
        return "constant"
    if node.get("nodeType") == "Identifier":
        # Could be parameter, local var, or state var - we mark as parameter-like
        return "parameter"
    if node.get("nodeType") == "BinaryOperation":
        return "computed"
    # Default for complex expressions
    return "expression"


def _emit_loop_complexity(ctx, cu, fu, fnode_id) -> None:
    """Extract loop nesting depth and iteration bound dependencies for gas DoS detection.
    
    Records structural loop patterns that could lead to excessive gas consumption:
    - Nested loops (quadratic or worse complexity)
    - Loops with parameter-dependent bounds (unbounded iteration)
    
    This is purely structural observation; no gas consumption claims are made.
    """
    # First pass: collect all loops with their AST nodes
    loops = []
    for node, parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") in ("ForStatement", "WhileStatement", "DoWhileStatement"):
            loops.append((node, parent))
    
    if not loops:
        return
    
    # Build parent map for nesting calculation
    parent_map = {}
    for node, parent in ast_utils.walk(fu.body_node):
        if parent is not None and "id" in node and "id" in parent:
            parent_map[node["id"]] = parent
    
    # Second pass: analyze each loop
    for loop_node, parent in loops:
        # Calculate nesting depth
        depth = 1
        current = parent_map.get(loop_node.get("id"))
        while current:
            if current.get("nodeType") in ("ForStatement", "WhileStatement", "DoWhileStatement"):
                depth += 1
            current = parent_map.get(current.get("id"))
        
        # Extract iteration bound information
        bound_type = "unbounded"
        bound_expr = ""
        
        if loop_node.get("nodeType") == "ForStatement":
            condition = loop_node.get("condition")
            if condition:
                bound_expr = _src_text(ctx, fu.file, condition)
                # Check if condition references parameters or state
                if condition.get("nodeType") == "BinaryOperation":
                    right = condition.get("rightExpression") or {}
                    if right.get("nodeType") == "Identifier":
                        bound_type = "parameter"  # Could be parameter or state var
                    elif right.get("nodeType") == "Literal":
                        bound_type = "constant"
                    else:
                        bound_type = "expression"
        
        src_ref = ctx.source_ref(fu.file, loop_node)
        evid = ctx.make_evidence(fu.file, loop_node)
        
        _emit_fact(
            ctx, fu, "loop_nesting_depth", src_ref, evid,
            {"function": fu.key},
            {
                "nesting_level": depth,
                "loop_type": loop_node.get("nodeType"),
                "bound_dependency": bound_type,
                "bound_expression": bound_expr,
            },
            "observed", confidence="high",
        )
        
        # Emit derived complexity indicator for high-risk patterns
        if depth >= 2 or bound_type in ("parameter", "expression"):
            _emit_fact(
                ctx, fu, "computational_complexity_indicator", src_ref, evid,
                {"function": fu.key},
                {
                    "pattern": "nested_loop" if depth >= 2 else "parameter_dependent_iteration",
                    "nesting_level": depth,
                    "bound_type": bound_type,
                    "risk_category": "gas_dos_potential",
                },
                "derived", confidence="medium",
            )


def _emit_randomness_patterns(ctx, cu, fu, fnode_id) -> None:
    """Extract randomness source usage patterns for statistical exploit detection.
    
    Records usage of predictable on-chain randomness sources:
    - block.timestamp, block.number, block.difficulty, block.prevrandao
    - blockhash()
    
    Multiple uses in same function may indicate seed reuse vulnerability.
    This is structural observation; no randomness quality claims are made.
    """
    randomness_uses = []
    
    for node, parent in ast_utils.walk(fu.body_node):
        # Check for block.* randomness sources
        if node.get("nodeType") == "MemberAccess":
            base = node.get("expression") or {}
            if base.get("nodeType") == "Identifier" and base.get("name") == "block":
                member = node.get("memberName")
                if member in ("timestamp", "number", "difficulty", "prevrandao"):
                    src_ref = ctx.source_ref(fu.file, node)
                    evid = ctx.make_evidence(fu.file, node)
                    source_expr = f"block.{member}"
                    consumer = _enclosing_use(node, parent)
                    
                    _emit_fact(
                        ctx, fu, "randomness_source_usage", src_ref, evid,
                        {"function": fu.key},
                        {
                            "source": source_expr,
                            "source_type": "block_environment",
                            "immediate_consumer": consumer,
                            "predictability": "high",
                            "note": "On-chain randomness sources are manipulable by miners/validators",
                        },
                        "observed", confidence="high",
                    )
                    randomness_uses.append(node)
        
        # Check for blockhash() calls
        if node.get("nodeType") == "FunctionCall":
            expr = node.get("expression") or {}
            if expr.get("nodeType") == "Identifier" and expr.get("name") == "blockhash":
                src_ref = ctx.source_ref(fu.file, node)
                evid = ctx.make_evidence(fu.file, node)
                consumer = _enclosing_use(node, parent)
                
                _emit_fact(
                    ctx, fu, "randomness_source_usage", src_ref, evid,
                    {"function": fu.key},
                    {
                        "source": "blockhash",
                        "source_type": "blockhash_function",
                        "immediate_consumer": consumer,
                        "predictability": "high",
                        "note": "blockhash is predictable and has limited availability (last 256 blocks)",
                    },
                    "observed", confidence="high",
                )
                randomness_uses.append(node)
    
    # If multiple randomness uses detected, emit reuse indicator
    if len(randomness_uses) > 1:
        # Use first occurrence for provenance
        first_node = randomness_uses[0]
        src_ref = ctx.source_ref(fu.file, first_node)
        evid = ctx.make_evidence(fu.file, first_node)
        
        _emit_fact(
            ctx, fu, "repeated_randomness_consumer", src_ref, evid,
            {"function": fu.key},
            {
                "usage_count": len(randomness_uses),
                "pattern": "multiple_draws_same_function",
                "risk_category": "seed_reuse_potential",
            },
            "derived", confidence="medium",
        )


def _emit_decode_encode(
    ctx, fu, fnode_id, node, expr, src_ref, evid,
) -> None:
    """Emit `decode_operation` / `encode_operation` facts for abi.decode /
    abi.encode* / msg.data.

    Covers the external-data → decoded-internal-value boundary needed by
    Class B reasoning. Purely structural: records what is decoded/encoded
    and its immediate consumer. No semantic validation is performed.

    BUGFIX: previously both decode AND encode operations were emitted under
    the single fact type `"decode_operation"`, distinguished only by a
    `properties.kind` field ("decode" vs "encode"). A consumer filtering on
    `type == "decode_operation"` — the reasonable, literal reading of that
    type name — would silently also receive `abi.encodePacked`/`abi.encode`/
    etc. facts that are not decode operations at all. This produced a real,
    observed misattribution (an external verification pass reported "4
    decode_operation facts, all abi.decode" when only 2 of the 4 were
    actually decode calls; the other 2 were encodePacked calls in unrelated
    files). The fact TYPE now matches its contents exactly: `decode_operation`
    is abi.decode only, `encode_operation` covers the encode family. This is
    an additive-shape rename (properties unchanged), not a schema redesign.
    """
    if expr.get("nodeType") != "MemberAccess":
        return
    member = expr.get("memberName", "")
    obj = expr.get("expression") or {}
    if obj.get("nodeType") == "Identifier" and obj.get("name") == "abi":
        if member not in ("decode", "encode", "encodePacked", "encodeWithSignature", "encodeWithSelector"):
            return
        is_decode = member == "decode"
        fact_type = "decode_operation" if is_decode else "encode_operation"
        args = node.get("arguments", [])
        data_source = _src_text(ctx, fu.file, args[0]) if args else ""
        types_str = ""
        if is_decode and len(args) > 1:
            types_str = _src_text(ctx, fu.file, args[1])
        consumer = _enclosing_use(node, None)
        _emit_fact(
            ctx, fu, fact_type, src_ref, evid,
            {"function": fu.key},
            {
                "operation": member,
                "kind": "decode" if is_decode else "encode",
                "data_source": data_source,
                "types": types_str,
                "immediate_consumer": consumer,
                "note": "structural extraction only" if is_decode else "encoding preparation",
            },
            "observed", confidence="high",
        )


def _emit_special_features(ctx, cu, fu, fnode_id) -> None:
    for node, _parent in ast_utils.walk(fu.body_node):
        ntype = node.get("nodeType")
        if ntype in _SPECIAL_NODE_TYPES:
            src_ref = ctx.source_ref(fu.file, node)
            evid = ctx.make_evidence(fu.file, node)
            _emit_fact(
                ctx, fu, "special_evm_feature", src_ref, evid,
                {"function": fu.key},
                {"feature": _SPECIAL_NODE_TYPES[ntype]},
                "observed", confidence="high",
            )
        if ntype == "FunctionCall":
            expr = node.get("expression") or {}
            if expr.get("nodeType") == "Identifier" and expr.get("name") in ("selfdestruct", "suicide"):
                pass  # already recorded in _emit_calls
        if ntype == "MemberAccess" and node.get("memberName") in ("code", "codehash"):
            base_type = _type_string(node.get("expression") or {})
            if _is_address_type(base_type):
                src_ref = ctx.source_ref(fu.file, node)
                evid = ctx.make_evidence(fu.file, node)
                _emit_fact(
                    ctx, fu, "special_evm_feature", src_ref, evid,
                    {"function": fu.key},
                    {"feature": f"address.{node.get('memberName')}"},
                    "observed", confidence="high",
                )

    for node, _parent in ast_utils.walk(fu.body_node):
        if node.get("nodeType") == "FunctionCallOptions":
            # value:/gas:/salt: options on a call, e.g. foo{value: x, salt: y}(...)
            names = node.get("names") or []
            if "salt" in names:
                src_ref = ctx.source_ref(fu.file, node)
                evid = ctx.make_evidence(fu.file, node)
                _emit_fact(
                    ctx, fu, "special_evm_feature", src_ref, evid,
                    {"function": fu.key}, {"feature": "create2_salt_option"}, "observed", confidence="high",
                )


def analyze_modifier(ctx: ProjectContext, cu: ContractUnit, mu) -> None:
    """Modifier bodies are analyzed for the same authorization/state-access
    signals a function body would carry — a `require(msg.sender == owner)`
    written inside `modifier onlyOwner()` is exactly as much an
    authorization_check as one written inline in a function, and a function
    that merely `uses` such a modifier inherits that protection.

    Deliberately scoped down from the full analyze_function() pass (no call
    graph / control-flow / capability extraction for modifiers): the value
    needed here is specifically "does this modifier gate on an authorization
    condition", not a full expression analysis of every modifier body. This
    keeps the change additive and avoids re-deriving machinery
    (recon/relationships.py::derive_role_privilege_facts) that already
    consumes function-level authorization_check facts and simply needs the
    modifier-level equivalent to exist.
    """
    if mu.body_node is None:
        return

    visible_state_vars = build_visible_state_vars(ctx, cu)

    # state reads (writes inside modifiers are rare and are intentionally
    # out of scope for this pass — see module docstring).
    for node, _parent in ast_utils.walk(mu.body_node):
        if node.get("nodeType") != "Identifier":
            continue
        sv = visible_state_vars.get(node.get("referencedDeclaration"))
        if sv is None:
            continue
        src_ref = ctx.source_ref(mu.file, node)
        evid = ctx.make_evidence(mu.file, node)
        _emit_fact(
            ctx, mu, "state_read", src_ref, evid,
            {"modifier": mu.key, "state_variable": sv.key, "name": sv.name},
            {"type": sv.type_string},
            "observed", confidence="high",
        )

    # require()/authorization detection, reusing the exact same logic a
    # function body would go through.
    for node, _parent in ast_utils.walk(mu.body_node):
        if node.get("nodeType") != "FunctionCall":
            continue
        expr = node.get("expression") or {}
        if expr.get("nodeType") == "Identifier" and expr.get("name") == "require":
            src_ref = ctx.source_ref(mu.file, node)
            evid = ctx.make_evidence(mu.file, node)
            _emit_require(ctx, mu, None, node, src_ref, evid, visible_state_vars, subject_key="modifier")
