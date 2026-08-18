"""Fact + graph-node emission for the static contract/function/state inventory.

This module answers: "what declarations exist, and how do they relate
structurally (inherits / implements / declares)?" It performs no expression-
level analysis (that is call_analysis.py / state_analysis.py / etc.).
"""

from __future__ import annotations

from . import ids
from .context import ProjectContext
from .inventory import ContractUnit, canonical_signature
from .models import Fact, GraphEdge, GraphNode

_PROXY_STATE_NAMES = {"implementation", "_implementation", "impl"}
_UPGRADE_NAMES = {"upgradeto", "upgradeandcall", "setimplementation"}
_INITIALIZER_NAMES = {"initialize", "initializer"}
_INITIALIZED_STATE_NAMES = {"initialized", "_initialized", "isInitialized"}


def contract_node_id(cu: ContractUnit) -> str:
    return ids.node_id("contract", cu.key)


def function_node_id(fu) -> str:
    return ids.node_id("function", fu.key)


def state_var_node_id(sv) -> str:
    return ids.node_id("state_var", sv.key)


def event_node_id(ev) -> str:
    return ids.node_id("event", ev.key)


def error_node_id(er) -> str:
    return ids.node_id("error", er.key)


def modifier_node_id(mu) -> str:
    return ids.node_id("modifier", mu.key)


def resolve_bases(ctx: ProjectContext) -> None:
    """Second pass: resolve each contract's textual/AST-id base references to
    concrete contract_keys, now that every file/group has been indexed.
    """
    # index by (group, ast_id) -> contract_key, already partially available via
    # ctx.decl_index, but that is per-file; build one global lookup here.
    by_group_id: dict[tuple[str, int], str] = {}
    for cu in ctx.contracts.values():
        by_group_id[(cu.group, cu.ast_id)] = cu.key

    for cu in ctx.contracts.values():
        resolved = []
        for raw_id in cu.base_keys:
            try:
                rid = int(raw_id)
            except ValueError:
                continue
            key = by_group_id.get((cu.group, rid))
            if key:
                resolved.append(key)
        cu.base_keys = resolved


def emit_inventory_facts(ctx: ProjectContext) -> None:
    for cu in sorted(ctx.contracts.values(), key=lambda c: c.key):
        _emit_contract(ctx, cu)


def _emit_contract(ctx: ProjectContext, cu: ContractUnit) -> None:
    cnode_id = contract_node_id(cu)
    ctx.add_node(
        GraphNode(
            id=cnode_id,
            kind="contract",
            label=cu.name,
            properties={
                "contract_kind": cu.kind,
                "is_abstract": cu.is_abstract,
                "file": cu.file,
            },
        )
    )

    src_ref = ctx.source_ref(cu.file, cu.node)
    ev = ctx.make_evidence(cu.file, cu.node)
    fact = Fact(
        id=ids.fact_id("contract_exists", cu.file, cu.ast_id),
        type="contract_exists",
        status="observed",
        subject={"contract": cu.key, "name": cu.name},
        properties={"kind": cu.kind, "is_abstract": cu.is_abstract},
        source=src_ref,
        evidence=[ev] if ev else [],
        confidence="high",
        extraction_method="ast",
    )
    ctx.add_fact(fact)

    # Inheritance / interface implementation
    for base_key, base_name in zip(
        cu.base_keys + [None] * (len(cu.base_names) - len(cu.base_keys)), cu.base_names
    ):
        status = "observed" if base_key else "unknown"
        base_kind = ctx.contracts[base_key].kind if base_key and base_key in ctx.contracts else None
        fact_type = "interface_implementation" if base_kind == "interface" else "inheritance"
        f = Fact(
            id=ids.fact_id(fact_type, cu.file, f"{cu.ast_id}:{base_name}"),
            type=fact_type,
            status=status,
            subject={"contract": cu.key, "base_name": base_name, "base_contract": base_key},
            properties={"resolved": bool(base_key)},
            source=src_ref,
            evidence=[ev] if ev else [],
            confidence="high" if base_key else "low",
            extraction_method="ast",
        )
        ctx.add_fact(f)
        if base_key and base_key in ctx.contracts:
            edge_type = "IMPLEMENTS" if base_kind == "interface" else "INHERITS"
            target_node = contract_node_id(ctx.contracts[base_key])
            ctx.add_edge(
                GraphEdge(
                    id=ids.edge_id(edge_type, cnode_id, target_node),
                    type=edge_type,
                    source=cnode_id,
                    target=target_node,
                    status="observed",
                    fact_ids=[f.id],
                )
            )

    for using in cu.using_for:
        lib_name = ((using.get("libraryName") or {}).get("name"))
        if not lib_name:
            continue
        f = Fact(
            id=ids.fact_id("library_usage", cu.file, using.get("id")),
            type="library_usage",
            status="observed",
            subject={"contract": cu.key, "library_name": lib_name},
            properties={"type": (using.get("typeName") or {}).get("typeString")},
            source=ctx.source_ref(cu.file, using),
            evidence=[ctx.make_evidence(cu.file, using) or ""],
            confidence="high",
            extraction_method="ast",
        )
        ctx.add_fact(f)

    for sv in cu.state_vars:
        _emit_state_var(ctx, cu, sv, cnode_id)
    for ev_unit in cu.events:
        _emit_event(ctx, cu, ev_unit, cnode_id)
    for er_unit in cu.errors:
        _emit_error(ctx, cu, er_unit, cnode_id)
    for mu in cu.modifiers:
        _emit_modifier(ctx, cu, mu, cnode_id)
    for fu in cu.functions:
        _emit_function(ctx, cu, fu, cnode_id)
    _emit_proxy_upgradeability_facts(ctx, cu, cnode_id, src_ref, ev)


def _emit_state_var(ctx, cu, sv, cnode_id) -> None:
    node_id = state_var_node_id(sv)
    ctx.add_node(
        GraphNode(
            id=node_id,
            kind="state_variable",
            label=sv.name,
            properties={"type": sv.type_string, "visibility": sv.visibility, "mutability": sv.mutability},
        )
    )
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id("DECLARES", cnode_id, node_id),
            type="DECLARES",
            source=cnode_id,
            target=node_id,
            status="observed",
        )
    )
    ev = ctx.make_evidence(sv.file, sv.node)
    ctx.add_fact(
        Fact(
            id=ids.fact_id("state_variable", sv.file, sv.ast_id),
            type="state_variable",
            status="observed",
            subject={"contract": cu.key, "state_variable": sv.key, "name": sv.name},
            properties={"type": sv.type_string, "visibility": sv.visibility, "mutability": sv.mutability},
            source=ctx.source_ref(sv.file, sv.node),
            evidence=[ev] if ev else [],
            confidence="high",
            extraction_method="ast",
        )
    )


def _emit_event(ctx, cu, ev_unit, cnode_id) -> None:
    node_id = event_node_id(ev_unit)
    ctx.add_node(
        GraphNode(
            id=node_id,
            kind="event",
            label=ev_unit.name,
            properties={"parameters": [p.type_string for p in ev_unit.parameters]},
        )
    )
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id("DECLARES", cnode_id, node_id),
            type="DECLARES",
            source=cnode_id,
            target=node_id,
            status="observed",
        )
    )
    ev_evid = ctx.make_evidence(ev_unit.file, ev_unit.node)
    ctx.add_fact(
        Fact(
            id=ids.fact_id("event_definition", ev_unit.file, ev_unit.ast_id),
            type="event_definition",
            status="observed",
            subject={"contract": cu.key, "event": ev_unit.key, "name": ev_unit.name},
            properties={
                "parameters": [
                    {"name": p.name, "type": p.type_string} for p in ev_unit.parameters
                ]
            },
            source=ctx.source_ref(ev_unit.file, ev_unit.node),
            evidence=[ev_evid] if ev_evid else [],
            confidence="high",
            extraction_method="ast",
        )
    )


def _emit_error(ctx, cu, er_unit, cnode_id) -> None:
    node_id = error_node_id(er_unit)
    ctx.add_node(
        GraphNode(
            id=node_id,
            kind="error",
            label=er_unit.name,
            properties={"parameters": [p.type_string for p in er_unit.parameters]},
        )
    )
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id("DECLARES", cnode_id, node_id),
            type="DECLARES",
            source=cnode_id,
            target=node_id,
            status="observed",
        )
    )
    er_evid = ctx.make_evidence(er_unit.file, er_unit.node)
    ctx.add_fact(
        Fact(
            id=ids.fact_id("error_definition", er_unit.file, er_unit.ast_id),
            type="error_definition",
            status="observed",
            subject={"contract": cu.key, "error": er_unit.key, "name": er_unit.name},
            properties={
                "parameters": [
                    {"name": p.name, "type": p.type_string} for p in er_unit.parameters
                ]
            },
            source=ctx.source_ref(er_unit.file, er_unit.node),
            evidence=[er_evid] if er_evid else [],
            confidence="high",
            extraction_method="ast",
        )
    )


def _emit_modifier(ctx, cu, mu, cnode_id) -> None:
    node_id = modifier_node_id(mu)
    ctx.add_node(
        GraphNode(
            id=node_id,
            kind="modifier",
            label=mu.name,
            properties={"parameters": [p.type_string for p in mu.parameters]},
        )
    )
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id("DECLARES", cnode_id, node_id),
            type="DECLARES",
            source=cnode_id,
            target=node_id,
            status="observed",
        )
    )
    evid = ctx.make_evidence(mu.file, mu.node)
    ctx.add_fact(
        Fact(
            id=ids.fact_id("modifier_definition", mu.file, mu.ast_id),
            type="modifier_definition",
            status="observed",
            subject={"contract": cu.key, "modifier": mu.key, "name": mu.name},
            properties={
                "parameters": [{"name": p.name, "type": p.type_string} for p in mu.parameters],
                "has_body": mu.body_node is not None,
            },
            source=ctx.source_ref(mu.file, mu.node),
            evidence=[evid] if evid else [],
            confidence="high",
            extraction_method="ast",
        )
    )


def _emit_proxy_upgradeability_facts(ctx, cu, cnode_id, src_ref, ev) -> None:
    impl_vars = [
        sv for sv in cu.state_vars
        if (sv.name or "").lower() in _PROXY_STATE_NAMES and "address" in (sv.type_string or "").lower()
    ]
    upgrade_functions = [
        fu for fu in cu.functions
        if (fu.name or "").lower() in _UPGRADE_NAMES
    ]
    initializer_functions = [
        fu for fu in cu.functions
        if (fu.name or "").lower() in _INITIALIZER_NAMES
    ]
    initialized_state_vars = [
        sv for sv in cu.state_vars
        if (sv.name or "") in _INITIALIZED_STATE_NAMES
    ]
    fallback_functions = [
        fu for fu in cu.functions
        if fu.kind in ("fallback", "receive") or (fu.name or "").lower() in ("fallback", "receive")
    ]
    delegatecall_functions = []

    proxy_like = bool(impl_vars and (upgrade_functions or fallback_functions))
    if proxy_like:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("proxy_like_contract", cu.file, f"{cu.ast_id}:proxy_like"),
                type="proxy_like_contract",
                status="observed",
                subject={"contract": cu.key, "name": cu.name},
                properties={
                    "implementation_slots": [sv.key for sv in impl_vars],
                    "upgrade_functions": [fu.key for fu in upgrade_functions],
                    "fallback_functions": [fu.key for fu in fallback_functions],
                    "delegatecall_functions": [fu.key for fu in delegatecall_functions],
                    "initializer_functions": [fu.key for fu in initializer_functions],
                    "initialized_state_variables": [sv.key for sv in initialized_state_vars],
                },
                source=src_ref,
                evidence=[ev] if ev else [],
                confidence="medium",
                extraction_method="ast+heuristic",
            )
        )

    for sv in impl_vars:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("implementation_slot", sv.file, sv.ast_id),
                type="implementation_slot",
                status="observed",
                subject={"contract": cu.key, "state_variable": sv.key, "name": sv.name},
                properties={"type": sv.type_string},
                source=ctx.source_ref(sv.file, sv.node),
                evidence=[ctx.make_evidence(sv.file, sv.node)] if ctx.make_evidence(sv.file, sv.node) else [],
                confidence="high",
                extraction_method="ast",
            )
        )

    for fu in upgrade_functions:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("upgrade_function", fu.file, fu.ast_id),
                type="upgrade_function",
                status="observed",
                subject={"contract": cu.key, "function": fu.key, "name": fu.name},
                properties={"signature": canonical_signature(fu)},
                source=ctx.source_ref(fu.file, fu.node),
                evidence=[ctx.make_evidence(fu.file, fu.node)] if ctx.make_evidence(fu.file, fu.node) else [],
                confidence="high",
                extraction_method="ast",
            )
        )

    for fu in initializer_functions:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("initializer_function", fu.file, fu.ast_id),
                type="initializer_function",
                status="observed",
                subject={"contract": cu.key, "function": fu.key, "name": fu.name},
                properties={"signature": canonical_signature(fu)},
                source=ctx.source_ref(fu.file, fu.node),
                evidence=[ctx.make_evidence(fu.file, fu.node)] if ctx.make_evidence(fu.file, fu.node) else [],
                confidence="high",
                extraction_method="ast",
            )
        )

    for fu in [f for f in cu.functions if f.kind == "constructor"]:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("constructor_function", fu.file, fu.ast_id),
                type="constructor_function",
                status="observed",
                subject={"contract": cu.key, "function": fu.key, "name": fu.name},
                properties={"signature": canonical_signature(fu)},
                source=ctx.source_ref(fu.file, fu.node),
                evidence=[ctx.make_evidence(fu.file, fu.node)] if ctx.make_evidence(fu.file, fu.node) else [],
                confidence="high",
                extraction_method="ast",
            )
        )





def _emit_function(ctx, cu, fu, cnode_id) -> None:
    node_id = function_node_id(fu)
    sig = canonical_signature(fu)
    ctx.add_node(
        GraphNode(
            id=node_id,
            kind="function",
            label=fu.name,
            properties={
                "kind": fu.kind,
                "visibility": fu.visibility,
                "state_mutability": fu.state_mutability,
                "signature": sig,
            },
        )
    )
    ctx.add_edge(
        GraphEdge(
            id=ids.edge_id("DECLARES", cnode_id, node_id),
            type="DECLARES",
            source=cnode_id,
            target=node_id,
            status="observed",
        )
    )
    src_ref = ctx.source_ref(fu.file, fu.node)
    ev = ctx.make_evidence(fu.file, fu.node)

    ctx.add_fact(
        Fact(
            id=ids.fact_id("function_exists", fu.file, fu.ast_id),
            type="function_exists",
            status="observed",
            subject={"contract": cu.key, "function": fu.key, "name": fu.name},
            properties={
                "kind": fu.kind,
                "signature": sig,
                "is_virtual": fu.is_virtual,
                "overrides_base": fu.overrides_base,
                "has_body": fu.body_node is not None,
            },
            source=src_ref,
            evidence=[ev] if ev else [],
            confidence="high",
            extraction_method="ast",
        )
    )
    ctx.add_fact(
        Fact(
            id=ids.fact_id("function_visibility", fu.file, fu.ast_id),
            type="function_visibility",
            status="observed",
            subject={"function": fu.key},
            properties={"visibility": fu.visibility},
            source=src_ref,
            evidence=[ev] if ev else [],
            confidence="high",
            extraction_method="ast",
        )
    )
    ctx.add_fact(
        Fact(
            id=ids.fact_id("function_mutability", fu.file, fu.ast_id),
            type="function_mutability",
            status="observed",
            subject={"function": fu.key},
            properties={"state_mutability": fu.state_mutability},
            source=src_ref,
            evidence=[ev] if ev else [],
            confidence="high",
            extraction_method="ast",
        )
    )
    for p in fu.parameters:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("function_parameter", fu.file, p.ast_id),
                type="function_parameter",
                status="observed",
                subject={"function": fu.key, "parameter": p.name or f"#{p.ast_id}"},
                properties={"type": p.type_string},
                source=src_ref,
                evidence=[ev] if ev else [],
                confidence="high",
                extraction_method="ast",
            )
        )
    for r in fu.returns:
        ctx.add_fact(
            Fact(
                id=ids.fact_id("function_return", fu.file, r.ast_id),
                type="function_return",
                status="observed",
                subject={"function": fu.key, "return": r.name or f"#{r.ast_id}"},
                properties={"type": r.type_string},
                source=src_ref,
                evidence=[ev] if ev else [],
                confidence="high",
                extraction_method="ast",
            )
        )
    for m, ref_id in zip(fu.modifiers, fu.modifier_ref_ids):
        decl = ctx.decl_index.get((fu.group, ref_id)) if ref_id is not None else None
        modifier_key = decl.get("modifier_key") if decl and decl.get("kind") == "modifier" else None
        f = Fact(
            id=ids.fact_id("modifier_usage", fu.file, f"{fu.ast_id}:{m}"),
            type="modifier_usage",
            status="observed" if modifier_key else "partial",
            subject={"function": fu.key, "modifier_name": m, "modifier": modifier_key},
            properties={},
            source=src_ref,
            evidence=[ev] if ev else [],
            confidence="high" if modifier_key else "medium",
            extraction_method="ast",
        )
        ctx.add_fact(f)
        if modifier_key and modifier_key in ctx.modifier_by_key:
            target_node = modifier_node_id(ctx.modifier_by_key[modifier_key])
            ctx.add_edge(
                GraphEdge(
                    id=ids.edge_id("USES_MODIFIER", node_id, target_node),
                    type="USES_MODIFIER",
                    source=node_id,
                    target=target_node,
                    status="observed",
                    fact_ids=[f.id],
                )
            )
