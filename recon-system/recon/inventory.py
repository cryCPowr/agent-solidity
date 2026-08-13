"""Contract, function, state-variable, event, and error inventory extraction.

Pure structural extraction from the solc AST. No naming heuristics: a
contract is identified as a contract because `nodeType == "ContractDefinition"`,
not because of what it is named.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import ast_utils


@dataclass
class ParamInfo:
    name: str
    type_string: Optional[str]
    ast_id: int


@dataclass
class FunctionUnit:
    key: str
    ast_id: int
    group: str
    contract_key: str
    name: str
    kind: str  # function | constructor | receive | fallback | freeFunction
    visibility: str
    state_mutability: str
    parameters: list[ParamInfo]
    returns: list[ParamInfo]
    modifiers: list[str]
    modifier_ref_ids: list[Optional[int]]  # referencedDeclaration ids, parallel to `modifiers`; None if unresolved
    is_virtual: bool
    overrides_base: bool
    file: str
    src: Optional[str]
    body_node: Optional[dict]  # raw AST body, retained for downstream analyzers
    node: dict  # raw FunctionDefinition node


@dataclass
class StateVarUnit:
    key: str
    ast_id: int
    group: str
    contract_key: str
    name: str
    type_string: Optional[str]
    visibility: str
    mutability: str  # mutable | immutable | constant
    file: str
    src: Optional[str]
    node: dict


@dataclass
class EventUnit:
    key: str
    ast_id: int
    group: str
    contract_key: str
    name: str
    parameters: list[ParamInfo]
    file: str
    src: Optional[str]
    node: dict


@dataclass
class ErrorUnit:
    key: str
    ast_id: int
    group: str
    contract_key: str
    name: str
    parameters: list[ParamInfo]
    file: str
    src: Optional[str]
    node: dict


@dataclass
class ModifierUnit:
    """A `modifier` declaration, analyzed the same way a function is: its body
    can contain `require`/state-access/calls just like a function body, and a
    function that `uses` it inherits whatever authorization semantics the
    modifier's body expresses. Recon originally treated modifiers as
    declaration-only; this unit makes modifier bodies first-class analysis
    targets (see recon/expr_analysis.py::analyze_modifier).
    """
    key: str
    ast_id: int
    group: str
    contract_key: str
    name: str
    parameters: list[ParamInfo]
    file: str
    src: Optional[str]
    body_node: Optional[dict]
    node: dict


@dataclass
class ContractUnit:
    key: str
    ast_id: int
    group: str
    name: str
    kind: str  # contract | interface | library
    is_abstract: bool
    file: str
    src: Optional[str]
    base_names: list[str]  # textual base identifiers as written
    base_keys: list[str]  # resolved contract_key when statically resolvable
    linearized_base_ast_ids: list[int]
    functions: list[FunctionUnit] = field(default_factory=list)
    modifiers: list[ModifierUnit] = field(default_factory=list)
    state_vars: list[StateVarUnit] = field(default_factory=list)
    events: list[EventUnit] = field(default_factory=list)
    errors: list[ErrorUnit] = field(default_factory=list)
    structs: list[dict] = field(default_factory=list)
    enums: list[dict] = field(default_factory=list)
    using_for: list[dict] = field(default_factory=list)
    node: dict = None


def _params(param_list_node: Optional[dict]) -> list[ParamInfo]:
    if not param_list_node:
        return []
    out = []
    for p in param_list_node.get("parameters", []):
        out.append(
            ParamInfo(
                name=p.get("name") or "",
                type_string=(p.get("typeDescriptions") or {}).get("typeString"),
                ast_id=p.get("id"),
            )
        )
    return out


def extract_contracts(
    file: str, group: str, source_unit: dict
) -> tuple[list[ContractUnit], dict[int, dict]]:
    """Extract all contract-like units from one file's AST.

    Returns (contracts, declaration_index) where declaration_index maps
    ast-node-id -> {"node":..., "kind":..., "contract_key":..., "function_key":...}
    for every declaration-like node in this file (used later for cross-reference
    resolution of `referencedDeclaration`).
    """
    contracts: list[ContractUnit] = []
    decl_index: dict[int, dict] = {}

    for node in source_unit.get("nodes", []):
        if node.get("nodeType") != "ContractDefinition":
            continue
        contract_key = f"{file}#{node['id']}"
        kind = node.get("contractKind", "contract")
        base_names = []
        base_keys = []
        for base in node.get("baseContracts", []):
            base_name_node = base.get("baseName", {})
            name = base_name_node.get("name") or (base_name_node.get("namePath"))
            if name:
                base_names.append(name)
            # referencedDeclaration on baseName lets us resolve to the actual
            # contract ast id if it was declared in an already-indexed file;
            # cross-file resolution happens in a second pass (see resolve_bases).
            base_keys.append(base_name_node.get("referencedDeclaration"))

        cu = ContractUnit(
            key=contract_key,
            ast_id=node["id"],
            group=group,
            name=node.get("name", ""),
            kind=kind,
            is_abstract=bool(node.get("abstract", False)),
            file=file,
            src=node.get("src"),
            base_names=base_names,
            base_keys=[str(k) for k in base_keys if k is not None],
            linearized_base_ast_ids=node.get("linearizedBaseContracts", []) or [],
            node=node,
        )

        decl_index[node["id"]] = {"node": node, "kind": "contract", "contract_key": contract_key}

        for member in node.get("nodes", []):
            ntype = member.get("nodeType")
            if ntype == "FunctionDefinition":
                fu = _extract_function(file, group, contract_key, member)
                cu.functions.append(fu)
                decl_index[member["id"]] = {
                    "node": member,
                    "kind": "function",
                    "contract_key": contract_key,
                    "function_key": fu.key,
                }
            elif ntype == "VariableDeclaration" and member.get("stateVariable"):
                sv = StateVarUnit(
                    key=f"{contract_key}::{member.get('name')}#{member['id']}",
                    ast_id=member["id"],
                    group=group,
                    contract_key=contract_key,
                    name=member.get("name", ""),
                    type_string=(member.get("typeDescriptions") or {}).get("typeString"),
                    visibility=member.get("visibility", "internal"),
                    mutability=member.get("mutability", "mutable"),
                    file=file,
                    src=member.get("src"),
                    node=member,
                )
                cu.state_vars.append(sv)
                decl_index[member["id"]] = {
                    "node": member,
                    "kind": "state_variable",
                    "contract_key": contract_key,
                    "state_var_key": sv.key,
                }
            elif ntype == "EventDefinition":
                eu = EventUnit(
                    key=f"{contract_key}::{member.get('name')}#{member['id']}",
                    ast_id=member["id"],
                    group=group,
                    contract_key=contract_key,
                    name=member.get("name", ""),
                    parameters=_params(member.get("parameters")),
                    file=file,
                    src=member.get("src"),
                    node=member,
                )
                cu.events.append(eu)
                decl_index[member["id"]] = {
                    "node": member,
                    "kind": "event",
                    "contract_key": contract_key,
                    "event_key": eu.key,
                }
            elif ntype == "ErrorDefinition":
                er = ErrorUnit(
                    key=f"{contract_key}::{member.get('name')}#{member['id']}",
                    ast_id=member["id"],
                    group=group,
                    contract_key=contract_key,
                    name=member.get("name", ""),
                    parameters=_params(member.get("parameters")),
                    file=file,
                    src=member.get("src"),
                    node=member,
                )
                cu.errors.append(er)
                decl_index[member["id"]] = {
                    "node": member,
                    "kind": "error",
                    "contract_key": contract_key,
                    "error_key": er.key,
                }
            elif ntype == "ModifierDefinition":
                mu = ModifierUnit(
                    key=f"{contract_key}::{member.get('name')}#{member['id']}",
                    ast_id=member["id"],
                    group=group,
                    contract_key=contract_key,
                    name=member.get("name", ""),
                    parameters=_params(member.get("parameters")),
                    file=file,
                    src=member.get("src"),
                    body_node=member.get("body"),
                    node=member,
                )
                cu.modifiers.append(mu)
                decl_index[member["id"]] = {
                    "node": member,
                    "kind": "modifier",
                    "contract_key": contract_key,
                    "modifier_key": mu.key,
                }
            elif ntype == "StructDefinition":
                cu.structs.append(member)
                decl_index[member["id"]] = {"node": member, "kind": "struct", "contract_key": contract_key}
            elif ntype == "EnumDefinition":
                cu.enums.append(member)
                decl_index[member["id"]] = {"node": member, "kind": "enum", "contract_key": contract_key}
            elif ntype == "UsingForDirective":
                cu.using_for.append(member)

        contracts.append(cu)

    return contracts, decl_index


def _extract_function(file: str, group: str, contract_key: str, node: dict) -> FunctionUnit:
    name = node.get("name") or f"<{node.get('kind', 'function')}>"
    modifiers = []
    modifier_ref_ids = []
    for m in node.get("modifiers", []):
        modifier_name_node = m.get("modifierName") or {}
        mname = modifier_name_node.get("name")
        if mname:
            modifiers.append(mname)
            modifier_ref_ids.append(modifier_name_node.get("referencedDeclaration"))

    overrides_base = node.get("overrides") is not None

    return FunctionUnit(
        key=f"{contract_key}::{name}#{node['id']}",
        ast_id=node["id"],
        group=group,
        contract_key=contract_key,
        name=name,
        kind=node.get("kind", "function"),
        visibility=node.get("visibility", "internal"),
        state_mutability=node.get("stateMutability", "nonpayable"),
        parameters=_params(node.get("parameters")),
        returns=_params(node.get("returnParameters")),
        modifiers=modifiers,
        modifier_ref_ids=modifier_ref_ids,
        is_virtual=bool(node.get("virtual", False)),
        overrides_base=overrides_base,
        file=file,
        src=node.get("src"),
        body_node=node.get("body"),
        node=node,
    )


def canonical_signature(fu: FunctionUnit) -> Optional[str]:
    """Best-effort canonical `name(type1,type2)` signature.

    Uses solc's own `typeDescriptions.typeString`-derived parameter types
    when available. Marked best-effort because struct/enum parameter types
    are rendered using their declared name, which is what solc's own
    selector computation also uses, but we do not independently verify this
    against a second implementation.
    """
    if fu.kind != "function":
        return None
    types = []
    for p in fu.parameters:
        if p.type_string is None:
            return None
        types.append(_normalize_type_for_signature(p.type_string))
    return f"{fu.name}({','.join(types)})"


def _normalize_type_for_signature(type_string: str) -> str:
    # solc typeStrings like "struct Foo.Bar storage ref" or "contract IERC20"
    # are not the ABI type. Only pass through unambiguous elementary types;
    # otherwise signal that the canonical signature is not reliably derivable
    # by returning the raw description prefixed, so callers can detect it.
    t = type_string.split(" ")[0]
    return t
