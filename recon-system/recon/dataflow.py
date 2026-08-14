"""Conservative local data-flow / expression propagation.

Extends the existing "peel to root identifier" one-hop resolution used by
``expr_analysis._emit_call_argument_flows`` (sections 8-9) with bounded
def-use propagation through *simple, unambiguous* local variable
assignments, so a chain like

    parameter -> local variable -> local variable -> arithmetic -> use

can be recovered instead of stopping at the nearest identifier.

This module is intentionally pure (no ``ctx``/``ids``/AST-provenance
plumbing) so it can be unit-tested directly against hand-built AST
fragments, independent of the rest of the recon pipeline.

Conservatism rules (false positives are worse than missing inferences):

  * A local variable is only ever "resolved" if it has EXACTLY ONE
    assignment/initializer in the entire function body, and that write is
    NOT nested inside a conditional (`if`, ternary), loop
    (`for`/`while`/`do-while`), or `try`/`catch` construct. A variable
    written more than once, or written only inside a branch, is left
    unresolved -- this module never merges/unions possible values across
    branches or reassignments.
  * Only a small, semantically-safe set of expression shapes propagate:
    identifier copies, literals, `msg`/`block`/`tx` member reads, unary
    `+`/`-`/`~`, binary arithmetic/bitwise operators where BOTH operands
    resolve, and single-argument type conversions (`uint160(x)`,
    `address(x)`, `payable(x)`, ...), which are transparent wrappers over
    their argument's value.
  * Any other shape -- external/internal call results (including
    `abi.encode*`, which recon does not special-case), index/mapping
    access, struct member access, `new` expressions, ternaries -- is a
    deliberate resolution boundary. Recon does not guess what such an
    expression's value derives from; it reports `unresolved` instead.
  * A chain is only ever built from the *union of both* sides of a binary
    operation succeeding. If either operand is unresolved, the whole
    expression is unresolved -- recon never reports a partial chain that
    silently drops an operand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Statement/expression node types that make a value assigned underneath
# them control-dependent. Resolving through such a definition would
# require reasoning about which branch executes, which recon deliberately
# does not attempt.
_BRANCH_NODE_TYPES = {
    "IfStatement", "ForStatement", "WhileStatement", "DoWhileStatement",
    "TryStatement", "Conditional",  # ternary `cond ? a : b`
}

_ARITHMETIC_OPERATORS = {
    "+", "-", "*", "/", "%", "**",
    "&", "|", "^", "<<", ">>",
}

_ENV_ROOTS = {"msg", "block", "tx"}


@dataclass
class Hop:
    """One link in an origin chain, root-first."""
    kind: str       # "parameter" | "return_variable" | "local_variable" |
                     # "state_variable" | "environment" | "literal" | "arithmetic"
    name: Optional[str]
    relation: str    # "root" | "copy" | "definition" | "unary" | "binary"
    ast_id: Optional[int] = None
    operator: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"kind": self.kind, "name": self.name, "relation": self.relation}
        if self.operator:
            d["operator"] = self.operator
        return d


@dataclass
class OriginResult:
    status: str                          # "observed" | "derived" | "unknown"
    kind: str                            # terminal kind, or "unresolved"
    name: Optional[str]
    chain: list = field(default_factory=list)   # list[Hop], root-first


def _unresolved() -> OriginResult:
    return OriginResult(status="unknown", kind="unresolved", name=None, chain=[])


def _ok(result: OriginResult) -> bool:
    return result.status in ("observed", "derived")


def build_local_defs(body_node: dict) -> tuple[dict, dict]:
    """Collect single-static-assignment local variable definitions.

    Returns ``(defs, ambiguous)``:

      * ``defs``: ``{var_ast_id: rhs_expr_node}`` for locals with EXACTLY
        ONE assignment/initializer in the function body, occurring outside
        any branch/loop/try construct.
      * ``ambiguous``: ``{var_ast_id: (reason, representative_node)}`` for
        locals that were written but could not be treated as a single
        unambiguous definition. ``reason`` is ``"multiple_assignments"``
        or ``"branch_guarded_assignment"``.

    A variable with no assignment/initializer at all (e.g. a bare
    declaration, or one only ever touched via compound assignment /
    increment) appears in neither dict -- callers must treat that as
    "no known definition", not silently skip it.
    """
    # Each site: {"node": <node to use for source-ref>, "in_branch": bool,
    #             "usable": bool, "rhs": rhs_node_or_None}. "usable" is False
    # for compound assignments (`+=` etc.) and `++`/`--`/`delete`: they are
    # real writes (so they must count toward ambiguity) but carry no single
    # expression whose value we could propagate.
    write_sites: dict[int, list] = {}

    def _record(vid, node, in_branch, usable, rhs):
        write_sites.setdefault(vid, []).append(
            {"node": node, "in_branch": in_branch, "usable": usable, "rhs": rhs}
        )

    def walk(node, in_branch: bool) -> None:
        if not isinstance(node, dict):
            return
        ntype = node.get("nodeType")
        nested_branch = in_branch or ntype in _BRANCH_NODE_TYPES

        if ntype == "VariableDeclarationStatement":
            decls = node.get("declarations") or []
            value = node.get("initialValue")
            if value is not None and len(decls) == 1 and decls[0] is not None:
                _record(decls[0]["id"], value, in_branch, True, value)
        elif ntype == "Assignment":
            lhs = node.get("leftHandSide") or {}
            if lhs.get("nodeType") == "Identifier":
                vid = lhs.get("referencedDeclaration")
                if vid is not None:
                    if node.get("operator") == "=":
                        rhs = node.get("rightHandSide")
                        _record(vid, rhs, in_branch, True, rhs)
                    else:
                        # compound assignment (+=, -=, ...): a real write,
                        # but not a single propagable value.
                        _record(vid, node, in_branch, False, None)
        elif ntype == "UnaryOperation" and node.get("operator") in ("++", "--", "delete"):
            sub = node.get("subExpression") or {}
            if sub.get("nodeType") == "Identifier":
                vid = sub.get("referencedDeclaration")
                if vid is not None:
                    _record(vid, node, in_branch, False, None)

        for v in node.values():
            if isinstance(v, dict):
                walk(v, nested_branch)
            elif isinstance(v, list):
                for item in v:
                    walk(item, nested_branch)

    walk(body_node, False)

    defs: dict[int, dict] = {}
    ambiguous: dict[int, tuple] = {}
    for vid, sites in write_sites.items():
        if len(sites) > 1:
            ambiguous[vid] = ("multiple_assignments", sites[0]["node"])
            continue
        site = sites[0]
        if not site["usable"]:
            # A single write, but not one with a propagable value (e.g. the
            # variable is only ever `++`'d, or only ever compound-assigned).
            ambiguous[vid] = ("non_simple_write", site["node"])
            continue
        if site["in_branch"]:
            ambiguous[vid] = ("branch_guarded_assignment", site["node"])
            continue
        defs[vid] = site["rhs"]

    return defs, ambiguous


def _peel_type_conversion(node: Optional[dict]) -> Optional[dict]:
    """Type conversions (`uint160(x)`, `address(x)`, `payable(x)`) change
    type, not value provenance, so propagation passes straight through the
    single argument.
    """
    while (
        node is not None
        and node.get("nodeType") == "FunctionCall"
        and node.get("kind") == "typeConversion"
        and len(node.get("arguments") or []) == 1
    ):
        node = node["arguments"][0]
    return node


def resolve_origin(
    node: Optional[dict],
    local_defs: dict,
    local_scope: dict,
    visible_state_var_names: dict,
    _seen: Optional[frozenset] = None,
) -> OriginResult:
    """Resolve the origin of an expression, propagating through simple,
    unambiguous local def-use chains. Never guesses across branches,
    reassignments, calls, or unmodeled expression shapes -- returns an
    ``unresolved`` result in those cases rather than fabricating a link.

    ``local_scope``: ``{ast_id: "parameter" | "return_variable" |
    "local_variable"}`` (as already built by
    ``expr_analysis.analyze_function``).
    ``visible_state_var_names``: ``{ast_id: name}``.
    """
    if _seen is None:
        _seen = frozenset()

    if node is None:
        return _unresolved()

    node = _peel_type_conversion(node)
    while node is not None and node.get("nodeType") == "TupleExpression" and len(node.get("components") or []) == 1:
        node = (node.get("components") or [None])[0]
    if node is None:
        return _unresolved()

    ntype = node.get("nodeType")

    if ntype == "Literal":
        return OriginResult("observed", "literal", node.get("value"),
                             [Hop("literal", node.get("value"), "root")])

    if ntype == "Identifier":
        refid = node.get("referencedDeclaration")
        name = node.get("name")

        if refid in visible_state_var_names:
            svname = visible_state_var_names[refid]
            return OriginResult("observed", "state_variable", svname,
                                 [Hop("state_variable", svname, "root", ast_id=node.get("id"))])

        if refid in local_scope:
            kind = local_scope[refid]
            if kind in ("parameter", "return_variable"):
                return OriginResult("observed", kind, name,
                                     [Hop(kind, name, "root", ast_id=node.get("id"))])
            # local_variable: propagate through its single def, if any.
            if refid in _seen or refid not in local_defs:
                return OriginResult("unknown", "local_variable", name,
                                     [Hop("local_variable", name, "root", ast_id=node.get("id"))])
            inner = resolve_origin(
                local_defs[refid], local_defs, local_scope, visible_state_var_names,
                _seen | {refid},
            )
            if not _ok(inner):
                return OriginResult("unknown", "local_variable", name,
                                     [Hop("local_variable", name, "root", ast_id=node.get("id"))])
            chain = inner.chain + [Hop("local_variable", name, "copy", ast_id=node.get("id"))]
            return OriginResult("derived", inner.kind, inner.name, chain)

        if name in _ENV_ROOTS:
            return OriginResult("observed", "environment", name,
                                 [Hop("environment", name, "root", ast_id=node.get("id"))])

        return _unresolved()

    if ntype == "MemberAccess":
        base = node.get("expression") or {}
        if base.get("nodeType") == "Identifier" and base.get("name") in _ENV_ROOTS:
            origin = f"{base['name']}.{node.get('memberName')}"
            return OriginResult("observed", "environment", origin,
                                 [Hop("environment", origin, "root", ast_id=node.get("id"))])
        # Struct fields, mapping/array member calls, etc: not modeled --
        # do not guess that `a.b` shares provenance with `a`.
        return _unresolved()

    if ntype == "UnaryOperation" and node.get("operator") in ("-", "+", "~"):
        inner = resolve_origin(node.get("subExpression"), local_defs, local_scope,
                                visible_state_var_names, _seen)
        if not _ok(inner):
            return _unresolved()
        chain = inner.chain + [Hop("arithmetic", None, "unary", operator=node.get("operator"))]
        return OriginResult("derived", "arithmetic", inner.name, chain)

    if ntype == "BinaryOperation" and node.get("operator") in _ARITHMETIC_OPERATORS:
        left = resolve_origin(node.get("leftExpression"), local_defs, local_scope,
                               visible_state_var_names, _seen)
        right = resolve_origin(node.get("rightExpression"), local_defs, local_scope,
                                visible_state_var_names, _seen)
        if not _ok(left) or not _ok(right):
            # Conservative: if EITHER operand can't be traced, the combined
            # value's provenance is not fully known -- never report a chain
            # that silently omits an operand.
            return _unresolved()
        chain = left.chain + right.chain + [
            Hop("arithmetic", None, "binary", operator=node.get("operator"))
        ]
        return OriginResult("derived", "arithmetic", None, chain)

    # Function calls (internal/external/abi.encode*/...), index/mapping
    # access, `new` expressions, ternaries, etc: deliberate resolution
    # boundary. Recon does not interpret call semantics here.
    return _unresolved()
