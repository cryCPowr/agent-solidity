"""Unit tests for recon/dataflow.py (local def-use / expression
propagation).

These are deliberately independent of the full recon pipeline: they build
minimal, hand-crafted fragments that mimic solc's AST JSON shape directly,
so they exercise `build_local_defs` / `resolve_origin` in isolation without
needing solc, ast_utils, or a real ProjectContext.

Covers, per the requested minimal matrix:
  - parameter -> local
  - local -> local
  - parameter -> arithmetic -> local
  - local -> function call argument
  - branch/condition (ambiguous, must NOT resolve)
  - unknown/unresolved expression (call result, mapping/array read)

Run with: pytest test_dataflow_propagation.py
"""

from __future__ import annotations

import itertools

import pytest

from recon import dataflow

_ids = itertools.count(1)


def nid() -> int:
    return next(_ids)


def ident(name: str, refid: int) -> dict:
    return {"nodeType": "Identifier", "id": nid(), "name": name, "referencedDeclaration": refid}


def literal(value: str) -> dict:
    return {"nodeType": "Literal", "id": nid(), "value": value}


def member_access(base_name: str, member: str) -> dict:
    return {
        "nodeType": "MemberAccess",
        "id": nid(),
        "memberName": member,
        "expression": {"nodeType": "Identifier", "id": nid(), "name": base_name, "referencedDeclaration": None},
    }


def binop(op: str, left: dict, right: dict) -> dict:
    return {"nodeType": "BinaryOperation", "id": nid(), "operator": op, "leftExpression": left, "rightExpression": right}


def unary(op: str, sub: dict) -> dict:
    return {"nodeType": "UnaryOperation", "id": nid(), "operator": op, "subExpression": sub}


def var_decl_stmt(var_id: int, value: dict) -> dict:
    return {
        "nodeType": "VariableDeclarationStatement",
        "id": nid(),
        "declarations": [{"id": var_id, "nodeType": "VariableDeclaration"}],
        "initialValue": value,
    }


def assignment(target_id: int, target_name: str, value: dict, op: str = "=") -> dict:
    return {
        "nodeType": "Assignment",
        "id": nid(),
        "operator": op,
        "leftHandSide": {"nodeType": "Identifier", "id": nid(), "name": target_name, "referencedDeclaration": target_id},
        "rightHandSide": value,
    }


def if_stmt(true_body_statements: list, false_body_statements: list = None) -> dict:
    return {
        "nodeType": "IfStatement",
        "id": nid(),
        "trueBody": {"nodeType": "Block", "id": nid(), "statements": true_body_statements},
        "falseBody": (
            {"nodeType": "Block", "id": nid(), "statements": false_body_statements}
            if false_body_statements is not None else None
        ),
    }


def block(statements: list) -> dict:
    return {"nodeType": "Block", "id": nid(), "statements": statements}


def call(callee: dict, args: list, kind: str = "functionCall") -> dict:
    return {"nodeType": "FunctionCall", "id": nid(), "kind": kind, "expression": callee, "arguments": args}


def type_conversion(type_name: str, arg: dict) -> dict:
    return call({"nodeType": "ElementaryTypeNameExpression", "id": nid(), "typeName": type_name},
                [arg], kind="typeConversion")


def index_access(base: dict, index: dict) -> dict:
    return {"nodeType": "IndexAccess", "id": nid(), "baseExpression": base, "indexExpression": index}


# ---------------------------------------------------------------------
# parameter -> local
# ---------------------------------------------------------------------

def test_parameter_copied_into_local_resolves():
    # uint x = amount;
    AMOUNT_ID = nid()
    x_id = nid()
    body = block([var_decl_stmt(x_id, ident("amount", AMOUNT_ID))])

    local_scope = {AMOUNT_ID: "parameter"}
    defs, ambiguous = dataflow.build_local_defs(body)

    assert x_id in defs
    assert ambiguous == {}

    result = dataflow.resolve_origin(defs[x_id], defs, local_scope, {})
    assert result.status == "observed"
    assert result.kind == "parameter"
    assert result.name == "amount"
    assert [h.kind for h in result.chain] == ["parameter"]


# ---------------------------------------------------------------------
# local -> local
# ---------------------------------------------------------------------

def test_local_copied_into_another_local_resolves_through_chain():
    # uint x = amount; uint y = x;
    AMOUNT_ID = nid()
    x_id = nid()
    y_id = nid()
    body = block([
        var_decl_stmt(x_id, ident("amount", AMOUNT_ID)),
        var_decl_stmt(y_id, ident("x", x_id)),
    ])

    local_scope = {AMOUNT_ID: "parameter", x_id: "local_variable", y_id: "local_variable"}
    defs, ambiguous = dataflow.build_local_defs(body)
    assert ambiguous == {}

    result = dataflow.resolve_origin(defs[y_id], defs, local_scope, {})
    assert result.status == "derived"
    assert result.kind == "parameter"
    assert result.name == "amount"
    # chain: parameter(amount) -> local_variable(x, copy)
    assert [h.kind for h in result.chain] == ["parameter", "local_variable"]
    assert result.chain[-1].name == "x"
    assert result.chain[-1].relation == "copy"


# ---------------------------------------------------------------------
# parameter -> arithmetic -> local
# ---------------------------------------------------------------------

def test_arithmetic_over_resolved_parameter_resolves_as_derived():
    # uint x = amount; uint y = x * 2;
    AMOUNT_ID = nid()
    x_id = nid()
    y_id = nid()
    body = block([
        var_decl_stmt(x_id, ident("amount", AMOUNT_ID)),
        var_decl_stmt(y_id, binop("*", ident("x", x_id), literal("2"))),
    ])

    local_scope = {AMOUNT_ID: "parameter", x_id: "local_variable", y_id: "local_variable"}
    defs, ambiguous = dataflow.build_local_defs(body)
    assert ambiguous == {}

    result = dataflow.resolve_origin(defs[y_id], defs, local_scope, {})
    assert result.status == "derived"
    assert result.kind == "arithmetic"
    # chain includes the parameter, the literal, and the binary op itself
    kinds = [h.kind for h in result.chain]
    assert "parameter" in kinds
    assert "arithmetic" in kinds
    assert result.chain[-1].relation == "binary"
    assert result.chain[-1].operator == "*"


def test_binary_operation_unresolved_if_either_operand_unresolved():
    # uint y = x * externalCall();  (x resolvable, but the call is not)
    AMOUNT_ID = nid()
    x_id = nid()
    body_defs_only = block([var_decl_stmt(x_id, ident("amount", AMOUNT_ID))])
    local_scope = {AMOUNT_ID: "parameter", x_id: "local_variable"}
    defs, _ = dataflow.build_local_defs(body_defs_only)

    unresolved_call = call({"nodeType": "Identifier", "id": nid(), "name": "externalCall",
                             "referencedDeclaration": 9999}, [])
    expr = binop("*", ident("x", x_id), unresolved_call)

    result = dataflow.resolve_origin(expr, defs, local_scope, {})
    assert result.kind == "unresolved"
    assert result.status == "unknown"
    # must never silently report a chain that drops the unresolved operand
    assert result.chain == []


# ---------------------------------------------------------------------
# local -> function call argument
# ---------------------------------------------------------------------

def test_local_variable_flows_into_call_argument():
    # uint x = amount; uint y = x * 2; foo(y);
    AMOUNT_ID = nid()
    x_id = nid()
    y_id = nid()
    body = block([
        var_decl_stmt(x_id, ident("amount", AMOUNT_ID)),
        var_decl_stmt(y_id, binop("*", ident("x", x_id), literal("2"))),
    ])
    local_scope = {AMOUNT_ID: "parameter", x_id: "local_variable", y_id: "local_variable"}
    defs, ambiguous = dataflow.build_local_defs(body)
    assert ambiguous == {}

    call_arg = ident("y", y_id)
    result = dataflow.resolve_origin(call_arg, defs, local_scope, {})
    assert result.status == "derived"
    assert result.kind == "arithmetic"
    kinds = [h.kind for h in result.chain]
    # full chain: parameter -> ... -> arithmetic -> local_variable(y, copy)
    assert kinds[0] == "parameter"
    assert kinds[-1] == "local_variable"
    assert result.chain[-1].name == "y"


def test_type_conversion_is_transparent_pass_through():
    # target.call(abi_style): uint160(x) should resolve exactly like x
    AMOUNT_ID = nid()
    x_id = nid()
    body = block([var_decl_stmt(x_id, ident("amount", AMOUNT_ID))])
    local_scope = {AMOUNT_ID: "parameter", x_id: "local_variable"}
    defs, _ = dataflow.build_local_defs(body)

    wrapped = type_conversion("uint160", ident("x", x_id))
    result = dataflow.resolve_origin(wrapped, defs, local_scope, {})
    assert result.status == "derived"
    assert result.kind == "parameter"
    assert result.name == "amount"


# ---------------------------------------------------------------------
# branch / condition -- must NOT resolve
# ---------------------------------------------------------------------

def test_variable_assigned_only_inside_branch_is_ambiguous():
    # if (cond) { x = a; } else { x = b; }
    A_ID = nid()
    B_ID = nid()
    x_id = nid()
    body = block([
        if_stmt(
            true_body_statements=[assignment(x_id, "x", ident("a", A_ID))],
            false_body_statements=[assignment(x_id, "x", ident("b", B_ID))],
        )
    ])
    defs, ambiguous = dataflow.build_local_defs(body)

    assert x_id not in defs
    assert x_id in ambiguous
    reason, _node = ambiguous[x_id]
    assert reason == "multiple_assignments"


def test_variable_assigned_once_but_inside_branch_is_ambiguous():
    # if (cond) { uint x = a; }
    A_ID = nid()
    x_id = nid()
    body = block([
        if_stmt(true_body_statements=[var_decl_stmt(x_id, ident("a", A_ID))])
    ])
    defs, ambiguous = dataflow.build_local_defs(body)

    assert x_id not in defs
    assert x_id in ambiguous
    reason, _node = ambiguous[x_id]
    assert reason == "branch_guarded_assignment"


def test_downstream_use_of_branch_guarded_local_is_unresolved():
    # if (cond) { x = a; } else { x = b; }  ...  uint y = x * 2;
    A_ID = nid()
    B_ID = nid()
    x_id = nid()
    y_id = nid()
    body = block([
        if_stmt(
            true_body_statements=[assignment(x_id, "x", ident("a", A_ID))],
            false_body_statements=[assignment(x_id, "x", ident("b", B_ID))],
        ),
        var_decl_stmt(y_id, binop("*", ident("x", x_id), literal("2"))),
    ])
    local_scope = {A_ID: "parameter", B_ID: "parameter", x_id: "local_variable", y_id: "local_variable"}
    defs, ambiguous = dataflow.build_local_defs(body)
    assert x_id not in defs

    result = dataflow.resolve_origin(defs[y_id], defs, local_scope, {})
    assert result.kind == "unresolved"
    assert result.status == "unknown"
    assert result.chain == []


# ---------------------------------------------------------------------
# unknown / unresolved expression shapes
# ---------------------------------------------------------------------

def test_call_result_assigned_to_local_is_unresolved():
    # uint x = externalCall();
    x_id = nid()
    unresolved_call = call({"nodeType": "Identifier", "id": nid(), "name": "externalCall",
                             "referencedDeclaration": 4242}, [])
    body = block([var_decl_stmt(x_id, unresolved_call)])
    defs, ambiguous = dataflow.build_local_defs(body)
    assert ambiguous == {}
    assert x_id in defs

    result = dataflow.resolve_origin(defs[x_id], defs, {}, {})
    assert result.kind == "unresolved"
    assert result.status == "unknown"


def test_mapping_index_access_is_unresolved():
    # uint x = balances[msg.sender];
    x_id = nid()
    idx = index_access(ident("balances", 777), member_access("msg", "sender"))
    body = block([var_decl_stmt(x_id, idx)])
    defs, _ = dataflow.build_local_defs(body)

    result = dataflow.resolve_origin(defs[x_id], defs, {}, {})
    assert result.kind == "unresolved"
    assert result.status == "unknown"


def test_environment_member_access_resolves_directly():
    # uint x = msg.value;
    x_id = nid()
    body = block([var_decl_stmt(x_id, member_access("msg", "value"))])
    defs, _ = dataflow.build_local_defs(body)

    result = dataflow.resolve_origin(defs[x_id], defs, {}, {})
    assert result.status == "observed"
    assert result.kind == "environment"
    assert result.name == "msg.value"


def test_state_variable_read_resolves_directly():
    STATE_VAR_ID = 555
    x_id = nid()
    body = block([var_decl_stmt(x_id, ident("owner", STATE_VAR_ID))])
    defs, _ = dataflow.build_local_defs(body)

    result = dataflow.resolve_origin(defs[x_id], defs, {}, {STATE_VAR_ID: "owner"})
    assert result.status == "observed"
    assert result.kind == "state_variable"
    assert result.name == "owner"


def test_reassigned_variable_is_ambiguous_not_silently_first_write():
    # uint x = a; x = b;
    A_ID = nid()
    B_ID = nid()
    x_id = nid()
    body = block([
        var_decl_stmt(x_id, ident("a", A_ID)),
        assignment(x_id, "x", ident("b", B_ID)),
    ])
    defs, ambiguous = dataflow.build_local_defs(body)

    assert x_id not in defs
    assert x_id in ambiguous
    assert ambiguous[x_id][0] == "multiple_assignments"


def test_compound_assignment_after_initializer_is_ambiguous_not_stale():
    # uint x = a; x += 1;
    # Must NOT resolve x to `a` downstream -- that would be a false
    # positive (x's real value is a+1, and recon does not track statement
    # ordering to know where in the body a later use sits).
    A_ID = nid()
    x_id = nid()
    body = block([
        var_decl_stmt(x_id, ident("a", A_ID)),
        assignment(x_id, "x", literal("1"), op="+="),
    ])
    defs, ambiguous = dataflow.build_local_defs(body)
    assert x_id not in defs
    assert x_id in ambiguous
    assert ambiguous[x_id][0] == "multiple_assignments"


def test_variable_only_ever_incremented_has_no_propagable_value():
    # uint x; x++;
    x_id = nid()
    body = block([
        {"nodeType": "VariableDeclarationStatement", "id": nid(),
         "declarations": [{"id": x_id, "nodeType": "VariableDeclaration"}], "initialValue": None},
        unary("++", ident("x", x_id)),
    ])
    defs, ambiguous = dataflow.build_local_defs(body)
    assert x_id not in defs
    assert x_id in ambiguous
    assert ambiguous[x_id][0] == "non_simple_write"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
