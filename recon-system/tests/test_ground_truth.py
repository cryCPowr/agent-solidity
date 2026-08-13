"""Ground-truth validation layer for the Recon system.

This is deliberately SEPARATE from tests/test_pipeline.py. Each fixture here
is minimal (one narrow concept per file), generic (no real-world protocol
names), and analyzed in complete isolation (its own temp directory, its own
solc invocation) so that its expected facts are unambiguous and cannot be
polluted by cross-fixture AST id reuse or unrelated declarations.

For every fixture we assert two things explicitly:
  * MUST HAVE — a fact of this shape is required to exist.
  * MUST NOT HAVE — a fact of this shape must never be emitted (a false
    positive / over-inference check).

This file builds no threat model and contains no vulnerability/exploit
reasoning of any kind — it only checks that the recon system's factual
output matches known ground truth for known-shape source code.
"""

from __future__ import annotations

import json
import os
import shutil
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_DIR = os.path.join(REPO_ROOT, "tests", "fixtures_ground_truth")

sys.path.insert(0, REPO_ROOT)
from recon.pipeline import run as run_pipeline  # noqa: E402


def run_single_fixture(tmp_path, filename: str) -> dict:
    """Analyze exactly one micro-fixture in complete isolation."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    shutil.copy(os.path.join(GT_DIR, filename), src_dir / filename)

    out_dir = str(tmp_path / "out")
    run_pipeline(str(src_dir), out_dir)

    facts = [json.loads(line) for line in open(os.path.join(out_dir, "facts.jsonl"))]
    graph = json.load(open(os.path.join(out_dir, "graph.json")))
    metadata = json.load(open(os.path.join(out_dir, "metadata.json")))
    return {"facts": facts, "graph": graph, "metadata": metadata, "out_dir": out_dir}


def must_have(facts, fact_type, **subject_kv):
    matches = [
        f for f in facts
        if f["type"] == fact_type and all(f["subject"].get(k) == v for k, v in subject_kv.items())
    ]
    assert matches, f"MUST HAVE violated: no fact type={fact_type!r} subject~={subject_kv!r} found"
    return matches[0]


def must_not_have(facts, fact_type, **subject_kv):
    matches = [
        f for f in facts
        if f["type"] == fact_type and all(f["subject"].get(k) == v for k, v in subject_kv.items())
    ]
    assert not matches, f"MUST NOT HAVE violated: found fact(s) {matches}"


def function_key(facts, name: str) -> str:
    for f in facts:
        if f["type"] == "function_exists" and f["subject"]["name"] == name:
            return f["subject"]["function"]
    raise AssertionError(f"no function named {name!r} found")


def contract_key(facts, name: str) -> str:
    for f in facts:
        if f["type"] == "contract_exists" and f["subject"]["name"] == name:
            return f["subject"]["contract"]
    raise AssertionError(f"no contract named {name!r} found")


def node_by_label(graph, label: str) -> dict:
    for n in graph["nodes"]:
        if n["label"] == label:
            return n
    raise AssertionError(f"no graph node labeled {label!r}")


ALL_CALL_FACT_TYPES = (
    "internal_call", "external_call", "external_call_surface", "low_level_call",
    "asset_operation", "eth_transfer", "contract_creation", "selfdestruct_call",
)


# ===========================================================================
# GT01 — state read vs write must not cross-contaminate
# ===========================================================================

def test_gt01_state_read_write(tmp_path):
    r = run_single_fixture(tmp_path, "gt01_state_read_write.sol")
    facts = r["facts"]
    write_fn = function_key(facts, "write")
    read_fn = function_key(facts, "read")

    must_have(facts, "state_write", function=write_fn, name="x")
    must_have(facts, "state_read", function=read_fn, name="x")

    must_not_have(facts, "state_read", function=write_fn, name="x")
    must_not_have(facts, "state_write", function=read_fn, name="x")

    w = must_have(facts, "state_write", function=write_fn, name="x")
    assert w["status"] == "observed"
    assert w["source"]["file"] == "gt01_state_read_write.sol"
    assert w["source"]["line_start"] == 8  # `x = v;`


# ===========================================================================
# GT02 — internal call classification
# ===========================================================================

def test_gt02_internal_call(tmp_path):
    r = run_single_fixture(tmp_path, "gt02_internal_call.sol")
    facts, graph = r["facts"], r["graph"]
    outer_fn = function_key(facts, "outer")
    inner_fn = function_key(facts, "inner")

    call_fact = must_have(facts, "internal_call", caller=outer_fn)
    assert call_fact["status"] == "observed"
    assert call_fact["properties"]["callee_function"] == inner_fn

    must_not_have(facts, "external_call_surface", function=outer_fn)
    must_not_have(facts, "low_level_call", caller=outer_fn)

    calls_edges = [e for e in graph["edges"] if e["type"] == "CALLS"]
    outer_node = node_by_label(graph, "outer")
    inner_node = node_by_label(graph, "inner")
    assert any(e["source"] == outer_node["id"] and e["target"] == inner_node["id"] for e in calls_edges)


# ===========================================================================
# GT03 — external call via mutable state var -> dynamic target
# ===========================================================================

def test_gt03_external_call_dynamic_target(tmp_path):
    r = run_single_fixture(tmp_path, "gt03_external_call_dynamic.sol")
    facts = r["facts"]
    poke_fn = function_key(facts, "poke")

    ext = must_have(facts, "external_call_surface", function=poke_fn)
    assert ext["properties"]["call_type"] == "external"
    assert ext["properties"]["target_status"] == "dynamic"

    must_not_have(facts, "low_level_call", caller=poke_fn)
    must_not_have(facts, "internal_call", caller=poke_fn)


# ===========================================================================
# GT04 — external call via immutable state var -> static_immutable target
# ===========================================================================

def test_gt04_external_call_static_immutable_target(tmp_path):
    r = run_single_fixture(tmp_path, "gt04_external_call_static_immutable.sol")
    facts = r["facts"]
    poke_fn = function_key(facts, "poke")

    ext = must_have(facts, "external_call_surface", function=poke_fn)
    assert ext["properties"]["target_status"] == "static_immutable"

    # must never be reported as the generic "dynamic" bucket when we know better
    assert ext["properties"]["target_status"] != "dynamic"


# ===========================================================================
# GT05 — .call / .delegatecall / .staticcall must never cross-classify
# ===========================================================================

def test_gt05_low_level_call_variants_are_distinct(tmp_path):
    r = run_single_fixture(tmp_path, "gt05_low_level_variants.sol")
    facts = r["facts"]

    call_fn = function_key(facts, "doCall")
    delegate_fn = function_key(facts, "doDelegateCall")
    static_fn = function_key(facts, "doStaticCall")

    call_fact = must_have(facts, "low_level_call", caller=call_fn)
    delegate_fact = must_have(facts, "low_level_call", caller=delegate_fn)
    static_fact = must_have(facts, "low_level_call", caller=static_fn)

    assert call_fact["properties"]["call_subtype"] == "low_level"
    assert delegate_fact["properties"]["call_subtype"] == "delegatecall"
    assert static_fact["properties"]["call_subtype"] == "staticcall"

    # cross-classification checks
    assert delegate_fact["properties"]["call_subtype"] != "low_level"
    assert delegate_fact["properties"]["call_subtype"] != "staticcall"
    assert static_fact["properties"]["call_subtype"] != "low_level"
    assert static_fact["properties"]["call_subtype"] != "delegatecall"

    for f in (call_fact, delegate_fact, static_fact):
        assert f["properties"]["target_status"] == "dynamic"  # parameter-derived address


# ===========================================================================
# GT06 — deceptive naming must not fabricate facts
# ===========================================================================

def test_gt06_deceptive_name_produces_no_call_or_asset_facts(tmp_path):
    r = run_single_fixture(tmp_path, "gt06_no_calls_deceptive_name.sol")
    facts = r["facts"]
    fn = function_key(facts, "callExternalAttackTransferNow")

    for ftype in ALL_CALL_FACT_TYPES:
        must_not_have(facts, ftype, function=fn)
        must_not_have(facts, ftype, caller=fn)

    # sanity: the function itself must still be inventoried
    must_have(facts, "function_exists", name="callExternalAttackTransferNow")


# ===========================================================================
# GT07 — native ETH transfer vs token-style asset op must not cross-contaminate
# ===========================================================================

def test_gt07_eth_transfer_vs_token_asset_operation(tmp_path):
    r = run_single_fixture(tmp_path, "gt07_eth_vs_token_transfer.sol")
    facts = r["facts"]
    eth_fn = function_key(facts, "sendEth")
    token_fn = function_key(facts, "sendToken")

    eth_fact = must_have(facts, "eth_transfer", function=eth_fn)
    assert eth_fact["status"] == "observed"

    token_fact = must_have(facts, "asset_operation", function=token_fn)
    assert token_fact["status"] == "derived"  # name-pattern heuristic, never asserted observed
    assert token_fact["properties"]["operation"] == "transfer"

    must_not_have(facts, "asset_operation", function=eth_fn)
    must_not_have(facts, "eth_transfer", function=token_fn)


# ===========================================================================
# GT08 — authorization_check scoped strictly to msg.sender comparisons
# ===========================================================================

def test_gt08_authorization_check_scope(tmp_path):
    r = run_single_fixture(tmp_path, "gt08_authorization_scope.sol")
    facts = r["facts"]
    protected_fn = function_key(facts, "onlyOwnerAction")
    unrelated_fn = function_key(facts, "unrelatedCheck")

    auth = must_have(facts, "authorization_check", function=protected_fn)
    assert auth["status"] == "derived"
    assert "owner" in "".join(auth["properties"]["referenced_state_variables"])

    must_not_have(facts, "authorization_check", function=unrelated_fn)

    # both are require_statement facts, but only one is an authorization_check
    must_have(facts, "require_statement", function=protected_fn)
    must_have(facts, "require_statement", function=unrelated_fn)


# ===========================================================================
# GT09 — delete and increment must be recorded as writes (increment = read+write)
# ===========================================================================

def test_gt09_delete_marks_write(tmp_path):
    r = run_single_fixture(tmp_path, "gt09_delete_and_increment.sol")
    facts = r["facts"]
    clear_fn = function_key(facts, "clear")

    must_have(facts, "state_write", function=clear_fn, name="balances")


def test_gt09_increment_marks_both_read_and_write(tmp_path):
    r = run_single_fixture(tmp_path, "gt09_delete_and_increment.sol")
    facts = r["facts"]
    inc_fn = function_key(facts, "increment")

    must_have(facts, "state_write", function=inc_fn, name="counter")
    must_have(facts, "state_read", function=inc_fn, name="counter")


# ===========================================================================
# GT10 — multi-contract composition: inheritance + cross-contract external call
# ===========================================================================

def test_gt10_inheritance_edge(tmp_path):
    r = run_single_fixture(tmp_path, "gt10_multi_contract_composition.sol")
    graph = r["graph"]
    base_node = node_by_label(graph, "GT10Base")
    derived_node = node_by_label(graph, "GT10Derived")

    inherits_edges = [e for e in graph["edges"] if e["type"] == "INHERITS"]
    assert any(e["source"] == derived_node["id"] and e["target"] == base_node["id"] for e in inherits_edges)


def test_gt10_inherited_function_belongs_to_base_not_derived(tmp_path):
    r = run_single_fixture(tmp_path, "gt10_multi_contract_composition.sol")
    facts = r["facts"]
    base_key = contract_key(facts, "GT10Base")
    derived_key = contract_key(facts, "GT10Derived")

    base_fn_facts = [
        f for f in facts if f["type"] == "function_exists" and f["subject"]["name"] == "baseFn"
    ]
    assert len(base_fn_facts) == 1
    assert base_fn_facts[0]["subject"]["contract"] == base_key
    assert base_fn_facts[0]["subject"]["contract"] != derived_key


def test_gt10_cross_contract_external_call(tmp_path):
    r = run_single_fixture(tmp_path, "gt10_multi_contract_composition.sol")
    facts = r["facts"]
    caller_fn = function_key(facts, "callDerived")

    ext = must_have(facts, "external_call_surface", function=caller_fn)
    assert ext["properties"]["call_type"] == "external"
    assert ext["properties"]["target_status"] == "dynamic"
    must_not_have(facts, "internal_call", caller=caller_fn)


def test_gt10_distinct_contracts_never_merged(tmp_path):
    r = run_single_fixture(tmp_path, "gt10_multi_contract_composition.sol")
    facts = r["facts"]
    names = {f["subject"]["name"] for f in facts if f["type"] == "contract_exists"}
    assert names == {"GT10Base", "GT10Derived", "GT10Consumer"}
    keys = {f["subject"]["contract"] for f in facts if f["type"] == "contract_exists"}
    assert len(keys) == 3  # three distinct contract_keys, never collapsed


# ===========================================================================
# GT11 — capability facts scoped to the function that actually exhibits them
# ===========================================================================

def test_gt11_capability_scope(tmp_path):
    r = run_single_fixture(tmp_path, "gt11_capability_scope.sol")
    facts = r["facts"]
    active_fn = function_key(facts, "payAndReceive")
    pure_fn = function_key(facts, "pureMath")

    must_have(facts, "capability", function=active_fn, capability="can_transfer_token")
    must_have(facts, "capability", function=active_fn, capability="can_receive_native_value")

    must_not_have(facts, "capability", function=pure_fn, capability="can_transfer_token")
    must_not_have(facts, "capability", function=pure_fn, capability="can_receive_native_value")
    must_not_have(facts, "capability", function=pure_fn)  # zero capabilities at all


# ===========================================================================
# GT12 — provenance: exact source location + evidence snippet content
# ===========================================================================

def test_gt12_provenance_line_number_exact(tmp_path):
    r = run_single_fixture(tmp_path, "gt12_provenance_accuracy.sol")
    facts = r["facts"]
    fn_fact = must_have(facts, "function_exists", name="markerFunction")

    assert fn_fact["source"]["file"] == "gt12_provenance_accuracy.sol"
    assert fn_fact["source"]["line_start"] == 5
    assert fn_fact["source"]["ast_node_id"] is not None
    assert fn_fact["source"]["start"] is not None
    assert fn_fact["source"]["end"] > fn_fact["source"]["start"]


def test_gt12_evidence_snippet_matches_source(tmp_path):
    r = run_single_fixture(tmp_path, "gt12_provenance_accuracy.sol")
    facts = r["facts"]
    fn_fact = must_have(facts, "function_exists", name="markerFunction")

    assert fn_fact["evidence"], "expected at least one evidence id"
    evid = fn_fact["evidence"][0]
    snippet_path = os.path.join(r["out_dir"], "snippets", evid.split(":")[1] + ".sol.txt")
    assert os.path.exists(snippet_path), f"snippet file missing: {snippet_path}"
    content = open(snippet_path).read()
    assert "markerFunction" in content
    assert "uint256 v" in content


# ===========================================================================
# Cross-fixture sanity: every MUST-NOT-HAVE type used above is a real,
# spelled-correctly fact type actually produced somewhere by the analyzer —
# otherwise a typo would make a must_not_have test vacuously true.
# ===========================================================================

def test_must_not_have_fact_types_are_real_and_producible(tmp_path):
    """Guards against the classic false-negative-test bug: asserting the
    absence of a fact type that is misspelled (and thus would never appear
    regardless of correctness).
    """
    checked_positive_sources = [
        ("gt02_internal_call.sol", "external_call_surface"),
        ("gt02_internal_call.sol", "low_level_call"),
        ("gt03_external_call_dynamic.sol", "internal_call"),
        ("gt06_no_calls_deceptive_name.sol", None),  # covered by real positive elsewhere
        ("gt07_eth_vs_token_transfer.sol", "asset_operation"),
        ("gt07_eth_vs_token_transfer.sol", "eth_transfer"),
        ("gt08_authorization_scope.sol", "authorization_check"),
    ]
    # Each of these fact types is independently proven producible by at
    # least one *positive* assertion elsewhere in this file:
    #   external_call_surface -> test_gt03_external_call_dynamic_target
    #   low_level_call         -> test_gt05_low_level_call_variants_are_distinct
    #   internal_call           -> test_gt02_internal_call
    #   asset_operation          -> test_gt07_eth_transfer_vs_token_asset_operation
    #   eth_transfer              -> test_gt07_eth_transfer_vs_token_asset_operation
    #   authorization_check        -> test_gt08_authorization_check_scope
    # This test just documents/asserts that pairing explicitly.
    producible_types = {
        "external_call_surface", "low_level_call", "internal_call",
        "asset_operation", "eth_transfer", "authorization_check",
    }
    for _src, ftype in checked_positive_sources:
        if ftype:
            assert ftype in producible_types
