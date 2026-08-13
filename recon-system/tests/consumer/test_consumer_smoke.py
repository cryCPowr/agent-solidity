"""Recon Consumer Smoke Test.

Question this file answers: "Can a downstream consumer reliably retrieve the
structural facts a future security-reasoning agent would need, using ONLY
the artifacts recon.cli already writes to disk?"

This is NOT another recon implementation, NOT a vulnerability detector, and
NOT a replacement for tests/test_pipeline.py or tests/test_ground_truth.py
(which test recon's own internal correctness by importing recon.pipeline
directly). This file treats recon as a black box: it shells out to
`python -m recon.cli` exactly as an external consumer would, then reads only
facts.jsonl / graph.json / summary.json / snippets/ via
tests/consumer/recon_reader.py.

Every assertion here is a STRUCTURAL fact ("function F performs a low-level
delegatecall", "parameter X reaches call argument 0", "fact F resolves to
source line N") — never a security/severity/exploitability judgment.

Per the task constraints, this file does NOT modify recon/ and does NOT add
new fixtures: it uses the existing tests/fixtures/ corpus exactly as-is. Two
genuine gaps discovered while grounding these assertions in real output are
documented at the bottom (test_gap_documented_create2_target_type_is_null)
rather than patched.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recon_reader import ReconOutput  # noqa: E402
from conftest import FIXTURES_DIR  # noqa: E402


# ===========================================================================
# A. Dynamic / arbitrary external call target
# ===========================================================================

def test_A_dynamic_external_call_target_is_identifiable(recon: ReconOutput):
    """pingDynamic(address target, uint256 x) casts a caller-supplied address
    to an interface and calls it — the target is not resolvable at analysis
    time and must be reported as such, never as static.
    """
    fn = recon.function_key("pingDynamic", "03_calls.sol")
    fact = recon.find_one_fact("external_call_surface", function=fn)
    assert fact is not None, "consumer cannot find the external_call_surface fact at all"
    assert fact["properties"]["call_type"] == "external"
    assert fact["properties"]["target_status"] == "dynamic"
    assert fact["properties"]["target_status"] != "static_immutable"


# ===========================================================================
# B. User-controlled call data reaching a low-level call
# ===========================================================================

def test_B_parameter_controlled_calldata_reaches_low_level_call(recon: ReconOutput):
    """rawCall(address target, bytes calldata data) forwards `data` directly
    into target.call(data). A consumer must be able to see that the call's
    argument 0 originates from a function parameter, not a literal/constant.
    """
    fn = recon.function_key("rawCall", "03_calls.sol")
    low_level = recon.find_one_fact("low_level_call", caller=fn)
    assert low_level is not None
    assert low_level["properties"]["arguments"] == ["data"]

    dataflow = recon.find_one_fact(
        "call_argument_dataflow", function=fn
    )
    assert dataflow is not None
    assert dataflow["properties"]["origin_kind"] == "parameter"
    assert dataflow["properties"]["origin_name"] == "data"
    assert dataflow["properties"]["argument_expression"] == "data"


# ===========================================================================
# C. call / staticcall / delegatecall must not collapse into one bucket
# ===========================================================================

def test_C_low_level_call_subtypes_are_distinguished(recon: ReconOutput):
    call_fn = recon.function_key("rawCall", "03_calls.sol")
    static_fn = recon.function_key("readOnlyCall", "03_calls.sol")
    delegate_fn = recon.function_key("delegateTo", "03_calls.sol")

    call_fact = recon.find_one_fact("low_level_call", caller=call_fn)
    static_fact = recon.find_one_fact("low_level_call", caller=static_fn)
    delegate_fact = recon.find_one_fact("low_level_call", caller=delegate_fn)

    assert call_fact["properties"]["call_subtype"] == "low_level"
    assert static_fact["properties"]["call_subtype"] == "staticcall"
    assert delegate_fact["properties"]["call_subtype"] == "delegatecall"

    subtypes = {call_fact["properties"]["call_subtype"],
                static_fact["properties"]["call_subtype"],
                delegate_fact["properties"]["call_subtype"]}
    assert len(subtypes) == 3, "consumer would see these three distinct call kinds collapse into one bucket"


# ===========================================================================
# D. Token-transfer capability — hardened: every supporting fact must belong
#    to the SAME function context and must itself be a genuine transfer-style
#    operation (not merely "some asset_operation exists somewhere").
# ===========================================================================

TOKEN_TRANSFER_OPERATIONS = {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "safeBatchTransferFrom"}


def test_D_token_transfer_capability_is_identifiable(recon: ReconOutput):
    fn = recon.function_key("payOut", "06_tokens_callbacks.sol")
    cap = recon.find_one_fact("capability", function=fn, capability="can_transfer_token")
    assert cap is not None
    assert cap["status"] == "derived"  # never asserted as a hard observation
    supporting_ids = cap["properties"]["supporting_facts"]
    assert supporting_ids, "capability must be traceable to underlying facts"

    for sid in supporting_ids:
        supporting = recon.fact(sid)
        assert supporting is not None, f"capability's supporting fact id {sid} must actually resolve"
        # same function context — not just "an asset_operation exists somewhere"
        assert supporting["subject"].get("function") == fn, (
            f"supporting fact {sid} belongs to {supporting['subject'].get('function')!r}, "
            f"not the function the capability is attached to ({fn!r})"
        )
        assert supporting["type"] == "asset_operation"
        assert supporting["properties"]["operation"] in TOKEN_TRANSFER_OPERATIONS, (
            f"supporting fact's operation {supporting['properties']['operation']!r} "
            f"is not actually a transfer-style operation"
        )

    # negative half of the same contract: a function with NO transfer call
    # must not carry this capability, even though it lives in the same file.
    other_fn = recon.function_key("approveSpender", "06_tokens_callbacks.sol")
    assert recon.find_one_fact("capability", function=other_fn, capability="can_transfer_token") is None, (
        "approveSpender calls .approve(), not .transfer()/.transferFrom() — it must "
        "NOT be reported as having the can_transfer_token capability"
    )


# ===========================================================================
# E. Approval / spender capability — hardened: dataflow must be tied to the
#    EXACT approve() call site (same source location as the asset_operation
#    fact), not merely "some parameter-origin dataflow exists in this function".
# ===========================================================================

def test_E_approval_capability_is_identifiable(recon: ReconOutput):
    fn = recon.function_key("approveSpender", "06_tokens_callbacks.sol")
    cap = recon.find_one_fact("capability", function=fn, capability="can_approve_spender")
    assert cap is not None
    supporting_ids = cap["properties"]["supporting_facts"]
    assert supporting_ids

    approve_op = recon.fact(supporting_ids[0])
    assert approve_op["type"] == "asset_operation"
    assert approve_op["properties"]["operation"] == "approve"
    assert approve_op["subject"]["function"] == fn
    call_site_ast_id = approve_op["source"]["ast_node_id"]

    dataflows = recon.find_facts("call_argument_dataflow", function=fn)
    assert len(dataflows) >= 2, "approve(spender, amount) has two arguments; expected a dataflow fact per argument"

    # every dataflow fact for this function must be about the SAME call site
    # as the approve() operation itself — not just coincidentally present in
    # the same function body.
    for df in dataflows:
        assert df["source"]["ast_node_id"] == call_site_ast_id, (
            "call_argument_dataflow fact is not anchored to the approve() call "
            "site — a consumer could not safely assume it describes the "
            "approval operation's own arguments"
        )
        assert df["properties"]["origin_kind"] == "parameter"

    by_index = {df["properties"]["argument_index"]: df for df in dataflows}
    assert by_index[0]["properties"]["origin_name"] == "spender"
    assert by_index[1]["properties"]["origin_name"] == "amount"


# ===========================================================================
# G. Authorization check + the specific state variable it references
# ===========================================================================

def test_G_authorization_check_references_correct_state_variable(recon: ReconOutput):
    fn = recon.function_key("operatorOnlyAction", "05_authorization_signatures.sol")
    auth = recon.find_one_fact("authorization_check", function=fn)
    assert auth is not None
    assert auth["properties"]["mechanism"] == "require_msg_sender_comparison"

    contract = recon.contract_key("AccessAndSignatures")
    operators_key = recon.state_variable_key("operators", contract_key=contract)
    assert operators_key in auth["properties"]["referenced_state_variables"], (
        "authorization_check must point at the SAME state_variable key the "
        "independent state_variable fact uses, not just a matching name"
    )


# ===========================================================================
# H. Signature recovery / digest construction
# ===========================================================================

def test_H_signature_recovery_and_digest_construction_are_identifiable(recon: ReconOutput):
    fn = recon.function_key("verifyAndConsume", "05_authorization_signatures.sol")
    sig = recon.find_one_fact("signature_recovery_operation", function=fn)
    digest = recon.find_one_fact("digest_construction_operation", function=fn)
    assert sig is not None and sig["properties"]["builtin"] == "ecrecover"
    assert digest is not None and digest["properties"]["builtin"] == "keccak256"


# ===========================================================================
# I. Delegatecall surface AND its graph relation together
# ===========================================================================

def test_I_delegatecall_fact_and_graph_edge_agree(recon: ReconOutput):
    fn = recon.function_key("delegateTo", "03_calls.sol")
    fact = recon.find_one_fact("low_level_call", caller=fn)
    assert fact is not None
    assert fact["properties"]["call_subtype"] == "delegatecall"

    fn_node = recon.function_node_via_contract("Caller", "delegateTo")
    delegate_edges = recon.outgoing_edges(fn_node["id"], edge_type="DELEGATES_TO")
    assert len(delegate_edges) == 1, "expected exactly one DELEGATES_TO edge out of delegateTo"
    target_node = recon.node(delegate_edges[0]["target"])
    assert target_node["kind"] == "external_target"

    # cross-check: the graph edge is backed by the exact same fact the
    # consumer already found via facts.jsonl, not a coincidentally-similar one.
    assert fact["id"] in delegate_edges[0]["fact_ids"]


# ===========================================================================
# J. CREATE vs CREATE2 distinguished
# ===========================================================================

def test_J_create_vs_create2_distinguished(recon: ReconOutput):
    plain_fn = recon.function_key("deployPlain", "09_proxy_create.sol")
    det_fn = recon.function_key("deployDeterministic", "09_proxy_create.sol")

    plain_creation = recon.find_one_fact("contract_creation", function=plain_fn)
    det_creation = recon.find_one_fact("contract_creation", function=det_fn)
    assert plain_creation is not None
    assert det_creation is not None

    # CREATE2 is distinguished by an accompanying salt-option fact that CREATE
    # (plain `new X(...)`) never gets.
    plain_salt = recon.find_facts("special_evm_feature", function=plain_fn)
    det_salt = recon.find_one_fact("special_evm_feature", function=det_fn)
    assert not any(f["properties"].get("feature") == "create2_salt_option" for f in plain_salt)
    assert det_salt is not None
    assert det_salt["properties"]["feature"] == "create2_salt_option"

    # graph identity: anchor on the (unambiguous) declaring contract and
    # follow DECLARES rather than a bare global label search.
    plain_node = recon.function_node_via_contract("Factory", "deployPlain")
    det_node = recon.function_node_via_contract("Factory", "deployDeterministic")
    assert len(recon.outgoing_edges(plain_node["id"], edge_type="CREATES")) == 1
    assert len(recon.outgoing_edges(det_node["id"], edge_type="CREATES")) == 1


# ===========================================================================
# K. State read/write connected to the correct function, including a
#    non-Assignment write (array push) — not just simple `x = v`.
# ===========================================================================

def test_K_state_writes_connect_to_correct_function_including_array_push(recon: ReconOutput):
    deposit_fn = recon.function_key("deposit", "04_data_structures.sol")
    writes = recon.find_facts("state_write", function=deposit_fn)
    written_names = {f["subject"]["name"] for f in writes}
    assert "accounts" in written_names   # accounts[msg.sender].balance += amount
    assert "history" in written_names    # history.push(amount) — not an Assignment node

    read_fn = recon.function_key("readBalance", "04_data_structures.sol")
    reads = recon.find_facts("state_read", function=read_fn)
    assert any(f["subject"]["name"] == "accounts" for f in reads)
    # readBalance is a view function: it must show zero writes
    assert recon.find_facts("state_write", function=read_fn) == []


# ===========================================================================
# L. Evidence resolution: fact -> evidence id -> snippet -> byte-exact match
#    against the original fixture source (ground truth).
# ===========================================================================

def test_L_evidence_resolves_byte_exact_to_original_source(recon: ReconOutput):
    fn = recon.function_key("operatorOnlyAction", "05_authorization_signatures.sol")
    auth = recon.find_one_fact("authorization_check", function=fn)
    assert auth["evidence"], "fact must carry at least one evidence id"

    resolved = recon.resolve_evidence(auth["evidence"][0])
    assert resolved["exists"], f"snippet file missing on disk: {resolved['snippet_path']}"
    assert resolved["content"], "snippet file exists but is empty"

    src = auth["source"]
    ground_truth = recon.raw_source_slice(FIXTURES_DIR, src["file"], src["start"], src["end"])
    assert resolved["content"] == ground_truth, (
        "recon's snippet must byte-exactly match the original fixture source "
        "at the offsets the fact itself claims"
    )
    assert "msg.sender" in resolved["content"]

    # a second, independent fact type/fixture — guards against the evidence
    # pipeline being correct only for the one fact type spot-checked above.
    delegate_fn = recon.function_key("delegateTo", "03_calls.sol")
    low_level = recon.find_one_fact("low_level_call", caller=delegate_fn)
    assert low_level["evidence"], "low_level_call fact must also carry evidence"
    resolved2 = recon.resolve_evidence(low_level["evidence"][0])
    assert resolved2["exists"]
    src2 = low_level["source"]
    ground_truth2 = recon.raw_source_slice(FIXTURES_DIR, src2["file"], src2["start"], src2["end"])
    assert resolved2["content"] == ground_truth2
    assert "delegatecall" in resolved2["content"]


# ===========================================================================
# M. Graph traversal across the full relationship set recon claims to expose
# ===========================================================================

def test_M_graph_traversal_declares_calls_reads_writes(recon: ReconOutput):
    # `deposit` is deliberately NOT looked up by a bare label search: several
    # fixtures in this corpus reuse common function names (e.g. both
    # 04_data_structures.sol's Ledger and 07_payable_eth.sol's Vault declare
    # a `deposit`). A real consumer must disambiguate via the unambiguous
    # contract node and follow DECLARES, exactly as demonstrated here.
    contract_node = recon.node_by_label("Ledger", kind="contract")
    deposit_node = recon.function_node_via_contract("Ledger", "deposit")
    declares = recon.outgoing_edges(contract_node["id"], edge_type="DECLARES")
    assert any(e["target"] == deposit_node["id"] for e in declares), \
        "contract -> DECLARES -> function must be traversable"

    accounts_node = recon.node_by_label("accounts", kind="state_variable")
    write_edges = recon.outgoing_edges(deposit_node["id"], edge_type="WRITES")
    assert any(e["target"] == accounts_node["id"] for e in write_edges), \
        "function -> WRITES -> state must be traversable"

    helper_caller_node = recon.function_node_via_contract("Caller", "useHelper")
    helper_node = recon.function_node_via_contract("Caller", "_helper")
    calls_edges = recon.outgoing_edges(helper_caller_node["id"], edge_type="CALLS")
    assert any(e["target"] == helper_node["id"] for e in calls_edges), \
        "function -> CALLS -> function must be traversable for internal calls"


def test_M_graph_traversal_creates_and_delegates_to(recon: ReconOutput):
    deploy_node = recon.function_node_via_contract("Factory", "deployPlain")
    creates_edges = recon.outgoing_edges(deploy_node["id"], edge_type="CREATES")
    assert len(creates_edges) == 1
    creation_target = recon.node(creates_edges[0]["target"])
    assert creation_target["kind"] == "creation_target"

    delegate_node = recon.function_node_via_contract("Caller", "delegateTo")
    delegates_edges = recon.outgoing_edges(delegate_node["id"], edge_type="DELEGATES_TO")
    assert len(delegates_edges) == 1
    external_target = recon.node(delegates_edges[0]["target"])
    assert external_target["kind"] == "external_target"
    # cross-check the edge is backed by the exact low_level_call fact found
    # independently via facts.jsonl in test_I / test_M above, not a
    # coincidentally-similar one.
    delegate_fn = recon.function_key("delegateTo", "03_calls.sol")
    low_level = recon.find_one_fact("low_level_call", caller=delegate_fn)
    assert low_level["id"] in delegates_edges[0]["fact_ids"]


# ===========================================================================
# Cross-cutting: no security-judgment vocabulary leaks into what a consumer
# would read (regression guard on the scope boundary itself).
# ===========================================================================

def test_no_security_judgment_vocabulary_visible_to_consumer(recon: ReconOutput):
    banned = ("vulnerab", "exploit", "attack", "severity", "mitigat", "recommend")
    for f in recon.facts:
        assert not any(term in f["type"] for term in banned), f
    for e in recon.graph["edges"]:
        assert not any(term in e["type"] for term in banned), e


# ===========================================================================
# DOCUMENTED GAP (xfail, not patched): CREATE2's contract_creation fact loses
# target_type because `new X{salt: s}(...)` wraps the NewExpression in a
# FunctionCallOptions node that `_emit_creation` does not unwrap before
# reading `.typeName`. Plain `new X(...)` (no options) is unaffected. Marked
# strict=True: if a future recon change fixes this, this test will fail loudly
# and must be updated/removed rather than silently staying green.
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="known gap: contract_creation.target_type is null for CREATE2 (salt-optioned `new` expressions); see module docstring")
def test_gap_documented_create2_target_type_is_null(recon: ReconOutput):
    det_fn = recon.function_key("deployDeterministic", "09_proxy_create.sol")
    det_creation = recon.find_one_fact("contract_creation", function=det_fn)
    assert det_creation["properties"]["target_type"] == "contract Thing"


# ===========================================================================
# DOCUMENTED GAP (not xfail — not a bug, an uncovered code path): the
# `callback_capable_call` fact type is implemented in expr_analysis.py but no
# fixture in the existing corpus contains a call SITE targeting an
# IERC721Receiver/IERC1155Receiver/ERC777-typed expression (fixture
# 06_tokens_callbacks.sol only IMPLEMENTS such an interface, never calls one).
# This test documents that category F is currently unverifiable from the
# existing fixture corpus, without adding a new fixture (out of scope here)
# or inventing a schema field.
# ===========================================================================

def test_gap_documented_callback_surface_has_no_fixture_coverage(recon: ReconOutput):
    callback_facts = recon.facts_of_type("callback_capable_call")
    assert callback_facts == [], (
        "if this starts failing, a fixture now exercises the callback-capable-call "
        "path — category F should be promoted to a real positive assertion above"
    )
