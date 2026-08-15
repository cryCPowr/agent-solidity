"""Recon pipeline test suite.

Runs the pipeline once against tests/fixtures/ and asserts on the resulting
facts.jsonl / graph.json / metadata.json / summary.json. Covers section 27
(positive coverage across generic fixtures) and section 28 (negative tests:
the analyzer must not over-infer from names/comments).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")


@pytest.fixture(scope="session")
def recon_output(tmp_path_factory):
    sys.path.insert(0, REPO_ROOT)
    from recon.pipeline import run

    out_dir = str(tmp_path_factory.mktemp("recon_out"))
    ctx = run(FIXTURES_DIR, out_dir)

    facts = [json.loads(line) for line in open(os.path.join(out_dir, "facts.jsonl"))]
    graph = json.load(open(os.path.join(out_dir, "graph.json")))
    metadata = json.load(open(os.path.join(out_dir, "metadata.json")))
    summary = json.load(open(os.path.join(out_dir, "summary.json")))
    schema = json.load(open(os.path.join(out_dir, "schema.json")))

    return {
        "dir": out_dir,
        "ctx": ctx,
        "facts": facts,
        "graph": graph,
        "metadata": metadata,
        "summary": summary,
        "schema": schema,
    }


def _facts_of_type(facts, ftype):
    return [f for f in facts if f["type"] == ftype]


def _find(facts, ftype, **subject_match):
    for f in facts:
        if f["type"] != ftype:
            continue
        if all(f["subject"].get(k) == v for k, v in subject_match.items()):
            return f
    return None


def _function_key(facts, name, file_substring):
    for f in facts:
        if (
            f["type"] == "function_exists"
            and f["subject"]["name"] == name
            and file_substring in f["source"]["file"]
        ):
            return f["subject"]["function"]
    raise AssertionError(f"no function_exists fact found for name={name!r} in file~={file_substring!r}")


def _nodes_by_label(graph, kind=None):
    return {
        n["label"]: n
        for n in graph["nodes"]
        if kind is None or n["kind"] == kind
    }


# ---------------------------------------------------------------------------
# Section 26/29: compiler robustness + coverage reporting
# ---------------------------------------------------------------------------

def test_all_fixtures_compile_and_analysis_completes(recon_output):
    metadata = recon_output["metadata"]
    assert metadata["analysis_status"] == "complete", metadata
    assert len(metadata["files_failed"]) == 0
    assert len(metadata["files_analyzed"]) == 13


def test_no_hard_compiler_errors(recon_output):
    hard_errors = [e for e in recon_output["metadata"]["errors"] if e.get("severity") == "error"]
    assert hard_errors == []


# ---------------------------------------------------------------------------
# Section 20/24/25: no security-judgment vocabulary, facts have valid status
# ---------------------------------------------------------------------------

BANNED_TERMS = ("vulnerab", "exploit", "attack", "severity", "mitigat", "recommend")


def test_no_security_judgment_vocabulary_in_analyzer_output(recon_output):
    """The only place a banned term may legitimately appear is inside a raw
    `name`/`condition`/`snippet` field that is a verbatim copy of the
    source text (e.g. a variable literally named `exploitTarget` in the
    negative fixture). It must never appear in a `type` or as an
    analyzer-authored judgment.
    """
    for f in recon_output["facts"]:
        assert not any(term in f["type"] for term in BANNED_TERMS), f
    for e in recon_output["graph"]["edges"]:
        assert not any(term in e["type"] for term in BANNED_TERMS), e


def test_all_fact_statuses_are_valid(recon_output):
    valid = {"observed", "derived", "unknown", "partial"}
    for f in recon_output["facts"]:
        assert f["status"] in valid, f


def test_facts_are_deterministic_and_sorted(recon_output):
    ids = [f["id"] for f in recon_output["facts"]]
    assert ids == sorted(ids), "facts.jsonl must be sorted by id for determinism"
    assert len(ids) == len(set(ids)), "fact ids must be unique"


# ---------------------------------------------------------------------------
# Section 6/7: contract & function inventory
# ---------------------------------------------------------------------------

def test_simple_contract_inventory(recon_output):
    facts = recon_output["facts"]
    contract = _find(facts, "contract_exists", name="SimpleStore")
    assert contract is not None
    assert contract["properties"]["kind"] == "contract"
    assert contract["status"] == "observed"

    setval = _find(facts, "function_exists", name="setValue")
    assert setval is not None
    assert setval["properties"]["signature"] == "setValue(uint256)"

    modifier_fact = _find(facts, "modifier_usage", function=setval["subject"]["function"])
    assert modifier_fact is not None
    assert modifier_fact["properties"] == {} or "modifier_name" in modifier_fact["subject"]
    assert modifier_fact["subject"]["modifier_name"] == "onlyOwner"


def test_every_fact_with_source_has_resolvable_evidence(recon_output):
    evidence_ids = set()
    for f in recon_output["facts"]:
        evidence_ids.update(f["evidence"])
    # every referenced evidence id must correspond to an actual snippet file
    out_dir = recon_output["dir"]
    # Evidence isn't a top-level file; reconstruct snippet paths from facts.
    missing = []
    for f in recon_output["facts"]:
        for evid in f["evidence"]:
            snippet_glob = evid.split(":")[1] + ".sol.txt"
            path = os.path.join(out_dir, "snippets", snippet_glob)
            if not os.path.exists(path):
                missing.append((f["id"], evid))
    assert missing == [], f"facts reference evidence with no snippet file: {missing[:5]}"


# ---------------------------------------------------------------------------
# Section 6: inheritance / interface implementation (fixture 02)
# ---------------------------------------------------------------------------

def test_inheritance_and_interface_implementation_edges(recon_output):
    graph = recon_output["graph"]
    nodes = _nodes_by_label(graph, "contract")
    inherits_edges = [e for e in graph["edges"] if e["type"] == "INHERITS"]
    implements_edges = [e for e in graph["edges"] if e["type"] == "IMPLEMENTS"]

    assert any(
        e["source"] == nodes["EnglishGreeter"]["id"] and e["target"] == nodes["BaseGreeter"]["id"]
        for e in inherits_edges
    )
    assert any(
        e["source"] == nodes["BaseGreeter"]["id"] and e["target"] == nodes["IGreeter"]["id"]
        for e in implements_edges
    )
    assert any(
        e["source"] == nodes["Marketplace"]["id"] and e["target"] == nodes["IERC721Receiver"]["id"]
        for e in implements_edges
    )


def test_overloaded_functions_get_distinct_signatures(recon_output):
    combine_facts = [
        f for f in recon_output["facts"]
        if f["type"] == "function_exists" and f["subject"]["name"] == "combine"
    ]
    signatures = {f["properties"]["signature"] for f in combine_facts}
    assert signatures == {"combine(uint256,uint256)", "combine(uint256,uint256,uint256)"}


def test_overridden_function_is_flagged(recon_output):
    greet_facts = [
        f for f in recon_output["facts"]
        if f["type"] == "function_exists" and f["subject"]["name"] == "greet"
    ]
    impl = [f for f in greet_facts if f["properties"]["has_body"]]
    assert len(impl) == 1
    assert impl[0]["properties"]["overrides_base"] is True


# ---------------------------------------------------------------------------
# Section 11: call graph (fixture 03)
# ---------------------------------------------------------------------------

def test_internal_call_graph_edge(recon_output):
    graph = recon_output["graph"]
    functions = _nodes_by_label(graph, "function")
    calls_edges = [e for e in graph["edges"] if e["type"] == "CALLS"]
    assert any(
        e["source"] == functions["useHelper"]["id"] and e["target"] == functions["_helper"]["id"]
        for e in calls_edges
    )


def test_low_level_call_classification(recon_output):
    facts = recon_output["facts"]
    raw_call = _find(facts, "low_level_call", caller="03_calls.sol#302::rawCall#246")
    assert raw_call is not None
    assert raw_call["properties"]["call_subtype"] == "low_level"
    assert raw_call["properties"]["target_status"] == "dynamic"

    delegate = _find(facts, "low_level_call", caller="03_calls.sol#302::delegateTo#264")
    assert delegate["properties"]["call_subtype"] == "delegatecall"

    static = _find(facts, "low_level_call", caller="03_calls.sol#302::readOnlyCall#282")
    assert static["properties"]["call_subtype"] == "staticcall"


def test_dynamic_call_target_never_marked_static(recon_output):
    facts = recon_output["facts"]
    fn_key = _function_key(facts, "pingDynamic", "03_calls.sol")
    dynamic_ping = _find(facts, "external_call_surface", function=fn_key)
    assert dynamic_ping is not None
    assert dynamic_ping["properties"]["target_status"] == "dynamic"


def test_nested_internal_then_external_call_chain(recon_output):
    facts = recon_output["facts"]
    fn_key = _function_key(facts, "chained", "03_calls.sol")
    chained_internal = _find(facts, "internal_call", caller=fn_key)
    chained_external = _find(facts, "external_call_surface", function=fn_key)
    assert chained_internal is not None and chained_internal["status"] == "observed"
    assert chained_external is not None


# ---------------------------------------------------------------------------
# Section 10: state read/write, mappings, arrays, structs (fixture 04)
# ---------------------------------------------------------------------------

def test_mapping_and_struct_field_write_resolves_to_root_state_var(recon_output):
    facts = recon_output["facts"]
    writes = [
        f for f in facts
        if f["type"] == "state_write" and f["subject"].get("function") == "04_data_structures.sol#394::deposit#348"
    ]
    names = {f["subject"]["name"] for f in writes}
    assert "accounts" in names  # accounts[msg.sender].balance += ... / .active = true
    assert "history" in names  # history.push(amount)


def test_array_push_recorded_as_state_write(recon_output):
    facts = recon_output["facts"]
    mutation = _find(facts, "array_mutation", function="04_data_structures.sol#394::addMember#360")
    assert mutation is not None
    assert mutation["properties"]["operation"] == "push"
    write = [
        f for f in facts
        if f["type"] == "state_write"
        and f["subject"].get("function") == "04_data_structures.sol#394::addMember#360"
        and f["subject"]["name"] == "members"
    ]
    assert len(write) == 1


def test_delete_marks_write(recon_output):
    facts = recon_output["facts"]
    fn_key = _function_key(facts, "clearAccount", "04_data_structures.sol")
    writes = [
        f for f in facts
        if f["type"] == "state_write" and f["subject"].get("function") == fn_key
    ]
    assert any(f["subject"]["name"] == "accounts" for f in writes)


# ---------------------------------------------------------------------------
# Section 15/16: authorization + signature verification (fixture 05)
# ---------------------------------------------------------------------------

def test_authorization_check_records_referenced_state_variable(recon_output):
    facts = recon_output["facts"]
    check = _find(facts, "authorization_check", function="05_authorization_signatures.sol#520::operatorOnlyAction#455")
    assert check is not None
    assert check["status"] == "derived"
    assert any("operators" in v for v in check["properties"]["referenced_state_variables"])


def test_signature_recovery_and_digest_construction_facts(recon_output):
    facts = recon_output["facts"]
    sig = _find(facts, "signature_recovery_operation", function="05_authorization_signatures.sol#520::verifyAndConsume#519")
    digest = _find(facts, "digest_construction_operation", function="05_authorization_signatures.sol#520::verifyAndConsume#519")
    assert sig is not None and sig["properties"]["builtin"] == "ecrecover"
    assert digest is not None and digest["properties"]["builtin"] == "keccak256"


# ---------------------------------------------------------------------------
# Section 14: ERC20/721/1155-style asset operations + callback surface (fixture 06)
# ---------------------------------------------------------------------------

def test_erc20_style_operations_marked_derived_not_observed(recon_output):
    facts = recon_output["facts"]
    op = _find(facts, "asset_operation", function="06_tokens_callbacks.sol#727::payOut#632")
    assert op is not None
    assert op["status"] == "derived"  # name-pattern heuristic, never asserted as fact
    assert "not verified" in op["properties"]["note"]


def test_erc721_and_erc1155_operations_present(recon_output):
    facts = recon_output["facts"]
    assert _find(facts, "asset_operation", function="06_tokens_callbacks.sol#727::moveNft#684") is not None
    assert _find(facts, "asset_operation", function="06_tokens_callbacks.sol#727::moveMulti#708") is not None


def test_capability_can_transfer_token(recon_output):
    caps = _facts_of_type(recon_output["facts"], "capability")
    functions_with_cap = {
        c["subject"]["function"] for c in caps if c["subject"]["capability"] == "can_transfer_token"
    }
    assert "06_tokens_callbacks.sol#727::payOut#632" in functions_with_cap


# ---------------------------------------------------------------------------
# Section 14: payable / ETH transfers (fixture 07)
# ---------------------------------------------------------------------------

def test_payable_function_and_eth_transfer_facts(recon_output):
    facts = recon_output["facts"]
    deposit_key = _function_key(facts, "deposit", "07_payable_eth.sol")
    mutability = _find(facts, "function_mutability", function=deposit_key)
    assert mutability["properties"]["state_mutability"] == "payable"

    withdraw_key = _function_key(facts, "withdraw", "07_payable_eth.sol")
    transfer_fact = _find(facts, "eth_transfer", function=withdraw_key)
    assert transfer_fact is not None
    assert transfer_fact["properties"]["member"] == "transfer"

    withdraw_via_call_key = _function_key(facts, "withdrawViaCall", "07_payable_eth.sol")
    call_value_transfer = _find(facts, "eth_transfer", function=withdraw_via_call_key)
    assert call_value_transfer is not None
    assert call_value_transfer["properties"]["member"] == "call{value:}"


def test_receive_and_fallback_functions_inventoried(recon_output):
    facts = recon_output["facts"]
    kinds = {
        f["properties"]["kind"]
        for f in facts
        if f["type"] == "function_exists" and "07_payable_eth.sol" in f["source"]["file"]
    }
    assert "receive" in kinds
    assert "fallback" in kinds


# ---------------------------------------------------------------------------
# Section 18/20: control flow, try/catch, assembly, unchecked (fixture 08)
# ---------------------------------------------------------------------------

def test_control_flow_constructs_detected(recon_output):
    facts = recon_output["facts"]
    constructs = {
        f["properties"]["construct"]
        for f in facts
        if f["type"] == "control_flow_structure" and "08_control_flow_special.sol" in f["source"]["file"]
    }
    assert {"loop", "if_statement", "try_catch", "unchecked_block"}.issubset(constructs)


def test_assembly_block_detected(recon_output):
    facts = recon_output["facts"]
    asm = [
        f for f in facts
        if f["type"] == "special_evm_feature"
        and f["properties"].get("feature") == "assembly_block"
        and "08_control_flow_special.sol" in f["source"]["file"]
    ]
    assert len(asm) == 1


# ---------------------------------------------------------------------------
# Section 20: proxy-like delegation + create/create2 (fixture 09)
# ---------------------------------------------------------------------------

def test_proxy_fallback_delegatecall_in_assembly_detected(recon_output):
    facts = recon_output["facts"]
    asm = [
        f for f in facts
        if f["type"] == "special_evm_feature" and f["properties"].get("feature") == "assembly_block"
        and "09_proxy_create.sol" in f["source"]["file"]
    ]
    assert len(asm) == 1


def test_create_and_create2_distinguished(recon_output):
    facts = recon_output["facts"]
    plain = _find(facts, "contract_creation", function="09_proxy_create.sol#1120::deployPlain#1085")
    det = _find(facts, "contract_creation", function="09_proxy_create.sol#1120::deployDeterministic#1119")
    assert plain is not None and det is not None
    salt_feature = _find(facts, "special_evm_feature", function="09_proxy_create.sol#1120::deployDeterministic#1119")
    assert salt_feature is not None
    assert salt_feature["properties"]["feature"] == "create2_salt_option"

    caps = _facts_of_type(facts, "capability")
    det_caps = {c["subject"]["capability"] for c in caps if c["subject"]["function"] == det["subject"]["function"]}
    assert "can_create_contracts_deterministically" in det_caps


# ---------------------------------------------------------------------------
# Section 28: negative tests — the analyzer must not over-infer
# ---------------------------------------------------------------------------

def test_name_lookalike_does_not_produce_asset_operation(recon_output):
    """`transfer()` in the negative fixture takes no arguments and touches no
    token/address; it must NOT be classified as an asset_operation, even
    though its name matches the ERC20 `transfer` pattern.
    """
    facts = recon_output["facts"]
    fn_key_candidates = [
        f["subject"]["function"] for f in facts
        if f["type"] == "function_exists" and f["subject"]["name"] == "transfer"
        and "10_negative.sol" in f["source"]["file"]
    ]
    assert fn_key_candidates, "expected to find the lookalike transfer() function"
    fn_key = fn_key_candidates[0]
    asset_ops = [f for f in facts if f["type"] == "asset_operation" and f["subject"].get("function") == fn_key]
    assert asset_ops == []


def test_comment_claiming_fake_behavior_produces_no_matching_fact(recon_output):
    """The comment on `_rekt()` claims it drains a vault, but the body is
    pure arithmetic. No call/asset/external-call fact should be attached to
    this function.
    """
    facts = recon_output["facts"]
    fn_key_candidates = [
        f["subject"]["function"] for f in facts
        if f["type"] == "function_exists" and f["subject"]["name"] == "_rekt"
    ]
    assert fn_key_candidates
    fn_key = fn_key_candidates[0]
    suspicious_types = {"asset_operation", "external_call", "low_level_call", "eth_transfer", "internal_call"}
    matches = [f for f in facts if f["subject"].get("function") == fn_key and f["type"] in suspicious_types]
    assert matches == []


def test_dynamically_derived_call_target_marked_dynamic_not_resolved(recon_output):
    facts = recon_output["facts"]
    call = _find(facts, "low_level_call", caller="10_negative.sol#1199::callDerivedAddress#1198")
    assert call is not None
    assert call["properties"]["target_status"] == "dynamic"
    assert call["properties"]["target_function"] is None


def test_unrelated_similarly_named_contract_is_keyed_separately(recon_output):
    """Two different `Owned`-style / lookalike contracts must never be
    merged: facts must be keyed by contract_key (file+AST id), not by name.
    """
    facts = recon_output["facts"]
    owned_contracts = [
        f for f in facts if f["type"] == "contract_exists" and f["subject"]["name"] == "Owned"
    ]
    assert len(owned_contracts) == 1
    owned = owned_contracts[0]
    # It must have no functions, no state writes, no authorization checks —
    # it is just a struct-free contract with a single string constant.
    contract_key = owned["subject"]["contract"]
    assoc_functions = [
        f for f in facts if f["type"] == "function_exists" and f["subject"]["contract"] == contract_key
    ]
    assert assoc_functions == []


def test_struct_field_named_owner_is_not_treated_as_access_control(recon_output):
    """`Metadata.owner` is a struct field on an unrelated type, not a
    contract-level access-control variable. Writing `info.label` must not
    produce any authorization_check or capability fact.
    """
    facts = recon_output["facts"]
    fn_key_candidates = [
        f["subject"]["function"] for f in facts
        if f["type"] == "function_exists" and f["subject"]["name"] == "setLabel"
        and "10_negative.sol" in f["source"]["file"]
    ]
    assert fn_key_candidates
    fn_key = fn_key_candidates[0]
    auth_facts = [
        f for f in facts if f["subject"].get("function") == fn_key and f["type"] == "authorization_check"
    ]
    assert auth_facts == []


# ---------------------------------------------------------------------------
# Section 24: determinism
# ---------------------------------------------------------------------------

def test_rerun_produces_identical_facts_and_graph(tmp_path):
    sys.path.insert(0, REPO_ROOT)
    from recon.pipeline import run

    out1 = str(tmp_path / "run1")
    out2 = str(tmp_path / "run2")
    run(FIXTURES_DIR, out1)
    run(FIXTURES_DIR, out2)

    facts1 = open(os.path.join(out1, "facts.jsonl")).read()
    facts2 = open(os.path.join(out2, "facts.jsonl")).read()
    assert facts1 == facts2

    graph1 = json.load(open(os.path.join(out1, "graph.json")))
    graph2 = json.load(open(os.path.join(out2, "graph.json")))
    assert graph1 == graph2


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

def test_cli_runs_end_to_end(tmp_path):
    out_dir = str(tmp_path / "cli_out")
    proc = subprocess.run(
        [sys.executable, "-m", "recon.cli", FIXTURES_DIR, "-o", out_dir],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    assert os.path.exists(os.path.join(out_dir, "facts.jsonl"))
    assert os.path.exists(os.path.join(out_dir, "graph.json"))
    assert os.path.exists(os.path.join(out_dir, "schema.json"))
    assert os.path.exists(os.path.join(out_dir, "metadata.json"))
    assert os.path.exists(os.path.join(out_dir, "summary.json"))
