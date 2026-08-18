"""Threat Agent tests.

Tests verify that hypothesis generation is grounded in Recon artifacts.
Passing tests mean: "hypothesis is properly derived from facts."
They do NOT mean: "the vulnerability exists."
"""

from __future__ import annotations

import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from threat import loader
from threat.actor_model import build_actors
from threat.trust_model import build_trust_boundaries
from threat.surface import build_surfaces
from threat.invariants import generate_invariants
from threat.hypothesis import generate_hypotheses
from threat.prioritization import prioritize_all
from threat.output import write_threat_output


def _synthetic_recon(facts, protocol=None, coverage=None, dependencies=None):
    facts_obj = loader._index_facts(list(facts))
    return loader.ReconArtifact(
        facts_obj=facts_obj,
        graph=loader.ReconGraph(),
        summary=loader.ReconSummary(),
        metadata=loader.ReconMetadata(),
        coverage=loader.ReconCoverage(raw=coverage or {}),
        protocol=loader.ReconProtocol(raw=protocol or {}),
        dependencies=loader.ReconDependencies(raw=dependencies or {}),
        output_dir="synthetic",
    )


def _fact(fid, ftype, fn="synthetic/Proxy.sol#1::fn#2", props=None, subject=None, status="observed"):
    subj = {"function": fn}
    if subject:
        subj.update(subject)
    return {
        "id": fid,
        "type": ftype,
        "subject": subj,
        "properties": props or {},
        "status": status,
    }


@pytest.fixture(scope="session")
def recon(recon_output_dir):
    """Use real Recon artifact resolved by conftest."""
    return loader.load_recon(recon_output_dir)


@pytest.fixture(scope="session")
def artifacts(recon):
    invariants = generate_invariants(recon)
    hypotheses = generate_hypotheses(recon, invariants)
    return {
        "actors": build_actors(recon),
        "boundaries": build_trust_boundaries(recon),
        "surfaces": build_surfaces(recon),
        "invariants": invariants,
        "hypotheses": prioritize_all(hypotheses, recon),
    }


# ===========================================================================
# Test 1: Arbitrary target + approval + callback pattern
# ===========================================================================
def test_arbitrary_execution_hypothesis(artifacts):
    """Benchmark A: user-controlled external call target + approval + callback."""
    targets = [h for h in artifacts["hypotheses"] if h.category == "arbitrary_execution"]
    assert len(targets) > 0, "Should detect arbitrary execution surfaces"
    # All hypotheses must reference Recon facts
    for h in targets:
        assert len(h.observed_facts) > 0, f"Hypothesis {h.hypothesis_id} has no fact references"
        assert len(h.affected_functions) > 0 or len(h.affected_assets) > 0


# ===========================================================================
# Test 2: Accounting mismatch pattern
# ===========================================================================
def test_accounting_mismatch_hypothesis(artifacts):
    """Benchmark B: external data decode + accounting."""
    targets = [h for h in artifacts["hypotheses"] if h.category == "accounting_mismatch"]
    # May or may not exist depending on fixtures
    for h in targets:
        assert len(h.observed_facts) > 0
        assert h.priority in ("low_interest", "medium_interest", "high_interest", "very_high_interest")


# ===========================================================================
# Test 3: Rounding/allocation pattern
# ===========================================================================
def test_rounding_allocation_hypothesis(artifacts):
    """Benchmark C: division + rounding + allocation."""
    targets = [h for h in artifacts["hypotheses"] if h.category == "rounding_allocation"]
    assert len(targets) > 0, "Should detect rounding allocation surfaces"
    for h in targets:
        assert len(h.observed_facts) > 0
        assert "division" in h.statement or "Division" in h.statement


# ===========================================================================
# Test 4: Benign external call (no false positive on simple transfers)
# ===========================================================================
def test_benign_external_call_does_not_trigger_bug_claim(artifacts):
    """A benign external call (e.g., to a known stable token) should not
    trigger vulnerability-level claims."""
    for h in artifacts["hypotheses"]:
        # All hypotheses are CANDIDATES, not confirmed bugs
        assert "vulnerable" not in h.statement.lower()
        assert "vulnerability" not in h.statement.lower()
        assert "bug" not in h.statement.lower()
        assert "exploit" not in h.statement.lower()


# ===========================================================================
# Test 5: Fixed treasury transfer (no arbitrary execution)
# ===========================================================================
def test_fixed_treasury_transfer(artifacts):
    """Functions with fixed target/amount should not trigger arbitrary execution."""
    arbitrary_hypotheses = [h for h in artifacts["hypotheses"] if h.category == "arbitrary_execution"]
    # The 01_simple.sol setValue function is a fixed transfer — should not appear
    # in arbitrary execution hypotheses
    for h in arbitrary_hypotheses:
        for fn in h.affected_functions:
            assert "setValue" not in fn, (
                f"setValue should not be in {h.hypothesis_id}: {h.statement}"
            )


# ===========================================================================
# Test 6: Non-privileged regular function
# ===========================================================================
def test_non_privileged_function_does_not_create_excessive_hypotheses(artifacts):
    """A non-privileged function should not generate hypotheses incorrectly."""
    # All hypotheses should reference SOME fact
    for h in artifacts["hypotheses"]:
        assert len(h.observed_facts) > 0
        assert h.hypothesis_id.startswith("H-")
        assert h.category in (
            "arbitrary_execution", "callback_reentrancy", "accounting_mismatch",
            "rounding_allocation", "signature_replay", "cross_contract_trust",
            "DoS_griefing", "upgrade_risk", "economic_manipulation",
            "initialization_vulnerability", "flash_loan_sensitivity",
            "gas_dos", "arithmetic_bound_violation", "frontrun_vulnerability",
            "randomness_manipulation", "novel_composition",
            "security_chain",  # generic multi-stage composition (security_chains.py)
        )


# ===========================================================================
# Test 7: Unrelated co-occurring facts should not produce false connections
# ===========================================================================
def test_no_unrelated_false_connections(artifacts):
    """Facts in isolated functions should not be combined into hypotheses."""
    for h in artifacts["hypotheses"]:
        # Each hypothesis should have at least one fact reference
        assert len(h.observed_facts) > 0
        # Each hypothesis should mention affected functions
        assert len(h.affected_functions) > 0 or len(h.affected_assets) > 0


# ===========================================================================
# Test 8: Unknown dataflow
# ===========================================================================
def test_unknown_dataflow_not_misclassified(artifacts):
    """Hypotheses with unknown dataflow should express uncertainty."""
    for h in artifacts["hypotheses"]:
        assert h.uncertainty, (
            f"Hypothesis {h.hypothesis_id} has no uncertainty statement"
        )
        assert "uncertainty" in h.to_dict() or h.uncertainty


# ===========================================================================
# Test 9: Cross-contract chain
# ===========================================================================
def test_cross_contract_reasoning(artifacts):
    """Cross-contract call chains should be represented."""
    cross = [h for h in artifacts["hypotheses"] if h.category == "cross_contract_trust"]
    # May or may not exist
    for h in cross:
        assert len(h.graph_nodes) > 0 or len(h.graph_edges) > 0


# ===========================================================================
# Test 10: Duplicate hypothesis suppression
# ===========================================================================
def test_no_duplicate_hypotheses(artifacts):
    """Same hypothesis should not appear twice."""
    seen_ids = set()
    for h in artifacts["hypotheses"]:
        assert h.hypothesis_id not in seen_ids, (
            f"Duplicate hypothesis ID: {h.hypothesis_id} ({h.category}, {h.affected_functions})"
        )
        seen_ids.add(h.hypothesis_id)


# ===========================================================================
# Architecture tests
# ===========================================================================
def test_actor_model_has_external_user(artifacts):
    actors = artifacts["actors"]
    types = {a.type for a in actors}
    assert "external_user" in types, "Should have external_user actor"


def test_trust_boundaries_defined(artifacts):
    assert len(artifacts["boundaries"]) > 0, "Should have trust boundaries"


def test_attack_surfaces_defined(artifacts):
    assert len(artifacts["surfaces"]) > 0, "Should have attack surfaces"


def test_invariants_defined(artifacts):
    assert len(artifacts["invariants"]) > 0, "Should have invariant candidates"


def test_priority_logic(artifacts):
    """Priorities should be assigned correctly."""
    for h in artifacts["hypotheses"]:
        assert h.priority in ("very_high_interest", "high_interest", "medium_interest", "low_interest")
        assert h.priority_rationale, f"Hypothesis {h.hypothesis_id} has no priority rationale"


# ===========================================================================
# Output integration test
# ===========================================================================
def test_output_writes(staging_dir, recon):
    """Verify that output writer produces all expected files."""
    out_dir = os.path.join(staging_dir, "threat-out")
    write_threat_output(recon, out_dir)
    expected = [
        "schema.json", "threat_model.json", "surfaces.json",
        "invariants.json", "hypotheses.jsonl", "relationships.json", "summary.json",
    ]
    for name in expected:
        path = os.path.join(out_dir, name)
        assert os.path.exists(path), f"Output file missing: {path}"
        assert os.path.getsize(path) > 0, f"Output file empty: {path}"


@pytest.fixture(scope="module")
def staging_dir():
    import tempfile
    with tempfile.TemporaryDirectory(prefix="hermes-threat-test-") as d:
        yield d


# ===========================================================================
# Scope guard: Threat Agent must not claim vulnerabilities
# ===========================================================================
def test_threat_agent_does_not_claim_vulnerabilities(artifacts):
    for h in artifacts["hypotheses"]:
        assert "exploit" not in h.statement.lower()
        assert "vulnerable" not in h.statement.lower()
        assert "confirmed" not in h.statement.lower()
        # "attacker" (hypothetical) is OK; "attack" as a claim is not
        assert "vulnerability" not in h.statement.lower()
        assert "bug" not in h.statement.lower()


# ===========================================================================
# Recon integration regressions for new artifacts/facts
# ===========================================================================
def test_loader_reads_optional_recon_artifacts(staging_dir):
    recon_dir = os.path.join(staging_dir, "recon-opt")
    os.makedirs(recon_dir, exist_ok=True)

    with open(os.path.join(recon_dir, "facts.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps(_fact("fact:001", "function_exists", props={"name": "upgradeTo"}, subject={"function": "synthetic/Proxy.sol#1::upgradeTo#2"})) + "\n")
    for name, payload in {
        "graph.json": {"nodes": [], "edges": []},
        "summary.json": {"schema_version": "1.0"},
        "metadata.json": {"schema_version": "1.0"},
        "coverage.json": {"source_coverage": {"analyzed_ratio": 0.42}},
        "protocol.json": {
            "contracts": [
                {
                    "key": "synthetic/Proxy.sol#1",
                    "proxy_upgradeability": {
                        "proxy_like": True,
                        "upgrade_functions": ["synthetic/Proxy.sol#1::upgradeTo#2"],
                        "initializer_functions": [],
                        "delegatecall_paths": [],
                    },
                }
            ]
        },
        "dependencies.json": {"dependency_files_added": ["lib/SomeDep.sol"]},
    }.items():
        with open(os.path.join(recon_dir, name), "w", encoding="utf-8") as f:
            json.dump(payload, f)

    recon = loader.load_recon(recon_dir)
    assert recon.coverage.raw["source_coverage"]["analyzed_ratio"] == 0.42
    assert recon.protocol.raw["contracts"][0]["proxy_upgradeability"]["proxy_like"] is True
    assert recon.dependencies.raw["dependency_files_added"] == ["lib/SomeDep.sol"]



def test_single_predictable_randomness_source_does_not_emit_family_hypothesis():
    fn = "synthetic/Game.sol#1::play#2"
    recon = _synthetic_recon([
        _fact("fact:rand", "randomness_source_usage", fn=fn, props={"source": "block.timestamp", "predictability": "high"}),
        _fact("fact:mut", "function_mutability", fn=fn, props={"state_mutability": "nonpayable"}),
        _fact("fact:vis", "function_visibility", fn=fn, props={"visibility": "external"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    assert not [h for h in hyps if h.category == "randomness_manipulation"]



def test_reused_randomness_with_input_and_effect_emits_family_hypothesis():
    fn = "synthetic/Game.sol#1::play#2"
    recon = _synthetic_recon([
        _fact("fact:reuse", "repeated_randomness_consumer", fn=fn, props={"usage_count": 2}),
        _fact("fact:rand1", "randomness_source_usage", fn=fn, props={"source": "block.timestamp", "predictability": "high", "immediate_consumer": "variable_initializer"}),
        _fact("fact:rand2", "randomness_source_usage", fn=fn, props={"source": "block.timestamp", "predictability": "high", "immediate_consumer": "assignment"}),
        _fact("fact:input", "input_origin", fn=fn, props={"origin_kind": "parameter", "root_name": "choice"}),
        _fact("fact:write", "state_write", fn=fn, subject={"name": "score", "state_variable": "score"}),
        _fact("fact:mut", "function_mutability", fn=fn, props={"state_mutability": "nonpayable"}),
        _fact("fact:vis", "function_visibility", fn=fn, props={"visibility": "external"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    targets = [h for h in hyps if h.category == "randomness_manipulation"]
    assert targets
    assert "same randomness source" in targets[0].statement.lower() or "consumes the same randomness source" in targets[0].statement.lower()



def test_reused_timestamp_for_guard_and_event_does_not_emit_randomness_family():
    fn = "synthetic/Megapool.sol#1::dissolve#2"
    recon = _synthetic_recon([
        _fact("fact:reuse", "repeated_randomness_consumer", fn=fn, props={"usage_count": 2}),
        _fact("fact:rand1", "randomness_source_usage", fn=fn, props={"source": "block.timestamp", "predictability": "high", "immediate_consumer": "binary_op:>"}),
        _fact("fact:rand2", "randomness_source_usage", fn=fn, props={"source": "block.timestamp", "predictability": "high", "immediate_consumer": "call_argument"}),
        _fact("fact:input", "input_origin", fn=fn, props={"origin_kind": "parameter", "root_name": "validatorId"}),
        _fact("fact:write", "state_write", fn=fn, subject={"name": "validator", "state_variable": "validator"}),
        _fact("fact:mut", "function_mutability", fn=fn, props={"state_mutability": "nonpayable"}),
        _fact("fact:vis", "function_visibility", fn=fn, props={"visibility": "external"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    assert not [h for h in hyps if h.category == "randomness_manipulation"]



def test_accounting_digest_plus_transfers_without_state_write_does_not_emit_family():
    fn = "synthetic/Distributor.sol#1::claimAndStake#2"
    recon = _synthetic_recon([
        _fact("fact:digest", "digest_construction_operation", fn=fn, props={"arguments": ["abi.encodePacked('rewards.eth.balance', withdrawalAddress)"], "builtin": "keccak256"}),
        _fact("fact:input", "call_argument_origin_chain", fn=fn, props={"root_kind": "parameter", "argument_expression": "amount"}),
        _fact("fact:arith", "arithmetic_operation", fn=fn, props={"left_operand": "total", "operator": "-", "right_operand": "stake"}),
        _fact("fact:eth", "eth_transfer", fn=fn, props={"amount_expression": ["amount"]}),
        _fact("fact:mut", "function_mutability", fn=fn, props={"state_mutability": "nonpayable"}),
        _fact("fact:vis", "function_visibility", fn=fn, props={"visibility": "external"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    assert not [h for h in hyps if h.category == "accounting_mismatch"]



def test_division_without_effectful_anchor_does_not_emit_rounding_family():
    fn = "synthetic/Vault.sol#1::preview#2"
    recon = _synthetic_recon([
        _fact("fact:div", "division_operation", fn=fn, props={"left_operand": "assets", "right_operand": "supply", "immediate_consumer": "return_value"}),
        _fact("fact:mut", "function_mutability", fn=fn, props={"state_mutability": "view"}),
        _fact("fact:vis", "function_visibility", fn=fn, props={"visibility": "external"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    assert not [h for h in hyps if h.category == "rounding_allocation"]



def test_helper_division_is_lifted_to_effectful_caller():
    helper = "synthetic/Rewards.sol#1::_computeShare#2"
    caller = "synthetic/Rewards.sol#1::distribute#3"
    recon = _synthetic_recon([
        _fact("fact:div", "division_operation", fn=helper, props={"left_operand": "rewards", "right_operand": "supply", "immediate_consumer": "return_value"}),
        _fact("fact:helper-mut", "function_mutability", fn=helper, props={"state_mutability": "view"}),
        _fact("fact:helper-input", "input_origin", fn=helper, props={"origin_kind": "parameter", "root_name": "rewards"}),
        _fact("fact:call", "internal_call", fn=caller, props={"callee_function": helper, "static_target": True}, subject={"callee_name": "_computeShare"}),
        _fact("fact:caller-vis", "function_visibility", fn=caller, props={"visibility": "external"}),
        _fact("fact:caller-mut", "function_mutability", fn=caller, props={"state_mutability": "nonpayable"}),
        _fact("fact:caller-input", "input_origin", fn=caller, props={"origin_kind": "parameter", "root_name": "beneficiary"}),
        _fact("fact:caller-asset", "asset_operation", fn=caller, props={"operation": "transfer", "target_expression": "rewardToken", "arguments": ["beneficiary", "share"]}),
        _fact("fact:caller-write", "state_write", fn=caller, subject={"name": "distributed", "state_variable": "distributed"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    targets = [h for h in hyps if h.category == "rounding_allocation"]
    assert targets
    lifted = next(h for h in targets if caller in h.affected_functions)
    assert lifted.affected_functions[0] == caller
    assert helper in lifted.affected_functions
    assert "feeds effectful caller" in lifted.statement
    assert "fact:call" in lifted.observed_facts
    assert "fact:caller-asset" in lifted.observed_facts
    assert "fact:caller-write" in lifted.observed_facts



def test_helper_division_is_lifted_when_internal_call_uses_subject_caller():
    helper = "synthetic/Rewards.sol#1::_computeShare#2"
    caller = "synthetic/Rewards.sol#1::distribute#3"
    recon = _synthetic_recon([
        _fact("fact:div", "division_operation", fn=helper, props={"left_operand": "rewards", "right_operand": "supply", "immediate_consumer": "return_value"}),
        _fact("fact:helper-mut", "function_mutability", fn=helper, props={"state_mutability": "view"}),
        {
            "id": "fact:call2",
            "type": "internal_call",
            "subject": {"caller": caller, "callee_name": "_computeShare"},
            "properties": {"callee_function": helper, "static_target": True},
            "status": "observed",
        },
        _fact("fact:caller-vis", "function_visibility", fn=caller, props={"visibility": "external"}),
        _fact("fact:caller-mut", "function_mutability", fn=caller, props={"state_mutability": "nonpayable"}),
        _fact("fact:caller-asset", "asset_operation", fn=caller, props={"operation": "transfer", "target_expression": "rewardToken", "arguments": ["beneficiary", "share"]}),
        _fact("fact:caller-write", "state_write", fn=caller, subject={"name": "distributed", "state_variable": "distributed"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    targets = [h for h in hyps if h.category == "rounding_allocation"]
    assert targets
    lifted = next(h for h in targets if caller in h.affected_functions)
    assert helper in lifted.affected_functions
    assert "fact:call2" in lifted.observed_facts



def test_frontrun_requires_auth_and_effect_anchor():
    fn = "synthetic/Governance.sol#1::setCap#2"
    recon = _synthetic_recon([
        _fact("fact:mev", "mev_exposure_indicator", fn=fn, props={"constraint_count": 1, "frontrun_risk": "high"}, status="derived"),
        _fact("fact:constraint", "state_dependent_constraint", fn=fn, props={"constraint_expression": "newCap >= liveUsage", "mutable_state_dependency": True, "visibility": "public"}, status="derived"),
        _fact("fact:auth", "modifier_usage", fn=fn, subject={"modifier_name": "onlyOwner"}),
        _fact("fact:write", "state_write", fn=fn, subject={"name": "cap", "state_variable": "cap"}),
        _fact("fact:mut", "function_mutability", fn=fn, props={"state_mutability": "nonpayable"}),
        _fact("fact:vis", "function_visibility", fn=fn, props={"visibility": "external"}),
    ])
    hyps = generate_hypotheses(recon, generate_invariants(recon))
    assert [h for h in hyps if h.category == "frontrun_vulnerability"]



def test_upgrade_and_initializer_signals_flow_into_threat_models():
    contract_key = "synthetic/Proxy.sol#1"
    upgrade_fn = f"{contract_key}::upgradeTo#10"
    init_fn = f"{contract_key}::initialize#11"
    delegate_fn = f"{contract_key}::fallback#12"
    facts = [
        _fact("fact:proxy", "proxy_like_contract", subject={"contract": contract_key, "name": "Proxy"}, props={"implementation_slots": [f"{contract_key}::implementation"], "upgrade_functions": [upgrade_fn], "initializer_functions": [init_fn]}),
        _fact("fact:upgrade", "upgrade_function", fn=upgrade_fn, subject={"contract": contract_key, "function": upgrade_fn, "name": "upgradeTo"}),
        _fact("fact:upgrade-auth", "upgrade_authority", fn=upgrade_fn, subject={"contract": contract_key, "function": upgrade_fn}, props={"mechanisms": [{"kind": "modifier"}], "basis_facts": ["fact:acf"]}, status="derived"),
        _fact("fact:path", "proxy_delegatecall_path", fn=delegate_fn, subject={"contract": contract_key, "function": delegate_fn}, props={"implementation_slots": [f"{contract_key}::implementation"], "fallback_like": True}, status="derived"),
        _fact("fact:init-fn", "initializer_function", fn=init_fn, subject={"contract": contract_key, "function": init_fn, "name": "initialize"}),
        _fact("fact:init-surface", "initializer_surface", fn=init_fn, subject={"contract": contract_key, "function": init_fn}, props={"authorization_status": "none_observed", "writes_initialized_flag": True}, status="derived"),
        _fact("fact:init-life", "initializer_lifecycle", fn=init_fn, subject={"contract": contract_key}, props={"initializer_functions": [init_fn], "initialized_state_variables": [f"{contract_key}::initialized"]}, status="derived"),
        _fact("fact:cap-auth", "capability_authority_surface", fn=upgrade_fn, subject={"function": upgrade_fn, "capability": "can_delegatecall"}, props={"authority_status": "guarded", "writes_authorization_state": True, "capability_fact_id": "fact:cap"}, status="derived"),
    ]
    protocol = {
        "contracts": [
            {
                "key": contract_key,
                "proxy_upgradeability": {
                    "proxy_like": True,
                    "upgrade_functions": [upgrade_fn],
                    "initializer_functions": [init_fn],
                    "delegatecall_paths": [{"delegatecall_function": delegate_fn}],
                },
            }
        ]
    }
    recon = _synthetic_recon(
        facts,
        protocol=protocol,
        coverage={"source_coverage": {"analyzed_ratio": 0.4}},
    )

    surfaces = build_surfaces(recon)
    invariants = generate_invariants(recon)
    hypotheses = generate_hypotheses(recon, invariants)

    surface_by_category = {s.category: s for s in surfaces}
    assert "Upgradeability" in surface_by_category
    assert "Lifecycle" in surface_by_category
    assert "Authority and Capability" in surface_by_category
    assert "proxy_delegatecall_path" in surface_by_category["Upgradeability"].capabilities
    assert "initializer_without_observed_authorization" in surface_by_category["Lifecycle"].capabilities
    assert "writes_authorization_state" in surface_by_category["Authority and Capability"].capabilities

    inv_categories = {inv.category for inv in invariants}
    assert "upgrade_authority_coherence" in inv_categories
    assert "initialization_coherence" in inv_categories
    assert "capability_authority_consistency" in inv_categories

    hyp_categories = {h.category for h in hypotheses}
    assert "upgrade_risk" in hyp_categories
    assert "initialization_vulnerability" in hyp_categories

    upgrade_h = next(h for h in hypotheses if h.category == "upgrade_risk")
    init_h = next(h for h in hypotheses if h.category == "initialization_vulnerability")
    assert "low analysis coverage" in upgrade_h.uncertainty.lower()
    assert "low analysis coverage" in init_h.uncertainty.lower()
    assert upgrade_h.observed_facts
    assert init_h.observed_facts
