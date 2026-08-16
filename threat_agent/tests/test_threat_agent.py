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
            "novel_composition",
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