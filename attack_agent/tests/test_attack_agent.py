"""Attack Agent tests: path building, strategies, consequences, dedup,
scoring, validator plans, evidence discipline, genericity guards, e2e.

All fixtures are synthetic and generic (see conftest.py).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from attack import relevance, strategies
from attack import attacker as attacker_mod
from attack import consequences, dedup, paths, prioritize
from attack.loader import load_recon, load_threat
from attack.model import INFERRED, POSSIBLE, PROVEN, UNKNOWN
from attack.output import write_attack_output
from attack.pipeline import generate_attacks, select_high_value

from conftest import FN_ENTRY, FN_ROOT, _fact, make_recon_facts, make_threat_hypotheses


# ---------------------------------------------------------------------------
# High-value selection
# ---------------------------------------------------------------------------

def test_selects_high_value_hypotheses(synthetic_threat):
    selected = select_high_value(synthetic_threat)
    ids = {h["hypothesis_id"] for h in selected}
    assert "H-strong0001" in ids
    assert "H-strong0002" in ids          # high_interest
    assert "H-struct0003" not in ids      # low_interest, structural


# ---------------------------------------------------------------------------
# Entry / attacker / relevance
# ---------------------------------------------------------------------------

def test_entry_resolves_to_external_caller(synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    entry = attacker_mod.resolve_entry(synthetic_recon, hyp)
    assert entry["function"] == FN_ENTRY
    assert entry["visibility"] == "external"
    assert entry["status"] == PROVEN
    # no authorization fact on the entry -> stated as absence, not proof
    assert entry["required_role_status"] == INFERRED
    assert "absence of evidence" in attacker_mod.attacker_model(hyp, entry)



def test_entry_resolution_accepts_internal_call_subject_caller(tmp_path):
    import json
    hyp = json.loads(json.dumps(make_threat_hypotheses()[0]))
    hyp["affected_functions"] = [FN_ROOT]
    facts = [f for f in make_recon_facts() if f["id"] != "fact:syn003"]
    facts.append({
        "id": "fact:syn003",
        "type": "internal_call",
        "subject": {"caller": FN_ENTRY, "callee_name": "dispatchFunds"},
        "properties": {"callee_function": FN_ROOT, "static_target": True},
        "status": "observed",
        "source": {"file": "src/Protocol.sol", "line_start": 17, "line_end": 17},
    })
    recon = _recon_from_facts(facts, tmp_path)
    threat = synthetic_threat_like([hyp])
    entry = attacker_mod.resolve_entry(recon, threat.hypotheses[0])
    assert entry["function"] == FN_ENTRY
    assert entry["call_chain"] == [FN_ENTRY, FN_ROOT]
    assert entry["root_reachable"] == PROVEN


def test_relevance_classification_generic():
    assert relevance.classify_path("src/Protocol.sol") == relevance.PRODUCTION
    assert relevance.classify_path("test/Protocol.t.sol") == relevance.TEST_MOCK
    assert relevance.classify_path("contracts/mocks/Double.sol") == relevance.TEST_MOCK
    assert relevance.classify_path("node_modules/lib/Lib.sol") == relevance.DEPENDENCY
    assert relevance.classify_path("") == relevance.UNKNOWN


# ---------------------------------------------------------------------------
# Path building: sink + control + propagation
# ---------------------------------------------------------------------------

def test_sink_prefers_protocol_custody_asset_flow(synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    sink = paths.choose_sink(synthetic_recon, hyp, FN_ROOT)
    assert sink["class"] == "token_approval"
    assert sink["custody"] == "grant"
    assert sink["status"] == PROVEN
    assert sink["fact_id"] == "fact:syn009"
    assert "src/Protocol.sol:23-23" == sink["location"]



def test_accounting_family_demotes_fixed_approval_sink(tmp_path):
    facts = [
        _fact(100, "function_exists", FN_ROOT),
        _fact(101, "function_visibility", FN_ROOT, {"visibility": "external"}, line=20),
        _fact(102, "asset_operation", FN_ROOT, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["getContractAddress(\"fixedSpender\")", "amount"],
        }, line=21),
        _fact(103, "state_write", FN_ROOT, subject_extra={"name": "ledger", "state_variable": "ledger"}, line=22),
        _fact(104, "eth_transfer", FN_ROOT, {}, line=23),
    ]
    recon = _recon_from_facts(facts, tmp_path)
    hyp = {
        "hypothesis_id": "H-accounting",
        "category": "accounting_mismatch",
        "statement": "synthetic accounting lens",
        "actor": "external_user",
        "priority": "high_interest",
        "evidence_tier": "ARGUMENT_DEPENDENCY",
        "observed_facts": ["fact:syn102", "fact:syn103", "fact:syn104"],
        "affected_functions": [FN_ROOT],
        "affected_assets": [],
        "uncertainty": "",
        "preconditions": [],
        "chain": [],
    }
    sink = paths.choose_sink(recon, hyp, FN_ROOT)
    assert sink["class"] in ("state_mutation", "native_value_transfer")
    assert sink["class"] != "token_approval"


def test_controlled_inputs_from_parameter_flows(synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    inputs = paths.controlled_inputs(synthetic_recon, hyp, FN_ROOT)
    assert inputs, "parameter-rooted flow must yield a controlled input"
    assert all(i["status"] == PROVEN for i in inputs)
    exprs = {i["expression"] for i in inputs}
    assert any("routeData" in e for e in exprs)



def test_controlled_inputs_exclude_literals_state_and_registry_shapes(tmp_path):
    facts = [
        _fact(100, "function_exists", FN_ROOT),
        _fact(101, "function_visibility", FN_ROOT, {"visibility": "external"}, line=20),
        _fact(102, "call_argument_origin_chain", FN_ROOT, {
            "root_kind": "parameter", "argument_expression": "amount",
        }, line=21),
        _fact(103, "call_argument_origin_chain", FN_ROOT, {
            "root_kind": "literal", "argument_expression": '"rocketNodeStaking"',
        }, line=22),
        _fact(104, "call_argument_origin_chain", FN_ROOT, {
            "root_kind": "state_variable", "argument_expression": "rocketVaultKey",
        }, line=22),
        _fact(105, "call_argument_dataflow", FN_ROOT, {
            "origin_kind": "local_variable", "argument_expression": "address(rocketNodeStaking)",
        }, line=22),
        {
            "id": "fact:syn106",
            "type": "input_origin",
            "subject": {"function": FN_ROOT, "origin": "block.timestamp"},
            "properties": {"category": "environment_variable"},
            "status": "observed",
            "source": {"file": "src/Protocol.sol", "line_start": 23, "line_end": 23},
        },
        {
            "id": "fact:syn107",
            "type": "input_origin",
            "subject": {"function": FN_ROOT, "origin": "msg.sender"},
            "properties": {"category": "environment_variable"},
            "status": "observed",
            "source": {"file": "src/Protocol.sol", "line_start": 24, "line_end": 24},
        },
    ]
    recon = _recon_from_facts(facts, tmp_path)
    threat = synthetic_threat_like([{
        "hypothesis_id": "H-control",
        "category": "accounting_mismatch",
        "statement": "synthetic",
        "actor": "external_user",
        "priority": "high_interest",
        "evidence_tier": "ARGUMENT_DEPENDENCY",
        "observed_facts": [f["id"] for f in facts],
        "affected_functions": [FN_ROOT],
        "affected_assets": [],
        "uncertainty": "",
        "preconditions": [],
        "chain": [],
    }])
    inputs = paths.controlled_inputs(recon, threat.hypotheses[0], FN_ROOT)
    exprs = {i["expression"] for i in inputs}
    assert exprs == {"amount", "msg.sender"}


def test_propagation_path_spans_internal_call_edge(synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    propa = paths.propagation_path(synthetic_recon, hyp, FN_ROOT, FN_ENTRY)
    stages = [p["stage"] for p in propa]
    assert "untrusted_influence" in stages
    influence = next(p for p in propa if p["stage"] == "untrusted_influence")
    assert influence["via_internal_call_edge"]["from"] == FN_ENTRY
    assert influence["via_internal_call_edge"]["to"] == FN_ROOT
    assert influence["status"] == PROVEN


# ---------------------------------------------------------------------------
# Evidence discipline: strategies never upgrade uncertainty
# ---------------------------------------------------------------------------

def test_approval_abuse_and_validation_gap_fire_on_full_chain(
        synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    ctx = strategies.AttackContext(synthetic_recon, synthetic_threat, hyp, FN_ROOT, FN_ENTRY)
    selected = strategies.select_strategies(ctx)
    names = [s["name"] for s in selected]
    assert "approval abuse" in names
    assert "stale/incomplete validation (check passes, authority persists)" in names
    approval = next(s for s in selected if s["name"] == "approval abuse")
    assert approval["status"] == PROVEN
    assert approval["assumptions"], "strategy must carry its assumptions"


def test_possible_callback_yields_no_attacker_controlled_target():
    """Evidence rule: a POSSIBLE downstream grade must not become an
    attacker-controlled-target strategy."""
    from conftest import make_threat_hypotheses, make_recon_facts
    import json
    hyp = json.loads(json.dumps(make_threat_hypotheses()[0]))
    hyp["chain"] = [
        s for s in hyp["chain"]
        if s["stage"] != "downstream_execution_opportunity"
    ] + [{
        "stage": "downstream_execution_opportunity", "status": "uncertain",
        "grade": "POSSIBLE", "fact_ids": [],
    }]
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "facts.jsonl"), "w") as f:
            for fact in make_recon_facts():
                f.write(json.dumps(fact) + "\n")
        with open(os.path.join(d, "graph.json"), "w") as f:
            f.write('{"nodes": [], "edges": []}')
        recon = load_recon(d)
    threat = synthetic_threat_like([hyp])
    ctx = strategies.AttackContext(recon, threat, hyp, FN_ROOT, FN_ENTRY)
    names = [s["name"] for s in strategies.select_strategies(ctx)]
    assert "attacker-controlled external target" not in names
    # callback/reentrancy must not fire on POSSIBLE-only either
    assert "callback/hook reentrancy" not in names


def synthetic_threat_like(hypotheses):
    from attack.loader import ThreatArtifact
    return ThreatArtifact(hypotheses=hypotheses, invariants=[
        {"id": "INV-001", "statement": "assets cover liabilities",
         "involved_facts": ["fact:syn009"], "involved_functions": [FN_ROOT],
         "involved_assets": ["tokens"], "uncertainty": "", "category": "",
         "rationale": "", "confidence": "medium"},
    ])


def test_consequence_reflects_custody_and_gap(synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    ctx = strategies.AttackContext(synthetic_recon, synthetic_threat, hyp, FN_ROOT, FN_ENTRY)
    approval = next(s for s in strategies.select_strategies(ctx)
                    if s["name"] == "approval abuse")
    consequence = consequences.classify_consequence(approval, ctx)
    assert consequence["class"] in ("theft / loss of funds",)
    assert consequence["status"] == INFERRED
    assert consequence["asset_at_risk"] is True


# ---------------------------------------------------------------------------
# Premature certainty: attacker-controlled AMOUNT != attacker-controlled
# BENEFICIARY. Regression for the RocketMerkleDistributorMainnet pattern:
# approve(getContractAddress("fixedSpender"), attackerControlledAmount).
# ---------------------------------------------------------------------------

def _fixed_beneficiary_recon_facts():
    """Same synthetic protocol as conftest, but the approve() spender is a
    registry-resolved / fixed expression that shares no identifier with any
    caller-controlled input. A SEPARATE controlled-input fact proves the
    AMOUNT ('claimValue') is attacker-controlled -- mirroring the real
    RocketMerkleDistributorMainnet pattern: approve(getContractAddress(...),
    attackerControlledAmount). The amount being controlled must never be
    read as proof that the spender/beneficiary is attacker-chosen."""
    facts = [f for f in make_recon_facts() if f["id"] != "fact:syn009"]
    facts.append(
        _fact(9, "asset_operation", FN_ROOT, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["getContractAddress(\"fixedSpender\")", "claimValue"],
        }, line=23)
    )
    facts.append(
        _fact(15, "call_argument_origin_chain", FN_ROOT, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "claimValue",
            "chain": [{"kind": "parameter", "name": "claimValue", "relation": "root"}],
        }, line=23)
    )
    return facts


def test_fixed_beneficiary_discards_approval_abuse(tmp_path):
    """A caller-controlled amount must never be treated as proof that the
    approval's beneficiary/spender is attacker-chosen. When the spender is
    provably fixed (no identifier overlap with any controlled input),
    'approval abuse' must be discarded (Mandatory Attack Gate: target
    control), not merely downgraded."""
    recon = _recon_from_facts(_fixed_beneficiary_recon_facts(), tmp_path)
    threat = synthetic_threat_like(make_threat_hypotheses())
    hyp = next(h for h in threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    ctx = strategies.AttackContext(recon, threat, hyp, FN_ROOT, FN_ENTRY)
    names = [s["name"] for s in strategies.select_strategies(ctx)]
    assert "approval abuse" not in names
    assert "transferFrom abuse" not in names


def _fixed_beneficiary_threat_hypotheses():
    """Same hypotheses as conftest, but H-strong0001 also observes the
    amount-controlled call_argument_origin_chain fact (fact:syn015). Without
    this, the fixture is vacuously true: the amount is never modeled as a
    controlled input at all (controlled_inputs() only resolves facts listed
    in the hypothesis's own observed_facts), so the amount-vs-beneficiary
    distinction this regression targets is never actually exercised and the
    pipeline degrades to zero attacks for an unrelated reason (no proven
    controlled input -> input_provenance gate BLOCKED)."""
    hyps = json.loads(json.dumps(make_threat_hypotheses()))
    strong = next(h for h in hyps if h["hypothesis_id"] == "H-strong0001")
    strong["observed_facts"].append("fact:syn015")
    return hyps


def test_fixed_beneficiary_never_claimed_attacker_controlled_downstream(tmp_path):
    """End-to-end: with the amount proven attacker-controlled but the
    spender/beneficiary provably fixed, at least one attack must survive
    (via a fallback strategy), and no downstream field may make the
    POSITIVE claim that the fixed spender is attacker-controlled/chosen.
    Negated statements ("...is NOT an attacker-chosen beneficiary") are
    the correct, honest phrasing and must not trip this check."""
    recon = _recon_from_facts(_fixed_beneficiary_recon_facts(), tmp_path)
    threat = synthetic_threat_like(_fixed_beneficiary_threat_hypotheses())
    attacks = generate_attacks(recon, threat)
    survivors = [a for a in attacks if a.root_function == FN_ROOT]
    assert survivors, "the amount-controlled/beneficiary-fixed case must still degrade to SOME attack, not silently vanish"
    false_positive_phrases = (
        "grants spending authority over its assets to the attacker-chosen beneficiary.",
        "in favor of the attacker-controlled beneficiary",
        "must be able to act as the approved spender",
    )
    for attack in survivors:
        assert attack.attack_strategy not in ("approval abuse", "transferFrom abuse")
        assert attack.beneficiary_control.get("status") == "FIXED"
        blob = json.dumps(attack.to_dict()).lower()
        for phrase in false_positive_phrases:
            assert phrase.lower() not in blob, f"false attacker-control claim leaked: {phrase!r}"


def test_beneficiary_overlap_still_allows_approval_abuse(synthetic_recon, synthetic_threat):
    """Sanity check: the original fixture, where the spender IS derived
    from a caller-controlled parameter, must keep firing 'approval abuse'."""
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    ctx = strategies.AttackContext(synthetic_recon, synthetic_threat, hyp, FN_ROOT, FN_ENTRY)
    names = [s["name"] for s in strategies.select_strategies(ctx)]
    assert "approval abuse" in names


def _family_recon_facts(extra_fact):
    extras = extra_fact if isinstance(extra_fact, list) else [extra_fact]
    return [
        _fact(100, "function_exists", FN_ENTRY),
        _fact(101, "function_visibility", FN_ENTRY, {"visibility": "external"}, line=11),
        _fact(102, "internal_call", FN_ENTRY, {"callee_function": FN_ROOT, "static_target": True}, {"callee_name": "dispatchFunds"}, line=12),
        _fact(103, "function_exists", FN_ROOT),
        _fact(104, "function_visibility", FN_ROOT, {"visibility": "private"}, line=20),
        _fact(105, "call_argument_origin_chain", FN_ROOT, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "userValue",
            "chain": [{"kind": "parameter", "name": "userValue", "relation": "root"}],
        }, line=21),
        *extras,
    ]


def _family_hypothesis(hyp_id, category, extra_fact_id, statement, preconditions, actor="external_user", priority="low_interest", tier="CO_OCCURRENCE"):
    return {
        "hypothesis_id": hyp_id,
        "category": category,
        "statement": statement,
        "actor": actor,
        "priority": priority,
        "evidence_tier": tier,
        "control_provenance": "PROVEN",
        "observed_facts": ["fact:syn101", "fact:syn102", "fact:syn104", "fact:syn105", extra_fact_id],
        "affected_functions": [FN_ROOT, FN_ENTRY],
        "affected_assets": [],
        "preconditions": preconditions,
        "uncertainty": "",
        "chain": [],
    }


def test_low_priority_benchmark_family_is_selected_for_attacking():
    threat = synthetic_threat_like([
        _family_hypothesis(
            "H-round0001",
            "rounding_allocation",
            "fact:syn106",
            "Integer division truncates and may skew allocation.",
            ["Division result influences allocation or distribution", "Rounding favors the caller"],
        )
    ])
    selected = select_high_value(threat)
    assert [h["hypothesis_id"] for h in selected] == ["H-round0001"]


@pytest.mark.parametrize(
    "category, extra_fact, strategy_name, statement, preconditions",
    [
        (
            "rounding_allocation",
            _fact(106, "division_operation", FN_ROOT, {
                "left_operand": "userValue", "right_operand": "poolSize", "immediate_consumer": "return_value",
            }, line=22),
            "rounding / precision exploitation",
            "Integer division truncates and may skew allocation.",
            ["Division result influences allocation or distribution", "Rounding favors the caller"],
        ),
        (
            "accounting_mismatch",
            _fact(106, "state_write", FN_ROOT, {"type": "uint256"}, {"name": "trackedBalance", "state_variable": "trackedBalance"}, line=22),
            "accounting mismatch",
            "Externally influenced data ingestion reaches accounting state mutation without reconciliation.",
            ["Data ingestion and state mutation can violate an implicit accounting assumption"],
        ),
        (
            "frontrun_vulnerability",
            [
                _fact(106, "state_dependent_constraint", FN_ROOT, {
                    "constraint_expression": "userValue <= liveCap", "mutable_state_dependency": True, "visibility": "public",
                }, line=22),
                _fact(107, "modifier_usage", FN_ROOT, {}, {"modifier_name": "onlyOwner"}, line=22),
            ],
            "frontrun_race",
            "A temporal constraint uses mutable live state and is exploitable via mempool frontrunning.",
            ["The involved signals (authorization, temporal_constraint) can be chained in a way that violates an implicit protocol assumption"],
        ),
        (
            "gas_dos",
            _fact(106, "control_flow_structure", FN_ROOT, {"construct": "for_loop"}, line=22),
            "gas_dos",
            "Parameter-dependent iteration may exceed practical gas limits.",
            ["Loop bounds depend on caller-supplied parameters or unbounded state"],
        ),
        (
            "randomness_manipulation",
            _fact(106, "randomness_source_usage", FN_ROOT, {
                "source": "block.timestamp", "source_type": "block_environment", "predictability": "high",
            }, line=22),
            "statistical_exploit",
            "The same seed is reused across multiple draws, so predictable randomness can bias the outcome.",
            ["Function relies on on-chain randomness for security-critical decision"],
        ),
        (
            "arithmetic_bound_violation",
            _fact(106, "bitshift_operation", FN_ROOT, {
                "operand": "1", "operator": "<<", "shift_amount": "userValue", "shift_amount_source": "expression",
            }, line=22),
            "arithmetic_overflow",
            "Shift amount may exceed representation bounds.",
            ["Shift amount not validated against type bounds"],
        ),
    ],
)
def test_benchmark_family_strategies_emit_attack_candidates(tmp_path, category, extra_fact, strategy_name, statement, preconditions):
    recon = _recon_from_facts(_family_recon_facts(extra_fact), tmp_path)
    fact_ids = [f["id"] for f in (extra_fact if isinstance(extra_fact, list) else [extra_fact])]
    hypothesis = _family_hypothesis("H-family0001", category, fact_ids[0], statement, preconditions)
    hypothesis["observed_facts"].extend(fact_ids[1:])
    threat = synthetic_threat_like([hypothesis])
    attacks = generate_attacks(recon, threat)
    assert attacks, f"{category} should produce an attack candidate when its benchmark anchor is present"
    assert attacks[0].attack_strategy == strategy_name


def test_rounding_family_without_control_or_state_anchor_is_pruned(tmp_path):
    extra_fact = _fact(106, "division_operation", FN_ROOT, {
        "left_operand": "fixedValue", "right_operand": "poolSize", "immediate_consumer": "return_value",
    }, line=22)
    facts = [
        _fact(100, "function_exists", FN_ENTRY),
        _fact(101, "function_visibility", FN_ENTRY, {"visibility": "external"}, line=11),
        _fact(102, "internal_call", FN_ENTRY, {"callee_function": FN_ROOT, "static_target": True}, {"callee_name": "dispatchFunds"}, line=12),
        _fact(103, "function_exists", FN_ROOT),
        _fact(104, "function_visibility", FN_ROOT, {"visibility": "external"}, line=20),
        _fact(107, "function_mutability", FN_ROOT, {"state_mutability": "view"}, line=20),
        extra_fact,
    ]
    recon = _recon_from_facts(facts, tmp_path)
    threat = synthetic_threat_like([
        _family_hypothesis(
            "H-roundweak",
            "rounding_allocation",
            extra_fact["id"],
            "Integer division truncates and may skew allocation.",
            ["Division result influences allocation or distribution", "Rounding favors the caller"],
        )
    ])
    assert not generate_attacks(recon, threat)


def test_randomness_family_without_reuse_anchor_is_pruned(tmp_path):
    extra_fact = _fact(106, "randomness_source_usage", FN_ROOT, {
        "source": "block.timestamp", "source_type": "block_environment", "predictability": "high",
    }, line=22)
    facts = _family_recon_facts(extra_fact) + [
        _fact(107, "function_mutability", FN_ROOT, {"state_mutability": "nonpayable"}, line=20),
    ]
    recon = _recon_from_facts(facts, tmp_path)
    threat = synthetic_threat_like([
        _family_hypothesis(
            "H-randweak",
            "randomness_manipulation",
            extra_fact["id"],
            "Function uses predictable randomness source (block.timestamp).",
            ["Function relies on on-chain randomness for security-critical decision"],
        )
    ])
    assert not generate_attacks(recon, threat)


def _rocketpool_like_weak_chain_hypotheses():
    """Synthetic analogue of the surviving RocketPool false path: fixed
    beneficiary, no validation gap, and only a POSSIBLE downstream execution
    signal. This must not survive as a generic novel-composition attack."""
    hyps = _fixed_beneficiary_threat_hypotheses()
    strong = next(h for h in hyps if h["hypothesis_id"] == "H-strong0001")
    strong["chain"] = [
        dict(stage, grade="POSSIBLE", status="uncertain")
        if stage.get("stage") == "downstream_execution_opportunity"
        else stage
        for stage in strong["chain"]
        if stage.get("stage") != "validation_gap"
    ]
    strong["uncertainty"] = "Only a weak downstream execution signal remains."
    return hyps


def test_weak_security_chain_without_anchor_is_pruned(tmp_path):
    recon = _recon_from_facts(_fixed_beneficiary_recon_facts(), tmp_path)
    threat = synthetic_threat_like(_rocketpool_like_weak_chain_hypotheses())
    hyp = next(h for h in threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    ctx = strategies.AttackContext(recon, threat, hyp, FN_ROOT, FN_ENTRY)
    names = [s["name"] for s in strategies.select_strategies(ctx)]
    assert "approval abuse" not in names
    assert "transferFrom abuse" not in names
    assert "novel composition (protocol-specific path)" not in names
    assert not generate_attacks(recon, threat)


# ---------------------------------------------------------------------------
# Pipeline: dedup, scoring, steps, validator plans, output
# ---------------------------------------------------------------------------

def test_pipeline_dedups_and_scores(synthetic_recon, synthetic_threat):
    attacks = generate_attacks(synthetic_recon, synthetic_threat)
    # The weaker duplicate lacks sink-input provenance and is rejected before
    # deduplication; only the executable candidate survives.
    roots = [a.root_function for a in attacks]
    assert roots.count(FN_ROOT) == 1
    attack = next(a for a in attacks if a.root_function == FN_ROOT)
    assert "H-strong0002" not in attack.linked_hypothesis_ids
    assert attack.attack_gates["entry_reachability"]["status"] == "REACHABLE"
    assert attack.attack_gates["input_provenance"]["status"] == "REACHABLE"
    assert attack.attack_strategy == "approval abuse"
    assert attack.exploitability_score > 7.0
    assert attack.exploitability_band == "high"
    # structural hypothesis produced no attack
    assert all(a.source_hypothesis_id != "H-struct0003" for a in attacks)
    # every attack ends with a validator plan
    for a in attacks:
        plan = a.validator_plan
        assert plan["functions_to_test"]
        assert plan["attacker_setup"]
        assert plan["confirm_if"] and plan["reject_if"]
        assert plan["call_chain"]


def test_attack_steps_concrete_and_ordered(synthetic_recon, synthetic_threat):
    attacks = generate_attacks(synthetic_recon, synthetic_threat)
    attack = next(a for a in attacks if a.root_function == FN_ROOT)
    steps = attack.attack_steps
    assert [s.order for s in steps] == list(range(1, len(steps) + 1))
    actions = " ".join(s.action for s in steps)
    assert "Attacker calls" in actions
    assert "internal call edge" in actions
    assert "spending authority" in actions
    assert "delta validation still passes" in actions
    # grounding: at least one step cites a fact id and a location
    assert any(s.fact_ids for s in steps)
    assert any(s.location for s in steps)
    # statuses never invented above PROVEN
    assert all(s.status in (PROVEN, INFERRED, POSSIBLE, UNKNOWN) for s in steps)


def test_privileged_entry_is_not_emitted_as_attack(tmp_path):
    import json
    facts = make_recon_facts() + [
        _fact(40, "access_controlled_function", FN_ENTRY, {"mechanism": "modifier"}, {"modifier": "onlyOwner"}, line=15),
    ]
    recon = _recon_from_facts(facts, tmp_path)
    threat = synthetic_threat_like([make_threat_hypotheses()[0]])
    attacks = generate_attacks(recon, threat)
    assert not attacks, "privileged-only entries must be rejected unless attacker role acquisition is proven"


def test_internal_root_requires_external_caller_chain(tmp_path):
    import json
    hyp = json.loads(json.dumps(make_threat_hypotheses()[0]))
    hyp["affected_functions"] = [FN_ROOT]
    threat = synthetic_threat_like([hyp])
    recon = _recon_from_facts(make_recon_facts(), tmp_path)
    attacks = generate_attacks(recon, threat)
    assert attacks, "an internal root may become an attack only through an observed external caller chain"
    attack = attacks[0]
    assert attack.entry_point["function"] == FN_ENTRY
    assert attack.entry_point["call_chain"] == [FN_ENTRY, FN_ROOT]
    assert attack.entry_point["root_visibility"] == "private"


def test_validator_plan_records_call_chain(synthetic_recon, synthetic_threat):
    attack = next(a for a in generate_attacks(synthetic_recon, synthetic_threat) if a.root_function == FN_ROOT)
    plan = attack.validator_plan
    assert plan["call_chain"] == [FN_ENTRY, FN_ROOT]
    assert "caller chain" in plan["attacker_setup"]


def test_validator_plan_is_executable_candidate_contract(synthetic_recon, synthetic_threat):
    attack = next(a for a in generate_attacks(synthetic_recon, synthetic_threat) if a.root_function == FN_ROOT)
    plan = attack.validator_plan
    assert plan["execution_plan"]
    assert any("Invoke entry function" in step for step in plan["execution_plan"])
    assert any("pre-state snapshots" in step for step in plan["execution_plan"])
    assert any("post-state snapshots" in step for step in plan["execution_plan"])
    assert plan["attack_gates"]["privilege_proof"]["status"] == "REACHABLE"
    assert attack.attack_graph["call_chain"] == [FN_ENTRY, FN_ROOT]
    assert attack.expected_consequence["concrete_effect"]
    assert attack.expected_consequence["required_observation"]


def test_output_artifacts_written(tmp_path, synthetic_recon, synthetic_threat):
    out = str(tmp_path / "attack-out")
    attacks = generate_attacks(synthetic_recon, synthetic_threat)
    summary = write_attack_output(attacks, out)
    assert os.path.exists(os.path.join(out, "attacks.jsonl"))
    assert os.path.exists(os.path.join(out, "summary.json"))
    assert os.path.exists(os.path.join(out, "schema.json"))
    assert summary["attack_count"] == len(attacks)
    assert summary["merged_duplicate_hypotheses"] == 0
    assert summary["attack_gates_by_status"]["REACHABLE"] > 0
    import json
    with open(os.path.join(out, "attacks.jsonl")) as f:
        loaded = [json.loads(line) for line in f if line.strip()]
    for record in loaded:
        for field in ("attack_id", "source_hypothesis_id", "root_function",
                      "attacker_model", "production_relevance", "attack_strategy",
                      "validator_plan", "exploitability_score"):
            assert field in record


def test_pipeline_deterministic(tmp_path, synthetic_recon, synthetic_threat):
    run1 = [a.to_dict() for a in generate_attacks(synthetic_recon, synthetic_threat)]
    run2 = [a.to_dict() for a in generate_attacks(synthetic_recon, synthetic_threat)]
    assert run1 == run2


# ---------------------------------------------------------------------------
# Guard: no benchmark identifiers anywhere in the engine
# ---------------------------------------------------------------------------

def test_no_benchmark_identifiers_in_engine():
    import re as _re
    import attack as attack_pkg
    banned = ("jackpot", "megapot", "initia", "monetrix", "usdc",
              "safetransferfrom", "bridgefunds", "claimwinnings",
              "buytickets", "code4rena", "warden")
    pkg_dir = os.path.dirname(attack_pkg.__file__)
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            source = f.read().lower()
        for marker in banned:
            assert not _re.search(rf"\b{_re.escape(marker)}\b", source), (
                f"{fname} references benchmark identifier {marker!r}"
            )


# ---------------------------------------------------------------------------
# Cross-asset blind spot (generic warden-reasoning pattern)
# ---------------------------------------------------------------------------

def _cross_asset_recon_facts(with_other_asset: bool):
    """Same synthetic protocol as conftest, plus (optionally) another
    contract function that demonstrably moves a SECOND asset (a
    non-fungible holding), and an error/library call target that must
    NOT be classified as an asset."""
    facts = make_recon_facts()
    if with_other_asset:
        fn_nft = "src/Protocol.sol#10::moveHolding#40"
        facts += [
            _fact(30, "function_exists", fn_nft),
            _fact(31, "function_visibility", fn_nft, {"visibility": "public"}, line=40),
            _fact(32, "asset_operation", fn_nft, {
                "operation": "transferFrom",
                "target_expression": "HoldingToken(address(holdingNft))",
                "arguments": ["msg.sender", "address(this)", "holdingId"],
            }, line=41),
        ]
    # noise: error-library and helper call targets (never asset objects)
    fn_noisy = "src/Protocol.sol#10::reportState#50"
    facts += [
        _fact(33, "function_exists", fn_noisy),
        _fact(34, "external_call_surface", fn_noisy, {
            "call_type": "external", "member": "InvalidRoute",
            "target_expression": "ProtocolErrors", "target_status": "dynamic",
        }, line=50),
        _fact(35, "external_call_surface", fn_noisy, {
            "call_type": "external", "member": "toChecksum",
            "target_expression": "CodecLib", "target_status": "static",
        }, line=51),
    ]
    return facts


def _recon_from_facts(facts, tmp_path):
    import json
    d = tmp_path / "recon-x"
    d.mkdir(exist_ok=True)
    with open(d / "facts.jsonl", "w") as f:
        for fact in facts:
            f.write(json.dumps(fact) + "\n")
    (d / "graph.json").write_text('{"nodes": [], "edges": []}')
    return load_recon(str(d))


def test_cross_asset_blind_spot_detected(tmp_path, synthetic_threat):
    """When the check probes asset A and the same contract demonstrably
    moves another asset B, the attack must state the cross-asset blind
    spot, list B (not A), and enrich the validator plan."""
    from attack.pipeline import generate_attacks
    recon = _recon_from_facts(_cross_asset_recon_facts(True), tmp_path)
    attacks = generate_attacks(recon, synthetic_threat)
    attack = next(a for a in attacks if a.root_function == FN_ROOT)
    steps = " ".join(s.action for s in attack.attack_steps)
    assert "Cross-asset blind spot" in steps
    assert "holdingnft" in steps, "the OTHER asset must be named"
    assert "Cross-asset blind spot: the check measures only 'reservetoken'" in steps.replace(
        "reserveToken", "reservetoken") or "reservetoken" in steps
    # probed asset is the reserve token, not the holding
    blind = attack.expected_consequence["cross_asset_blind_spot"]
    assert blind["probed_asset"] == "reservetoken"
    assert blind["other_assets"] == ["holdingnft"]
    # noise targets never leak in
    assert "protocolerrors" not in steps and "codeclib" not in steps
    # validator plan carries the cross-asset confirm condition
    assert "cross-asset path" in attack.validator_plan["confirm_if"]
    assert "holdingnft" in attack.validator_plan["invariant_to_test"]


def test_no_cross_asset_claim_without_other_assets(tmp_path, synthetic_threat):
    """Without a second demonstrably-held asset there must be NO
    cross-asset claim (evidence discipline)."""
    from attack.pipeline import generate_attacks
    recon = _recon_from_facts(_cross_asset_recon_facts(False), tmp_path)
    attacks = generate_attacks(recon, synthetic_threat)
    attack = next(a for a in attacks if a.root_function == FN_ROOT)
    steps = " ".join(s.action for s in attack.attack_steps)
    assert "Cross-asset blind spot" not in steps
    assert "cross_asset_blind_spot" not in attack.expected_consequence
