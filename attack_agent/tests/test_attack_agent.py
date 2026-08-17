"""Attack Agent tests: path building, strategies, consequences, dedup,
scoring, validator plans, evidence discipline, genericity guards, e2e.

All fixtures are synthetic and generic (see conftest.py).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from attack import relevance, strategies
from attack import attacker as attacker_mod
from attack import consequences, dedup, paths, prioritize
from attack.loader import load_recon, load_threat
from attack.model import INFERRED, POSSIBLE, PROVEN, UNKNOWN
from attack.output import write_attack_output
from attack.pipeline import generate_attacks, select_high_value

from conftest import FN_ENTRY, FN_ROOT, _fact, make_recon_facts


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


def test_controlled_inputs_from_parameter_flows(synthetic_recon, synthetic_threat):
    hyp = next(h for h in synthetic_threat.hypotheses if h["hypothesis_id"] == "H-strong0001")
    inputs = paths.controlled_inputs(synthetic_recon, hyp, FN_ROOT)
    assert inputs, "parameter-rooted flow must yield a controlled input"
    assert all(i["status"] == PROVEN for i in inputs)
    exprs = {i["expression"] for i in inputs}
    assert any("routeData" in e for e in exprs)


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
# Pipeline: dedup, scoring, steps, validator plans, output
# ---------------------------------------------------------------------------

def test_pipeline_dedups_and_scores(synthetic_recon, synthetic_threat):
    attacks = generate_attacks(synthetic_recon, synthetic_threat)
    # the two chain hypotheses share root+strategy+sink -> one attack
    roots = [a.root_function for a in attacks]
    assert roots.count(FN_ROOT) == 1
    attack = next(a for a in attacks if a.root_function == FN_ROOT)
    assert "H-strong0002" in attack.linked_hypothesis_ids
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


def test_output_artifacts_written(tmp_path, synthetic_recon, synthetic_threat):
    out = str(tmp_path / "attack-out")
    attacks = generate_attacks(synthetic_recon, synthetic_threat)
    summary = write_attack_output(attacks, out)
    assert os.path.exists(os.path.join(out, "attacks.jsonl"))
    assert os.path.exists(os.path.join(out, "summary.json"))
    assert os.path.exists(os.path.join(out, "schema.json"))
    assert summary["attack_count"] == len(attacks)
    assert summary["merged_duplicate_hypotheses"] >= 1
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
