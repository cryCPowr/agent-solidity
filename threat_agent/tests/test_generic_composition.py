"""Generic security-composition hardening tests (threat-perbaikan.md).

All fixtures here are SYNTHETIC and GENERIC: invented function/contract
names, no benchmark identifiers. They pin the generic reasoning rules:

1.  isolated dynamic call = weak
2.  unknown control provenance = weaker than proven control
3.  proven attacker influence = stronger
4.  capability + external execution = stronger composition
5.  downstream callback/hook opportunity = compositional evidence
6.  asset/state impact strengthens the hypothesis
7.  invariant/check involvement strengthens the hypothesis
8.  unrelated facts are NOT composed
9.  graph reachability alone does NOT imply security relevance
10. deterministic output
11. existing evidence-tier hardening remains intact
12. (guard) no benchmark-specific identifiers anywhere in the engine
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from threat import loader
from threat.evidence import EvidenceTier
from threat.hypothesis import generate_hypotheses, ThreatHypothesis
from threat.invariants import generate_invariants
from threat.prioritization import prioritize, prioritize_all, EVIDENCE_CEILING
from threat.provenance import ControlProvenance, build_control_profiles
from threat.security_chains import compose_security_chains

PRIORITY_ORDER = {
    "low_interest": 0,
    "medium_interest": 1,
    "high_interest": 2,
    "very_high_interest": 3,
}

FN = "synthetic/Generic.sol#1::{fn}#2"


# ---------------------------------------------------------------------------
# Synthetic generic fixture helpers
# ---------------------------------------------------------------------------

def _synthetic_recon(facts, nodes=(), edges=()):
    facts_obj = loader._index_facts(list(facts))
    graph = loader.ReconGraph(nodes=list(nodes), edges=list(edges))
    for node in graph.nodes:
        graph.nodes_by_id[node["id"]] = node
    for edge in graph.edges:
        graph.edges_by_id[edge["id"]] = edge
        graph.outgoing.setdefault(edge["source"], []).append(edge)
        graph.incoming.setdefault(edge["target"], []).append(edge)
    return loader.ReconArtifact(
        facts_obj=facts_obj, graph=graph,
        summary=loader.ReconSummary(), metadata=loader.ReconMetadata(),
        output_dir="synthetic",
    )


def _fid(i):
    return f"fact:syn{i:03d}"


def _fact(i, ftype, fn, props=None, subject_extra=None, status="observed"):
    subj = {"function": fn}
    if subject_extra:
        subj.update(subject_extra)
    return {"id": _fid(i), "type": ftype, "subject": subj,
            "properties": props or {}, "status": status}


def _entrypoint(i, fn):
    return _fact(i, "function_visibility", fn, {"visibility": "external"})


def _input_origin(i, fn, origin="msg.sender"):
    return _fact(i, "input_origin", fn, {}, {"origin": origin})


def _param_flow(i, fn):
    return _fact(i, "call_argument_origin_chain", fn,
                 {"root_kind": "parameter", "hop_count": 1,
                  "chain": [{"kind": "parameter", "name": "value", "relation": "root"}]})


def _dynamic_call(i, fn, member="forward"):
    return _fact(i, "external_call_surface", fn,
                 {"call_type": "external", "member": member,
                  "target_expression": "target", "target_status": "dynamic"})


def _static_call(i, fn, member="query"):
    return _fact(i, "external_call_surface", fn,
                 {"call_type": "external", "member": member,
                  "target_expression": "registry", "target_status": "static"})


def _state_write(i, fn, name="ledger"):
    return _fact(i, "state_write", fn, {}, {"name": name, "state_variable": f"{fn}::{name}"})


def _post_effect(i, fn):
    return _fact(i, "post_call_state_effect", fn,
                 {"note": "structural adjacency only; semantic causation requires verification"},
                 status="derived")


def _asset_op(i, fn):
    return _fact(i, "asset_operation", fn, {})


def _arithmetic(i, fn):
    return _fact(i, "arithmetic_operation", fn, {})


def _capability(i, fn, capability="can_transfer_token"):
    return _fact(i, "capability", fn, {}, {"capability": capability})


def _rel_chain(i, fn, certainty="FACT"):
    return _fact(i, "security_relationship_chain", fn,
                 {"pattern": "user_influenced_dynamic_call",
                  "overall_certainty": certainty,
                  "steps": [
                      {"actor": "caller", "certainty": certainty,
                       "relation": "controls", "target": "parameter(s) of entry"},
                      {"actor": "call target", "certainty": certainty,
                       "relation": "is", "target": "dynamic"},
                  ]},
                 status="derived")


def _pipeline(facts):
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    hypos = prioritize_all(generate_hypotheses(recon, invariants), recon)
    return recon, invariants, hypos


def _chains_for(hypos, fn_substring):
    return [h for h in hypos
            if h.category == "security_chain" and fn_substring in " ".join(h.affected_functions)]


def _max_priority(hypos, fn_substring):
    related = [h for h in hypos if fn_substring in " ".join(h.affected_functions)]
    if not related:
        return None
    return max(PRIORITY_ORDER[h.priority] for h in related)


# ---------------------------------------------------------------------------
# 1. Isolated dynamic call = weak
# ---------------------------------------------------------------------------

def test_isolated_dynamic_call_is_weak():
    """A dynamic-target call with no influence/propagation evidence must
    not become a security chain, and whatever weak hypothesis does mention
    it stays at the bottom of the queue."""
    fn = FN.format(fn="isolatedDynamic")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _fact(2, "low_level_call", fn, {"target_status": "dynamic", "call_subtype": "low_level"}),
    ]
    _, _, hypos = _pipeline(facts)

    assert _chains_for(hypos, fn) == [], "isolated dynamic call must not compose a chain"
    related = [h for h in hypos if fn in " ".join(h.affected_functions)]
    for h in related:
        assert h.priority == "low_interest", h.statement
        assert h.control_provenance != "PROVEN"


# ---------------------------------------------------------------------------
# 2 + 3. Provenance ladder: UNKNOWN < INFERRED < PROVEN
# ---------------------------------------------------------------------------

def test_unknown_provenance_weaker_than_proven():
    fn_unknown = FN.format(fn="unknownControl")
    fn_proven = FN.format(fn="provenControl")
    facts = [
        # unknown: dynamic interaction, internal function, no influence facts
        _fact(2, "low_level_call", fn_unknown, {"target_status": "dynamic", "call_subtype": "low_level"}),
        # proven: entrypoint + parameter-rooted flow + dynamic interaction
        _entrypoint(10, fn_proven),
        _input_origin(11, fn_proven),
        _param_flow(12, fn_proven),
        _dynamic_call(13, fn_proven),
        _state_write(14, fn_proven),
    ]
    _, _, hypos = _pipeline(facts)

    assert _chains_for(hypos, fn_unknown) == []
    proven_chains = _chains_for(hypos, fn_proven)
    assert proven_chains and proven_chains[0].control_provenance == "PROVEN"

    unknown_level = _max_priority(hypos, fn_unknown)
    proven_level = PRIORITY_ORDER[proven_chains[0].priority]
    assert unknown_level is None or unknown_level < proven_level


def test_provenance_ordering_within_equal_impact():
    """Unit-level: identical hypotheses differing only in control
    provenance never rank UNKNOWN above INFERRED above PROVEN, and the
    extremes are strictly separated (the quality bonus is bounded, so
    adjacent levels may tie -- never invert)."""

    def _h(prov, chain_len=3):
        return ThreatHypothesis(
            hypothesis_id="H-T", category="security_chain", statement="probe",
            actor="external_user", observed_facts=[],
            affected_functions=["synthetic::none#0"],
            # no asset impact: keeps the +2 provenance bonus band-separating
            # instead of clipped flat by the ARGUMENT_DEPENDENCY ceiling.
            affected_assets=[],
            evidence_tier="ARGUMENT_DEPENDENCY",
            control_provenance=prov,
            chain=[{"stage": f"s{i}", "description": "", "fact_ids": [], "status": "proven"}
                   for i in range(chain_len)],
        )

    recon = _synthetic_recon([])
    levels = {}
    for prov in ("UNKNOWN", "INFERRED", "PROVEN"):
        h = _h(prov)
        prioritize(h, recon)
        levels[prov] = PRIORITY_ORDER[h.priority]
    assert levels["UNKNOWN"] <= levels["INFERRED"] <= levels["PROVEN"]
    assert levels["UNKNOWN"] < levels["PROVEN"]


# ---------------------------------------------------------------------------
# 4. Capability + external execution = stronger composition
# ---------------------------------------------------------------------------

def test_capability_plus_external_execution_strengthens():
    fn_plain = FN.format(fn="plainExternal")
    fn_cap = FN.format(fn="capableExternal")
    facts = [
        # both externally reachable with a dynamic interaction; only the
        # second additionally carries a security-relevant capability
        _entrypoint(0, fn_plain),
        _input_origin(1, fn_plain),
        _dynamic_call(2, fn_plain),
        _entrypoint(10, fn_cap),
        _input_origin(11, fn_cap),
        _dynamic_call(12, fn_cap),
        _capability(13, fn_cap),
        _state_write(14, fn_cap),
    ]
    _, _, hypos = _pipeline(facts)

    plain_chains = _chains_for(hypos, fn_plain)
    cap_chains = _chains_for(hypos, fn_cap)
    assert plain_chains and cap_chains
    assert (PRIORITY_ORDER[cap_chains[0].priority]
            >= PRIORITY_ORDER[plain_chains[0].priority])
    # The capability-bearing composition itself is a proven chain.
    assert cap_chains[0].control_provenance in ("PROVEN", "INFERRED")


# ---------------------------------------------------------------------------
# 5. Downstream callback/hook opportunity = compositional evidence
# ---------------------------------------------------------------------------

def test_callback_opportunity_is_a_chain_stage_with_uncertainty():
    fn = FN.format(fn="callbackChance")
    facts = [
        _entrypoint(0, fn),
        _param_flow(1, fn),
        _dynamic_call(2, fn),
        _post_effect(3, fn),
    ]
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    chains = compose_security_chains(recon, invariants, lambda: "H-T")
    assert chains, "dynamic interaction + proven flow must compose"
    stages = {s["stage"]: s for s in chains[0].chain}

    # Generic downstream-execution concept, not an interface-specific one.
    assert "downstream_execution_opportunity" in stages
    cb = stages["downstream_execution_opportunity"]
    assert cb["status"] == "uncertain"
    assert "cannot be proven statically" in cb["description"]
    assert "state_value_effect" in stages

    # Static-target variant: no callback opportunity stage, shallower chain.
    facts_static = [
        _entrypoint(0, fn),
        _param_flow(1, fn),
        _static_call(2, fn),
        _post_effect(3, fn),
    ]
    recon_static = _synthetic_recon(facts_static)
    chains_static = compose_security_chains(
        recon_static, generate_invariants(recon_static), lambda: "H-T"
    )
    assert chains_static
    static_stages = {s["stage"] for s in chains_static[0].chain}
    assert "downstream_execution_opportunity" not in static_stages
    assert len(chains_static[0].chain) < len(chains[0].chain)


# ---------------------------------------------------------------------------
# 6. Asset/state impact strengthens
# ---------------------------------------------------------------------------

def test_state_value_effect_strengthens_chain():
    from threat.prioritization import _score

    def _h(with_effect):
        chain = [
            {"stage": "untrusted_influence", "description": "", "fact_ids": [], "status": "proven"},
            {"stage": "argument_propagation", "description": "", "fact_ids": [], "status": "proven"},
            {"stage": "external_execution", "description": "", "fact_ids": [], "status": "proven"},
            {"stage": "invariant_concern", "description": "", "fact_ids": [], "status": "uncertain"},
        ]
        if with_effect:
            chain.insert(3, {"stage": "state_value_effect", "description": "",
                             "fact_ids": [], "status": "observed"})
        return ThreatHypothesis(
            hypothesis_id="H-T", category="security_chain", statement="probe",
            actor="external_user" if with_effect else "unknown_actor",
            observed_facts=[],
            affected_functions=["synthetic::none#0"],
            affected_assets=["protocol assets"] if with_effect else [],
            evidence_tier="ARGUMENT_DEPENDENCY",
            control_provenance="PROVEN", chain=chain,
        )

    recon = _synthetic_recon([])
    without, with_effect = _h(False), _h(True)
    # Raw composition quality: the state/value effect strictly strengthens.
    assert _score(with_effect, recon) > _score(without, recon)
    # And in a band-separating configuration, the priority follows.
    prioritize(without, recon)
    prioritize(with_effect, recon)
    assert PRIORITY_ORDER[with_effect.priority] > PRIORITY_ORDER[without.priority]


# ---------------------------------------------------------------------------
# 7. Invariant involvement strengthens
# ---------------------------------------------------------------------------

def test_invariant_involvement_strengthens():
    from threat.prioritization import _score

    recon = _synthetic_recon([])

    def _h(inv):
        return ThreatHypothesis(
            hypothesis_id="H-T", category="security_chain", statement="probe",
            actor="unknown_actor", observed_facts=[],
            affected_functions=["synthetic::none#0"],
            evidence_tier="ARGUMENT_DEPENDENCY",
            control_provenance="PROVEN",
            invariant_candidate_id=inv,
            chain=[{"stage": f"s{i}", "description": "", "fact_ids": [], "status": "proven"}
                   for i in range(4)],
        )

    plain, with_inv = _h(""), _h("IV-TEST-1")
    assert _score(with_inv, recon) > _score(plain, recon)
    prioritize(plain, recon)
    prioritize(with_inv, recon)
    assert PRIORITY_ORDER[with_inv.priority] > PRIORITY_ORDER[plain.priority]


# ---------------------------------------------------------------------------
# 8. Unrelated facts are NOT composed
# ---------------------------------------------------------------------------

def test_unrelated_facts_are_not_composed():
    """Dynamic call + arithmetic + state write with no relation evidence
    (no dataflow, no relationship chain, no shared influence) must not be
    bundled into a security chain or any strong hypothesis."""
    fn = FN.format(fn="unrelatedMix")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _fact(2, "low_level_call", fn, {"target_status": "dynamic", "call_subtype": "low_level"}),
        _arithmetic(3, fn),
        _state_write(4, fn),
    ]
    _, _, hypos = _pipeline(facts)

    assert _chains_for(hypos, fn) == []
    for h in hypos:
        if fn in " ".join(h.affected_functions):
            assert h.evidence_tier == EvidenceTier.CO_OCCURRENCE.value
            assert h.priority == "low_interest", h.statement
            assert h.chain == [], "unrelated facts must not appear as chain stages"


# ---------------------------------------------------------------------------
# 9. Graph reachability alone does not imply security relevance
# ---------------------------------------------------------------------------

def test_graph_reachability_alone_is_not_security_relevance():
    nodes = [{"id": "n1", "kind": "function", "label": "a", "name": "a"},
             {"id": "n2", "kind": "external_target", "label": "b", "name": "b"}]
    edges = [{"id": "e1", "type": "CALLS", "source": "n1", "target": "n2"}]
    recon = _synthetic_recon([], nodes, edges)

    graph_only = ThreatHypothesis(
        hypothesis_id="H-G", category="cross_contract_trust",
        statement="structural path only", actor="unknown_actor",
        observed_facts=[], graph_nodes=["n1", "n2"], graph_edges=["e1"],
        affected_functions=["synthetic::none#0"],
        evidence_tier="GRAPH_REACHABILITY",
    )
    proven_chain = ThreatHypothesis(
        hypothesis_id="H-C", category="security_chain",
        statement="proven multi-stage chain", actor="external_user",
        observed_facts=[], affected_functions=["synthetic::none#0"],
        affected_assets=["protocol assets"],
        evidence_tier="ARGUMENT_DEPENDENCY",
        control_provenance="PROVEN",
        chain=[{"stage": f"s{i}", "description": "", "fact_ids": [], "status": "proven"}
               for i in range(5)],
    )
    prioritize(graph_only, recon)
    prioritize(proven_chain, recon)

    # Structural connectivity without security evidence stays below a
    # proven multi-stage composition (and contains no chain stages).
    assert PRIORITY_ORDER[graph_only.priority] < PRIORITY_ORDER[proven_chain.priority]
    assert graph_only.chain == []
    assert graph_only.evidence_tier == EvidenceTier.GRAPH_REACHABILITY.value


# ---------------------------------------------------------------------------
# 10. Deterministic output
# ---------------------------------------------------------------------------

def test_chain_output_is_deterministic():
    fn = FN.format(fn="determinism")
    facts = [
        _entrypoint(0, fn),
        _input_origin(1, fn),
        _param_flow(2, fn),
        _dynamic_call(3, fn),
        _post_effect(4, fn),
        _asset_op(5, fn),
    ]

    def _run():
        recon = _synthetic_recon(facts)
        invariants = generate_invariants(recon)
        return prioritize_all(generate_hypotheses(recon, invariants), recon)

    run1, run2 = _run(), _run()
    sig1 = {h.hypothesis_id: (h.category, h.evidence_tier, h.priority,
                              h.control_provenance,
                              tuple(s["stage"] for s in h.chain))
            for h in run1}
    sig2 = {h.hypothesis_id: (h.category, h.evidence_tier, h.priority,
                              h.control_provenance,
                              tuple(s["stage"] for s in h.chain))
            for h in run2}
    assert sig1 == sig2
    assert any(h.category == "security_chain" for h in run1)


# ---------------------------------------------------------------------------
# 11. Evidence-tier hardening remains intact
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fixture_run(recon_output_dir):
    recon = loader.load_recon(recon_output_dir)
    invariants = generate_invariants(recon)
    return recon, prioritize_all(generate_hypotheses(recon, invariants), recon)


def test_tier_hardening_intact_with_chain_layer(fixture_run):
    _, hypos = fixture_run
    assert hypos
    canonical = set(EvidenceTier.all())
    for h in hypos:
        assert h.evidence_tier in canonical
        # CO_OCCURRENCE ceiling still binds: never above low_interest.
        if h.evidence_tier == EvidenceTier.CO_OCCURRENCE.value:
            assert h.priority == "low_interest"
        # Chain layer hypotheses carry provenance and canonical tiers only.
        if h.category == "security_chain":
            assert h.control_provenance in ("PROVEN", "INFERRED")
            assert h.evidence_tier in (
                EvidenceTier.ARGUMENT_DEPENDENCY.value,
                EvidenceTier.RELATIONSHIP_GROUNDED.value,
                EvidenceTier.GRAPH_REACHABILITY.value,
            )
    assert set(EVIDENCE_CEILING.keys()) == canonical


def test_provenance_profiles_are_fact_based(fixture_run):
    recon, _ = fixture_run
    profiles = build_control_profiles(recon)
    for profile in profiles.values():
        # Provenance is derived, never defaulted upward.
        assert profile.provenance in set(ControlProvenance)
        if profile.provenance is ControlProvenance.PROVEN:
            assert profile.relationship_chains or (
                profile.is_entrypoint and profile.parameter_rooted_flows
            )


# ---------------------------------------------------------------------------
# 12. Guard: no benchmark-specific identifiers in the engine
# ---------------------------------------------------------------------------

def test_no_benchmark_identifiers_in_engine():
    import re as _re

    import threat as threat_pkg
    banned = ("jackpot", "megapot", "initia", "monetrix", "usdc",
              "safetransferfrom", "onerc721received", "ierc721receiver",
              "bridgefunds", "code4rena")
    pkg_dir = os.path.dirname(threat_pkg.__file__)
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            source = f.read().lower()
        for marker in banned:
            # Word-boundary match so generic vocabulary (e.g.
            # "initialization_vulnerability") is not confused with a
            # benchmark name.
            assert not _re.search(rf"\b{_re.escape(marker)}\b", source), (
                f"{fname} references benchmark identifier {marker!r}"
            )
