"""Evidence-tier hardening regression tests (Bugs 1-4).

Bug 1: GRAPH_REACHABILITY must represent actual graph reachability
       (graph nodes + edges + a verified bounded path), never a
       security_relationship_chain fact alone.
Bug 2: ARGUMENT_DEPENDENCY must be backed by real argument/dataflow
       evidence; a relationship chain without dataflow degrades to
       RELATIONSHIP_GROUNDED.
Bug 3: Priority must be evidence-aware; weak evidence cannot become
       very_high_interest by stacking independent signal points.
Bug 4: threat/evidence.py is the single canonical classifier used by
       composition.py, hypothesis.py and prioritization.py.

Classifier semantics are unit-tested against small synthetic artifacts
(loader indexes built directly, no files on disk); priority and pipeline
behavior is tested against the real Recon artifact resolved by conftest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from threat import loader
from threat import evidence
from threat.evidence import EvidenceTier, classify_evidence, MAX_PATH_EDGES
from threat.invariants import generate_invariants
from threat.hypothesis import generate_hypotheses, ThreatHypothesis
from threat.prioritization import prioritize, prioritize_all, EVIDENCE_CEILING
from threat import composition
from threat import hypothesis as hypothesis_module
from threat import prioritization as prioritization_module


PRIORITY_ORDER = {
    "low_interest": 0,
    "medium_interest": 1,
    "high_interest": 2,
    "very_high_interest": 3,
}


@pytest.fixture(scope="session")
def recon(recon_output_dir):
    return loader.load_recon(recon_output_dir)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _synthetic_recon(facts, nodes=(), edges=()):
    """Build an in-memory ReconArtifact with the same indexes the loader
    builds from disk, so classifier tests need no fixture files."""
    facts_obj = loader._index_facts(list(facts))
    graph = loader.ReconGraph(nodes=list(nodes), edges=list(edges))
    for node in graph.nodes:
        graph.nodes_by_id[node["id"]] = node
    for edge in graph.edges:
        graph.edges_by_id[edge["id"]] = edge
        graph.outgoing.setdefault(edge["source"], []).append(edge)
        graph.incoming.setdefault(edge["target"], []).append(edge)
    return loader.ReconArtifact(
        facts_obj=facts_obj,
        graph=graph,
        summary=loader.ReconSummary(),
        metadata=loader.ReconMetadata(),
        output_dir="synthetic",
    )


def _fact(fid, ftype, fn="synthetic::fn#1"):
    return {
        "id": fid,
        "type": ftype,
        "subject": {"function": fn},
        "properties": {},
        "status": "observed",
    }


def _node(nid, kind="function"):
    return {"id": nid, "kind": kind, "label": nid, "name": nid}


def _edge(eid, src, tgt, etype="CALLS"):
    return {"id": eid, "type": etype, "source": src, "target": tgt}


def _first_fact_of_type(recon, ftype):
    facts = recon.facts_obj.by_type.get(ftype, [])
    assert facts, f"Real Recon artifact must contain {ftype} facts for this test"
    return facts[0]


def _max_impact_hypothesis(tier):
    """A hypothesis with every security-impact signal stacked.

    Identical fields for every tier, so any priority difference is caused
    by evidence strength alone. affected_functions references no real
    function, so the cross-contract signal is 0 for all variants.
    Base score: assets(3) + external_contract actor(2+1) + invariant(2)
    + economic category(1) = 9 -- enough to hit any band a ceiling allows.
    """
    return ThreatHypothesis(
        hypothesis_id="H-TEST",
        category="economic_manipulation",
        statement="Synthetic max-impact hypothesis for tier "
                  f"{EvidenceTier.coerce(tier).value}",
        actor="external_contract",
        observed_facts=["fact:synthetic"],
        affected_functions=["synthetic::no_such_function#0"],
        affected_assets=["protocol assets"],
        invariant_candidate_id="IV-TEST-1",
        evidence_tier=tier if isinstance(tier, str) else tier.value,
    )


# ===========================================================================
# Bug 1 -- GRAPH_REACHABILITY requires a verified bounded graph path
# ===========================================================================

def test_bug1_relationship_chain_alone_is_not_graph_reachability(recon):
    """Required test 1: a security_relationship_chain fact alone must
    classify as RELATIONSHIP_GROUNDED, never GRAPH_REACHABILITY."""
    # Real artifact: the relationship-chain fact by itself
    rel = _first_fact_of_type(recon, "security_relationship_chain")
    tier = classify_evidence([rel["id"]], [], [], recon)
    assert tier == EvidenceTier.RELATIONSHIP_GROUNDED, (
        f"relationship-chain fact alone classified as {tier}"
    )

    # Synthetic: even when the artifact HAS a graph, a chain fact with no
    # graph references still does not earn GRAPH_REACHABILITY
    syn = _synthetic_recon(
        facts=[_fact("fact:rel", "security_relationship_chain")],
        nodes=[_node("n1"), _node("n2")],
        edges=[_edge("e1", "n1", "n2")],
    )
    assert classify_evidence(["fact:rel"], [], [], syn) is EvidenceTier.RELATIONSHIP_GROUNDED


def test_bug1_real_graph_path_is_graph_reachability(recon):
    """Required test 2: a real, connected path in recon.graph classifies
    as GRAPH_REACHABILITY -- and broken/disjoint/unbounded references do
    not."""
    edge = next(e for e in recon.graph.edges if e.get("type") == "CALLS")
    src, tgt, eid = edge["source"], edge["target"], edge["id"]

    # Real path: existing nodes + existing edge connecting them
    assert classify_evidence([], [src, tgt], [eid], recon) is EvidenceTier.GRAPH_REACHABILITY

    # Unknown node
    assert classify_evidence([], [src, "node:does-not-exist"], [eid], recon) \
        is not EvidenceTier.GRAPH_REACHABILITY
    # Unknown edge
    assert classify_evidence([], [src, tgt], ["edge:does-not-exist"], recon) \
        is not EvidenceTier.GRAPH_REACHABILITY
    # Nodes without any edge
    assert classify_evidence([], [src, tgt], [], recon) \
        is not EvidenceTier.GRAPH_REACHABILITY

    # Disjoint edges are not a path: two real CALLS edges sharing no node
    calls_edges = [e for e in recon.graph.edges if e.get("type") == "CALLS"]
    if len(calls_edges) >= 2:
        e1, e2 = calls_edges[0], calls_edges[1]
        if {e1["source"], e1["target"]}.isdisjoint({e2["source"], e2["target"]}):
            nodes = [e1["source"], e1["target"], e2["source"], e2["target"]]
            assert classify_evidence([], nodes, [e1["id"], e2["id"]], recon) \
                is not EvidenceTier.GRAPH_REACHABILITY

    # Bounded path enforcement on a synthetic artifact
    chain_nodes = [_node(f"n{i}") for i in range(MAX_PATH_EDGES + 2)]
    chain_edges = [
        _edge(f"e{i}", f"n{i}", f"n{i+1}") for i in range(MAX_PATH_EDGES + 1)
    ]
    syn = _synthetic_recon(facts=[], nodes=chain_nodes, edges=chain_edges)
    node_ids = [n["id"] for n in chain_nodes]
    edge_ids = [e["id"] for e in chain_edges]
    # In-bounds path passes...
    ok_syn = _synthetic_recon(
        facts=[], nodes=chain_nodes[:4],
        edges=[_edge("p1", "n0", "n1"), _edge("p2", "n1", "n2"), _edge("p3", "n2", "n3")],
    )
    assert classify_evidence([], ["n0", "n1", "n2", "n3"], ["p1", "p2", "p3"], ok_syn) \
        is EvidenceTier.GRAPH_REACHABILITY
    # ...but the same graph rejects a path longer than MAX_PATH_EDGES
    assert classify_evidence([], node_ids, edge_ids, syn) \
        is not EvidenceTier.GRAPH_REACHABILITY


# ===========================================================================
# Bug 2 -- ARGUMENT_DEPENDENCY requires real argument/dataflow evidence
# ===========================================================================

def test_bug2_argument_dataflow_is_argument_dependency(recon):
    """Required test 3: real argument/dataflow facts (as emitted by Recon)
    classify as ARGUMENT_DEPENDENCY."""
    for ftype in ("call_argument_dataflow", "call_argument_origin_chain", "input_origin"):
        fact = _first_fact_of_type(recon, ftype)
        tier = classify_evidence([fact["id"]], [], [], recon)
        assert tier is EvidenceTier.ARGUMENT_DEPENDENCY, (
            f"{ftype} fact classified as {tier}"
        )

    # Forward-compatible aliases
    syn = _synthetic_recon([
        _fact("fact:p", "parameter_origin"),
        _fact("fact:a", "argument_origin"),
    ])
    assert classify_evidence(["fact:p"], [], [], syn) is EvidenceTier.ARGUMENT_DEPENDENCY
    assert classify_evidence(["fact:a"], [], [], syn) is EvidenceTier.ARGUMENT_DEPENDENCY


def test_bug2_relationship_without_dataflow_is_relationship_grounded(recon):
    """Required test 4: a relationship chain observed alongside generic
    facts (no dataflow) stays RELATIONSHIP_GROUNDED -- it must not be
    promoted to ARGUMENT_DEPENDENCY just to make the count non-zero."""
    rel = _first_fact_of_type(recon, "security_relationship_chain")
    cap = _first_fact_of_type(recon, "capability")

    tier = classify_evidence([rel["id"], cap["id"]], [], [], recon)
    assert tier is EvidenceTier.RELATIONSHIP_GROUNDED
    assert tier is not EvidenceTier.ARGUMENT_DEPENDENCY
    assert tier is not EvidenceTier.GRAPH_REACHABILITY

    # Synthetic: relationship + co-occurring signals, no dataflow facts
    syn = _synthetic_recon([
        _fact("fact:cap", "capability"),
        _fact("fact:write", "state_write"),
        _fact("fact:rel", "security_relationship_chain"),
    ])
    assert classify_evidence(
        ["fact:cap", "fact:write", "fact:rel"], [], [], syn
    ) is EvidenceTier.RELATIONSHIP_GROUNDED

    # Adding one real dataflow fact promotes the same set to
    # ARGUMENT_DEPENDENCY
    syn2 = _synthetic_recon([
        _fact("fact:cap", "capability"),
        _fact("fact:write", "state_write"),
        _fact("fact:rel", "security_relationship_chain"),
        _fact("fact:df", "call_argument_dataflow"),
    ])
    assert classify_evidence(
        ["fact:cap", "fact:write", "fact:rel", "fact:df"], [], [], syn2
    ) is EvidenceTier.ARGUMENT_DEPENDENCY


def test_bug2_pure_co_occurrence_stays_co_occurrence():
    """Only co-occurring signals -> CO_OCCURRENCE (nothing manufactured)."""
    syn = _synthetic_recon([
        _fact("fact:cap", "capability"),
        _fact("fact:write", "state_write"),
        _fact("fact:arith", "arithmetic_operation"),
    ])
    assert classify_evidence(
        ["fact:cap", "fact:write", "fact:arith"], [], [], syn
    ) is EvidenceTier.CO_OCCURRENCE


# ===========================================================================
# Bug 3 -- evidence-aware priority
# ===========================================================================

def test_bug3_co_occurrence_cannot_stack_to_very_high(recon):
    """Required test 5: stacking every independent signal point still
    cannot push CO_OCCURRENCE past its ceiling."""
    h = _max_impact_hypothesis(EvidenceTier.CO_OCCURRENCE)
    prioritize(h, recon)
    assert h.priority != "very_high_interest", (
        f"CO_OCCURRENCE reached {h.priority} by signal stacking: {h.priority_rationale}"
    )
    assert h.priority == "low_interest"

    # End-to-end on the real pipeline: no CO_OCCURRENCE hypothesis may
    # end up very_high_interest.
    invariants = generate_invariants(recon)
    hypotheses = prioritize_all(generate_hypotheses(recon, invariants), recon)
    offenders = [
        h.hypothesis_id for h in hypotheses
        if h.evidence_tier == EvidenceTier.CO_OCCURRENCE.value
        and h.priority == "very_high_interest"
    ]
    assert not offenders, f"CO_OCCURRENCE hypotheses at very_high: {offenders}"


def test_bug3_stronger_evidence_outranks_weaker_equal_impact(recon):
    """Required test 6 (a): with identical security impact, the four tiers
    land on strictly increasing priority bands."""
    tiers = [
        EvidenceTier.CO_OCCURRENCE,
        EvidenceTier.RELATIONSHIP_GROUNDED,
        EvidenceTier.ARGUMENT_DEPENDENCY,
        EvidenceTier.GRAPH_REACHABILITY,
    ]
    results = []
    for tier in tiers:
        h = _max_impact_hypothesis(tier)
        prioritize(h, recon)
        results.append(h.priority)

    assert results == ["low_interest", "medium_interest", "high_interest", "very_high_interest"], (
        f"equal-impact priorities not strictly ordered by tier: {results}"
    )
    for weaker, stronger in zip(results, results[1:]):
        assert PRIORITY_ORDER[stronger] > PRIORITY_ORDER[weaker]


def test_bug3_co_occurrence_never_outranks_stronger_equal_impact(recon):
    """Required test 6 (b): at ANY base score, CO_OCCURRENCE cannot
    outrank stronger evidence with equal impact (monotone ceilings)."""
    signal_sets = [
        # progressively weaker impact configurations (base scores 9..0)
        dict(affected_assets=["protocol assets"], actor="external_contract",
             invariant_candidate_id="IV-1", category="economic_manipulation"),
        dict(affected_assets=["protocol assets"], actor="external_user",
             invariant_candidate_id="", category="arbitrary_execution"),
        dict(affected_assets=[], actor="external_user",
             invariant_candidate_id="", category="arbitrary_execution"),
        dict(affected_assets=[], actor="unknown_actor",
             invariant_candidate_id="", category="novel_composition"),
    ]
    for signals in signal_sets:
        priorities = {}
        for tier in EvidenceTier:
            h = ThreatHypothesis(
                hypothesis_id="H-TEST",
                category=signals["category"],
                statement="equal-impact probe",
                actor=signals["actor"],
                affected_functions=["synthetic::no_such_function#0"],
                affected_assets=signals["affected_assets"],
                invariant_candidate_id=signals["invariant_candidate_id"],
                evidence_tier=tier.value,
            )
            prioritize(h, recon)
            priorities[tier] = PRIORITY_ORDER[h.priority]
        values = [priorities[t] for t in EvidenceTier]  # enum order = weak->strong
        assert values == sorted(values), (
            f"stronger evidence outranked by weaker at signals={signals}: {priorities}"
        )
        # CO_OCCURRENCE specifically never above any stronger tier
        for t in EvidenceTier.stronger_than(EvidenceTier.CO_OCCURRENCE.value):
            assert priorities[EvidenceTier.CO_OCCURRENCE] <= priorities[EvidenceTier(t)]


# ===========================================================================
# Bug 4 -- single source of truth for tier classification
# ===========================================================================

def test_bug4_all_consumers_use_canonical_classifier():
    """Required test 7: composition.py, hypothesis.py and prioritization.py
    all bind the SAME classifier/enum from threat/evidence.py, and no
    local duplicate exists."""
    assert composition.classify_evidence is evidence.classify_evidence
    assert hypothesis_module.classify_evidence is evidence.classify_evidence
    assert composition.EvidenceTier is evidence.EvidenceTier
    assert prioritization_module.EvidenceTier is evidence.EvidenceTier

    # The priority ceiling table covers exactly the canonical tiers
    assert set(EVIDENCE_CEILING.keys()) == set(EvidenceTier.all())

    # No consumer module defines its own tier vocabulary
    for mod in (composition, hypothesis_module, prioritization_module):
        source = open(mod.__file__, encoding="utf-8").read()
        assert "class EvidenceTier" not in source, (
            f"{mod.__name__} defines a local EvidenceTier duplicate"
        )


def test_bug4_pipeline_emits_only_canonical_tiers(recon):
    """Every generated hypothesis carries a canonical tier value."""
    invariants = generate_invariants(recon)
    hypotheses = generate_hypotheses(recon, invariants)
    assert hypotheses
    for h in hypotheses:
        assert h.evidence_tier in EvidenceTier.all(), (
            f"{h.hypothesis_id} has non-canonical tier {h.evidence_tier!r}"
        )


# ===========================================================================
# Determinism
# ===========================================================================

def test_bug4_deterministic_tier_and_priority(recon):
    """Required test 8: identical evidence produces identical tier and
    priority across independent full-pipeline runs."""
    invariants = generate_invariants(recon)

    run1 = prioritize_all(generate_hypotheses(recon, invariants), recon)
    run2 = prioritize_all(generate_hypotheses(recon, invariants), recon)

    ids1 = [h.hypothesis_id for h in run1]
    ids2 = [h.hypothesis_id for h in run2]
    assert ids1 == ids2

    sig1 = {h.hypothesis_id: (h.evidence_tier, h.priority) for h in run1}
    sig2 = {h.hypothesis_id: (h.evidence_tier, h.priority) for h in run2}
    assert sig1 == sig2, "tier/priority assignment is not deterministic"

    # Classifier itself is pure: repeated calls agree
    for h in run1[:10]:
        again = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
        assert again is EvidenceTier.coerce(h.evidence_tier)
