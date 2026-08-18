"""Cross-Artifact Consistency Checks.

Recon produces multiple artifacts that a downstream consumer may read
independently (facts.jsonl, graph.json, summary.json, metadata.json,
coverage.json, protocol.json, dependencies.json, snippets/). This file checks that they actually agree with each other and
contain no dangling references — i.e. that treating any one of them as a
"partial view" and cross-referencing another is safe.

This is Layer 2 (consumer/evaluation), not Layer 1 (recon) or Layer 3
(threat reasoning): every check here is "does artifact X's claim match
artifact Y's claim", never a security judgment. All counts/fields checked
below are read directly from the actual output; none are invented.
"""

from __future__ import annotations

import os

from recon_reader import ReconOutput


# ===========================================================================
# No dangling references between facts.jsonl and graph.json
# ===========================================================================

def test_every_edge_fact_id_resolves_in_facts_jsonl(recon: ReconOutput):
    referenced = recon.all_fact_ids_referenced_by_edges()
    assert referenced, "sanity: expected at least some edges to carry fact_ids"
    fact_ids = {f["id"] for f in recon.facts}
    dangling = referenced - fact_ids
    assert dangling == set(), f"graph edges reference fact ids that don't exist in facts.jsonl: {dangling}"


def test_no_dangling_graph_node_references_in_edges(recon: ReconOutput):
    node_ids = {n["id"] for n in recon.graph["nodes"]}
    dangling = [
        e for e in recon.graph["edges"]
        if e["source"] not in node_ids or e["target"] not in node_ids
    ]
    assert dangling == [], f"edges reference node ids absent from graph.json's nodes list: {dangling[:5]}"


def test_graph_node_and_edge_ids_are_unique(recon: ReconOutput):
    node_ids = [n["id"] for n in recon.graph["nodes"]]
    edge_ids = [e["id"] for e in recon.graph["edges"]]
    assert len(node_ids) == len(set(node_ids)), "duplicate graph node ids"
    assert len(edge_ids) == len(set(edge_ids)), "duplicate graph edge ids"


# ===========================================================================
# No dangling references from facts.jsonl to snippets/
# ===========================================================================

def test_every_fact_evidence_id_resolves_to_a_snippet_file(recon: ReconOutput):
    checked = 0
    missing = []
    for f in recon.facts:
        for evid in f.get("evidence", []):
            checked += 1
            resolved = recon.resolve_evidence(evid)
            if not resolved["exists"]:
                missing.append((f["id"], evid))
    assert checked > 0, "sanity: expected at least some facts to carry evidence"
    assert missing == [], f"facts reference evidence ids with no snippet file on disk: {missing[:5]}"


def test_fact_ids_are_globally_unique(recon: ReconOutput):
    ids = [f["id"] for f in recon.facts]
    assert len(ids) == len(set(ids)), "facts.jsonl contains duplicate fact ids"


# ===========================================================================
# summary.json agrees with facts.jsonl (independently recomputed from the
# black-box artifact, not by importing recon's own counting logic)
# ===========================================================================

def test_summary_function_and_state_variable_counts_match_facts(recon: ReconOutput):
    assert recon.summary["function_count"] == recon.fact_type_count("function_exists")
    assert recon.summary["state_variable_count"] == recon.fact_type_count("state_variable")
    assert recon.summary["event_count"] == recon.fact_type_count("event_definition")
    assert recon.summary["error_count"] == recon.fact_type_count("error_definition")


def test_summary_asset_and_auth_counts_match_facts(recon: ReconOutput):
    assert recon.summary["asset_operation_count"] == recon.fact_type_count("asset_operation")
    assert recon.summary["eth_transfer_count"] == recon.fact_type_count("eth_transfer")
    assert recon.summary["authorization_check_count"] == recon.fact_type_count("authorization_check")
    assert recon.summary["callback_capable_call_count"] == recon.fact_type_count("callback_capable_call")


def test_summary_capabilities_match_capability_facts(recon: ReconOutput):
    capability_facts = recon.facts_of_type("capability")
    recomputed = {}
    for f in capability_facts:
        cap_name = f["subject"]["capability"]
        recomputed[cap_name] = recomputed.get(cap_name, 0) + 1
    assert recon.summary["capabilities"] == recomputed, (
        "summary.json's capability counts must match an independent recount of "
        "the capability facts in facts.jsonl"
    )


def test_summary_graph_statistics_match_graph_json(recon: ReconOutput):
    stats = recon.summary["graph_statistics"]
    assert stats["node_count"] == len(recon.graph["nodes"])
    assert stats["edge_count"] == len(recon.graph["edges"])

    from collections import Counter
    recomputed_nodes = dict(Counter(n["kind"] for n in recon.graph["nodes"]))
    recomputed_edges = dict(Counter(e["type"] for e in recon.graph["edges"]))
    assert stats["nodes_by_kind"] == recomputed_nodes
    assert stats["edges_by_type"] == recomputed_edges


def test_summary_contract_list_matches_contract_exists_facts(recon: ReconOutput):
    fact_contract_keys = {f["subject"]["contract"] for f in recon.facts_of_type("contract_exists")}
    summary_contract_keys = {c["key"] for c in recon.summary["contracts"]}
    assert fact_contract_keys == summary_contract_keys


# ===========================================================================
# metadata.json agrees with the actual analysis inputs and with facts.jsonl
# ===========================================================================

def test_metadata_files_analyzed_matches_actual_fixture_directory(recon: ReconOutput, fixtures_dir):
    on_disk = {f for f in os.listdir(fixtures_dir) if f.endswith(".sol")}
    assert set(recon.metadata["files_analyzed"]) == on_disk
    assert recon.metadata["files_failed"] == []
    assert recon.metadata["files_partially_analyzed"] == []
    assert recon.metadata["analysis_status"] == "complete"


def test_every_fact_source_file_was_reported_analyzed(recon: ReconOutput):
    analyzed = set(recon.metadata["files_analyzed"])
    referenced_files = {f["source"]["file"] for f in recon.facts if f.get("source")}
    unreported = referenced_files - analyzed
    assert unreported == set(), (
        f"facts.jsonl references source files metadata.json never reported as analyzed: {unreported}"
    )


def test_metadata_and_summary_agree_on_files_analyzed_count(recon: ReconOutput):
    assert recon.summary["analysis_coverage"]["files_analyzed"] == len(recon.metadata["files_analyzed"])
    assert recon.summary["analysis_coverage"]["files_failed"] == len(recon.metadata["files_failed"])
    assert recon.summary["analysis_coverage"]["partial_source_coverage"] == recon.metadata["partial_source_coverage"]
