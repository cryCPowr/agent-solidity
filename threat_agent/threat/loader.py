"""Recon artifact loader.

Loads facts.jsonl, graph.json, summary.json, metadata.json from Recon output
directory. Provides a unified, structured view for downstream Threat Agent
modules. Does NOT re-parse Solidity sources.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReconFacts:
    """Indexed view of Recon facts."""

    facts: list[dict[str, Any]] = field(default_factory=list)
    by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_type: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    by_function: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class ReconGraph:
    """Indexed view of Recon graph (nodes + edges)."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    nodes_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    outgoing: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    incoming: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class ReconSummary:
    """Recon summary statistics (raw)."""

    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconMetadata:
    """Recon run metadata."""

    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconArtifact:
    """Combined Recon artifact set, primary input for Threat Agent."""

    facts_obj: ReconFacts
    graph: ReconGraph
    summary: ReconSummary
    metadata: ReconMetadata
    output_dir: str


def load_facts(path: str) -> ReconFacts:
    """Load facts.jsonl into indexed view."""
    facts: list[dict[str, Any]] = []
    if not os.path.exists(path):
        return ReconFacts()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            facts.append(json.loads(line))
    return _index_facts(facts)


def _index_facts(facts: list[dict[str, Any]]) -> ReconFacts:
    obj = ReconFacts(facts=facts)
    for fact in facts:
        fid = fact.get("id", "")
        obj.by_id[fid] = fact
        ftype = fact.get("type", "")
        obj.by_type.setdefault(ftype, []).append(fact)
        subj = fact.get("subject") or {}
        fn = subj.get("function") or subj.get("caller") or ""
        if fn:
            obj.by_function.setdefault(fn, []).append(fact)
    return obj


def load_graph(path: str) -> ReconGraph:
    """Load graph.json into indexed view."""
    graph = ReconGraph()
    if not os.path.exists(path):
        return graph
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    graph.nodes = data.get("nodes") or []
    graph.edges = data.get("edges") or []
    for node in graph.nodes:
        nid = node.get("id", "")
        graph.nodes_by_id[nid] = node
    for edge in graph.edges:
        eid = edge.get("id", "")
        graph.edges_by_id[eid] = edge
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        graph.outgoing.setdefault(src, []).append(edge)
        graph.incoming.setdefault(tgt, []).append(edge)
    return graph


def load_summary(path: str) -> ReconSummary:
    if not os.path.exists(path):
        return ReconSummary()
    with open(path, "r", encoding="utf-8") as f:
        return ReconSummary(raw=json.load(f))


def load_metadata(path: str) -> ReconMetadata:
    if not os.path.exists(path):
        return ReconMetadata()
    with open(path, "r", encoding="utf-8") as f:
        return ReconMetadata(raw=json.load(f))


def load_recon(output_dir: str) -> ReconArtifact:
    """Load all Recon artifacts from a given output directory."""
    facts_obj = load_facts(os.path.join(output_dir, "facts.jsonl"))
    graph = load_graph(os.path.join(output_dir, "graph.json"))
    summary = load_summary(os.path.join(output_dir, "summary.json"))
    metadata = load_metadata(os.path.join(output_dir, "metadata.json"))
    return ReconArtifact(
        facts_obj=facts_obj,
        graph=graph,
        summary=summary,
        metadata=metadata,
        output_dir=output_dir,
    )


def facts_for_function(recon: ReconArtifact, function_key: str) -> list[dict[str, Any]]:
    """Return all facts whose subject/caller references the given function key."""
    return recon.facts_obj.by_function.get(function_key, [])


def functions(recon: ReconArtifact) -> list[dict[str, Any]]:
    """Return all function-level facts (function_exists)."""
    return recon.facts_obj.by_type.get("function_exists", [])


def contracts(recon: ReconArtifact) -> list[dict[str, Any]]:
    """Return all contract-level facts (contract_exists)."""
    return recon.facts_obj.by_type.get("contract_exists", [])