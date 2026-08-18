"""Artifact loader for the Attack Agent.

Loads two upstream artifact sets:
  1. Recon artifacts (facts.jsonl / graph.json / summary.json /
     metadata.json) -- the same layout the Threat Agent consumes.
  2. Threat artifacts (hypotheses.jsonl / invariants.json / summary.json).

No Solidity parsing happens here; source grounding uses the source
locations embedded in Recon facts (file + line spans).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FactIndex:
    facts: list[dict[str, Any]] = field(default_factory=list)
    by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_type: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    by_function: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class GraphIndex:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    nodes_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    outgoing: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    incoming: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class ReconArtifact:
    facts_obj: FactIndex
    graph: GraphIndex
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    protocol: dict[str, Any] = field(default_factory=dict)
    dependencies: dict[str, Any] = field(default_factory=dict)
    output_dir: str = ""

    def facts_for_function(self, fn_key: str) -> list[dict[str, Any]]:
        return self.facts_obj.by_function.get(fn_key, [])

    def fact(self, fact_id: str) -> dict[str, Any] | None:
        return self.facts_obj.by_id.get(fact_id)

    def source_location(self, fact_id: str) -> str:
        """Human-readable source grounding for a fact, or ''."""
        fact = self.fact(fact_id)
        if not fact:
            return ""
        src = fact.get("source") or {}
        path = src.get("file") or src.get("path") or ""
        if not path:
            return ""
        start = src.get("line_start")
        end = src.get("line_end")
        if start is not None and end is not None:
            return f"{path}:{start}-{end}"
        if start is not None:
            return f"{path}:{start}"
        return path


@dataclass
class ThreatArtifact:
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    invariants: list[dict[str, Any]] = field(default_factory=list)
    surfaces: list[dict[str, Any]] = field(default_factory=list)
    threat_model: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    output_dir: str = ""

    def invariant(self, inv_id: str) -> dict[str, Any] | None:
        for inv in self.invariants:
            if inv.get("id") == inv_id:
                return inv
        return None


def _index_facts(facts: list[dict[str, Any]]) -> FactIndex:
    idx = FactIndex(facts=facts)
    for fact in facts:
        fid = fact.get("id", "")
        if fid:
            idx.by_id[fid] = fact
        idx.by_type.setdefault(fact.get("type", ""), []).append(fact)
        subj = fact.get("subject") or {}
        fn = subj.get("function") or subj.get("caller") or ""
        if fn:
            idx.by_function.setdefault(fn, []).append(fact)
    return idx


def _index_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> GraphIndex:
    g = GraphIndex(nodes=nodes or [], edges=edges or [])
    for node in g.nodes:
        g.nodes_by_id[node.get("id", "")] = node
    for edge in g.edges:
        eid = edge.get("id", "")
        g.edges_by_id[eid] = edge
        g.outgoing.setdefault(edge.get("source", ""), []).append(edge)
        g.incoming.setdefault(edge.get("target", ""), []).append(edge)
    return g


def load_recon(output_dir: str) -> ReconArtifact:
    def _json(name: str) -> dict[str, Any]:
        path = os.path.join(output_dir, name)
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    facts: list[dict[str, Any]] = []
    facts_path = os.path.join(output_dir, "facts.jsonl")
    if os.path.exists(facts_path):
        with open(facts_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    facts.append(json.loads(line))

    graph_raw = _json("graph.json")
    return ReconArtifact(
        facts_obj=_index_facts(facts),
        graph=_index_graph(graph_raw.get("nodes"), graph_raw.get("edges")),
        summary=_json("summary.json"),
        metadata=_json("metadata.json"),
        coverage=_json("coverage.json"),
        protocol=_json("protocol.json"),
        dependencies=_json("dependencies.json"),
        output_dir=output_dir,
    )


def load_threat(output_dir: str) -> ThreatArtifact:
    hypotheses: list[dict[str, Any]] = []
    hyp_path = os.path.join(output_dir, "hypotheses.jsonl")
    if os.path.exists(hyp_path):
        with open(hyp_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    hypotheses.append(json.loads(line))

    invariants: list[dict[str, Any]] = []
    inv_path = os.path.join(output_dir, "invariants.json")
    if os.path.exists(inv_path):
        with open(inv_path, encoding="utf-8") as f:
            data = json.load(f)
        invariants = data.get("invariants") or []

    surfaces: list[dict[str, Any]] = []
    surf_path = os.path.join(output_dir, "surfaces.json")
    if os.path.exists(surf_path):
        with open(surf_path, encoding="utf-8") as f:
            data = json.load(f)
        surfaces = data.get("surfaces") or []

    threat_model: dict[str, Any] = {}
    tm_path = os.path.join(output_dir, "threat_model.json")
    if os.path.exists(tm_path):
        with open(tm_path, encoding="utf-8") as f:
            threat_model = json.load(f)

    summary: dict[str, Any] = {}
    sum_path = os.path.join(output_dir, "summary.json")
    if os.path.exists(sum_path):
        with open(sum_path, encoding="utf-8") as f:
            summary = json.load(f)

    return ThreatArtifact(
        hypotheses=hypotheses,
        invariants=invariants,
        surfaces=surfaces,
        threat_model=threat_model,
        summary=summary,
        output_dir=output_dir,
    )
