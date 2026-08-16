"""Canonical evidence-tier classification (single source of truth).

This module is the ONE authority for evidence-tier classification across
the Threat Agent. Every consumer -- composition.py, hypothesis.py,
prioritization.py -- imports classify_evidence / EvidenceTier from here
and must not keep a local tiering implementation (Bug 4).

Evidence tiers represent the strength of evidence backing a hypothesis,
ordered from weakest to strongest:

    CO_OCCURRENCE < RELATIONSHIP_GROUNDED < ARGUMENT_DEPENDENCY < GRAPH_REACHABILITY

Each tier has strict semantic requirements:

1. GRAPH_REACHABILITY
   - The hypothesis references graph nodes AND graph edges that exist in
     recon.graph, form a single connected path, and stay within a bounded
     length. A security_relationship_chain fact alone is NOT enough (Bug 1).

2. ARGUMENT_DEPENDENCY
   - The observed facts include real argument/dataflow evidence from Recon:
     call_argument_dataflow, call_argument_origin_chain, input_origin
     (parameter/argument origin). Relationship chains without a dataflow
     component do NOT qualify (Bug 2).

3. RELATIONSHIP_GROUNDED
   - The observed facts include an explicit Recon relationship
     (security_relationship_chain, callback_relationship, ...) but no
     stronger evidence is proven.

4. CO_OCCURRENCE
   - Only co-occurring signals are present; fallback.

All fact lookups go through the loader's O(1) indexes (by_id), never
linear scans over the full fact list.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from . import loader

# A claimed graph path longer than this is not accepted as a bounded path.
MAX_PATH_EDGES = 32

# Recon fact types that constitute real argument/dataflow evidence (Bug 2).
# call_argument_dataflow: how a call argument is derived.
# call_argument_origin_chain: chain from a call argument back to its root
#   (root_kind=parameter is literally parameter origin).
# input_origin: where a function input originates (parameter/msg.sender).
# parameter_origin / argument_origin: forward-compatible aliases.
ARGUMENT_DATAFLOW_FACT_TYPES: frozenset[str] = frozenset({
    "call_argument_dataflow",
    "call_argument_origin_chain",
    "input_origin",
    "parameter_origin",
    "argument_origin",
})

# Recon fact types that constitute explicit relationship evidence. These
# ground a hypothesis at RELATIONSHIP_GROUNDED -- never higher on their own.
RELATIONSHIP_FACT_TYPES: frozenset[str] = frozenset({
    "security_relationship_chain",
    "callback_relationship",
    "relationship",
    "data_dependency",
    "control_dependency",
})


class EvidenceTier(str, Enum):
    """Evidence strength tiers, ordered from weakest to strongest."""

    CO_OCCURRENCE = "CO_OCCURRENCE"
    RELATIONSHIP_GROUNDED = "RELATIONSHIP_GROUNDED"
    ARGUMENT_DEPENDENCY = "ARGUMENT_DEPENDENCY"
    GRAPH_REACHABILITY = "GRAPH_REACHABILITY"

    @classmethod
    def all(cls) -> list[str]:
        return [t.value for t in cls]

    @classmethod
    def stronger_than(cls, tier: str) -> list[str]:
        """Return all tiers stronger than the given tier."""
        values = cls.all()
        idx = values.index(tier)
        return values[idx + 1:] if idx < len(values) - 1 else []

    @classmethod
    def coerce(cls, value: str | None) -> "EvidenceTier":
        """Best-effort conversion; empty/unknown values degrade to the
        weakest tier so unclassified evidence is never over-credited."""
        try:
            return cls(value) if value else cls.CO_OCCURRENCE
        except ValueError:
            return cls.CO_OCCURRENCE


def classify_evidence(
    observed_fact_ids: list[str],
    graph_nodes: list[str],
    graph_edges: list[str],
    recon: loader.ReconArtifact,
) -> EvidenceTier:
    """Canonical evidence-tier classifier.

    Semantics (strongest evidence wins, never inferred upward):
    - GRAPH_REACHABILITY: the referenced graph nodes/edges exist in
      recon.graph and form a verified bounded, connected path.
    - ARGUMENT_DEPENDENCY: an observed fact carries real argument/dataflow
      evidence (see ARGUMENT_DATAFLOW_FACT_TYPES).
    - RELATIONSHIP_GROUNDED: an observed fact carries an explicit Recon
      relationship (see RELATIONSHIP_FACT_TYPES), but nothing stronger.
    - CO_OCCURRENCE: only co-occurring signals.

    Args:
        observed_fact_ids: fact IDs referenced by the hypothesis
        graph_nodes: graph node IDs referenced by the hypothesis
        graph_edges: graph edge IDs referenced by the hypothesis
        recon: Recon artifact containing facts and graph

    Returns:
        EvidenceTier enum value
    """
    # Bug 1: GRAPH_REACHABILITY requires an actual, verified graph path.
    if _verify_graph_path(graph_nodes, graph_edges, recon):
        return EvidenceTier.GRAPH_REACHABILITY

    # Fact-level evidence, strongest first. O(len(observed_fact_ids)) with
    # O(1) by_id lookups -- no linear scans over the fact list.
    seen_dataflow = False
    seen_relationship = False
    for fid in observed_fact_ids:
        fact = recon.facts_obj.by_id.get(fid)
        if fact is None:
            continue
        ftype = fact.get("type", "")
        if ftype in ARGUMENT_DATAFLOW_FACT_TYPES:
            seen_dataflow = True
        elif ftype in RELATIONSHIP_FACT_TYPES:
            seen_relationship = True

    # Bug 2: only real argument/dataflow evidence qualifies.
    if seen_dataflow:
        return EvidenceTier.ARGUMENT_DEPENDENCY
    if seen_relationship:
        return EvidenceTier.RELATIONSHIP_GROUNDED
    return EvidenceTier.CO_OCCURRENCE


def _verify_graph_path(
    graph_nodes: list[str],
    graph_edges: list[str],
    recon: loader.ReconArtifact,
) -> bool:
    """Verify that the referenced nodes and edges form a bounded, connected
    path in recon.graph.

    A valid path means:
    - at least one node and at least one edge are referenced
    - the path length (unique edges) stays within MAX_PATH_EDGES
    - every referenced node exists in recon.graph
    - every referenced edge exists in recon.graph and both of its endpoints
      are among the referenced nodes
    - every referenced node is incident to a referenced edge, and the
      edge-induced subgraph is a single connected component (the edges
      form one chain, not disjoint fragments)

    Returns:
        True if a valid bounded path exists, False otherwise
    """
    if not graph_nodes or not graph_edges:
        return False

    edge_ids = list(dict.fromkeys(graph_edges))  # dedupe, keep order
    if len(edge_ids) > MAX_PATH_EDGES:
        return False

    node_set = set(graph_nodes)
    if any(n not in recon.graph.nodes_by_id for n in node_set):
        return False

    adjacency: dict[str, set[str]] = {}
    incident: set[str] = set()
    for eid in edge_ids:
        edge = recon.graph.edges_by_id.get(eid)
        if edge is None:
            return False
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src not in node_set or tgt not in node_set:
            return False
        adjacency.setdefault(src, set()).add(tgt)
        adjacency.setdefault(tgt, set()).add(src)
        incident.update((src, tgt))

    # Every referenced node must participate in the path...
    if incident != node_set:
        return False

    # ...and the path must be one connected component (undirected
    # traversal: a chain may branch at a hub node but must not split).
    start = next(iter(node_set))
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for neighbor in adjacency.get(current, ()):
            if neighbor not in seen:
                seen.add(neighbor)
                stack.append(neighbor)
    return seen == node_set
