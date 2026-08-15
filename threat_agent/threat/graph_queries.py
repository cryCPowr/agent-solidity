"""Graph queries for Threat Agent.

Provides reusable traversal patterns over the Recon graph:
- reachability_from(function_key)
- outgoing_capabilities(function_key)
- incoming_dependencies(function_key)
- cross_contract_chains(start_contract, max_depth=3)
- call_chains(function_key, max_depth=3)
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from . import loader


@dataclass
class PathEdge:
    edge_id: str
    edge_type: str
    source: str
    target: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Path:
    nodes: list[str]  # node IDs
    edges: list[PathEdge]


def reachability_from(
    recon: loader.ReconArtifact,
    function_key: str,
    max_depth: int = 5,
) -> Path:
    """Find all reachable nodes from a function node up to max_depth.

    Returns the full path (nodes + edges) traversed.
    """
    # Find the function node
    fn_node_id = _find_function_node(recon, function_key)
    if not fn_node_id:
        return Path(nodes=[], edges=[])

    visited: set[str] = {fn_node_id}
    queue: deque[tuple[str, list[PathEdge]]] = deque([(fn_node_id, [])])
    path = Path(nodes=[fn_node_id], edges=[])

    while queue:
        node_id, current_edges = queue.popleft()
        if len(current_edges) >= max_depth:
            continue

        for edge in recon.graph.outgoing.get(node_id, []):
            tgt = edge.get("target", "")
            if tgt not in visited:
                visited.add(tgt)
                pe = PathEdge(
                    edge_id=edge.get("id", ""),
                    edge_type=edge.get("type", ""),
                    source=edge.get("source", ""),
                    target=edge.get("target", ""),
                    properties=edge.get("properties") or {},
                )
                new_edges = current_edges + [pe]
                path.nodes.append(tgt)
                path.edges.append(pe)
                queue.append((tgt, new_edges))

    return path


def call_chains(
    recon: loader.ReconArtifact,
    function_key: str,
    max_depth: int = 3,
) -> list[Path]:
    """Find all call chains from a function (CALLS edges only).

    Returns a list of paths, each representing a chain of calls.
    """
    fn_node_id = _find_function_node(recon, function_key)
    if not fn_node_id:
        return []

    chains: list[Path] = []
    # BFS from function node through CALLS edges
    queue: deque[tuple[str, list[PathEdge]]] = deque()

    for edge in recon.graph.outgoing.get(fn_node_id, []):
        if edge.get("type") == "CALLS":
            tgt = edge.get("target", "")
            pe = PathEdge(
                edge_id=edge.get("id", ""),
                edge_type=edge.get("type", ""),
                source=edge.get("source", ""),
                target=edge.get("target", ""),
                properties=edge.get("properties") or {},
            )
            chains.append(Path(nodes=[fn_node_id, tgt], edges=[pe]))
            queue.append((tgt, [pe]))

    while queue:
        node_id, current_edges = queue.popleft()
        if len(current_edges) >= max_depth:
            continue
        for edge in recon.graph.outgoing.get(node_id, []):
            if edge.get("type") == "CALLS":
                tgt = edge.get("target", "")
                pe = PathEdge(
                    edge_id=edge.get("id", ""),
                    edge_type=edge.get("type", ""),
                    source=edge.get("source", ""),
                    target=edge.get("target", ""),
                    properties=edge.get("properties") or {},
                )
                new_edges = current_edges + [pe]
                chains.append(Path(
                    nodes=[fn_node_id] + [n for n, _ in _nodes_in_edges(new_edges)] + [tgt],
                    edges=new_edges,
                ))
                queue.append((tgt, new_edges))

    return chains


def cross_contract_chains(
    recon: loader.ReconArtifact,
    start_contract: str,
    max_depth: int = 3,
) -> list[Path]:
    """Find cross-contract chains from a contract.

    Traverses through CALLS, IMPLEMENTS, INHERITS edges.
    """
    # Find start contract node
    start_node_id = _find_contract_node(recon, start_contract)
    if not start_node_id:
        return []

    result: list[Path] = []
    visited_edges: set[str] = set()
    queue: deque[tuple[str, list[PathEdge], set[str]]] = deque([
        (start_node_id, [], set())
    ])

    while queue:
        node_id, edges, edge_visited = queue.popleft()
        if len(edges) >= max_depth:
            continue

        for edge in recon.graph.outgoing.get(node_id, []):
            eid = edge.get("id", "")
            if eid in edge_visited:
                continue
            if edge.get("type") not in ("CALLS", "IMPLEMENTS", "INHERITS", "DELEGATES_TO"):
                continue

            tgt_id = edge.get("target", "")
            tgt_node = recon.graph.nodes_by_id.get(tgt_id, {})
            tgt_contract = tgt_node.get("contract")

            # Only continue if we cross to a different contract
            if tgt_contract and tgt_contract != start_contract:
                pe = PathEdge(
                    edge_id=eid,
                    edge_type=edge.get("type", ""),
                    source=edge.get("source", ""),
                    target=edge.get("target", ""),
                    properties=edge.get("properties") or {},
                )
                new_visited = edge_visited | {eid}
                result.append(Path(
                    nodes=[node_id, tgt_id],
                    edges=edges + [pe],
                ))
                queue.append((tgt_id, edges + [pe], new_visited))

    return result


def _find_function_node(recon: loader.ReconArtifact, function_key: str) -> str | None:
    """Find the graph node ID for a function key."""
    for node in recon.graph.nodes:
        if node.get("kind") == "function":
            name = node.get("name", "")
            if name == function_key:
                return node.get("id")
            # Also check if function key matches a pattern in the name
            if function_key in name:
                return node.get("id")
    return None


def _find_contract_node(recon: loader.ReconArtifact, contract_key: str) -> str | None:
    """Find the graph node ID for a contract key."""
    for node in recon.graph.nodes:
        if node.get("kind") == "contract":
            name = node.get("name", "")
            key = node.get("contract") or name
            if key == contract_key or contract_key in name:
                return node.get("id")
    return None


def _nodes_in_edges(edges: list[PathEdge]) -> list[tuple[str, str]]:
    """Extract node IDs from a list of PathEdges."""
    nodes = []
    for e in edges:
        if e.source not in [n for n, _ in nodes]:
            nodes.append((e.source, e.target))
        nodes.append((e.source, e.target))
    return nodes
