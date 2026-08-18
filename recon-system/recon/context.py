"""Shared mutable context threaded through every analysis stage.

Centralizes: source access, line-number resolution, evidence/snippet
creation, and fact/graph accumulation, so individual analyzers stay focused
on *what* to extract rather than *how* to serialize it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Optional

from . import ast_utils, ids
from .inventory import ContractUnit, FunctionUnit
from .models import Evidence, Fact, GraphEdge, GraphNode, SourceRef


class IdCollisionError(Exception):
    """Raised when two distinct entities hash to the same truncated id.

    Node/edge ids (16 hex chars = 64 bits of a SHA1 digest, see
    ``recon/ids.py``) are computed independently at call sites *before*
    ``add_node``/``add_edge`` ever run, and other nodes/edges reference those
    precomputed id strings directly. That means -- unlike facts (see
    ``add_fact``) -- a colliding node/edge id can *not* be safely
    renamed/disambiguated after the fact: anything already holding the
    original id string would silently point at the wrong entity.
    So instead of overwriting (data loss) or silently renaming (dangling
    references), a genuine collision (same id, different payload) must fail
    loudly rather than corrupt the graph.
    """


@dataclass
class ProjectContext:
    repo_root: str
    snippets_dir: str

    files: dict = field(default_factory=dict)          # relpath -> content (str, as sent to solc)
    file_bytes: dict = field(default_factory=dict)       # relpath -> UTF-8 encoded bytes (matches solc `src` offsets)
    line_indexes: dict = field(default_factory=dict)   # relpath -> LineIndex
    asts: dict = field(default_factory=dict)            # relpath -> (group, source_unit)

    contracts: dict = field(default_factory=dict)        # contract_key -> ContractUnit
    decl_index: dict = field(default_factory=dict)        # (group, ast_id) -> decl info
    contract_by_group_ast_id: dict = field(default_factory=dict)  # (group, ast_id) -> contract_key
    function_by_key: dict = field(default_factory=dict)   # function_key -> FunctionUnit
    modifier_by_key: dict = field(default_factory=dict)   # modifier_key -> ModifierUnit
    event_by_key: dict = field(default_factory=dict)      # event_key -> EventUnit

    facts: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)          # evidence_id -> Evidence
    graph_nodes: dict = field(default_factory=dict)        # node_id -> GraphNode
    graph_edges: dict = field(default_factory=dict)        # edge_id -> GraphEdge

    warnings: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    dependency_graph: dict = field(default_factory=dict)
    partial_source_coverage: bool = False

    _fact_ids_seen: set = field(default_factory=set)
    _fact_id_collision_counts: dict = field(default_factory=dict)
    _edge_semantic_ids: dict = field(default_factory=dict)
    _edge_id_collision_counts: dict = field(default_factory=dict)

    # ---- source / evidence -------------------------------------------------

    def source_ref(self, file: str, node: dict, extra: str = "") -> Optional[SourceRef]:
        parsed = ast_utils.parse_src(node.get("src")) if node else None
        if not parsed:
            return None
        start, length, _fidx = parsed
        end = start + length
        li = self.line_indexes.get(file)
        line_start = li.line_for_offset(start) if li else None
        line_end = li.line_for_offset(max(end - 1, start)) if li else None
        return SourceRef(
            file=file,
            start=start,
            end=end,
            line_start=line_start,
            line_end=line_end,
            ast_node_id=str(node.get("id")),
        )

    def make_evidence(self, file: str, node: dict) -> Optional[str]:
        parsed = ast_utils.parse_src(node.get("src")) if node else None
        if not parsed:
            return None
        start, length, _fidx = parsed
        end = start + length
        eid = ids.evidence_id(file, start, end)
        if eid in self.evidence:
            return eid

        content = self.file_bytes.get(file, b"")
        snippet_bytes = content[start:end]
        # keep snippets concise: cap length, do not dump whole files/functions
        max_len = 800
        truncated = len(snippet_bytes) > max_len
        if truncated:
            snippet_bytes = snippet_bytes[:max_len]
        snippet = snippet_bytes.decode("utf-8", errors="replace")
        if truncated:
            snippet += "\n/* … truncated … */"

        li = self.line_indexes.get(file)
        start_line = li.line_for_offset(start) if li else None
        end_line = li.line_for_offset(max(end - 1, start)) if li else None

        snippet_rel = f"{eid.split(':')[1]}.sol.txt"
        snippet_path = os.path.join(self.snippets_dir, snippet_rel)
        with open(snippet_path, "w") as f:
            f.write(snippet)

        self.evidence[eid] = Evidence(
            id=eid,
            file=file,
            start_line=start_line,
            end_line=end_line,
            start=start,
            end=end,
            snippet_path=os.path.join("snippets", snippet_rel),
            fact_ids=[],
        )
        return eid

    def link_evidence(self, evidence_id: Optional[str], fact_id: str) -> None:
        if evidence_id and evidence_id in self.evidence:
            self.evidence[evidence_id].fact_ids.append(fact_id)

    # ---- facts ---------------------------------------------------------

    def add_fact(self, fact: Fact) -> Fact:
        if fact.id in self._fact_ids_seen:
            # Deterministic disambiguation: append an occurrence counter.
            # Traversal order is stable across runs, so this remains
            # reproducible. This should be rare (see _emit_fact's use of full
            # property content in its id digest) but must never silently
            # collide, drop, or overwrite a fact.
            n = self._fact_id_collision_counts.get(fact.id, 1) + 1
            self._fact_id_collision_counts[fact.id] = n
            original_id = fact.id
            fact.id = f"{fact.id}-{n}"
            self.warn("fact id collision disambiguated", original_id=original_id, new_id=fact.id)
        self._fact_ids_seen.add(fact.id)
        self.facts.append(fact)
        for ev in fact.evidence:
            self.link_evidence(ev, fact.id)
        return fact

    # ---- graph -----------------------------------------------------------

    def add_node(self, node: GraphNode) -> GraphNode:
        existing = self.graph_nodes.get(node.id)
        if existing is not None and existing.to_dict() != node.to_dict():
            raise IdCollisionError(
                f"graph node id collision on {node.id!r}: "
                f"existing={existing.to_dict()!r} new={node.to_dict()!r}"
            )
        self.graph_nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        semantic_key = (
            edge.type,
            edge.source,
            edge.target,
            edge.status,
            tuple(sorted(edge.properties.items())),
            tuple(sorted(set(edge.fact_ids))),
        )
        existing_id = self._edge_semantic_ids.get(semantic_key)
        if existing_id is not None:
            return self.graph_edges[existing_id]

        existing = self.graph_edges.get(edge.id)
        if existing is not None and existing.to_dict() != edge.to_dict():
            n = self._edge_id_collision_counts.get(edge.id, 1) + 1
            self._edge_id_collision_counts[edge.id] = n
            edge = replace(edge, id=f"{edge.id}-{n}")
            if edge.id in self.graph_edges:
                raise IdCollisionError(
                    f"graph edge id collision disambiguation reused existing id {edge.id!r}: "
                    f"new={edge.to_dict()!r}"
                )
            self.warn(
                "graph edge id collision disambiguated",
                original_id=existing.id,
                new_id=edge.id,
                existing=existing.to_dict(),
                new=edge.to_dict(),
            )

        self.graph_edges[edge.id] = edge
        self._edge_semantic_ids[semantic_key] = edge.id
        return edge

    def warn(self, message: str, **extra) -> None:
        entry = {"message": message}
        entry.update(extra)
        self.warnings.append(entry)
