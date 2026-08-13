"""Deterministic, content-derived identifier generation.

No identifier produced by this module is random. Every ID is a stable hash of
inputs that describe *where* the thing came from (file, source range, AST node
id, logical role). Re-running the analyzer on an unchanged source tree must
produce byte-identical IDs, which is what makes `recon/` output diffable and
suitable for downstream consumption.
"""

from __future__ import annotations

import hashlib


def _digest(*parts: str) -> str:
    h = hashlib.sha1("\x1f".join(parts).encode("utf-8"))
    return h.hexdigest()[:16]


def make_id(prefix: str, *parts: str) -> str:
    """Build a stable id like ``fact:9a3f1c2b4e5d6a7b``.

    ``parts`` should uniquely identify the entity within the whole repository
    (e.g. file path + AST node id + role string).
    """
    return f"{prefix}:{_digest(*[str(p) for p in parts])}"


def fact_id(fact_type: str, file: str, node_id: str, role: str = "") -> str:
    return make_id("fact", fact_type, file, str(node_id), role)


def evidence_id(file: str, start: int, end: int) -> str:
    return make_id("ev", file, str(start), str(end))


def node_id(kind: str, qualifier: str) -> str:
    return make_id("node", kind, qualifier)


def edge_id(edge_type: str, src: str, dst: str, qualifier: str = "") -> str:
    return make_id("edge", edge_type, src, dst, qualifier)
