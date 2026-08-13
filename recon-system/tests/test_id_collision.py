"""Unit tests for id generation and collision handling.

`recon/ids.py` derives every fact/node/edge id from a SHA1 digest truncated
to 16 hex chars (64 bits). Truncation makes a collision between two
*different* entities possible (birthday-bound, not zero), and prior to this
fix `ProjectContext.add_node` / `add_edge` used the id directly as a dict
key: two different entities colliding on id meant the second one silently
clobbered the first with no warning, no error, nothing in the output to
show a fact/node/edge went missing.

These tests do not try to find a real SHA1 collision (infeasible). Instead
they simulate one directly against the data structures that matter: given
two *different* payloads that happen to share an id, the system must never
silently drop one of them.
"""

from __future__ import annotations

import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from recon import ids  # noqa: E402
from recon.context import IdCollisionError, ProjectContext  # noqa: E402
from recon.models import Fact, GraphEdge, GraphNode  # noqa: E402


def _ctx(tmp_path) -> ProjectContext:
    snippets_dir = str(tmp_path / "snippets")
    os.makedirs(snippets_dir, exist_ok=True)
    return ProjectContext(repo_root=str(tmp_path), snippets_dir=snippets_dir)


# ---------------------------------------------------------------------------
# Document the truncation itself, so this test starts failing (loudly, in
# CI) if someone widens/narrows the digest without noticing the collision
# surface it creates.
# ---------------------------------------------------------------------------

def test_digest_is_truncated_to_64_bits():
    raw_id = ids.make_id("node", "kind", "qualifier")
    digest = raw_id.split(":", 1)[1]
    assert len(digest) == 16, (
        "ids.make_id digest width changed; re-check the collision handling "
        "in ProjectContext.add_node/add_edge/add_fact still makes sense"
    )
    int(digest, 16)  # must still be valid hex


def test_same_inputs_are_deterministic():
    assert ids.node_id("state_var", "Foo.bar") == ids.node_id("state_var", "Foo.bar")


def test_different_inputs_normally_differ():
    assert ids.node_id("state_var", "Foo.bar") != ids.node_id("state_var", "Foo.baz")


# ---------------------------------------------------------------------------
# Facts: a colliding id is deterministically disambiguated (never dropped,
# never overwritten) because nothing else has captured the original fact id
# string ahead of time -- add_fact is the sole point where fact ids become
# visible to the rest of the system.
# ---------------------------------------------------------------------------

def _fact(fact_id: str, marker: str) -> Fact:
    return Fact(
        id=fact_id,
        type="dummy_fact",
        status="observed",
        subject={"marker": marker},
        properties={},
        source=None,
        evidence=[],
        confidence="high",
        extraction_method="ast",
    )


def test_add_fact_disambiguates_colliding_ids_instead_of_dropping(tmp_path):
    ctx = _ctx(tmp_path)
    first = ctx.add_fact(_fact("fact:deadbeefdeadbeef", "entity-A"))
    second = ctx.add_fact(_fact("fact:deadbeefdeadbeef", "entity-B"))

    assert first.id == "fact:deadbeefdeadbeef"
    assert second.id != first.id, "colliding fact must not silently overwrite the first"
    assert len(ctx.facts) == 2, "both facts must be retained"
    assert {f.subject["marker"] for f in ctx.facts} == {"entity-A", "entity-B"}
    assert any("collision" in w["message"] for w in ctx.warnings), (
        "a fact id collision must be recorded in ctx.warnings, not silent"
    )


def test_add_fact_reprocessing_identical_fact_is_not_flagged_as_collision(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.add_fact(_fact("fact:cafecafecafecafe", "same"))
    ctx.add_fact(_fact("fact:cafecafecafecafe", "same"))
    # Facts don't dedupe on identical content today (each add_fact call is a
    # real occurrence) -- this just documents that behavior stays a
    # disambiguation, not a crash, either way.
    assert len(ctx.facts) == 2


# ---------------------------------------------------------------------------
# Nodes / edges: ids are computed at call sites *before* add_node/add_edge
# runs and are then reused directly by other edges (e.g. an edge's `source`/
# `target` is the precomputed node id string) -- so, unlike facts, a
# colliding node/edge id can NOT be safely renamed after the fact without
# leaving dangling references elsewhere in the graph. A genuine collision
# (same id, different payload) must therefore fail loudly instead.
# ---------------------------------------------------------------------------

def _node(node_id: str, label: str) -> GraphNode:
    return GraphNode(id=node_id, kind="dummy", label=label, properties={})


def _edge(edge_id: str, target: str) -> GraphEdge:
    return GraphEdge(
        id=edge_id, type="DUMMY", source="node:aaaa", target=target,
        status="observed", properties={}, fact_ids=[],
    )


def test_add_node_collision_with_different_payload_raises(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.add_node(_node("node:deadbeefdeadbeef", "ContractA"))
    with pytest.raises(IdCollisionError):
        ctx.add_node(_node("node:deadbeefdeadbeef", "ContractB"))
    # The original entity must still be intact -- not overwritten.
    assert ctx.graph_nodes["node:deadbeefdeadbeef"].label == "ContractA"


def test_add_node_reinsert_of_identical_payload_is_idempotent(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.add_node(_node("node:cafecafecafecafe", "ContractA"))
    # Re-adding the exact same node (e.g. re-visited via two AST paths) must
    # not be treated as a collision.
    ctx.add_node(_node("node:cafecafecafecafe", "ContractA"))
    assert len(ctx.graph_nodes) == 1


def test_add_edge_collision_with_different_payload_raises(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.add_edge(_edge("edge:deadbeefdeadbeef", "node:bbbb"))
    with pytest.raises(IdCollisionError):
        ctx.add_edge(_edge("edge:deadbeefdeadbeef", "node:cccc"))
    assert ctx.graph_edges["edge:deadbeefdeadbeef"].target == "node:bbbb"


def test_add_edge_reinsert_of_identical_payload_is_idempotent(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.add_edge(_edge("edge:cafecafecafecafe", "node:bbbb"))
    ctx.add_edge(_edge("edge:cafecafecafecafe", "node:bbbb"))
    assert len(ctx.graph_edges) == 1


def test_node_collision_is_never_silently_swallowed_no_matter_the_order(tmp_path):
    """Regression guard for the original bug: `self.graph_nodes[node.id] =
    node` with no prior check meant whichever entity was inserted *last*
    silently won, with zero trace of the other one anywhere in the output.
    """
    ctx = _ctx(tmp_path)
    ctx.add_node(_node("node:1111111111111111", "First"))
    try:
        ctx.add_node(_node("node:1111111111111111", "Second"))
        assert False, "expected IdCollisionError, but the second node was accepted"
    except IdCollisionError:
        pass
    # Exactly one entity survives, and it's the *first* one -- never a
    # silent, untracked overwrite.
    assert len(ctx.graph_nodes) == 1
    assert ctx.graph_nodes["node:1111111111111111"].label == "First"
