"""Composition-selectivity regression tests (threat-perbaikan.md #6/#7).

Negative fixtures: weak structural adjacency must NOT be promoted into
strong security chains. Positive fixture: a fully evidenced multi-stage
chain MUST compose into exactly one strong hypothesis.

All fixtures are SYNTHETIC and GENERIC -- invented names only, no
benchmark identifiers.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.test_generic_composition import (  # noqa: E402
    FN, PRIORITY_ORDER, _arithmetic, _capability, _chains_for,
    _dynamic_call, _entrypoint, _fact, _input_origin, _param_flow,
    _pipeline, _static_call, _state_write, _synthetic_recon,
)
from threat.hypothesis import generate_hypotheses  # noqa: E402
from threat.invariants import generate_invariants  # noqa: E402
from threat.prioritization import prioritize_all  # noqa: E402
from threat.security_chains import compose_security_chains  # noqa: E402


def _max_priority(hypos, fn_substring):
    related = [h for h in hypos if fn_substring in " ".join(h.affected_functions)]
    return max((PRIORITY_ORDER[h.priority] for h in related), default=None)


def _strong_chains(hypos, fn_substring):
    return [
        h for h in _chains_for(hypos, fn_substring)
        if h.composition_strength == "STRONG_SECURITY_CHAIN"
    ]


# ---------------------------------------------------------------------------
# Negative 1: dynamic call + unrelated state write
# ---------------------------------------------------------------------------

def test_dynamic_call_plus_unrelated_state_write_not_strong():
    """A state write whose variables share no identifier with the proven
    flows/interaction is same-function adjacency only: the effect stage
    may exist but must be linkage-graded adjacent_only (uncertain), must
    not attach an invariant, and must not yield a strong chain."""
    fn = FN.format(fn="unrelatedWrite")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _param_flow(3, fn),            # argument "value"
        _dynamic_call(4, fn),          # target "target", member "forward"
        _state_write(5, fn, name="bookkeeping"),  # no shared identifier
    ]
    _, _, hypos = _pipeline(facts)

    chains = _chains_for(hypos, fn)
    assert chains, "relation-backed chain may still exist"
    for h in chains:
        stages = {s["stage"]: s for s in h.chain}
        assert "state_value_effect" not in stages or (
            stages["state_value_effect"]["linkage"] == "adjacent_only"
            and stages["state_value_effect"]["status"] == "uncertain"
        ), "unrelated state write must at most be an adjacent_only effect"
        assert "invariant_concern" not in stages
        assert h.composition_strength != "STRONG_SECURITY_CHAIN"
    assert _strong_chains(hypos, fn) == []


# ---------------------------------------------------------------------------
# Negative 2: dynamic call + unrelated arithmetic
# ---------------------------------------------------------------------------

def test_dynamic_call_plus_unrelated_arithmetic_not_strong():
    """Arithmetic co-occurring with a dynamic call carries no chain meaning
    at all: it must never appear as a chain stage nor push any hypothesis
    of this function above the structural bands."""
    fn = FN.format(fn="unrelatedMath")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _param_flow(2, fn),
        _dynamic_call(3, fn),
        _arithmetic(4, fn),
    ]
    _, _, hypos = _pipeline(facts)

    for h in hypos:
        if fn in " ".join(h.affected_functions):
            stage_names = {s["stage"] for s in h.chain}
            assert "state_value_effect" not in stage_names
            assert h.composition_strength != "STRONG_SECURITY_CHAIN"
            # arithmetic is not security evidence: ceiling keeps it low
            if h.category != "security_chain":
                assert PRIORITY_ORDER[h.priority] <= PRIORITY_ORDER["medium_interest"]


# ---------------------------------------------------------------------------
# Negative 3: dynamic call + unrelated invariant primitive
# ---------------------------------------------------------------------------

def test_dynamic_call_plus_unrelated_invariant_not_attached():
    """An asset operation in the same function generates an
    asset-conservation invariant candidate covering the function, but if
    the asset flow shares no identifier with the chain's evidence the
    invariant must NOT be attached to the chain."""
    fn = FN.format(fn="unrelatedInvariant")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _param_flow(3, fn),            # argument "value"
        _dynamic_call(4, fn),          # target "target"
        _fact(5, "eth_transfer", fn, {"amount_expression": ["reserveBuffer"]}),
    ]
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    assert invariants, "fixture must produce an invariant candidate"

    chains = compose_security_chains(recon, invariants, lambda: "H-T")
    assert chains
    for h in chains:
        stages = {s["stage"]: s for s in h.chain}
        assert "invariant_concern" not in stages, (
            "invariant candidate without connecting evidence must not be "
            "attached to the chain"
        )
        assert "state_value_effect" not in stages or (
            stages["state_value_effect"]["linkage"] in
            ("adjacent_only", "post_call_derived")
        )
        assert h.composition_strength != "STRONG_SECURITY_CHAIN"


# ---------------------------------------------------------------------------
# Negative 4: dynamic call + uncertain callback only stays moderate/weak
# ---------------------------------------------------------------------------

def test_uncertain_callback_alone_stays_moderate():
    """caller input + dynamic call + uncertain callback opportunity (no
    related downstream effect, no authority, no invariant) must remain
    moderate/weak: the uncertain stage contributes no weight and the
    composition is not strong."""
    fn = FN.format(fn="callbackOnly")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _param_flow(3, fn),
        _dynamic_call(4, fn),
    ]
    _, _, hypos = _pipeline(facts)

    chains = _chains_for(hypos, fn)
    assert chains
    h = chains[0]
    cb = {s["stage"]: s for s in h.chain}["downstream_execution_opportunity"]
    assert cb["status"] == "uncertain"
    assert cb.get("weak_signal") is True
    assert h.composition_strength in ("", "STRUCTURAL", "SECURITY_RELEVANT")
    assert h.composition_strength != "STRONG_SECURITY_CHAIN"
    assert PRIORITY_ORDER[h.priority] <= PRIORITY_ORDER["medium_interest"], (
        "uncertain callback alone must not elevate the chain to high"
    )


# ---------------------------------------------------------------------------
# Negative 5: library/tester helper with externally reachable function
# ---------------------------------------------------------------------------

def test_helper_style_entrypoint_not_strong():
    """An externally reachable helper whose only interaction is a static
    (fixed-target) call plus an unrelated state write: no influence
    evidence, no dynamic target -> no security chain at all, and nothing
    for this function above the structural bands."""
    fn = FN.format(fn="helperProbe")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _static_call(2, fn),           # fixed target, no caller influence
        _state_write(3, fn, name="cacheSlot"),
        _arithmetic(4, fn),
    ]
    _, _, hypos = _pipeline(facts)

    assert _chains_for(hypos, fn) == [], (
        "static-target helper must not compose a security chain"
    )
    assert _strong_chains(hypos, fn) == []
    for h in hypos:
        if fn in " ".join(h.affected_functions):
            assert PRIORITY_ORDER[h.priority] <= PRIORITY_ORDER["medium_interest"], h.statement


# ---------------------------------------------------------------------------
# Negative 6: graph adjacency without semantic dependency
# ---------------------------------------------------------------------------

def test_graph_adjacency_without_semantic_dependency_not_strong():
    """A dynamic CALLS edge in the graph connects two nodes, but no fact
    ties any caller influence to the interaction: graph adjacency alone
    must not compose a security chain or rank above the structural bands."""
    nodes = [
        {"id": "n1", "kind": "function", "label": "originFn", "name": "originFn"},
        {"id": "n2", "kind": "external_target", "label": "sinkFn", "name": "sinkFn"},
    ]
    edges = [{
        "id": "e1", "type": "CALLS", "source": "n1", "target": "n2",
        "properties": {"target_status": "dynamic"},
    }]
    fn = FN.format(fn="graphAdjacent")
    facts = [_fact(0, "function_exists", fn)]
    recon = _synthetic_recon(facts, nodes, edges)
    invariants = generate_invariants(recon)
    hypos = prioritize_all(generate_hypotheses(recon, invariants), recon)

    assert _chains_for(hypos, fn) == []
    graph_only = [h for h in hypos if h.graph_edges]
    for h in graph_only:
        assert h.chain == [], "graph adjacency is not chain evidence"
        assert PRIORITY_ORDER[h.priority] <= PRIORITY_ORDER["medium_interest"]


# ---------------------------------------------------------------------------
# Positive: fully evidenced multi-stage chain composes exactly one strong
# hypothesis (threat-perbaikan.md #7)
# ---------------------------------------------------------------------------

def test_full_chain_composes_one_strong_hypothesis():
    fn = FN.format(fn="fullyEvidenced")
    facts = [
        _fact(0, "function_exists", fn),
        # attacker-controlled input
        _entrypoint(1, fn),
        _input_origin(2, fn, origin="msg.sender"),
        # security-relevant authority/capability
        _capability(3, fn, capability="can_transfer_token"),
        # proven propagation of the caller-chosen parameter
        _fact(4, "call_argument_origin_chain", fn, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "payout",
            "chain": [{"kind": "parameter", "name": "payout", "relation": "root"}],
        }),
        # external execution on a caller-influenced dynamic recipient
        _fact(5, "external_call_surface", fn, {
            "call_type": "external", "member": "dispatch",
            "target_expression": "payout", "target_status": "dynamic",
        }),
        # sensitive asset/state effect sharing the dataflow identifier
        _fact(6, "eth_transfer", fn, {"amount_expression": ["payout"]}),
        _state_write(7, fn, name="payout"),
    ]
    _, _, hypos = _pipeline(facts)

    strong = _strong_chains(hypos, fn)
    assert len(strong) == 1, (
        "the fully evidenced chain must produce exactly ONE strong composed "
        f"hypothesis, got {len(strong)}"
    )
    h = strong[0]
    stages = [s["stage"] for s in h.chain]
    assert stages == [
        "untrusted_influence",
        "argument_propagation",
        "external_execution",
        "downstream_execution_opportunity",
        "state_value_effect",
        "invariant_concern",
    ]
    by_stage = {s["stage"]: s for s in h.chain}
    assert by_stage["state_value_effect"]["status"] == "observed"
    assert h.control_provenance == "PROVEN"
    assert h.invariant_candidate_id, "evidence-linked invariant must be attached"
    assert PRIORITY_ORDER[h.priority] >= PRIORITY_ORDER["high_interest"]

    # ...and it ranks strictly above the moderate uncertain-callback chain
    # on the same fixture vocabulary (negative 4 shape).
    fn_weak = FN.format(fn="weakContrast")
    facts_weak = [
        _fact(10, "function_exists", fn_weak),
        _entrypoint(11, fn_weak),
        _input_origin(12, fn_weak),
        _param_flow(13, fn_weak),
        _dynamic_call(14, fn_weak),
    ]
    _, _, hypos_weak = _pipeline(facts_weak)
    weak_chains = _chains_for(hypos_weak, fn_weak)
    assert weak_chains
    assert PRIORITY_ORDER[h.priority] > PRIORITY_ORDER[weak_chains[0].priority]


# ===========================================================================
# Patch 2 (threat-perbaikan.md: HARDEN STRONG_SECURITY_CHAIN SEMANTICS)
# ===========================================================================

def test_asset_movement_plus_generic_invariant_not_strong():
    """threat-perbaikan.md #9: dynamic call + asset movement + generic
    invariant candidate must NOT become STRONG_SECURITY_CHAIN when the
    asset movement shares no identifier with the chain's dataflow
    (function-level asset presence is not linked asset flow)."""
    fn = FN.format(fn="coincidentalAssets")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _param_flow(3, fn),            # attacker argument "value"
        _dynamic_call(4, fn),          # target "target"
        # asset movement on unrelated identifiers -> adjacent_only
        _fact(5, "asset_operation", fn, {
            "operation": "transfer", "target_expression": "vaultToken",
            "arguments": ["treasuryBalance"],
        }),
    ]
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    assert invariants, "fixture must produce a generic invariant candidate"

    hypos = prioritize_all(generate_hypotheses(recon, invariants), recon)
    chains = _chains_for(hypos, fn)
    assert chains
    for h in chains:
        stages = {s["stage"]: s for s in h.chain}
        if "state_value_effect" in stages:
            assert stages["state_value_effect"]["linkage"] in (
                "adjacent_only", "post_call_derived",
            ), "unlinked asset movement must not be asset_flow_linked"
            assert stages["state_value_effect"]["status"] == "uncertain"
        assert "invariant_concern" not in stages, (
            "a generic invariant over unrelated asset facts must not "
            "attach to this chain"
        )
        assert h.composition_strength != "STRONG_SECURITY_CHAIN"
        assert h.affected_assets == [], (
            "function-level asset presence must not claim asset impact"
        )


def test_possible_callback_grade_alone_never_strong():
    """threat-perbaikan.md #4: a POSSIBLE (unlinked-recipient) downstream
    execution grade must never upgrade a chain to STRONG, even with a
    capability present."""
    fn = FN.format(fn="possibleOnly")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _param_flow(3, fn),            # attacker argument "value"
        _dynamic_call(4, fn),          # target "target": NOT attacker data
        _capability(5, fn, capability="can_transfer_token"),
        # linked state write so the chain has a real consequence
        _state_write(6, fn, name="value"),
    ]
    _, _, hypos = _pipeline(facts)

    chains = _chains_for(hypos, fn)
    assert chains
    h = chains[0]
    cb = {s["stage"]: s for s in h.chain}["downstream_execution_opportunity"]
    assert cb["grade"] == "POSSIBLE"
    assert cb["weak_signal"] is True
    # dataflow-linked write + authority, but the security-sensitive branch
    # needs STRUCTURALLY_INDICATED downstream execution -> not strong.
    assert h.composition_strength != "STRONG_SECURITY_CHAIN"


def test_structurally_indicated_callback_grades_up():
    """When the dynamic recipient IS attacker-influenced (shared flow
    identifiers) the downstream grade becomes STRUCTURALLY_INDICATED and,
    with authority + linked consequence, composes STRONG."""
    fn = FN.format(fn="recipientControlled")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _param_flow(3, fn),
        _fact(4, "external_call_surface", fn, {
            "call_type": "external", "member": "dispatch",
            "target_expression": "value", "target_status": "dynamic",
        }),
        _capability(5, fn, capability="can_transfer_token"),
        _state_write(6, fn, name="value"),
    ]
    _, _, hypos = _pipeline(facts)

    strong = _strong_chains(hypos, fn)
    assert len(strong) == 1
    cb = {s["stage"]: s for s in strong[0].chain}["downstream_execution_opportunity"]
    assert cb["grade"] == "STRUCTURALLY_INDICATED"
    assert cb["status"] == "inferred"


def test_semantic_same_flow_fixture_is_strong():
    """threat-perbaikan.md #10: the exact same asset/control flow --
    attacker-controlled spender -> approval authority -> external
    interaction -> same allowance flow -> downstream execution ->
    resulting asset movement -> invariant over that same flow -- composes
    STRONG_SECURITY_CHAIN."""
    fn = FN.format(fn="allowanceFlow")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn, origin="msg.sender"),
        # attacker-controlled spender reaches the sinks
        _fact(3, "call_argument_origin_chain", fn, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "spender",
            "chain": [{"kind": "parameter", "name": "spender", "relation": "root"}],
        }),
        # approval authority + arbitrary-target execution
        _capability(4, fn, capability="can_approve_spender"),
        _capability(5, fn, capability="can_call_arbitrary_target"),
        # the exact external interaction on the same identifiers
        _fact(6, "external_call_surface", fn, {
            "call_type": "external", "member": "approve",
            "target_expression": "reserveToken", "target_status": "static",
            "arguments": ["spender", "allowanceAmount"],
        }),
        # downstream execution pointed at attacker data
        _fact(7, "low_level_call", fn, {
            "target_expression": "spender", "target_status": "dynamic",
            "arguments": ["calldataPayload"],
        }),
        # resulting asset movement over the SAME flow identifiers
        _fact(8, "asset_operation", fn, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["spender", "allowanceAmount"],
        }),
        _state_write(9, fn, name="allowanceAmount"),
    ]
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    hypos = prioritize_all(generate_hypotheses(recon, invariants), recon)

    strong = _strong_chains(hypos, fn)
    assert len(strong) == 1
    h = strong[0]
    stages = {s["stage"]: s for s in h.chain}
    assert stages["state_value_effect"]["linkage"] == "asset_flow_linked"
    assert stages["state_value_effect"]["status"] == "observed"
    assert stages["downstream_execution_opportunity"]["grade"] == "STRUCTURALLY_INDICATED"
    assert h.invariant_candidate_id, "the same-flow invariant must attach"
    inv = next(i for i in invariants if i.id == h.invariant_candidate_id)
    assert set(inv.involved_facts) & set(h.observed_facts), (
        "attached invariant must be tied to the chain's own facts"
    )
    assert h.affected_assets == ["protocol assets"]
    assert PRIORITY_ORDER[h.priority] >= PRIORITY_ORDER["high_interest"]


def test_influence_inherited_across_internal_call_edge():
    """Evidence selection + semantic linkage: a private helper whose
    parameters flow into sensitive sinks, called by a PROVEN external
    function passing the same identifiers, inherits attacker influence
    and composes a strong chain spanning the call edge."""
    caller = FN.format(fn="publicEntry")
    helper = FN.format(fn="privateDispatch")
    facts = [
        # proven-influenced entrypoint
        _fact(0, "function_exists", caller),
        _entrypoint(1, caller),
        _input_origin(2, caller),
        _fact(3, "call_argument_origin_chain", caller, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "routeParams",
            "chain": [{"kind": "parameter", "name": "routeParams", "relation": "root"}],
        }),
        # internal call edge carrying the same identifiers onward
        _fact(4, "internal_call", caller, {"callee_function": helper, "static_target": True},
              {"callee_name": "privateDispatch"}),
        # private helper: params flow into approval + arbitrary execution
        _fact(5, "function_exists", helper),
        _fact(6, "function_visibility", helper, {"visibility": "private"}),
        _fact(7, "call_argument_origin_chain", helper, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "routeParams.spender",
            "chain": [{"kind": "parameter", "name": "routeParams", "relation": "root"}],
        }),
        _capability(8, helper, capability="can_approve_spender"),
        _fact(9, "low_level_call", helper, {
            "target_expression": "routeParams.spender", "target_status": "dynamic",
            "arguments": ["routeParams.calldata"],
        }),
        _fact(10, "asset_operation", helper, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["routeParams.spender", "claimedValue"],
        }),
    ]
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    hypos = prioritize_all(generate_hypotheses(recon, invariants), recon)

    helper_chains = _chains_for(hypos, helper)
    assert helper_chains, "helper must compose a chain via inherited influence"
    h = helper_chains[0]
    assert h.control_provenance == "PROVEN"
    assert caller in h.affected_functions, "chain must span the call edge"
    infl = {s["stage"]: s for s in h.chain}["untrusted_influence"]
    assert infl["status"] == "proven"
    assert "internal call edge" in infl["description"]
    assert h.composition_strength == "STRONG_SECURITY_CHAIN"
    assert _strong_chains(hypos, helper) == [h]


# ===========================================================================
# Patch 3 (threat-perbaikan.md: semantic composition of asset authorization
# + dynamic execution + paired-probe validation / custody semantics)
# ===========================================================================

def _probe(i, fn, var, expr):
    return _fact(i, "local_variable_origin", fn, {"expression": expr}, {"variable": var})


def _comparison(i, fn, left, right):
    return _fact(i, "arithmetic_operation", fn,
                 {"left_operand": left, "operator": "-", "right_operand": right,
                  "immediate_consumer": "ifstatement"})


def _revert(i, fn, line):
    f = _fact(i, "revert_site", fn, {"revert_kind": "custom_error"})
    f["source"] = {"line_start": line}
    return f


def _lined(fact, line):
    fact["source"] = {"line_start": line}
    return fact


def test_inbound_attacker_funded_flow_not_strong():
    """An attacker-FUNDED inflow (caller moves their own assets in) plus a
    POSSIBLE callback is a linked dataflow consequence but not a protocol
    custody risk: never STRONG on its own (generic mock/deposit pattern)."""
    fn = FN.format(fn="attackerFundedIn")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _fact(3, "call_argument_origin_chain", fn, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "depositValue",
            "chain": [{"kind": "parameter", "name": "depositValue", "relation": "root"}],
        }),
        _dynamic_call(4, fn),                 # recipient "target": not attacker data
        _capability(5, fn, capability="can_transfer_token"),
        _fact(6, "asset_operation", fn, {
            "operation": "transferFrom", "target_expression": "reserveToken",
            "arguments": ["msg.sender", "address(this)", "depositValue"],
        }),
    ]
    _, _, hypos = _pipeline(facts)

    chains = _chains_for(hypos, fn)
    assert chains
    for h in chains:
        stages = {s["stage"]: s for s in h.chain}
        assert stages["state_value_effect"]["linkage"] == "dataflow_linked", (
            "attacker-funded inflow must not grade as protocol custody"
        )
        assert h.composition_strength != "STRONG_SECURITY_CHAIN"
    assert _strong_chains(hypos, fn) == []


def test_self_ledger_transfer_not_strong():
    """A movement on a ledger the analyzed contract itself manages (self/
    super target: callers move their own entries) is not a protocol
    custody risk, whatever the argument overlap."""
    fn = FN.format(fn="selfLedger")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _fact(3, "call_argument_origin_chain", fn, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "moveAmount",
            "chain": [{"kind": "parameter", "name": "moveAmount", "relation": "root"}],
        }),
        _fact(4, "external_call_surface", fn, {
            "call_type": "external", "member": "transfer",
            "target_expression": "super", "target_status": "dynamic",
            "arguments": ["moveRecipient", "moveAmount"],
        }),
        _capability(5, fn, capability="can_transfer_token"),
        _fact(6, "asset_operation", fn, {
            "operation": "transfer", "target_expression": "super",
            "arguments": ["moveRecipient", "moveAmount"],
        }),
    ]
    _, _, hypos = _pipeline(facts)

    chains = _chains_for(hypos, fn)
    assert chains
    for h in chains:
        stages = {s["stage"]: s for s in h.chain}
        assert stages["state_value_effect"]["linkage"] == "dataflow_linked"
        cb = stages["downstream_execution_opportunity"]
        assert cb["grade"] == "POSSIBLE", "super/self target is not attacker-chosen"
        assert h.composition_strength != "STRONG_SECURITY_CHAIN"


def test_authorization_dynamic_execution_delta_check_composes_strong():
    """The full generic pattern: caller-chosen spending authority granted,
    attacker-directed dynamic execution INSIDE a pre/post delta-validation
    window (same probe expression captured twice, compared, revert on
    mismatch) -- the check validates the probed quantity only and may
    still pass while the granted authority persists."""
    fn = FN.format(fn="grantAndCheck")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn, origin="msg.sender"),
        _fact(3, "call_argument_origin_chain", fn, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "routeData",
            "chain": [{"kind": "parameter", "name": "routeData", "relation": "root"}],
        }),
        _capability(4, fn, capability="can_approve_spender"),
        _capability(5, fn, capability="can_call_arbitrary_target"),
        # authorization grant to the caller-chosen spender (before the call)
        _lined(_fact(6, "asset_operation", fn, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["routeData.spender", "claimValue"],
        }), 100),
        # attacker-directed dynamic execution between the probes
        _lined(_fact(7, "low_level_call", fn, {
            "target_expression": "routeData.target", "target_status": "dynamic",
            "arguments": ["routeData.payload"],
        }), 110),
        # paired pre/post probe + comparison + revert
        _lined(_probe(8, fn, "beforeValue", "reserveToken.balanceOf(address(this))"), 105),
        _lined(_probe(9, fn, "afterValue", "reserveToken.balanceOf(address(this))"), 115),
        _lined(_comparison(10, fn, "beforeValue", "afterValue"), 120),
        _revert(11, fn, 120),
    ]
    recon = _synthetic_recon(facts)
    invariants = generate_invariants(recon)
    hypos = prioritize_all(generate_hypotheses(recon, invariants), recon)

    strong = _strong_chains(hypos, fn)
    assert len(strong) == 1
    h = strong[0]
    stages = {s["stage"]: s for s in h.chain}
    # the exact semantic composition the pattern requires
    assert "asset_authorization" in stages
    assert stages["asset_authorization"]["linkage"] == "authorization_grant"
    assert "precedes" in stages["asset_authorization"]["description"]
    assert stages["downstream_execution_opportunity"]["grade"] == "STRUCTURALLY_INDICATED"
    assert stages["state_value_effect"]["linkage"] == "asset_flow_linked"
    assert "validation_gap" in stages
    assert "may still pass" in stages["validation_gap"]["description"]
    assert PRIORITY_ORDER[h.priority] >= PRIORITY_ORDER["high_interest"]


def test_validation_gap_requires_execution_inside_probe_window():
    """A paired-probe delta check whose dynamic execution lies OUTSIDE the
    probe window must not produce a validation-gap stage (the check does
    not bracket the execution)."""
    fn = FN.format(fn="checkOutsideWindow")
    facts = [
        _fact(0, "function_exists", fn),
        _entrypoint(1, fn),
        _input_origin(2, fn),
        _fact(3, "call_argument_origin_chain", fn, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "routeData",
            "chain": [{"kind": "parameter", "name": "routeData", "relation": "root"}],
        }),
        _capability(4, fn, capability="can_approve_spender"),
        _lined(_fact(5, "asset_operation", fn, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["routeData.spender", "claimValue"],
        }), 100),
        # dynamic execution far AFTER the probe window
        _lined(_fact(6, "low_level_call", fn, {
            "target_expression": "routeData.target", "target_status": "dynamic",
            "arguments": ["routeData.payload"],
        }), 300),
        _lined(_probe(7, fn, "beforeValue", "reserveToken.balanceOf(address(this))"), 105),
        _lined(_probe(8, fn, "afterValue", "reserveToken.balanceOf(address(this))"), 115),
        _lined(_comparison(9, fn, "beforeValue", "afterValue"), 120),
        _revert(10, fn, 120),
    ]
    recon = _synthetic_recon(facts)
    chains = compose_security_chains(recon, generate_invariants(recon), lambda: "H-T")
    assert chains
    for h in chains:
        assert "validation_gap" not in {s["stage"] for s in h.chain}, (
            "execution outside the probe window must not compose a "
            "validation gap"
        )
