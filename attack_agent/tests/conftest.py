"""Shared synthetic fixtures for Attack Agent tests.

Everything here is GENERIC and SYNTHETIC: invented contract/function
names, no benchmark identifiers. The fixtures mirror the Recon/Threat
artifact shapes consumed by the loader.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from attack import loader


FN_ROOT = "src/Protocol.sol#10::dispatchFunds#20"
FN_ENTRY = "src/Protocol.sol#10::claimRoute#15"


def _fact(i, ftype, fn, props=None, subject_extra=None, line=None, status="observed"):
    fact = {
        "id": f"fact:syn{i:03d}",
        "type": ftype,
        "subject": {"function": fn},
        "properties": props or {},
        "status": status,
    }
    if subject_extra:
        fact["subject"].update(subject_extra)
    if line is not None:
        fact["source"] = {"file": _file_of(fn), "line_start": line, "line_end": line}
    return fact


def _file_of(fn):
    return fn.split("#")[0] if "#" in fn else "src/Unknown.sol"


def make_recon_facts():
    """A proven attacker-influenced authorization + dynamic execution +
    paired-probe delta validation on one production function, reached
    through an external caller."""
    return [
        # external entry (production)
        _fact(0, "function_exists", FN_ENTRY),
        _fact(1, "function_visibility", FN_ENTRY, {"visibility": "external"}, line=15),
        _fact(2, "call_argument_origin_chain", FN_ENTRY, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "routeData",
            "chain": [{"kind": "parameter", "name": "routeData", "relation": "root"}],
        }, line=16),
        # internal call edge entry -> root
        _fact(3, "internal_call", FN_ENTRY,
              {"callee_function": FN_ROOT, "static_target": True},
              {"callee_name": "dispatchFunds"}, line=17),
        # root (private helper with the sinks)
        _fact(4, "function_exists", FN_ROOT),
        _fact(5, "function_visibility", FN_ROOT, {"visibility": "private"}, line=20),
        _fact(6, "call_argument_origin_chain", FN_ROOT, {
            "root_kind": "parameter", "hop_count": 1,
            "argument_expression": "routeData.spender",
            "chain": [{"kind": "parameter", "name": "routeData", "relation": "root"}],
        }, line=21),
        _fact(7, "capability", FN_ROOT, {}, {"capability": "can_approve_spender"}, line=22),
        _fact(8, "capability", FN_ROOT, {}, {"capability": "can_call_arbitrary_target"}, line=22),
        _fact(9, "asset_operation", FN_ROOT, {
            "operation": "approve", "target_expression": "reserveToken",
            "arguments": ["routeData.spender", "claimValue"],
        }, line=23),
        _fact(10, "low_level_call", FN_ROOT, {
            "target_expression": "routeData.target", "target_status": "dynamic",
            "arguments": ["routeData.payload"],
        }, line=24),
        _fact(11, "local_variable_origin", FN_ROOT,
              {"expression": "reserveToken.balanceOf(address(this))", "root_kind": "unresolved"},
              {"variable": "beforeValue"}, line=22),
        _fact(12, "local_variable_origin", FN_ROOT,
              {"expression": "reserveToken.balanceOf(address(this))", "root_kind": "unresolved"},
              {"variable": "afterValue"}, line=26),
        _fact(13, "arithmetic_operation", FN_ROOT, {
            "left_operand": "beforeValue", "operator": "-",
            "right_operand": "afterValue", "immediate_consumer": "ifstatement",
        }, line=27),
        _fact(14, "revert_site", FN_ROOT, {"revert_kind": "custom_error"}, line=27),
        # mock/test function (should classify TEST/MOCK, never discarded)
        _fact(20, "function_exists", "test/Protocol.t.sol#1::testHarness#2"),
        _fact(21, "function_visibility", "test/Protocol.t.sol#1::testHarness#2",
              {"visibility": "external"}, line=2),
        # dependency function (should classify DEPENDENCY)
        _fact(22, "function_exists", "node_modules/lib/Lib.sol#1::helper#2"),
    ]


CHAIN_STAGES = [
    {"stage": "untrusted_influence", "status": "proven", "fact_ids": ["fact:syn002", "fact:syn003"],
     "description": "inherited through internal call edge from claimRoute"},
    {"stage": "argument_propagation", "status": "proven", "fact_ids": ["fact:syn006"]},
    {"stage": "external_execution", "status": "proven", "fact_ids": ["fact:syn010"]},
    {"stage": "downstream_execution_opportunity", "status": "inferred",
     "grade": "STRUCTURALLY_INDICATED", "fact_ids": []},
    {"stage": "asset_authorization", "status": "observed", "linkage": "authorization_grant",
     "fact_ids": ["fact:syn009"]},
    {"stage": "state_value_effect", "status": "observed", "linkage": "asset_flow_linked",
     "fact_ids": ["fact:syn009"]},
    {"stage": "validation_gap", "status": "inferred", "linkage": "validation_gap",
     "fact_ids": ["fact:syn011", "fact:syn012", "fact:syn013", "fact:syn014"]},
    {"stage": "invariant_concern", "status": "uncertain", "linkage": "flow_linked",
     "fact_ids": ["fact:syn009"]},
]


def make_threat_hypotheses():
    return [
        {
            "hypothesis_id": "H-strong0001",
            "category": "security_chain",
            "statement": "Composed security chain in dispatchFunds (PROVEN, STRONG).",
            "actor": "external_user",
            "priority": "high_interest",
            "evidence_tier": "ARGUMENT_DEPENDENCY",
            "control_provenance": "PROVEN",
            "composition_strength": "STRONG_SECURITY_CHAIN",
            "observed_facts": [
                "fact:syn001", "fact:syn002", "fact:syn003", "fact:syn005",
                "fact:syn006", "fact:syn007", "fact:syn009", "fact:syn010",
                "fact:syn011", "fact:syn012", "fact:syn013", "fact:syn014",
            ],
            "affected_functions": [FN_ROOT, FN_ENTRY],
            "affected_assets": ["protocol assets"],
            "invariant_candidate_id": "INV-001",
            "uncertainty": "Whether the delta validation covers the grant.",
            "preconditions": ["The function is reachable by the influencing caller"],
            "chain": CHAIN_STAGES,
        },
        # duplicate variant of the same root exploit (must merge)
        {
            "hypothesis_id": "H-strong0002",
            "category": "security_chain",
            "statement": "Variant composition in dispatchFunds.",
            "actor": "external_user",
            "priority": "high_interest",
            "evidence_tier": "ARGUMENT_DEPENDENCY",
            "control_provenance": "PROVEN",
            "composition_strength": "SECURITY_RELEVANT",
            "observed_facts": ["fact:syn009", "fact:syn010"],
            "affected_functions": [FN_ROOT, FN_ENTRY],
            "affected_assets": ["protocol assets"],
            "invariant_candidate_id": "",
            "uncertainty": "",
            "preconditions": [],
            "chain": CHAIN_STAGES,
        },
        # structural-only hypothesis: no evidence-supported attack
        {
            "hypothesis_id": "H-struct0003",
            "category": "novel_composition",
            "statement": "co-occurrence only",
            "actor": "unknown_actor",
            "priority": "low_interest",
            "evidence_tier": "CO_OCCURRENCE",
            "observed_facts": ["fact:syn020", "fact:syn021"],
            "affected_functions": ["test/Protocol.t.sol#1::testHarness#2"],
            "affected_assets": [],
            "uncertainty": "",
            "preconditions": [],
            "chain": [],
        },
    ]


def make_invariants():
    return {
        "count": 1,
        "invariants": [{
            "id": "INV-001",
            "category": "asset_conservation",
            "statement": "Total protocol assets must cover liabilities.",
            "rationale": "asset operations exist",
            "involved_facts": ["fact:syn009"],
            "involved_functions": [FN_ROOT],
            "involved_assets": ["tokens"],
            "uncertainty": "candidate only",
            "confidence": "medium",
        }],
    }


@pytest.fixture()
def synthetic_recon(tmp_path):
    d = tmp_path / "recon"
    d.mkdir()
    with open(d / "facts.jsonl", "w") as f:
        for fact in make_recon_facts():
            f.write(f"{__import__('json').dumps(fact)}\n")
    (d / "graph.json").write_text('{"nodes": [], "edges": []}')
    return loader.load_recon(str(d))


@pytest.fixture()
def synthetic_threat(tmp_path):
    import json
    d = tmp_path / "threat"
    d.mkdir()
    with open(d / "hypotheses.jsonl", "w") as f:
        for h in make_threat_hypotheses():
            f.write(json.dumps(h) + "\n")
    (d / "invariants.json").write_text(json.dumps(make_invariants()))
    return loader.load_threat(str(d))
