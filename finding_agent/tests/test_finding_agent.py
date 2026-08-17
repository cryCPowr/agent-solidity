"""Finding Agent unit tests (no forge/solc required)."""

from __future__ import annotations

import json
import os
import re

import pytest

from finding import report as report_mod
from finding import severity as severity_mod
from finding.model import Finding
from finding.pipeline import run_finding
from finding.severity import assess_severity


def _attack(attack_id="A-1"):
    return {
        "attack_id": attack_id,
        "source_hypothesis_id": "H-1",
        "attack_strategy": "approval abuse",
        "strategy_status": "PROVEN",
        "root_function": "contracts/Vault.sol#10::settle#40",
        "entry_point": {"function": "contracts/Vault.sol#10::settle#40",
                        "visibility": "external"},
        "controlled_inputs": [{"expression": "route.spender"},
                              {"expression": "route.data"}],
        "capability_obtained": "spender authority over the vault's assets",
        "affected_assets": ["protocol assets", "holdingnft (other contract-held asset)"],
        "expected_consequence": {
            "class": "theft / loss of funds",
            "status": "INFERRED",
            "description": "drain while the check passes",
            "cross_asset_blind_spot": {"probed_asset": "token",
                                        "other_assets": ["holdingnft"]},
        },
        "attack_steps": [
            {"order": 1, "status": "PROVEN",
             "action": "Attacker calls settle (external).",
             "location": "contracts/Vault.sol:40", "fact_ids": ["F1"]},
            {"order": 2, "status": "INFERRED",
             "action": "Cross-asset blind spot: check measures only 'token'.",
             "location": "contracts/Vault.sol:45", "fact_ids": ["F2"]},
        ],
        "evidence": ["primary strategy: approval abuse (PROVEN)"],
        "fact_ids": ["F1", "F2"],
        "assumptions": ["payout stand-in models a winning entry"],
        "uncertainty": ["exact payout size depends on harness"],
        "production_relevance": "PRODUCTION",
        "exploitability_score": 10.0,
        "validator_plan": {"confirm_if": "attacker gains asset", "reject_if": "call reverts"},
    }


def _verdict(attack_id="A-1", verdict="CONFIRM"):
    return {
        "attack_id": attack_id,
        "verdict": verdict,
        "reason": "executed test satisfied the confirm conditions",
        "readiness": "READY",
        "test_file": "/tmp/ws/test/ValidateX.t.sol",
        "retry_hint": "",
        "evidence": ["t: passed"],
        "meta": {"workspace": "/tmp/ws",
                 "tests": {"test_attack_call_succeeds()": {"passed": True}}},
    }


def _env(tmp_path, attacks, verdicts):
    adir = tmp_path / "attacks"; adir.mkdir()
    (adir / "attacks.jsonl").write_text(
        "".join(json.dumps(a) + "\n" for a in attacks))
    vdir = tmp_path / "validator"; vdir.mkdir()
    (vdir / "verdicts.jsonl").write_text(
        "".join(json.dumps(v) + "\n" for v in verdicts))
    return adir, vdir


# --- loader discipline ------------------------------------------------------

def test_only_confirm_becomes_finding(tmp_path):
    adir, vdir = _env(tmp_path,
                      [_attack("A-ok"), _attack("A-rej"), _attack("A-inc")],
                      [_verdict("A-ok", "CONFIRM"),
                       _verdict("A-rej", "REJECT"),
                       _verdict("A-inc", "INCONCLUSIVE")])
    out = tmp_path / "out"
    findings = run_finding(str(adir), str(vdir), str(out))
    assert [f.attack_id for f in findings] == ["A-ok"]
    summary = json.load(open(out / "summary.json"))
    assert summary["confirmed_attacks"] == 1
    assert {n["verdict"] for n in summary["not_reported"]} == {"REJECT", "INCONCLUSIVE"}


# --- severity ---------------------------------------------------------------

def test_severity_theft_proven_is_critical():
    sev, why = assess_severity(_attack())
    assert sev == "critical"
    assert "PROVEN" in why


def test_severity_test_mock_demoted(tmp_path):
    attack = _attack()
    attack["production_relevance"] = "TEST/MOCK"
    sev, _ = assess_severity(attack)
    assert sev == "informational"


def test_severity_griefing_low_band():
    attack = _attack()
    attack["expected_consequence"] = {"class": "griefing"}
    attack["exploitability_score"] = 3.0
    sev, why = assess_severity(attack)
    assert sev == "low"
    assert "3.0" in why


# --- report -----------------------------------------------------------------

def test_report_structure_and_status_fidelity():
    finding = report_mod.build_finding(_attack(), _verdict(), sequence=1)
    md = report_mod.render_markdown(finding)
    for header in ("# ", "## Finding description and impact",
                   "## Attack path", "## Proof of Concept",
                   "## Recommended mitigation",
                   "## Evidence and traceability"):
        assert header in md
    # statuses repeated verbatim, never upgraded
    assert "**[PROVEN]**" in md and "**[INFERRED]**" in md
    assert "upgrade" in md  # the report disclaims upgrades
    # PoC command derived from workspace + test file
    assert "cd /tmp/ws && forge test" in finding.poc["command"]
    # mitigation mentions cross-asset and allowlist
    assert any("allowlist" in m for m in finding.mitigation)
    assert any("Cross-asset" in m for m in finding.mitigation)


def test_finding_ids_sequence_and_files(tmp_path):
    adir, vdir = _env(tmp_path, [_attack("A-1"), _attack("A-2")],
                      [_verdict("A-1"), _verdict("A-2")])
    out = tmp_path / "out"
    findings = run_finding(str(adir), str(vdir), str(out))
    assert [f.finding_id for f in findings] == ["F-001", "F-002"]
    assert (out / "finding-F-001.md").exists()
    assert (out / "finding-F-002.md").exists()
    assert (out / "findings.jsonl").exists()


# --- anti-benchmark guard ---------------------------------------------------

def test_no_benchmark_identifiers_in_engine():
    import finding as finding_pkg
    banned = ("jackpot", "megapot", "initia", "monetrix", "usdc",
              "safetransferfrom", "bridgefunds", "claimwinnings",
              "buytickets", "code4rena", "warden")
    pkg_dir = os.path.dirname(finding_pkg.__file__)
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            source = f.read().lower()
        for marker in banned:
            assert not re.search(rf"\b{re.escape(marker)}\b", source), (
                f"{fname} references benchmark identifier {marker!r}"
            )


def test_uncertainty_preserved_not_hidden():
    finding = report_mod.build_finding(_attack(), _verdict())
    md = report_mod.render_markdown(finding)
    assert "Remaining uncertainty" in md
    assert "payout stand-in models a winning entry" in md


def test_poc_path_recomputed_after_artifacts_moved(tmp_path):
    """Verdicts record absolute paths at run time; after artifacts move,
    the finding must point at the validator dir's actual layout."""
    import shutil as _sh
    # verdict recorded an old absolute location...
    attack = _attack("A-1")
    verdict = _verdict("A-1")
    verdict["test_file"] = "/gone/old/ws/test/ValidateA1.t.sol"
    verdict["meta"]["workspace"] = "/gone/old/ws"
    # ...but the workspace now lives under the validator output dir
    vdir = tmp_path / "validator"
    real_ws = vdir / "workspace" / "A-1" / "test"
    real_ws.mkdir(parents=True)
    (real_ws / "ValidateA1.t.sol").write_text("// test")
    (vdir / "verdicts.jsonl").write_text(json.dumps(verdict) + "\n")
    adir = tmp_path / "attacks"; adir.mkdir()
    (adir / "attacks.jsonl").write_text(json.dumps(attack) + "\n")

    out = tmp_path / "out"
    run_finding(str(adir), str(vdir), str(out))
    md = (out / "finding-F-001.md").read_text()
    assert "/gone/old" not in md
    assert str(vdir / "workspace" / "A-1") in md
    assert f"cd {vdir / 'workspace' / 'A-1'} && forge test" in md


def test_contract_scope_harness_flagged_in_report():
    verdict = _verdict()
    verdict["meta"]["harness_scope"] = "contract"
    finding = report_mod.build_finding(_attack(), verdict)
    md = report_mod.render_markdown(finding)
    assert "Scope note" in md and "CONTRACT-scoped" in md
    # function-scoped or absent -> no note
    finding2 = report_mod.build_finding(_attack(), _verdict())
    assert "Scope note" not in report_mod.render_markdown(finding2)
