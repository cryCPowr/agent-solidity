"""Validator Agent unit tests (no forge/solc required)."""

from __future__ import annotations

import json
import os

import pytest

from validator import codegen, planner, runner, verdicts
from validator.model import CONFIRM, INCONCLUSIVE, REJECT
from validator.pipeline import run_validator


def _attack(attack_id="A-1", root="contracts/Bridge.sol#10::claim#20"):
    return {
        "attack_id": attack_id,
        "source_hypothesis_id": "H-1",
        "attack_strategy": "approval abuse",
        "strategy_status": "PROVEN",
        "root_function": root,
        "entry_point": {"function": root, "visibility": "external"},
        "controlled_inputs": [{"expression": "route.approveTo"}],
        "expected_consequence": {
            "class": "theft / loss of funds",
            "cross_asset_blind_spot": {
                "probed_asset": "reservetoken",
                "other_assets": ["holdingnft"],
            },
        },
        "exploitability_score": 10.0,
        "validator_plan": {
            "functions_to_test": ["claim"],
            "attacker_setup": "attacker as spender + receiver",
            "confirm_if": "attacker gains the probed or cross asset",
            "reject_if": "call reverts or nothing gained",
        },
    }


def _write(path, attack_lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for a in attack_lines:
            f.write(json.dumps(a) + "\n")


# --- planner ---------------------------------------------------------------

def test_preflight_blocked_without_harness(tmp_path):
    attack = _attack()
    repo = tmp_path / "repo"; repo.mkdir()
    pre = planner.preflight(attack, str(repo), str(tmp_path / "harnesses"))
    assert pre["status"] == "BLOCKED_NO_HARNESS"
    assert any("no setup harness" in r for r in pre["reasons"])


def test_preflight_ready_with_harness(tmp_path):
    attack = _attack(root="contracts/Bridge.sol#10::claim#20")
    repo = tmp_path / "repo"; repo.mkdir()
    hdir = tmp_path / "harnesses"; hdir.mkdir()
    (hdir / "contracts_Bridge_sol.sol").write_text(
        "contract SuppliedHarness { function setup() external {} }"
    )
    pre = planner.preflight(attack, str(repo), str(hdir))
    assert pre["status"] == "READY"
    assert pre["harness"]["contract"] == "SuppliedHarness"


def test_preflight_blocked_on_incomplete_plan(tmp_path):
    attack = _attack()
    attack["validator_plan"] = {"confirm_if": "x"}  # missing fields
    repo = tmp_path / "repo"; repo.mkdir()
    pre = planner.preflight(attack, str(repo), None)
    assert pre["status"] == "BLOCKED_NO_HARNESS"


def test_preflight_ignores_generated_scaffold(tmp_path):
    attack = _attack(root="contracts/Bridge.sol#10::claim#20")
    repo = tmp_path / "repo"; repo.mkdir()
    hdir = tmp_path / "harnesses"; hdir.mkdir()
    (hdir / "contracts_Bridge_sol.sol").write_text(
        codegen.render_harness_scaffold(attack, "ScaffoldHarness")
    )
    pre = planner.preflight(attack, str(repo), str(hdir))
    assert pre["status"] == "BLOCKED_NO_HARNESS"
    assert pre["harness"] is None


# --- codegen ---------------------------------------------------------------

def test_render_test_contains_driver_and_attacker():
    src = codegen.render_test(_attack(), "SuppliedHarness")
    assert "interface IProtocolHarness" in src
    assert "contract GenericAttacker" in src
    assert "function test_attack_call_succeeds()" in src
    assert "function test_attacker_gains()" in src
    assert "contract SuppliedHarness" not in src  # harness is imported, not inlined
    assert "new SuppliedHarness()" in src
    # cross-asset assertions present only when the attack recorded them
    assert "crossAssetCount()" in src
    # no benchmark identifiers in generated code
    low = src.lower()
    for banned in ("jackpot", "megapot", "usdc", "warden", "code4rena"):
        assert banned not in low


def test_render_test_without_cross_assets():
    attack = _attack()
    attack["expected_consequence"] = {"class": "theft"}
    src = codegen.render_test(attack, "H")
    # no cross-asset CALL in the test body (interface decl may stay)
    assert "crossAssetAt(i)" not in src
    assert "probedAfter > probedBefore;" in src


def test_harness_scaffold_is_filled_from_attack_data():
    src = codegen.render_harness_scaffold(_attack(), "ScaffoldHarness")
    assert "contracts/Bridge.sol#10::claim#20" in src
    assert "route.approveTo" in src
    assert "reservetoken" in src
    assert "holdingnft" in src
    assert "TODO" in src


# --- verdicts ---------------------------------------------------------------

def _parsed(passed_call, passed_gain):
    return {
        "ok": passed_call and passed_gain,
        "tests": {
            "test_attack_call_succeeds()": {"passed": passed_call, "reason": ""},
            "test_attacker_gains()": {"passed": passed_gain, "reason": "attacker gained nothing"},
        },
        "raw": "",
    }


def test_verdict_confirm():
    v = verdicts.verdict_from_run(_attack(), _parsed(True, True), "t.sol")
    assert v.verdict == CONFIRM
    assert "confirm" in v.reason.lower()


def test_verdict_reject_when_call_reverts():
    v = verdicts.verdict_from_run(_attack(), _parsed(False, False), "t.sol")
    assert v.verdict == REJECT
    assert "reverts" in v.reason
    assert v.retry_hint


def test_verdict_reject_when_no_gain():
    v = verdicts.verdict_from_run(_attack(), _parsed(True, False), "t.sol")
    assert v.verdict == REJECT
    assert "gains nothing" in v.reason


def test_verdict_inconclusive_on_no_results():
    v = verdicts.verdict_from_run(_attack(), {"ok": False, "tests": {}, "raw": "cc: EVM version"}, "t.sol")
    assert v.verdict == INCONCLUSIVE
    assert "compilation" in v.reason


# --- pipeline with a FAKE forge -------------------------------------------

class FakeForge:
    """Monkeypatch target: simulate forge outcomes per attack id."""

    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.ran = []

    def fake_run(self, workspace, test_path, timeout=600):
        self.ran.append(test_path)
        attack_id = os.path.basename(workspace)
        outcome = self.outcomes.get(attack_id, "confirm")
        if outcome == "confirm":
            stdout = json.dumps(
                {"test/V.t.sol:V": {"test_results": {
                    "test_attack_call_succeeds()": {"status": "Success"},
                    "test_attacker_gains()": {"status": "Success"},
                }}}
            )
        elif outcome == "revert":
            stdout = json.dumps(
                {"test/V.t.sol:V": {"test_results": {
                    "test_attack_call_succeeds()": {"status": "Failure",
                     "reason": "attack call reverted"},
                    "test_attacker_gains()": {"status": "Failure"},
                }}}
            )
        else:  # compile error
            stdout = ""
        return {"status": "done", "returncode": 1 if outcome != "confirm" else 0,
                "stdout": stdout, "stderr": ""}


@pytest.fixture
def fake_forge(monkeypatch):
    def install(outcomes):
        ff = FakeForge(outcomes)
        monkeypatch.setattr("validator.runner.run_forge_test", ff.fake_run)
        return ff
    return install


def _env(tmp_path):
    repo = tmp_path / "repo"; (repo / "contracts").mkdir(parents=True)
    hdir = tmp_path / "harnesses"; hdir.mkdir()
    (hdir / "contracts_Bridge_sol.sol").write_text(
        "contract SuppliedHarness { function setup() external {} }"
    )
    adir = tmp_path / "attacks"; adir.mkdir()
    return repo, hdir, adir


def test_pipeline_confirm_reject_inconclusive(tmp_path, fake_forge):
    repo, hdir, adir = _env(tmp_path)
    a_confirm = _attack("A-confirm")
    a_revert = _attack("A-revert")
    a_broken = _attack("A-broken")
    a_broken["validator_plan"]["attacker_setup"] = ""  # incomplete plan -> blocked
    _write(str(adir / "attacks.jsonl"), [a_confirm, a_revert, a_broken])
    fake_forge({"A-confirm": "confirm", "A-revert": "revert", "A-broken": "compile"})

    out = tmp_path / "out"
    results = run_validator(str(adir), str(repo), str(hdir), str(out))

    by_id = {v.attack_id: v for v in results}
    assert by_id["A-confirm"].verdict == CONFIRM
    assert by_id["A-revert"].verdict == REJECT
    # incomplete plan is BLOCKED before execution -> INCONCLUSIVE, never REJECT
    assert by_id["A-broken"].verdict == INCONCLUSIVE
    assert by_id["A-broken"].readiness == "BLOCKED_NO_HARNESS"

    summary = json.load(open(out / "summary.json"))
    assert summary["verdict_counts"] == {CONFIRM: 1, REJECT: 1, INCONCLUSIVE: 1}
    assert summary["executed_attacks"] == 2
    assert summary["blocked_attacks"] == 1
    assert summary["readiness_counts"]["READY"] == 2
    assert summary["readiness_counts"]["BLOCKED_NO_HARNESS"] == 1
    assert summary["confirmed"][0]["attack_id"] == "A-confirm"
    # blocked attacks get a scaffold written for the orchestrator
    scaffold = hdir / "contracts_Bridge_sol.sol"
    assert scaffold.exists()


def test_pipeline_limit_takes_top_of_queue(tmp_path, fake_forge):
    repo, hdir, adir = _env(tmp_path)
    _write(str(adir / "attacks.jsonl"), [_attack("A-1"), _attack("A-2")])
    ff = fake_forge({"A-1": "confirm"})
    out = tmp_path / "out"
    run_validator(str(adir), str(repo), str(hdir), str(out), limit=1)
    assert len(ff.ran) == 1


def test_workspace_isolation_and_repo_untouched(tmp_path, fake_forge):
    repo, hdir, adir = _env(tmp_path)
    _write(str(adir / "attacks.jsonl"), [_attack("A-1")])
    fake_forge({"A-1": "confirm"})
    out = tmp_path / "out"
    run_validator(str(adir), str(repo), str(hdir), str(out))
    # generated test lives in the isolated workspace, not the repo
    ws = out / "workspace" / "A-1"
    assert (ws / "test").is_dir()
    assert list((repo / "contracts").iterdir()) == []


def test_build_workspace_uses_auto_detect_solc_for_mixed_version_repos(tmp_path):
    repo = tmp_path / "repo"
    (repo / "contracts").mkdir(parents=True)
    hdir = tmp_path / "harnesses"
    hdir.mkdir()
    harness_path = hdir / "contracts_Bridge_sol.sol"
    harness_path.write_text("contract SuppliedHarness { function setup() external {} }")
    ws = tmp_path / "ws"
    attack = _attack("A-mixed")
    runner.build_workspace(
        str(ws),
        str(repo),
        attack,
        {"path": str(harness_path), "contract": "SuppliedHarness"},
    )
    foundry = (ws / "foundry.toml").read_text()
    assert 'auto_detect_solc = true' in foundry
    assert 'solc_version = ' not in foundry
    assert 'evm_version = ' not in foundry
    assert 'via_ir = true' not in foundry


def test_function_scoped_harness_preferred_over_contract(tmp_path):
    """Harness lookup is function-scoped first; contract file is fallback."""
    attack = _attack(root="contracts/Bridge.sol#10::settle#40")
    hdir = tmp_path / "harnesses"; hdir.mkdir()
    (hdir / "contracts_Bridge_sol__settle.sol").write_text(
        "contract SettleHarness { function setup() external {} }")
    (hdir / "contracts_Bridge_sol.sol").write_text(
        "contract ContractHarness { function setup() external {} }")
    pre = planner.preflight(attack, str(tmp_path), str(hdir))
    assert pre["status"] == "READY"
    assert pre["harness"]["contract"] == "SettleHarness"
    assert pre["harness"]["scope"] == "function"
    # sibling root function falls back to contract scope
    sibling = _attack(root="contracts/Bridge.sol#10::withdraw#50")
    pre2 = planner.preflight(sibling, str(tmp_path), str(hdir))
    assert pre2["harness"]["contract"] == "ContractHarness"
    assert pre2["harness"]["scope"] == "contract"
