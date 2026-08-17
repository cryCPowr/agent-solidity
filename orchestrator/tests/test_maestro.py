"""MAESTRO (orchestrator) unit tests."""

from __future__ import annotations

import json
import os
import re

import pytest

from maestro import assistant, stages
from maestro.runner import prepare_run_dir, run_pipeline


# --- stage wiring -----------------------------------------------------------

def test_stage_specs_chain_artifacts(tmp_path):
    repo = str(tmp_path / "repo")
    run_dir = str(tmp_path / "run")
    specs = stages.stage_specs(repo, run_dir, "harness-dir", limit=5)
    names = [s["name"] for s in specs]
    assert names == ["RECON", "THREAT", "ATTACK", "VALIDATOR", "FINDING"]
    # each stage consumes the previous stage's output dir
    by = {s["name"]: s for s in specs}
    assert by["THREAT"]["cmd"][3] == os.path.join(run_dir, "recon")
    assert by["ATTACK"]["cmd"][3] == os.path.join(run_dir, "recon")
    assert by["ATTACK"]["cmd"][4] == os.path.join(run_dir, "threat")
    assert by["VALIDATOR"]["cmd"][3] == os.path.join(run_dir, "attack")
    assert by["FINDING"]["cmd"][3] == os.path.join(run_dir, "attack")
    assert by["FINDING"]["cmd"][4] == os.path.join(run_dir, "validator")
    # limit forwarded to the validator only
    assert "--limit" in by["VALIDATOR"]["cmd"]
    assert all("--limit" not in by[n]["cmd"] for n in names if n != "VALIDATOR")


def test_all_venv_pythons_exist():
    for agent in ("recon-system", "threat_agent", "attack_agent",
                  "validator_agent", "finding_agent"):
        py = os.path.join(stages.ROOT, agent, ".venv", "bin", "python")
        assert os.path.exists(py), f"missing venv python for {agent}"


# --- stats extractors --------------------------------------------------------

def _write(path: str, lines: list[dict]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for obj in lines:
            f.write(json.dumps(obj) + "\n")


def test_stats_extractors(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "recon", "facts.jsonl"), [{"id": 1}, {"id": 2}])
    assert stages._stats_recon(os.path.join(d, "recon")) == "2 facts"

    _write(os.path.join(d, "threat", "hypotheses.jsonl"),
           [{"composition_strength": "STRONG_SECURITY_CHAIN"},
            {"composition_strength": "STRUCTURAL"}])
    assert "1 strong" in stages._stats_threat(os.path.join(d, "threat"))

    _write(os.path.join(d, "attack", "attacks.jsonl"),
           [{"exploitability_score": 10.0}, {"exploitability_score": 4.0}])
    stats = stages._stats_attack(os.path.join(d, "attack"))
    assert "2 attacks" in stats and "10.0" in stats

    os.makedirs(os.path.join(d, "validator"), exist_ok=True)
    with open(os.path.join(d, "validator", "summary.json"), "w") as f:
        json.dump({"verdict_counts": {"CONFIRM": 1, "REJECT": 2}}, f)
    assert "1 CONFIRM" in stages._stats_validator(os.path.join(d, "validator"))

    os.makedirs(os.path.join(d, "finding"), exist_ok=True)
    with open(os.path.join(d, "finding", "summary.json"), "w") as f:
        json.dump({"confirmed_attacks": 1,
                   "findings": [{"severity": "critical"}]}, f)
    assert "CRITICAL" in stages._stats_finding(os.path.join(d, "finding"))


# --- run-dir hygiene ---------------------------------------------------------

def test_prepare_run_dir_refuses_dirty_without_clean(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    (tmp_path / "run" / "stale.txt").write_text("old target")
    with pytest.raises(RuntimeError, match="contaminate"):
        prepare_run_dir(run_dir, clean_run=False)
    # with clean flag the stale content is gone
    prepare_run_dir(run_dir, clean_run=True)
    assert not (tmp_path / "run" / "stale.txt").exists()


# --- assistant honesty -------------------------------------------------------

def test_assistant_dormant_without_key(monkeypatch):
    monkeypatch.delenv("AGENT_FINDER_LLM_API_KEY", raising=False)
    assert not assistant.available()
    assert "DORMANT" in assistant.status_line()
    result = assistant.fill_harness_scaffold("/nonexistent.sol")
    assert result["filled"] is False and "dormant" in result["reason"]
    assert assistant.reject_refinement_hint({"retry_hint": "x"}) == "x"


def test_looks_like_solidity():
    assert assistant.looks_like_solidity("pragma solidity ^0.8.20;\ncontract X {}")
    assert not assistant.looks_like_solidity("Here is the code you asked for:")
    assert not assistant.looks_like_solidity("")


# --- pipeline stop-on-failure (fake commands) --------------------------------

def test_run_pipeline_stops_on_first_failure(monkeypatch, tmp_path):
    specs_patch = [
        {"name": "ONE", "agent": "a", "cwd": str(tmp_path),
         "cmd": ["/bin/sh", "-c", "exit 3"],
         "out_dir": str(tmp_path / "one"), "stats": lambda d: "x"},
        {"name": "TWO", "agent": "b", "cwd": str(tmp_path),
         "cmd": ["/bin/sh", "-c", "echo never"],
         "out_dir": str(tmp_path / "two"), "stats": lambda d: "y"},
    ]
    monkeypatch.setattr("maestro.runner.stage_specs", lambda *a, **k: specs_patch)
    result = run_pipeline("repo", str(tmp_path / "run"), "h", clean_run=True)
    assert [s.name for s in result.stages] == ["ONE"]
    assert not result.all_ok and result.stages[0].returncode == 3


def test_no_benchmark_identifiers_in_engine():
    import maestro as pkg
    banned = ("jackpot", "megapot", "initia", "monetrix", "usdc",
              "bridgefunds", "claimwinnings", "code4rena", "warden")
    pkg_dir = os.path.dirname(pkg.__file__)
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            source = f.read().lower()
        for marker in banned:
            assert not re.search(rf"\b{re.escape(marker)}\b", source), (
                f"{fname} references benchmark identifier {marker!r}"
            )


# --- assistant CLI-backend slot ------------------------------------------------

def test_assistant_cli_backend_via_stub(monkeypatch, tmp_path):
    """The session/CLI slot: command gets the prompt on stdin, answer on
    stdout. Proven with a stub (upper-cases the prompt)."""
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\ncat | tr a-z A-Z | tail -1\n")
    stub.chmod(0o755)
    monkeypatch.setenv("AGENT_FINDER_LLM_CMD", str(stub))
    assert assistant.backend() == "cli"
    assert assistant.available()
    assert "via CLI" in assistant.status_line()
    answer = assistant._chat("system-prompt", "hello-line")
    assert answer.strip() == "HELLO-LINE"


def test_assistant_cli_backend_failure_not_fatal(monkeypatch):
    monkeypatch.setenv("AGENT_FINDER_LLM_CMD", "exit 7")
    result = assistant.fill_harness_scaffold("/nonexistent.sol")
    assert result["filled"] is False
    assert "assistant error" in result["reason"] or "cli backend" in result["reason"]
