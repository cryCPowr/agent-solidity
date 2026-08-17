"""Stage definitions: what to run, where, and how to read its stats.

Paths are resolved relative to the project root (parent of orchestrator/).
"""

from __future__ import annotations

import json
import os
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _py(agent_dir: str) -> str:
    return os.path.join(ROOT, agent_dir, ".venv", "bin", "python")


def _count_jsonl(path: str) -> int:
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def _load_json(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def stage_specs(repo: str, run_dir: str, harness_dir: str,
                limit: int = 0) -> list[dict[str, Any]]:
    """Ordered stage specifications for one target run."""
    specs: list[dict[str, Any]] = [
        {
            "name": "RECON",
            "agent": "recon-system",
            "cwd": os.path.join(ROOT, "recon-system"),
            "cmd": [_py("recon-system"), "-m", "recon.cli", repo,
                    "-o", os.path.join(run_dir, "recon")],
            "out_dir": os.path.join(run_dir, "recon"),
            "stats": _stats_recon,
        },
        {
            "name": "THREAT",
            "agent": "threat_agent",
            "cwd": os.path.join(ROOT, "threat_agent"),
            "cmd": [_py("threat_agent"), "-m", "threat.cli",
                    os.path.join(run_dir, "recon"),
                    "-o", os.path.join(run_dir, "threat")],
            "out_dir": os.path.join(run_dir, "threat"),
            "stats": _stats_threat,
        },
        {
            "name": "ATTACK",
            "agent": "attack_agent",
            "cwd": os.path.join(ROOT, "attack_agent"),
            "cmd": [_py("attack_agent"), "-m", "attack.cli",
                    os.path.join(run_dir, "recon"),
                    os.path.join(run_dir, "threat"),
                    "-o", os.path.join(run_dir, "attack"), "--clean"],
            "out_dir": os.path.join(run_dir, "attack"),
            "stats": _stats_attack,
        },
        {
            "name": "VALIDATOR",
            "agent": "validator_agent",
            "cwd": os.path.join(ROOT, "validator_agent"),
            "cmd": [_py("validator_agent"), "-m", "validator.cli",
                    os.path.join(run_dir, "attack"), repo,
                    "--harness", harness_dir,
                    "-o", os.path.join(run_dir, "validator"), "--clean"]
                + (["--limit", str(limit)] if limit else []),
            "out_dir": os.path.join(run_dir, "validator"),
            "stats": _stats_validator,
        },
        {
            "name": "FINDING",
            "agent": "finding_agent",
            "cwd": os.path.join(ROOT, "finding_agent"),
            "cmd": [_py("finding_agent"), "-m", "finding.cli",
                    os.path.join(run_dir, "attack"),
                    os.path.join(run_dir, "validator"),
                    "-o", os.path.join(run_dir, "finding"), "--clean"],
            "out_dir": os.path.join(run_dir, "finding"),
            "stats": _stats_finding,
        },
    ]
    return specs


def _stats_recon(out_dir: str) -> str:
    n = _count_jsonl(os.path.join(out_dir, "facts.jsonl"))
    return f"{n} facts" if n else "no facts produced"


def _stats_threat(out_dir: str) -> str:
    path = os.path.join(out_dir, "hypotheses.jsonl")
    n = _count_jsonl(path)
    strong = 0
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip() and "STRONG_SECURITY_CHAIN" in line:
                    strong += 1
    return f"{n} hypotheses ({strong} strong)" if n else "no hypotheses produced"


def _stats_attack(out_dir: str) -> str:
    path = os.path.join(out_dir, "attacks.jsonl")
    n = _count_jsonl(path)
    top = 0.0
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    top = max(top, float(json.loads(line).get("exploitability_score") or 0))
                except json.JSONDecodeError:
                    pass
    return f"{n} attacks (top score {top:.1f})" if n else "no attacks produced"


def _stats_validator(out_dir: str) -> str:
    summary = _load_json(os.path.join(out_dir, "summary.json"))
    counts = summary.get("verdict_counts", {})
    if not counts:
        return "no verdicts produced"
    parts = [f"{v} {k}" for k, v in sorted(counts.items())]
    return ", ".join(parts)


def _stats_finding(out_dir: str) -> str:
    summary = _load_json(os.path.join(out_dir, "summary.json"))
    n = summary.get("confirmed_attacks", 0)
    findings = summary.get("findings", [])
    if not n:
        return "no findings (nothing confirmed)"
    sevs = ", ".join(f"{f.get('severity', '?').upper()}" for f in findings)
    return f"{n} finding(s) [{sevs}]"
