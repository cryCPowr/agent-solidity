"""Validator pipeline orchestration.

    attacks.jsonl (queue order)
        -> preflight (plan complete? forge present? harness supplied?)
        -> [BLOCKED] -> INCONCLUSIVE + scaffold written
        -> [READY]   -> isolated forge workspace -> generated test
                      -> forge test -> CONFIRM / REJECT / INCONCLUSIVE
        -> verdicts.jsonl + summary.json (+ workspace kept for audit)
"""

from __future__ import annotations

import os
from typing import Any

from . import codegen, planner, runner, verdicts
from .loader import load_attack_summary, load_attacks
from .model import CONFIRM, INCONCLUSIVE, REJECT, Verdict


def run_validator(attack_dir: str, repo_dir: str, harness_dir: str,
                  output_dir: str, limit: int = 0,
                  timeout: int = runner.FORGE_TIMEOUT_DEFAULT) -> list[Verdict]:
    attacks = load_attacks(attack_dir)
    if limit:
        attacks = attacks[:limit]

    results: list[Verdict] = []
    for attack in attacks:
        pre = planner.preflight(attack, repo_dir, harness_dir)
        if pre["status"] != "READY":
            verdict = verdicts.verdict_blocked(attack, pre)
            _write_scaffold(attack, harness_dir)
        else:
            verdict = _execute(attack, pre, repo_dir, output_dir, timeout)
        results.append(verdict)

    results.sort(key=lambda v: (
        {CONFIRM: 0, REJECT: 1, INCONCLUSIVE: 2}.get(v.verdict, 3),
        v.attack_id,
    ))
    write_output(results, attacks, attack_dir, output_dir)
    return results


def _execute(attack: dict[str, Any], pre: dict[str, Any], repo_dir: str,
             output_dir: str, timeout: int) -> Verdict:
    workspace = os.path.join(output_dir, "workspace", attack["attack_id"])
    os.makedirs(workspace, exist_ok=True)
    test_path = runner.build_workspace(workspace, repo_dir, attack, pre["harness"])
    run = runner.run_forge_test(workspace, test_path, timeout=timeout)
    parsed = runner.parse_forge_json(run)
    verdict = verdicts.verdict_from_run(attack, parsed, test_path)
    verdict.meta["workspace"] = workspace
    verdict.meta["harness_scope"] = pre["harness"].get("scope", "contract")
    verdict.forge_output = parsed.get("raw", "")[:4000]
    return verdict


def _write_scaffold(attack: dict[str, Any], harness_dir: str) -> str:
    os.makedirs(harness_dir, exist_ok=True)
    key = planner.root_contract_key(attack)
    name = f"{key or 'Protocol'}Harness"
    path = os.path.join(harness_dir, f"{key or 'protocol'}.sol")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(codegen.render_harness_scaffold(attack, name))
    return path


def write_output(results: list[Verdict], attacks: list[dict[str, Any]],
                 attack_dir: str, output_dir: str) -> None:
    import json
    os.makedirs(output_dir, exist_ok=True)
    by_id = {a.get("attack_id"): a for a in attacks}

    with open(os.path.join(output_dir, "verdicts.jsonl"), "w", encoding="utf-8") as f:
        for verdict in results:
            attack = by_id.get(verdict.attack_id, {})
            record = verdict.to_dict()
            record["attack"] = {
                "source_hypothesis_id": attack.get("source_hypothesis_id", ""),
                "strategy": attack.get("attack_strategy", ""),
                "root_function": attack.get("root_function", ""),
                "exploitability_score": attack.get("exploitability_score", 0),
            }
            f.write(json.dumps(record) + "\n")

    counts = {CONFIRM: 0, REJECT: 0, INCONCLUSIVE: 0}
    readiness_counts: dict[str, int] = {}
    executed = 0
    blocked = 0
    for verdict in results:
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
        readiness = verdict.readiness or "READY"
        readiness_counts[readiness] = readiness_counts.get(readiness, 0) + 1
        if readiness == "READY":
            executed += 1
        else:
            blocked += 1
    summary = {
        "validated_attacks": len(results),
        "executed_attacks": executed,
        "blocked_attacks": blocked,
        "readiness_counts": readiness_counts,
        "verdict_counts": counts,
        "attack_summary_source": attack_dir,
        "confirmed": [
            {
                "attack_id": v.attack_id,
                "strategy": by_id.get(v.attack_id, {}).get("attack_strategy", ""),
                "root_function": by_id.get(v.attack_id, {}).get("root_function", ""),
                "reason": v.reason,
            }
            for v in results if v.verdict == CONFIRM
        ],
        "rejected": [
            {"attack_id": v.attack_id, "reason": v.reason}
            for v in results if v.verdict == REJECT
        ],
    }
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
