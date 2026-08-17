"""Finding Agent pipeline.

    attacks.jsonl + verdicts.jsonl
        -> join on attack_id, CONFIRM only
        -> build Finding (audit-report-style, statuses verbatim)
        -> findings.jsonl + finding-<id>.md + summary.json
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import loader, report
from .model import Finding


def run_finding(attack_dir: str, validator_dir: str, output_dir: str,
                clean: bool = False) -> list[Finding]:
    if clean and os.path.exists(output_dir):
        import shutil
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    findings = [
        report.build_finding(attack, verdict, sequence=i,
                             validator_dir=validator_dir)
        for i, (attack, verdict) in enumerate(loader.load_runs(attack_dir, validator_dir), 1)
    ]

    with open(os.path.join(output_dir, "findings.jsonl"), "w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding.to_dict()) + "\n")

    for finding in findings:
        path = os.path.join(output_dir, f"finding-{finding.finding_id}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(report.render_markdown(finding))

    summary = {
        "confirmed_attacks": len(findings),
        "findings": [
            {
                "finding_id": fl.finding_id,
                "attack_id": fl.attack_id,
                "severity": fl.severity,
                "title": fl.title,
                "report": f"finding-{fl.finding_id}.md",
            }
            for fl in findings
        ],
        "not_reported": _not_reported(validator_dir),
    }
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return findings


def _not_reported(validator_dir: str) -> list[dict[str, Any]]:
    return [
        {"attack_id": v.get("attack_id"), "verdict": v.get("verdict"),
         "reason": v.get("reason")}
        for v in loader.load_all_verdicts(validator_dir)
        if v.get("verdict") != "CONFIRM"
    ]
