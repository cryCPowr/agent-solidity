"""Finding Agent CLI.

Usage:
    python -m finding.cli <attack-output-dir> <validator-output-dir> -o <out> [--clean]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .pipeline import run_finding


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Finding Agent: audit-report-style reports for CONFIRMED attacks"
    )
    parser.add_argument("attack_dir", help="Attack Agent output directory")
    parser.add_argument("validator_dir", help="Validator Agent output directory")
    parser.add_argument("-o", "--output", default="finding-output")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir(args.attack_dir):
        print(f"Error: attack output not found: {args.attack_dir}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.validator_dir):
        print(f"Error: validator output not found: {args.validator_dir}", file=sys.stderr)
        sys.exit(1)

    findings = run_finding(args.attack_dir, args.validator_dir, args.output,
                           clean=args.clean)

    with open(os.path.join(args.output, "summary.json"), encoding="utf-8") as f:
        summary = json.load(f)
    print("\nFinding Summary:", file=sys.stderr)
    print(f"  Findings (CONFIRM only): {summary['confirmed_attacks']}", file=sys.stderr)
    for item in summary["findings"]:
        print(f"  [{item['severity'].upper():13}] {item['title']} -> {item['report']}",
              file=sys.stderr)
    for nr in summary["not_reported"]:
        print(f"  (not reported: {nr['verdict']} {nr['attack_id']})", file=sys.stderr)
    print(f"\nOutput written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
