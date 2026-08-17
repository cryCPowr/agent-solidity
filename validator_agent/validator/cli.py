"""Validator Agent CLI.

Usage:
    python -m validator.cli <attack-output-dir> <repo-dir> --harness <dir> -o <out>

Also accepts --limit N to validate only the top-N attacks.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .pipeline import run_validator


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validator Agent: executable CONFIRM/REJECT for attack hypotheses"
    )
    parser.add_argument("attack_dir", help="Attack Agent output directory")
    parser.add_argument("repo_dir", help="Repository under test (never modified)")
    parser.add_argument(
        "--harness", default="validator-harnesses",
        help="Directory of repo-specific IProtocolHarness contracts",
    )
    parser.add_argument("-o", "--output", default="validator-output")
    parser.add_argument("--limit", type=int, default=0, help="validate only top-N attacks")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir(args.attack_dir):
        print(f"Error: attack output not found: {args.attack_dir}", file=sys.stderr)
        sys.exit(1)

    if args.clean and os.path.exists(args.output):
        import shutil
        shutil.rmtree(args.output)

    print(f"Validating attacks from {args.attack_dir} against {args.repo_dir}...",
          file=sys.stderr)
    results = run_validator(
        args.attack_dir, args.repo_dir, args.harness, args.output,
        limit=args.limit, timeout=args.timeout,
    )

    with open(os.path.join(args.output, "summary.json"), encoding="utf-8") as f:
        summary = json.load(f)
    print("\nValidator Summary:", file=sys.stderr)
    print(f"  Validated: {summary['validated_attacks']}", file=sys.stderr)
    for verdict, count in summary["verdict_counts"].items():
        print(f"    {verdict}: {count}", file=sys.stderr)
    for confirmed in summary["confirmed"]:
        print(f"  CONFIRMED: {confirmed['strategy']} @ {confirmed['root_function']}",
              file=sys.stderr)
    print(f"\nOutput written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
