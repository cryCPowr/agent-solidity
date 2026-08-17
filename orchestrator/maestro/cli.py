"""MAESTRO CLI — run the whole AGENT FINDER pipeline over one target.

Usage:
    python -m maestro <repo-path> [--name <run-name>] [--limit N]
                      [--harness <dir>] [--clean-run] [--no-tui]

Defaults:
    run dir   : runs/<name>/  (name defaults to the repo folder name)
    harness   : validator_agent/validator-harnesses
    validator : validates the top --limit attacks (0 = all)

Cross-target hygiene: a run dir that already exists aborts the run unless
--clean-run is given (stale artifacts must never feed a new target).
"""

from __future__ import annotations

import argparse
import os
import sys

from .stages import ROOT


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="maestro", description="AGENT FINDER orchestrator (TUI)")
    parser.add_argument("repo", help="repository under test (never modified)")
    parser.add_argument("--name", default="",
                        help="run name (default: repo folder name)")
    parser.add_argument("--limit", type=int, default=3,
                        help="validate only top-N attacks (0 = all)")
    parser.add_argument("--harness", default="",
                        help="harness directory (default: "
                             "validator_agent/validator-harnesses)")
    parser.add_argument("--clean-run", action="store_true",
                        help="wipe an existing run dir first")
    parser.add_argument("--no-tui", action="store_true",
                        help="plain output (CI / piping)")
    args = parser.parse_args()

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"error: repository not found: {repo}", file=sys.stderr)
        sys.exit(1)

    name = args.name or os.path.basename(repo.rstrip("/"))
    run_dir = os.path.join(ROOT, "runs", name)
    harness = args.harness or os.path.join(
        ROOT, "validator_agent", "validator-harnesses")

    from .tui import run_plain, run_with_tui
    runner = run_plain if (args.no_tui or not sys.stdout.isatty()) else run_with_tui
    result = runner(repo, run_dir, harness, args.limit, args.clean_run)
    sys.exit(0 if result.all_ok else 1)


if __name__ == "__main__":
    main()
