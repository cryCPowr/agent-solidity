"""Attack Agent CLI.

Usage:
    python -m attack.cli <recon-output-dir> <threat-output-dir> -o <attack-output-dir>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import loader
from .output import write_attack_output
from .pipeline import generate_attacks


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attack Agent: concrete attack paths from Threat hypotheses"
    )
    parser.add_argument("recon_dir", help="Path to Recon output directory")
    parser.add_argument("threat_dir", help="Path to Threat output directory")
    parser.add_argument(
        "-o", "--output", default="attack-output",
        help="Output directory for Attack artifacts (default: attack-output)",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Clean output directory before writing",
    )
    args = parser.parse_args()

    for path, label in ((args.recon_dir, "Recon"), (args.threat_dir, "Threat")):
        if not os.path.exists(path):
            print(f"Error: {label} output directory not found: {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Loading Recon artifacts from {args.recon_dir}...", file=sys.stderr)
    recon = loader.load_recon(args.recon_dir)
    print(
        f"  Loaded {len(recon.facts_obj.facts)} facts, "
        f"{len(recon.graph.nodes)} nodes, {len(recon.graph.edges)} edges",
        file=sys.stderr,
    )
    print(f"Loading Threat artifacts from {args.threat_dir}...", file=sys.stderr)
    threat = loader.load_threat(args.threat_dir)
    print(f"  Loaded {len(threat.hypotheses)} hypotheses", file=sys.stderr)

    if args.clean and os.path.exists(args.output):
        import shutil
        shutil.rmtree(args.output)
        print(f"  Cleaned output directory: {args.output}", file=sys.stderr)

    print(f"Generating attack hypotheses in {args.output}...", file=sys.stderr)
    attacks = generate_attacks(recon, threat)

    summary = write_attack_output(attacks, args.output)

    print("\nAttack Agent Summary:", file=sys.stderr)
    print(f"  Attacks: {summary['attack_count']}", file=sys.stderr)
    for band, count in summary["attacks_by_band"].items():
        print(f"    {band}: {count}", file=sys.stderr)
    print(
        f"  Merged duplicate hypotheses: "
        f"{summary['merged_duplicate_hypotheses']}", file=sys.stderr,
    )
    print(f"\nOutput written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
