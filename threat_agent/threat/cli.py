"""Threat Agent CLI.

Usage:
    python -m threat.cli <recon-output-dir> -o <threat-output-dir>
"""

from __future__ import annotations

import argparse
import sys
import os
import json

from . import loader
from .output import write_threat_output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Threat Agent: security interpretation from Recon artifacts"
    )
    parser.add_argument("recon_dir", help="Path to Recon output directory")
    parser.add_argument(
        "-o", "--output", default="threat-output",
        help="Output directory for Threat artifacts (default: threat-output)",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Clean output directory before writing",
    )
    args = parser.parse_args()

    recon_dir = args.recon_dir
    if not os.path.exists(recon_dir):
        print(f"Error: Recon output directory not found: {recon_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading Recon artifacts from {recon_dir}...", file=sys.stderr)
    recon = loader.load_recon(recon_dir)
    print(
        f"  Loaded {len(recon.facts_obj.facts)} facts, "
        f"{len(recon.graph.nodes)} nodes, "
        f"{len(recon.graph.edges)} edges",
        file=sys.stderr,
    )

    output_dir = args.output
    if args.clean and os.path.exists(output_dir):
        import shutil
        shutil.rmtree(output_dir)
        print(f"  Cleaned output directory: {output_dir}", file=sys.stderr)

    print(f"Generating Threat artifacts in {output_dir}...", file=sys.stderr)
    write_threat_output(recon, output_dir)

    # Print summary
    summary_path = os.path.join(output_dir, "summary.json")
    if os.path.exists(summary_path):
        with open(summary_path) as f:
            summary = json.load(f)
        print(f"\nThreat Agent Summary:", file=sys.stderr)
        print(f"  Actors:           {summary.get('actor_count', 0)}", file=sys.stderr)
        print(f"  Trust Boundaries: {summary.get('trust_boundary_count', 0)}", file=sys.stderr)
        print(f"  Surfaces:         {summary.get('surface_count', 0)}", file=sys.stderr)
        print(f"  Invariants:       {summary.get('invariant_count', 0)}", file=sys.stderr)
        print(f"  Hypotheses:       {summary.get('hypothesis_count', 0)}", file=sys.stderr)
        for p, count in summary.get("hypotheses_by_priority", {}).items():
            print(f"    {p}: {count}", file=sys.stderr)
        print(f"\nOutput written to: {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()