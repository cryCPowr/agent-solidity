"""CLI entry point: `python -m recon.cli <repo_path> [-o OUTPUT_DIR]`."""

from __future__ import annotations

import argparse
import logging
import sys

from .pipeline import run


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Recon-only static analysis for Solidity/EVM repositories. "
                     "Extracts structured, source-traceable facts. Performs no "
                     "vulnerability or security analysis.",
    )
    parser.add_argument("repo_path", help="Path to the repository to analyze")
    parser.add_argument("-o", "--output", default="recon", help="Output directory (default: ./recon)")
    parser.add_argument(
        "--include-lib", action="store_true",
        help="Include files under the repo-root lib/ directory (Foundry git-submodule "
             "dependencies), which is skipped by default. Nested lib/ directories "
             "(e.g. contracts/lib/) are always discovered.",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Never run `npm install` to fetch a repo-requested solc version; only "
             "bundled/cached compilers are used, and units they cannot satisfy are "
             "reported unresolved. Recommended when analyzing untrusted repositories.",
    )
    parser.add_argument(
        "--max-solc-installs", type=int, default=None,
        help="Cap on distinct non-bundled solc versions this run may `npm install` "
             "(default: 5). Units beyond the cap are reported unresolved, never "
             "silently compiled with an incompatible compiler.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    ctx = run(
        args.repo_path,
        args.output,
        include_lib=args.include_lib,
        offline=args.offline,
        max_solc_installs=args.max_solc_installs,
    )

    print(f"Recon complete: {len(ctx.contracts)} contract-like units, {len(ctx.facts)} facts, "
          f"{len(ctx.graph_nodes)} graph nodes, {len(ctx.graph_edges)} graph edges.")
    print(f"Output written to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
