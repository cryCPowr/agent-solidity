"""CLI entry point: `python -m recon.cli <repo_path> [-o OUTPUT_DIR]`."""

from __future__ import annotations

import argparse
import json
import logging
import os
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

    # Read coverage metrics from metadata
    metadata_path = os.path.join(args.output, "metadata.json")
    coverage_info = None
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                coverage_info = metadata.get("coverage", {})
        except (OSError, json.JSONDecodeError):
            pass

    print(f"Recon complete: {len(ctx.contracts)} contract-like units, {len(ctx.facts)} facts, "
          f"{len(ctx.graph_nodes)} graph nodes, {len(ctx.graph_edges)} graph edges.")
    
    # Report coverage warnings
    if coverage_info:
        coverage_pct = coverage_info.get("coverage_percent", 0.0)
        files_discovered = coverage_info.get("files_discovered", 0)
        files_with_ast = coverage_info.get("files_with_ast", 0)
        files_failed = coverage_info.get("files_failed", 0)
        
        if coverage_pct < 100.0:
            print(f"WARNING: AST coverage is {coverage_pct}% ({files_with_ast}/{files_discovered} files)")
            if files_failed > 0:
                print(f"         {files_failed} files failed compilation (see file_diagnostics in metadata.json)")
            
            if coverage_pct < 50.0:
                print(f"         Coverage is critically low - results may be incomplete")
                print(f"         Check compiler constraints, missing dependencies, or pragma incompatibilities")
    
    print(f"Output written to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
