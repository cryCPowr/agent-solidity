"""Source discovery.

Finds candidate `.sol` files under a repository root. Does not parse or
interpret them. Deliberately conservative about what it skips: only
well-known dependency/build-artifact directory names are excluded, since the
Recon system must not assume a particular project layout.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Directory names that are near-universally dependency/build/cache output
# across Foundry, Hardhat, Truffle and Brownie projects. Skipping these is a
# discovery-efficiency decision, not a semantic assumption about the project.
SKIP_DIR_NAMES = {
    "node_modules",
    ".git",
    "artifacts",
    "cache",
    "cache_forge",
    "out",
    "build",
    ".foundry",
    "typechain",
    "typechain-types",
    "coverage",
    "coverage_artifacts",
    ".venv",
    "venv",
    "__pycache__",
    "lib",  # forge git-submodule deps commonly live here; still scanned if
            # --include-lib is passed (see discover_sources)
}


@dataclass(frozen=True)
class DiscoveredFile:
    absolute_path: str
    relative_path: str  # relative to repo root, POSIX separators


def discover_sources(
    repo_root: str,
    include_lib: bool = False,
    extra_skip_dirs: frozenset[str] = frozenset(),
) -> list[DiscoveredFile]:
    """Recursively find `.sol` files under `repo_root`.

    Returns results sorted by relative path for determinism.
    """
    repo_root = os.path.abspath(repo_root)
    skip = set(SKIP_DIR_NAMES) | set(extra_skip_dirs)
    if include_lib:
        skip.discard("lib")

    found: list[DiscoveredFile] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.startswith("."))
        for fname in sorted(filenames):
            if fname.endswith(".sol"):
                abspath = os.path.join(dirpath, fname)
                relpath = os.path.relpath(abspath, repo_root).replace(os.sep, "/")
                found.append(DiscoveredFile(absolute_path=abspath, relative_path=relpath))
    found.sort(key=lambda f: f.relative_path)
    return found
