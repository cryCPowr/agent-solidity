"""Source discovery.

Finds candidate `.sol` files under a repository root. Does not parse or
interpret them. Deliberately conservative about what it skips: only
well-known dependency/build-artifact directory names are excluded, since the
Recon system must not assume a particular project layout.

Filesystem boundary
--------------------
`repo_root` is treated as a hard filesystem boundary. A candidate file is
only accepted if its *resolved* real path (symlinks fully dereferenced) is
inside `repo_root`'s real path. This matters because `.sol` files can be
regular files, or symlinks whose target lives anywhere on disk. Without
this check, a repo could smuggle in - or an attacker could plant - a
symlink pointing at arbitrary files outside the repo (e.g.
`contracts/Vault.sol -> /outside-secret/Vault.sol`), which would then be
silently treated as part of the audited source universe.

Note that `os.walk` with the default `followlinks=False` already refuses to
descend into a *directory* symlink, so a `.sol` file that only exists
because some ancestor directory is a symlink is never even visited. The
realpath check below additionally covers the remaining case: a `.sol`
*file itself* is a symlink (its containing directory is a real directory,
but the file entry resolves elsewhere).
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
    # NOTE: "lib" is deliberately NOT in this set. Foundry keeps git-submodule
    # dependencies in a *root-level* lib/ -- that specific case is skipped in
    # discover_sources() (and re-enabled by --include-lib) -- but Hardhat and
    # Truffle projects routinely keep first-party sources in nested
    # directories that happen to be named lib/ (contracts/lib/...), which
    # must be discovered like any other source directory. Skipping every
    # directory named lib/ orphans those files and every contract importing
    # them then fails compilation with spurious "unresolved import" errors.
}


@dataclass(frozen=True)
class DiscoveredFile:
    absolute_path: str
    relative_path: str  # relative to repo root, POSIX separators


def _is_within_root(real_path: str, real_root: str) -> bool:
    """True if `real_path` is `real_root` or a descendant of it.

    Both arguments must already be resolved (`os.path.realpath`) and
    normalized. Comparison is purely path-string based (no extra syscalls),
    which keeps it deterministic and cheap to call per-candidate.
    """
    if real_path == real_root:
        return True
    # os.sep suffix guards against false positives like
    # real_root="/repo" matching real_path="/repo-evil/x.sol".
    return real_path.startswith(real_root + os.sep)


def discover_sources(
    repo_root: str,
    include_lib: bool = False,
    extra_skip_dirs: frozenset[str] = frozenset(),
) -> list[DiscoveredFile]:
    """Recursively find `.sol` files under `repo_root`.

    `repo_root` is a hard filesystem boundary: a candidate is only accepted
    if `os.path.realpath(candidate)` resolves inside
    `os.path.realpath(repo_root)`. This rejects `.sol` symlinks whose
    target lives outside the repository. Broken symlinks (target does not
    exist) are also rejected, since `realpath` cannot place them inside the
    boundary with any confidence.

    Returns results sorted by relative path for determinism.
    """
    repo_root = os.path.abspath(repo_root)
    repo_root_real = os.path.realpath(repo_root)
    skip = set(SKIP_DIR_NAMES) | set(extra_skip_dirs)

    found: list[DiscoveredFile] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # followlinks defaults to False: os.walk lists a symlinked directory
        # in dirnames but will not descend into it, so its contents (inside
        # or outside the repo) are never visited via that route. This is
        # what makes the "directory symlink" case deterministic - behavior
        # doesn't depend on the target, and there's no symlink-loop risk.
        is_root = dirpath == repo_root
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in skip
            and not d.startswith(".")
            # Root-level lib/ is the Foundry git-submodule directory; it is
            # skipped unless --include-lib is passed. Nested lib/ directories
            # (e.g. Hardhat's contracts/lib/) are first-party source dirs and
            # are always walked (see SKIP_DIR_NAMES).
            and not (d == "lib" and is_root and not include_lib)
        )
        for fname in sorted(filenames):
            if not fname.endswith(".sol"):
                continue
            abspath = os.path.join(dirpath, fname)
            real_abspath = os.path.realpath(abspath)
            if not _is_within_root(real_abspath, repo_root_real):
                # Symlink resolves outside the repository boundary. Reject.
                continue
            relpath = os.path.relpath(abspath, repo_root).replace(os.sep, "/")
            found.append(DiscoveredFile(absolute_path=abspath, relative_path=relpath))
    found.sort(key=lambda f: f.relative_path)
    return found
