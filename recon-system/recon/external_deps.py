"""Filesystem-backed expansion of the analyzed source set.

Discovery (discovery.py) deliberately skips dependency/build directories
(node_modules, root-level lib/, ...) so a repo's *first-party* universe is
analyzed without pulling in every transitive package. But solc needs the
full import closure present in one Standard JSON `sources` map, so a
first-party file importing `@openzeppelin/contracts/...` cannot compile
until that dependency's source text is added.

This module closes that gap *on demand*: given the in-memory source set and
the repository root, it finds every import that
import_resolution.build_import_graph reports as unresolved and tries to
locate the referenced file on disk, strictly inside the repository
boundary:

  1. remappings.txt prefix rewrites (Foundry-style `prefix=target` lines),
  2. `<repo>/node_modules/<raw_path>` (how Hardhat resolves bare imports),
  3. the raw path repo-root-relative (rescues first-party files that live
     in a directory discovery skips, e.g. `scripts/` or root-level `lib/`),
  4. plain relative resolution against the importing file's directory
     (safety net for `./`/`../` imports discovery somehow missed).

Once a dependency file is added under its true on-disk relpath (e.g.
``node_modules/@openzeppelin/contracts/access/Ownable.sol``), the bare
import text no longer matches any in-memory path, so this module also
exports `prefix_aliases` (raw-path prefix -> relpath prefix) that the
caller must thread into build_import_graph / group_sources_by_version so
subsequent import resolution maps the import text onto the added file.

Security model (hostile-repo safe):
  * every candidate's *realpath* must stay inside the repo root's realpath
    (same boundary rule as discovery.py -- no symlink escapes);
  * per-file and total size caps bound memory (same limits the pipeline
    applies to discovered files);
  * a hard cap on how many files expansion may add total;
  * `node_modules/solc/` is NEVER a valid source: that package is the
    *compiler*, and its version says nothing about the repo's pragma
    requirements (see solc_manager's resolution policy). Importing solc-js
    internals from a .sol file is never legitimate;
  * read-only: this module never executes anything from the repo.

Pure bookkeeping aside from bounded, read-only file access; no subprocess,
no network.
"""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field

try:  # normal usage: recon/ is a package
    from . import import_resolution
except ImportError:  # pragma: no cover - flat/colocated-test usage
    import import_resolution

# Same caps the pipeline enforces for discovered files (see pipeline.py).
MAX_ADDED_FILES = 2000
MAX_ADDED_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

_REMAPPING_RE = re.compile(r"^\s*([^\s=]+)\s*=\s*(\S+)\s*$")


@dataclass
class ExpansionResult:
    """Outcome of expanding a source set with on-disk dependencies."""

    sources: dict[str, str]                                     # original + added
    added: list[str] = field(default_factory=list)              # sorted relpaths added
    prefix_aliases: dict[str, str] = field(default_factory=dict)  # raw prefix -> relpath prefix
    # solc Standard-JSON `settings.remappings` entries ("raw=target")
    # derived from the resolved import statements: solc matches an import
    # string EXACTLY against the sources-map keys, so a bare import like
    # "@openzeppelin/contracts/access/Ownable.sol" must be remapped onto
    # the key it was added under ("node_modules/@openzeppelin/...").
    solc_remappings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)              # human-readable warnings
    unresolved_remaining: list[dict] = field(default_factory=list)


def parse_remappings(repo_root: str) -> list[tuple[str, str]]:
    """Parse `<repo_root>/remappings.txt` into (prefix, target) pairs.

    Foundry format: one `prefix=target` per line; `#` comments and blank
    lines ignored. Later lines override earlier ones for the same prefix
    (Foundry semantics); longest-prefix matching is applied by callers.
    """
    path = os.path.join(repo_root, "remappings.txt")
    if not os.path.isfile(path):
        return []
    out: list[tuple[str, str]] = []
    seen: dict[str, int] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _REMAPPING_RE.match(line)
                if not m:
                    continue
                prefix, target = m.group(1), m.group(2)
                if prefix in seen:           # later remapping wins
                    out[seen[prefix]] = (prefix, target)
                else:
                    seen[prefix] = len(out)
                    out.append((prefix, target))
    except OSError:
        return []
    return out


def _within_root(real_candidate: str, real_root: str) -> bool:
    return real_candidate == real_root or real_candidate.startswith(real_root + os.sep)


def _is_forbidden_source(relpath: str) -> bool:
    """Paths that must never enter the analyzed source set.

    node_modules/solc is the solc-js *compiler package* living inside the
    target repo. Its version is a JS dependency artifact -- frequently a
    different (transitive) version than the repo's pragmas require -- and
    must never be mistaken for either a source dependency or a compiler to
    invoke.
    """
    parts = relpath.split("/")
    return len(parts) >= 2 and parts[0] == "node_modules" and parts[1] == "solc"


def _candidate_relpaths(raw_path: str, importing_file: str, remappings: list[tuple[str, str]]) -> list[str]:
    """Deterministic, ordered candidate repo-relative paths for one
    unresolved import. Relative imports (./, ../) resolve strictly against
    the importing file, matching Solidity semantics; everything else goes
    through the longest matching remapping, then node_modules, then
    repo-root-relative."""
    raw = raw_path.strip().replace("\\", "/")
    if not raw:
        return []
    importing_dir = posixpath.dirname(importing_file)

    if raw.startswith("./") or raw.startswith("../"):
        joined = posixpath.normpath(posixpath.join(importing_dir, raw))
        return [joined] if joined != "." else []

    candidates: list[str] = []
    for prefix, target in sorted(remappings, key=lambda p: -len(p[0])):
        if raw == prefix or raw.startswith(prefix + "/"):
            suffix = raw[len(prefix):]
            if target.startswith("./") or target.startswith("../"):
                rewritten = posixpath.normpath(posixpath.join(importing_dir, target, suffix))
            else:
                rewritten = posixpath.normpath(posixpath.join(target, suffix))
            if rewritten not in candidates and not rewritten.startswith(".."):
                candidates.append(rewritten)
            break  # only the single longest matching remapping applies
    nm = posixpath.normpath(posixpath.join("node_modules", raw))
    if nm not in candidates:
        candidates.append(nm)
    root_rel = posixpath.normpath(raw)
    if root_rel not in candidates and not root_rel.startswith(".."):
        candidates.append(root_rel)
    return [c for c in candidates if c and c != "."]


def _read_candidate(repo_root: str, relpath: str, real_root: str, budget_left: int) -> tuple[str, str] | None:
    """Read one candidate relpath if it is a real, in-bounds .sol file.

    Returns (relpath, content) or None. Enforces the boundary check, the
    forbidden-path rule, and the per-file size cap; `budget_left` (bytes)
    bounds total expansion.
    """
    if relpath in ("", ".") or _is_forbidden_source(relpath):
        return None
    abspath = os.path.join(repo_root, relpath.replace("/", os.sep))
    real = os.path.realpath(abspath)
    if not _within_root(real, real_root) or not os.path.isfile(real):
        return None
    try:
        size = os.path.getsize(real)
    except OSError:
        return None
    if size > MAX_FILE_SIZE_BYTES or size > budget_left:
        return None
    try:
        with open(real, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return None
    return relpath, content


def expand_sources(sources: dict[str, str], repo_root: str) -> ExpansionResult:
    """Add on-disk dependency sources until the import graph has no
    resolvable-but-missing imports left.

    Iterates to a fixpoint (a newly added dependency has its own imports),
    bounded by MAX_ADDED_FILES / MAX_ADDED_TOTAL_BYTES. Files that still
    cannot be located are reported in `unresolved_remaining` -- the caller
    (solc_manager / pipeline) fails those compilation units closed with a
    concrete missing-import reason rather than guessing.

    The returned `prefix_aliases` maps each remapping prefix onto the
    relpath prefix its files were added under, so downstream in-memory
    import resolution can map import text onto expanded files.
    """
    repo_root = os.path.abspath(repo_root)
    real_root = os.path.realpath(repo_root)
    remappings = parse_remappings(repo_root)

    prefix_aliases: dict[str, str] = {}
    for prefix, target in remappings:
        if target.startswith("./") or target.startswith("../") or target.startswith("/"):
            continue  # relative-to-importer targets don't produce a stable alias
        normalized = posixpath.normpath(target)
        if normalized.startswith("..") or normalized == ".":
            continue
        prefix_aliases[prefix] = normalized

    current = dict(sources)
    added: list[str] = []
    notes: list[str] = []
    total_added_bytes = 0
    stop_reason: str | None = None

    while stop_reason is None:
        graph = import_resolution.build_import_graph(current, prefix_aliases=prefix_aliases)
        if not graph.unresolved:
            break
        if len(added) >= MAX_ADDED_FILES:
            stop_reason = (
                f"dependency expansion stopped after adding {MAX_ADDED_FILES} files; "
                "remaining unresolved imports reported as missing"
            )
            break

        newly_added: list[str] = []
        for u in graph.unresolved:
            if u.importing_file not in current:
                continue  # importer itself was dropped/never added
            located: tuple[str, str] | None = None
            for relpath in _candidate_relpaths(u.raw_path, u.importing_file, remappings):
                for candidate in (relpath, relpath + ".sol"):
                    if candidate in current:
                        # File already present under this key yet the import
                        # text still doesn't resolve onto it: re-adding the
                        # content under another key would duplicate sources,
                        # so this import stays unresolved (reported, never
                        # guessed).
                        located = None
                        break
                    read = _read_candidate(
                        repo_root, candidate, real_root,
                        MAX_ADDED_TOTAL_BYTES - total_added_bytes,
                    )
                    if read is not None:
                        located = read
                        break
                if located is not None:
                    break
            if located is not None:
                relpath, content = located
                current[relpath] = content
                newly_added.append(relpath)
                total_added_bytes += len(content.encode("utf-8"))
                if total_added_bytes >= MAX_ADDED_TOTAL_BYTES:
                    stop_reason = (
                        "dependency expansion byte budget reached; "
                        "remaining unresolved imports reported as missing"
                    )
                    break

        if not newly_added and stop_reason is None:
            break
        added.extend(sorted(set(newly_added)))

    if stop_reason:
        notes.append(stop_reason)

    final_graph = import_resolution.build_import_graph(current, prefix_aliases=prefix_aliases)

    # Derive solc remappings for bare imports whose on-disk key differs
    # from the spelled import text (node_modules convention, remapping
    # aliases). Relative imports need no remapping: solc resolves them
    # against the importing source unit's key, which is the true relpath.
    remappings: set[str] = set()
    known_files = set(current.keys())
    for stmt in final_graph.statements:
        raw = stmt.raw_path.strip().replace("\\", "/")
        if not raw or raw.startswith("./") or raw.startswith("../"):
            continue
        resolved = import_resolution.resolve_import_path(
            stmt.importing_file, raw, known_files, prefix_aliases
        )
        if resolved is not None and resolved != raw:
            remappings.add(f"{raw}={resolved}")

    return ExpansionResult(
        sources=current,
        added=sorted(set(added)),
        prefix_aliases=prefix_aliases,
        solc_remappings=sorted(remappings),
        notes=notes,
        unresolved_remaining=[
            {"importing_file": u.importing_file, "raw_path": u.raw_path, "line": u.line}
            for u in final_graph.unresolved
        ],
    )
