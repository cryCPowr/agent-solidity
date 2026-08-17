"""solc acquisition and invocation.

The environment this analyzer runs in can only reach the npm registry (not
the solc binary release servers), so we use `solc-js` (the pure JS/WASM build
of the Solidity compiler, published to npm as `solc`) rather than a native
solc binary or `py-solc-x`. This is a project-agnostic, network-appropriate
substitute for whatever "existing compiler infrastructure" a given repo might
normally use.

This module is explicitly a compiler-invocation shim. It performs no AST
interpretation.

Compiler resolution policy
---------------------------
Exact compiler *compatibility* is a prerequisite for treating AST output as
a trustworthy Recon fact -- it is not a best-effort convenience. A `pragma
solidity` statement is a semver constraint, not a single version token, and
this module resolves it as one (`^0.8.20`, `>=0.8.20 <0.9.0`, multiple
pragma statements ANDed together, etc.) via `resolve_compiler()`.

If no available compiler (bundled, cached, or installable from npm within
the allow-list/budget) actually satisfies a compilation unit's constraint,
that unit is NOT silently compiled with an incompatible substitute. It is
reported as `compatible=False` / `resolution_method="unresolved"`, the
`CompileResult` comes back with `ok=False` and no AST, and
`build_trust_summary()` surfaces it as a hard `analysis_status: "untrusted"`
blocker. Downstream consumers must treat an untrusted result as incomplete,
not as a normal (if imperfect) Recon output.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

try:  # normal usage: recon/ is a package (see pipeline.py's `from . import ...`)
    from . import import_resolution
except ImportError:  # pragma: no cover - flat/colocated-test usage
    import import_resolution

logger = logging.getLogger("recon.solc_manager")

_THIS_DIR = Path(__file__).resolve().parent.parent  # recon-system/
_COMPILE_JS = _THIS_DIR / "compile.js"
_BUNDLED_NODE_MODULES = _THIS_DIR / "node_modules"
_CACHE_DIR = _THIS_DIR / ".solc-cache"
# What we *aim* to ship as the bundled compiler. This is a declaration, not
# a fact: the authoritative bundled version is read from the bundled solc
# package's own package.json at import time (see _BUNDLED_VERSION below) so
# a stale constant can never make us claim "compiled with 0.8.24" while
# actually invoking whatever solc happens to be installed in node_modules.
_BUNDLED_DECLARED_VERSION = "0.8.24"

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_STRICT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _read_installed_solc_version(node_modules_dir: Path) -> str | None:
    """Return the *verified* version of the solc package under
    `node_modules_dir`, read from its package.json -- or None if it cannot
    be read (missing/corrupt package).

    Directory names are never trusted: the compiler actually invoked is
    whatever `require()` loads from this directory, and only package.json
    says which version that is.
    """
    try:
        with open(node_modules_dir / "solc" / "package.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    version = data.get("version")
    return version if isinstance(version, str) and _STRICT_SEMVER_RE.match(version) else None


def _bundled_version() -> str:
    """Verified bundled compiler version (declared value only as fallback
    when the bundled package cannot be read at all)."""
    verified = _read_installed_solc_version(_BUNDLED_NODE_MODULES)
    return verified if verified is not None else _BUNDLED_DECLARED_VERSION


# The bundled version as a module attribute (tests and call sites read it
# call-time via the module global; it reflects the *actual* bundled solc).
_BUNDLED_VERSION = _bundled_version()

# A single semver clause inside a pragma constraint expression, e.g.
# "^0.8.20", ">=0.8.20", "0.8.24", or the two-component "^0.8" / ">=0.6"
# form (legal and common in real repositories; npm/solidity treat the
# missing patch component as .0 for range purposes, so "^0.8" means
# ">=0.8.0 <0.9.0"). The operator is optional; a bare version is treated
# the same way solc treats it -- like `=version` (exact match).
# This is confirmed by solc's actual behavior: `pragma solidity 0.8.30;`
# compiles only with exactly 0.8.30, not 0.8.36 or anything else.
_CLAUSE_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+)\.(\d+)(?:\.(\d+))?")

# Hard cap on how many *distinct* non-bundled solc versions a single run is
# allowed to trigger `npm install` for. A repo can contain arbitrarily many
# `.sol` files each declaring a different pragma constraint; without a cap
# this becomes an attacker-controlled loop of subprocess/network calls (DoS
# via untrusted repo content). Any group beyond the cap is treated as
# unresolved (see module docstring: no silent substitute compiler).
_MAX_INSTALLS_PER_RUN = 5

# Known-good published solc-js releases on npm (major.minor families). This
# is an allow-list gate, not just a syntactic regex check: a version we're
# about to `npm install` must fall within a family we know npm actually
# publishes before we ever shell out. This blocks pragma-crafted version
# strings that are syntactically valid semver but nonsensical/non-existent
# (which would otherwise still cost a full npm-install network round trip
# before failing).
# Expanded to include newer major.minor families as encountered in real-world repos.
_KNOWN_SOLC_MINOR_FAMILIES = {
    (0, 4), (0, 5), (0, 6), (0, 7), (0, 8), (0, 9),
}


def _is_installable_version(version: str) -> bool:
    """Allow-list check: strict semver AND within a known-published family."""
    if not _STRICT_SEMVER_RE.match(version):
        return False
    major, minor, _patch = (int(p) for p in version.split("."))
    return (major, minor) in _KNOWN_SOLC_MINOR_FAMILIES


def _ver_tuple(version: str) -> tuple[int, int, int]:
    a, b, c = version.split(".")
    return (int(a), int(b), int(c))


# --------------------------------------------------------------------------
# Pragma constraint extraction
# --------------------------------------------------------------------------

def extract_pragma_constraint(source_text: str) -> str | None:
    """Extract the full solidity version constraint expression for a file.

    A file may contain more than one `pragma solidity ...;` statement (rare,
    but legal); when it does, the constraints are combined with AND, exactly
    like space-separated clauses within a single pragma are. Returns the
    combined, whitespace-normalized constraint expression, or None if the
    file has no `pragma solidity` statement at all.
    """
    exprs = [m.group(1).strip() for m in _PRAGMA_RE.finditer(source_text)]
    if not exprs:
        return None
    combined = " ".join(exprs)
    return re.sub(r"\s+", " ", combined).strip()


# --------------------------------------------------------------------------
# Semver constraint matching
# --------------------------------------------------------------------------

def _parse_or_groups(constraint_expr: str) -> list[list[tuple[str, tuple[int, int, int]]]]:
    """Parse a constraint expression into OR-of-AND clause groups.

    `||` separates alternative (OR) ranges; whitespace-separated clauses
    within a group are ANDed together (this matches how solidity pragma
    expressions like ">=0.8.20 <0.9.0" combine clauses). Returns [] if the
    expression contains no recognizable version clause at all -- callers
    must treat that as "cannot confirm compatibility", not as "matches
    everything".
    """
    or_groups: list[list[tuple[str, tuple[int, int, int]]]] = []
    for group_text in constraint_expr.split("||"):
        group_text = group_text.strip()
        if not group_text:
            continue
        clauses = [
            (
                m.group(1) or "=",
                (int(m.group(2)), int(m.group(3)), int(m.group(4) or "0")),
            )
            for m in _CLAUSE_RE.finditer(group_text)
        ]
        if clauses:
            or_groups.append(clauses)
    return or_groups


def _clause_matches(op: str, ver: tuple[int, int, int], candidate: tuple[int, int, int]) -> bool:
    if op == "=":
        return candidate == ver
    if op == ">=":
        return candidate >= ver
    if op == "<=":
        return candidate <= ver
    if op == ">":
        return candidate > ver
    if op == "<":
        return candidate < ver
    # "^" and bare-version ("~" treated the same, conservatively): matches
    # up to (but excluding) the next breaking boundary, same as npm/solidity
    # caret semantics -- same major if major > 0, else same minor if
    # minor > 0, else exact patch.
    major, minor, _patch = ver
    if major > 0:
        upper = (major + 1, 0, 0)
    elif minor > 0:
        upper = (0, minor + 1, 0)
    else:
        upper = (0, 0, ver[2] + 1)
    return ver <= candidate < upper


def version_satisfies(candidate: str, constraint_expr: str) -> bool:
    """True iff `candidate` (strict x.y.z) satisfies the pragma constraint.

    An unparseable constraint never matches -- we never want "couldn't
    parse the pragma" to silently degrade into "anything goes".
    """
    or_groups = _parse_or_groups(constraint_expr)
    if not or_groups:
        return False
    candidate_t = _ver_tuple(candidate)
    return any(
        all(_clause_matches(op, ver, candidate_t) for op, ver in group)
        for group in or_groups
    )


# --------------------------------------------------------------------------
# Grouping
# --------------------------------------------------------------------------

@dataclass
class CompileGroup:
    constraint_expr: str | None
    files: list[str] = field(default_factory=list)
    # Import-closure provenance, populated by group_sources_by_version().
    # Left at their defaults (empty) when a CompileGroup is constructed
    # directly with just constraint_expr/files, which is how existing
    # single-file-group tests and call sites build them -- compile_group()
    # treats an empty member_constraints/unresolved_imports the same as
    # "no import-graph information available" and falls back to the
    # original single-constraint behavior.
    member_constraints: dict[str, str | None] = field(default_factory=dict)
    unresolved_imports: list[dict] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)


def _can_coexist(constraint_a: str | None, constraint_b: str | None) -> bool:
    """True if two pragma constraints can be satisfied by the same compiler.
    
    Returns True when at least one available compiler (bundled, cached, or
    installable from the known families) satisfies both constraints
    simultaneously. This is used to split import-connected components into
    pragma-compatible subgroups.
    """
    if constraint_a is None or constraint_b is None:
        return True  # no-pragma files can compile with any versioned file
    
    # Quick check: if constraints are identical, they trivially coexist
    if constraint_a == constraint_b:
        return True
    
    # Check if any locally available compiler satisfies both
    local_candidates = {_BUNDLED_VERSION, *_cached_versions()}
    for v in sorted(local_candidates, key=_ver_tuple):
        if version_satisfies(v, constraint_a) and version_satisfies(v, constraint_b):
            return True
    
    # Check if any version from known solc families could satisfy both
    # This allows splitting even when the exact compiler isn't cached yet
    # Example: `0.7.6` and `>0.5.0 <0.9.0` can coexist via 0.7.6
    for major, minor in _KNOWN_SOLC_MINOR_FAMILIES:
        # Try a few patch versions (0, 6, 20) to sample the family
        for patch in [0, 6, 20]:
            v = f"{major}.{minor}.{patch}"
            try:
                if version_satisfies(v, constraint_a) and version_satisfies(v, constraint_b):
                    return True
            except Exception:
                continue
    
    return False


def _split_by_pragma_compatibility(
    comp_files: list[str],
    member_constraints: dict[str, str | None],
    graph,
) -> list[list[str]]:
    """Split an import-connected component into pragma-compatible subgroups.

    Solidity repos often have multiple compiler generations (e.g., 0.7.6 and
    0.8.30) sharing interfaces with broad pragmas (>0.5.0 <0.9.0). A single
    compiler cannot satisfy all constraints simultaneously, so they need
    separate compilation passes.

    Algorithm
    ---------
    1. Compute, for each file, the set of locally-available compilers that
       satisfy its pragma constraint.
    2. Attempt a universal satisfier: if one local compiler satisfies every
       file in the component, return the component as-is (no split needed).
    3. Identify "hard generations": files whose pragma can only be satisfied
       by exactly ONE local compiler. These are the split boundaries.
    4. For each hard generation, grow a subgroup via transitive import
       expansion, but only follow edges whose target files the generation's
       compiler can handle (pragma-compatible). Flexible files (satisfied by
       multiple compilers) get pulled into whichever generation imports them.
    5. Return the subgroups. A flexible file may appear in multiple subgroups
       (overlap is intentional and handled by the caller).

    Caller responsibility: pipeline.py must deduplicate — first successful
    AST for a given relpath wins; later groups that also produce AST for an
    already-seen relpath are silently skipped.
    """
    local_candidates = sorted({_BUNDLED_VERSION, *_cached_versions()}, key=_ver_tuple)

    # Step 1: compiler affinity for each file
    file_satisfying: dict[str, frozenset[str]] = {}
    for f in comp_files:
        constraint = member_constraints[f]
        if constraint is None:
            file_satisfying[f] = frozenset(local_candidates)
        else:
            file_satisfying[f] = frozenset(
                v for v in local_candidates if version_satisfies(v, constraint)
            )

    # Step 2: universal satisfier → no split needed
    universal = frozenset(local_candidates)
    for s in file_satisfying.values():
        universal = universal & s
    if universal:
        return [comp_files]

    # Step 3: hard-pinned generations — constraints only satisfiable by one
    # specific local compiler version
    hard_gen: dict[str, list[str]] = {}  # compiler_version -> seed files
    for f in comp_files:
        satisfying = file_satisfying[f]
        if len(satisfying) == 1:
            compiler = next(iter(satisfying))
            hard_gen.setdefault(compiler, []).append(f)

    if len(hard_gen) <= 1:
        # At most one hard generation — cannot split meaningfully
        return [comp_files]

    comp_set = set(comp_files)

    # Step 4: grow each generation via import closure, restricted to
    # files the generation's compiler can handle
    subgroups: list[list[str]] = []
    for compiler in sorted(hard_gen):  # deterministic order
        seed = hard_gen[compiler]
        subgroup: set[str] = set(seed)
        worklist = list(seed)
        visited: set[str] = set(seed)

        while worklist:
            f = worklist.pop()
            for imported in graph.edges.get(f, set()):
                if imported not in comp_set or imported in visited:
                    continue
                # Include only if the generation compiler can compile this file
                imported_constraint = member_constraints[imported]
                if imported_constraint is None or version_satisfies(compiler, imported_constraint):
                    visited.add(imported)
                    subgroup.add(imported)
                    worklist.append(imported)

        if subgroup:
            subgroups.append(sorted(subgroup))

    # Step 5: any file not covered by any generation (e.g. isolated flexible
    # files with no hard-generation importers) falls through; group them
    # separately so they are still compiled rather than silently dropped.
    covered = set().union(*subgroups) if subgroups else set()
    leftover = comp_set - covered
    if leftover:
        subgroups.append(sorted(leftover))

    return subgroups if len(subgroups) > 1 else [comp_files]


def group_sources_by_version(
    sources: dict[str, str], prefix_aliases: dict[str, str] | None = None
) -> list[CompileGroup]:
    """Build compiler-compatible compilation units from the *transitive
    import closure*, not from each file's pragma in isolation.

    `prefix_aliases` (raw import prefix -> relpath prefix, e.g. from a
    Foundry remappings.txt expanded by external_deps.expand_sources) is
    threaded into import resolution so remapped bare imports resolve onto
    the files added under their true on-disk relpaths.

    Pipeline: resolve every `import` in `sources` -> build the import graph
    -> compute weakly-connected components (the transitive dependency
    closure) -> **split each component by pragma compatibility** (Bug B fix)
    -> merge subgroups that share identical, compatible constraints.

    Compiling import-connected files in isolation (grouping by pragma
    alone) silently breaks: whichever file's group didn't happen to
    include its import partner's content produces a spurious "file not
    found" from solc, even though the file exists in the repo. Grouping by
    connected component fixes that structurally.
    
    However, a connected component may contain files with *incompatible*
    pragma constraints (e.g., 0.7.6 and 0.8.30 connected via imports). These
    must be split into pragma-compatible subgroups, each compiled separately
    with the appropriate compiler while preserving import resolution.

    Within one subgroup, every member's pragma constraint must hold
    *simultaneously* -- see `resolve_compiler_for_constraints`, which
    checks each member's constraint independently rather than
    string-concatenating them. A subgroup whose members' constraints can't
    be simultaneously satisfied gets its combined constraint_expr as an
    ` AND `-joined label for reporting, and `compile_group()` will report
    it as unresolved rather than guessing.

    A component with an import that couldn't be resolved to any file in
    `sources` at all (missing dependency) carries that in
    `unresolved_imports`; `compile_group()` fails closed on that
    information before ever invoking solc, since the compile is already
    known to be incomplete.
    """
    graph = import_resolution.build_import_graph(sources, prefix_aliases=prefix_aliases)
    components = import_resolution.connected_components(graph, files=sources.keys())
    all_cycles = import_resolution.find_cycles(graph)

    prelim: list[CompileGroup] = []
    for comp_files in components:
        comp_set = set(comp_files)
        member_constraints = {f: extract_pragma_constraint(sources[f]) for f in comp_files}
        
        # Split component by pragma compatibility (Bug B fix)
        subgroups = _split_by_pragma_compatibility(comp_files, member_constraints, graph)
        
        for subgroup_files in subgroups:
            subgroup_set = set(subgroup_files)
            subgroup_constraints = {f: member_constraints[f] for f in subgroup_files}
            distinct = sorted({c for c in subgroup_constraints.values() if c is not None})
            combined_label = " AND ".join(distinct) if distinct else None

            unresolved = [
                {"importing_file": u.importing_file, "raw_path": u.raw_path, "line": u.line}
                for u in graph.unresolved
                if u.importing_file in subgroup_set
            ]
            cycles = [c for c in all_cycles if set(c) <= subgroup_set]

            prelim.append(CompileGroup(
                constraint_expr=combined_label,
                files=list(subgroup_files),
                member_constraints=subgroup_constraints,
                unresolved_imports=unresolved,
                cycles=cycles,
            ))

    # Merge components that don't carry unresolved-import provenance and
    # share an identical combined constraint label -- this is the same
    # "one solc call per distinct constraint" efficiency the previous
    # pure-pragma grouping had for files that don't import each other at
    # all. A component with unresolved imports is keyed uniquely so its
    # provenance never gets diluted by merging into (or absorbing) an
    # unrelated group.
    merged: dict[str, CompileGroup] = {}
    order: list[str] = []
    for group in prelim:
        if group.unresolved_imports:
            key = "\0__unresolved__::" + ",".join(sorted(group.files))
        else:
            key = group.constraint_expr if group.constraint_expr is not None else "\0__no_pragma__"
        if key not in merged:
            merged[key] = group
            order.append(key)
        else:
            existing = merged[key]
            existing.files = sorted(set(existing.files) | set(group.files))
            existing.member_constraints.update(group.member_constraints)
            existing.cycles = existing.cycles + [c for c in group.cycles if c not in existing.cycles]

    result = [merged[k] for k in order]
    result.sort(key=lambda g: (g.files[0] if g.files else ""))
    return result


def _version_node_modules_dir(version: str) -> Path:
    return _CACHE_DIR / version / "node_modules"


def _node_modules_for(version: str) -> str | None:
    """Locate a node_modules directory whose solc package *verifiably* is
    `version` (package.json is the only authority -- never the directory
    name), or None if no such directory exists.

    Preference order:
    - the bundled recon-system/node_modules, when its verified version
      matches (or when it has no readable solc package at all: there is
      nothing to mislabel, and the compiler invocation itself will fail
      loudly rather than silently substitute a wrong version);
    - otherwise the first (deterministically sorted) .solc-cache entry
      whose verified version matches.

    A cache directory whose name promises one version but whose package
    says another is skipped: trusting it would invoke an unrequested
    compiler while reporting the requested one.
    """
    bundled_actual = _read_installed_solc_version(_BUNDLED_NODE_MODULES)
    if bundled_actual == version or bundled_actual is None:
        return str(_BUNDLED_NODE_MODULES)

    if _CACHE_DIR.exists():
        for child in sorted(_CACHE_DIR.iterdir()):
            if not child.is_dir() or not _STRICT_SEMVER_RE.match(child.name):
                continue
            if _read_installed_solc_version(child / "node_modules") == version:
                return str(child / "node_modules")
    return None


def _cached_versions() -> list[str]:
    """Versions actually installed in the Recon-managed cache, *verified*
    against each entry's solc package.json (a tampered or partially-written
    cache directory reports the version it really contains, not the one
    its name claims)."""
    if not _CACHE_DIR.exists():
        return []
    out: set[str] = set()
    for child in _CACHE_DIR.iterdir():
        if (
            child.is_dir()
            and _STRICT_SEMVER_RE.match(child.name)
            and (child / "node_modules" / "solc").exists()
        ):
            verified = _read_installed_solc_version(child / "node_modules")
            if verified is not None:
                out.add(verified)
    return sorted(out, key=_ver_tuple)


def _query_npm_available_versions(timeout: int = 30) -> list[str] | None:
    """Ask the npm registry which solc-js versions are actually published.

    Returns None on any failure (no network, npm missing, bad output) --
    callers must treat that as "couldn't confirm", not as "nothing
    published".
    """
    try:
        proc = subprocess.run(
            ["npm", "view", "solc", "versions", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("npm view solc versions failed: %s", exc)
        return None
    if proc.returncode != 0:
        logger.warning("npm view solc versions failed: %s", proc.stderr.strip())
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(data, str):
        data = [data]
    if not isinstance(data, list):
        return None
    return [v for v in data if isinstance(v, str)]


# --------------------------------------------------------------------------
# Install budget (unchanged behaviour, still gates every npm install)
# --------------------------------------------------------------------------

@dataclass
class InstallBudget:
    """Tracks/limits `npm install` calls for a single pipeline run.

    Untrusted repo content (pragma statements) chooses which solc versions
    get requested, so the number of *new* npm-install subprocesses per run
    must be bounded regardless of how many distinct constraints a repo
    declares. Versions already cached on disk from a previous run (or
    earlier in this run) don't count against the budget -- they're a cache
    hit, not a new install. Set `offline=True` to disallow npm installs
    (and npm registry queries) entirely.
    """

    offline: bool = False
    max_installs: int = _MAX_INSTALLS_PER_RUN
    installs_used: int = 0

    def try_reserve(self) -> bool:
        """Reserve one install slot. Returns False if none remain or offline."""
        if self.offline:
            return False
        if self.installs_used >= self.max_installs:
            return False
        self.installs_used += 1
        return True


def _install_version(version: str, budget: InstallBudget) -> bool:
    """Attempt `npm install solc@version` into the per-version cache dir.

    Returns True iff the install succeeded AND the installed package's
    version verifiably reads back as `version` from its package.json --
    a half-written or redirected install must not be reported as the
    requested compiler. Does not touch the budget itself beyond the single
    reservation the caller already made via `try_reserve()`.
    """
    target_dir = _CACHE_DIR / version
    node_modules = _version_node_modules_dir(version)
    target_dir.mkdir(parents=True, exist_ok=True)
    logger.info("attempting npm install of solc@%s", version)
    try:
        proc = subprocess.run(
            ["npm", "install", "--no-save", "--prefix", str(target_dir), f"solc@{version}"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("npm install failed for solc@%s: %s", version, exc)
        return False
    if proc.returncode != 0 or not (node_modules / "solc").exists():
        return False
    installed = _read_installed_solc_version(node_modules)
    if installed != version:
        logger.warning(
            "npm install of solc@%s produced a package reporting version %r; rejecting",
            version, installed,
        )
        return False
    return True


# --------------------------------------------------------------------------
# Compiler resolution
# --------------------------------------------------------------------------

@dataclass
class CompilerRequirement:
    """The outcome of resolving one compilation unit's pragma constraint
    against the compilers we actually have (or can get)."""

    constraint_expr: str | None
    resolved_version: str | None
    resolution_method: str  # see RESOLUTION_METHODS below
    compatible: bool
    # Diagnostics for structured failure reporting (never used to pick a
    # compiler): every concrete version that was considered and rejected,
    # and why resolution ended the way it did.
    attempted_versions: list[str] = field(default_factory=list)
    reason: str = ""


# no_pragma_bundled_default: no pragma present -> bundled used by convention
# bundled_compatible:        bundled version itself satisfies the constraint
# cache_compatible:          a previously-installed cached version satisfies it
# installed_compatible:      a fresh npm install of a satisfying version succeeded
# unparseable_constraint:    pragma text didn't parse into any version clause
# unresolved:                no local/installable compiler satisfies the constraint
# invocation_mismatch:       resolution succeeded but the compiler that was
#                             actually invoked reports a different version than
#                             the resolved one (verification failure: fail closed)
# missing_import:            a member file's import didn't resolve to any known
#                             source at all; set directly by compile_group()
#                             (never returned by resolve_compiler*()), since the
#                             unit is already known-incomplete before compiler
#                             resolution is even attempted
RESOLUTION_METHODS = frozenset({
    "no_pragma_bundled_default",
    "bundled_compatible",
    "cache_compatible",
    "installed_compatible",
    "unparseable_constraint",
    "unresolved",
    "invocation_mismatch",
    "missing_import",
})


def _normalize_hint(raw: str) -> str | None:
    """Normalize a build-metadata compiler hint to strict x.y.z, or None.

    Hints arrive from human-authored config (`0.8.28`, `^0.8.20`, `=0.8.28`);
    strip the comparison operators and validate. Anything that doesn't
    normalize to a real version is ignored -- a malformed hint must never
    block pragma-driven resolution.
    """
    cleaned = re.sub(r"[\^~<>=\s]+", "", raw.strip())
    return cleaned if _STRICT_SEMVER_RE.match(cleaned) else None


def extract_compiler_hints(repo_root: str) -> dict:
    """Read compiler version *hints* from target-repo build metadata.

    Inspected (best effort, regex/JSON only -- nothing from the repo is
    ever executed): hardhat.config.{ts,js,cjs,mjs}, foundry.toml,
    package.json (truffle/embark-style compilers.solc.version).

    Hints are diagnostics/tie-breakers ONLY: source pragmas remain the
    authoritative compatibility constraint, and the target repo's
    node_modules/solc version is deliberately never consulted here (a
    transitive JS dependency says nothing about pragma requirements).

    Returns {"by_file": {relpath: {"raw": str, "version": str|None}},
             "primary": str|None, "conflicting": bool} where `primary` is
    the single distinct normalized hint across all sources (None when
    absent or conflicting).
    """
    import os

    repo_root = os.path.abspath(repo_root)
    by_file: dict[str, dict] = {}

    hardhat_re = re.compile(r"version\s*[:=]\s*['\"]([^'\"]+)['\"]")
    for name in ("hardhat.config.ts", "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs"):
        path = os.path.join(repo_root, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(64 * 1024)
        except OSError:
            continue
        m = hardhat_re.search(text)
        if m:
            by_file[name] = {"raw": m.group(1), "version": _normalize_hint(m.group(1))}

    foundry_path = os.path.join(repo_root, "foundry.toml")
    if os.path.isfile(foundry_path):
        try:
            with open(foundry_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(64 * 1024)
        except OSError:
            text = ""
        m = (
            re.search(r"(?m)^\s*solc_version\s*=\s*['\"]([^'\"]+)['\"]", text)
            or re.search(r"(?m)^\s*solc\s*=\s*['\"]([^'\"]+)['\"]", text)
        )
        if m:
            by_file["foundry.toml"] = {"raw": m.group(1), "version": _normalize_hint(m.group(1))}

    pkg_path = os.path.join(repo_root, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            raw = (((pkg.get("compilers") or {}).get("solc")) or {}).get("version")
            if isinstance(raw, str):
                by_file["package.json"] = {"raw": raw, "version": _normalize_hint(raw)}
        except (OSError, json.JSONDecodeError):
            pass

    versions = sorted({v["version"] for v in by_file.values() if v["version"]})
    return {
        "by_file": dict(sorted(by_file.items())),
        "primary": versions[0] if len(versions) == 1 else None,
        "conflicting": len(versions) > 1,
    }


def _resolve_against_predicate(
    predicate: Callable[[str], bool], budget: InstallBudget, hint: str | None = None
) -> tuple[str | None, str, list[str], str]:
    """Shared version-search logic: bundled -> cached -> npm-install, in
    that preference order, trying each concrete version against
    `predicate` ("would this version satisfy the compilation unit?").

    `hint` (from build metadata) never widens what is acceptable -- every
    candidate must still pass `predicate` -- it only breaks ties *within*
    an acquisition tier: among multiple satisfying cached versions the
    hinted one is preferred over the highest, and among published versions
    the hinted one is preferred over the highest. A hint that itself fails
    the predicate is ignored entirely (pragmas are authoritative).

    Returns `(resolved_version, resolution_method, attempted_versions,
    reason)`; `resolved_version` is None iff `resolution_method ==
    "unresolved"`. Factored out of `resolve_compiler` so both the
    single-constraint and the multi-file, multi-constraint
    (`resolve_compiler_for_constraints`) resolution paths share one
    implementation of "prefer local, then install within budget" -- there
    is exactly one place that decides which concrete version gets used.
    """
    attempted: list[str] = []

    local_candidates = {_BUNDLED_VERSION, *_cached_versions()}
    rejected_local = sorted((v for v in local_candidates if not predicate(v)), key=_ver_tuple)
    attempted.extend(rejected_local)
    matching_local = sorted((v for v in local_candidates if predicate(v)), key=_ver_tuple)
    if _BUNDLED_VERSION in matching_local:
        return _BUNDLED_VERSION, "bundled_compatible", attempted, ""
    if matching_local:
        if hint is not None and hint in matching_local:
            chosen = hint
        else:
            chosen = matching_local[-1]
        return chosen, "cache_compatible", attempted, ""

    if budget.offline:
        logger.warning("no local solc satisfies the constraint and offline mode disallows npm; unresolved")
        return None, "unresolved", attempted, (
            "no local (bundled or cached) solc satisfies the constraint and "
            "offline mode disallows npm acquisition"
        )

    published = _query_npm_available_versions()
    if not published:
        return None, "unresolved", attempted, "npm registry query failed or returned no versions"

    satisfying = sorted(
        (v for v in published if _is_installable_version(v) and predicate(v)),
        key=_ver_tuple,
        reverse=True,
    )
    if not satisfying:
        logger.warning("no published/allow-listed solc satisfies the constraint")
        return None, "unresolved", attempted, "no published, allow-listed solc version satisfies the constraint"

    best = hint if (hint is not None and hint in satisfying) else satisfying[0]
    if not budget.try_reserve():
        logger.warning(
            "solc@%s would satisfy the constraint but the install budget (%s) is exhausted; unresolved",
            best, budget.max_installs,
        )
        return None, "unresolved", attempted, (
            f"solc@{best} satisfies the constraint but the per-run install "
            f"budget ({budget.max_installs}) is exhausted"
        )

    if _install_version(best, budget):
        return best, "installed_compatible", attempted, ""

    logger.warning("npm install of solc@%s failed; unresolved", best)
    return None, "unresolved", attempted, f"npm install of solc@{best} failed or installed an unverifiable package"


def resolve_compiler(
    constraint_expr: str | None,
    budget: InstallBudget | None = None,
    hint: str | None = None,
) -> CompilerRequirement:
    """Resolve a pragma constraint expression to a concrete, *compatible*
    solc version -- or report that none is available.

    This never returns `compatible=True` for a version that doesn't
    actually satisfy the constraint. There is deliberately no "fall back to
    the bundled compiler anyway" path here: an incompatible compiler
    producing an AST that looks like normal output is exactly the failure
    mode this function exists to prevent.

    `hint` (a normalized x.y.z from build metadata) may only influence
    which *already-satisfying* version is preferred, never whether a
    version is acceptable.
    """
    if budget is None:
        budget = InstallBudget()

    if constraint_expr is None:
        return CompilerRequirement(
            constraint_expr=None,
            resolved_version=_BUNDLED_VERSION,
            resolution_method="no_pragma_bundled_default",
            compatible=True,
        )

    if not _parse_or_groups(constraint_expr):
        logger.warning("unparseable solidity pragma constraint: %r", constraint_expr)
        return CompilerRequirement(
            constraint_expr=constraint_expr,
            resolved_version=None,
            resolution_method="unparseable_constraint",
            compatible=False,
            reason=f"pragma constraint {constraint_expr!r} did not parse into any version clause",
        )

    version, method, attempted, reason = _resolve_against_predicate(
        lambda v: version_satisfies(v, constraint_expr), budget, hint=hint
    )
    return CompilerRequirement(
        constraint_expr, version, method, version is not None,
        attempted_versions=attempted, reason=reason,
    )


def resolve_compiler_for_constraints(
    constraint_exprs: list[str | None],
    budget: InstallBudget | None = None,
    hint: str | None = None,
) -> CompilerRequirement:
    """Resolve ONE compiler version that satisfies every constraint in
    `constraint_exprs` *simultaneously* -- for a compilation unit made of
    several import-connected files, each of which may declare its own
    pragma.

    Each member constraint is checked independently via
    `version_satisfies`, and a candidate version must pass all of them.
    This deliberately does NOT string-concatenate the constraint
    expressions before matching: `"^0.8.20"` and `"0.7.6 || ^0.8.10"`
    naively joined as `"^0.8.20 0.7.6 || ^0.8.10"` would parse as the OR of
    two *different* clause groups instead of the AND of the two original
    expressions, silently changing what actually gets accepted. The
    returned `constraint_expr` is a human-readable ` AND `-joined label
    (for logging/reporting only) built from the distinct constraints
    actually present -- never re-parsed.
    """
    if budget is None:
        budget = InstallBudget()

    present = [e for e in constraint_exprs if e is not None]
    distinct = sorted(set(present))
    label = " AND ".join(distinct) if distinct else None

    if not present:
        return CompilerRequirement(
            constraint_expr=None,
            resolved_version=_BUNDLED_VERSION,
            resolution_method="no_pragma_bundled_default",
            compatible=True,
        )

    unparseable = [e for e in distinct if not _parse_or_groups(e)]
    if unparseable:
        logger.warning("unparseable solidity pragma constraint(s) in compilation unit: %r", unparseable)
        return CompilerRequirement(
            constraint_expr=label,
            resolved_version=None,
            resolution_method="unparseable_constraint",
            compatible=False,
            reason=f"unparseable pragma constraint(s) in unit: {unparseable!r}",
        )

    def predicate(v: str) -> bool:
        return all(version_satisfies(v, e) for e in present)

    version, method, attempted, reason = _resolve_against_predicate(predicate, budget, hint=hint)
    return CompilerRequirement(
        label, version, method, version is not None,
        attempted_versions=attempted, reason=reason,
    )


# --------------------------------------------------------------------------
# Compilation
# --------------------------------------------------------------------------

@dataclass
class CompileResult:
    version: str | None  # resolved concrete version actually used; None if unresolved
    requested_constraint: str | None
    files: list[str]
    ok: bool
    ast_by_file: dict  # relative_path -> ast dict
    errors: list[dict]
    compatible: bool
    resolution_method: str
    # Diagnostics mirroring CompilerRequirement + invocation verification.
    attempted_versions: list[str] = field(default_factory=list)
    reason: str = ""
    invoked_version: str | None = None  # version the compiler wrapper reports, when available


def _unwrap_compile_output(output: dict) -> tuple[dict, str | None]:
    """Split compile.js output into (solc_standard_output, invoked_version).

    compile.js wraps the solc Standard JSON Output as
    `{"solc_version": "...", "solc_output": {...}}` so the Python side can
    verify the compiler that actually ran. A bare solc output (no wrapper
    keys) is accepted for compatibility with older wrappers/tests, with
    invoked_version=None (verification simply not possible).
    """
    if isinstance(output, dict) and "solc_output" in output:
        wrapper_version = output.get("solc_version")
        return output["solc_output"] or {}, (
            wrapper_version.split("+", 1)[0] if isinstance(wrapper_version, str) else None
        )
    return output, None


def compile_group(
    group: CompileGroup,
    sources: dict[str, str],
    budget: InstallBudget | None = None,
    hint: str | None = None,
    remappings: list[str] | None = None,
) -> CompileResult:
    # Fail closed before ever shelling out: if any member's import didn't
    # resolve to a known source, this unit's Standard JSON `sources` map is
    # already incomplete and any AST solc produced from it (or the
    # generic "file not found" solc itself would report) would be less
    # trustworthy and less specific than reporting the exact missing
    # import(s) directly.
    if group.unresolved_imports:
        detail = "; ".join(
            f"{u['importing_file']}:{u['line']} imports {u['raw_path']!r} "
            f"(not found in the analyzed source set)"
            for u in group.unresolved_imports
        )
        return CompileResult(
            version=None,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{
                "type": "missing_import",
                "message": f"unresolved import(s) block compilation of this unit: {detail}",
                "severity": "error",
                "requested_constraint": group.constraint_expr,
                "resolution_method": "missing_import",
                "attempted_versions": [],
                "reason": detail,
            }],
            compatible=False,
            resolution_method="missing_import",
        )

    if group.member_constraints:
        # Import-graph-aware group: check every member's own pragma
        # independently (never string-concatenated -- see
        # resolve_compiler_for_constraints) so a version must satisfy all
        # of them simultaneously.
        constraint_exprs = [group.member_constraints.get(f, group.constraint_expr) for f in group.files]
        requirement = resolve_compiler_for_constraints(constraint_exprs, budget, hint=hint)
    else:
        requirement = resolve_compiler(group.constraint_expr, budget, hint=hint)

    if not requirement.compatible:
        message = (
            f"no compatible solc available for constraint "
            f"{group.constraint_expr!r} ({requirement.resolution_method})"
        )
        if requirement.reason:
            message += f": {requirement.reason}"
        if len(group.files) > 1 and len(set(group.member_constraints.values())) > 1:
            message += f"; member pragma constraints: {group.member_constraints}"
        return CompileResult(
            version=None,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{
                "type": "compiler_resolution_failed",
                "message": message,
                "severity": "error",
                "requested_constraint": group.constraint_expr,
                "resolution_method": requirement.resolution_method,
                "attempted_versions": list(requirement.attempted_versions),
                "reason": requirement.reason,
            }],
            compatible=False,
            resolution_method=requirement.resolution_method,
            attempted_versions=list(requirement.attempted_versions),
            reason=requirement.reason,
        )

    resolved_version = requirement.resolved_version
    node_modules = _node_modules_for(resolved_version)
    if node_modules is None:
        # Resolution said "use X", but no install location verifiably
        # contains X. Invoking whatever *is* installed would compile with
        # an unrequested compiler while reporting the requested one -- fail
        # closed instead.
        message = (
            f"resolved solc {resolved_version} could not be located with a "
            f"verified package version (directory names are not trusted)"
        )
        logger.error(message)
        return CompileResult(
            version=resolved_version,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{
                "type": "compiler_resolution_failed",
                "message": message,
                "severity": "error",
                "requested_constraint": group.constraint_expr,
                "resolution_method": "unresolved",
                "attempted_versions": list(requirement.attempted_versions),
                "reason": message,
            }],
            compatible=False,
            resolution_method="unresolved",
            attempted_versions=list(requirement.attempted_versions),
            reason=message,
        )

    std_input = {
        "language": "Solidity",
        "sources": {
            relpath: {"content": sources[relpath]}
            for relpath in group.files
            if relpath in sources
        },
        "settings": {
            "outputSelection": {"*": {"": ["ast"]}},
        },
    }
    if remappings:
        # solc matches an import string exactly against the sources-map
        # keys; bare dependency imports ("@openzeppelin/...") only resolve
        # when remapped onto the key the file is keyed under.
        std_input["settings"]["remappings"] = list(remappings)

    with _TempInput(std_input) as input_path:
        try:
            proc = subprocess.run(
                ["node", str(_COMPILE_JS), node_modules, input_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return CompileResult(
                version=resolved_version,
                requested_constraint=group.constraint_expr,
                files=list(group.files),
                ok=False,
                ast_by_file={},
                errors=[{"message": f"compiler invocation failed: {exc}", "severity": "error"}],
                compatible=True,
                resolution_method=requirement.resolution_method,
            )

    if proc.returncode != 0:
        return CompileResult(
            version=resolved_version,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{"message": proc.stderr.strip() or "unknown compiler error", "severity": "error"}],
            compatible=True,
            resolution_method=requirement.resolution_method,
        )

    try:
        raw_output = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return CompileResult(
            version=resolved_version,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{"message": f"could not parse compiler output: {exc}", "severity": "error"}],
            compatible=True,
            resolution_method=requirement.resolution_method,
        )

    output, invoked_version = _unwrap_compile_output(raw_output)

    # Verification: the compiler that actually ran must be the one we
    # resolved. A mismatch means the AST was produced by a different
    # compiler than reported -- never silently accept it.
    if invoked_version is not None and invoked_version != resolved_version:
        message = (
            f"compiler version mismatch: resolved {resolved_version} but the "
            f"invoked compiler reports {invoked_version}"
        )
        logger.error(message)
        return CompileResult(
            version=resolved_version,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{
                "type": "compiler_version_mismatch",
                "message": message,
                "severity": "error",
                "requested_constraint": group.constraint_expr,
                "resolution_method": "invocation_mismatch",
                "attempted_versions": list(requirement.attempted_versions),
                "reason": message,
            }],
            compatible=False,
            resolution_method="invocation_mismatch",
            invoked_version=invoked_version,
        )

    errors = output.get("errors", []) or []
    hard_errors = [e for e in errors if e.get("severity") == "error"]

    ast_by_file = {}
    for relpath, entry in (output.get("sources") or {}).items():
        if "ast" in entry:
            ast_by_file[relpath] = entry["ast"]

    return CompileResult(
        version=resolved_version,
        requested_constraint=group.constraint_expr,
        files=list(group.files),
        ok=len(hard_errors) == 0 and len(ast_by_file) > 0,
        ast_by_file=ast_by_file,
        errors=errors,
        compatible=True,
        resolution_method=requirement.resolution_method,
        invoked_version=invoked_version,
    )


def build_trust_summary(results: list[CompileResult]) -> dict:
    """Aggregate compile results into the hard trust gate downstream agents
    must check before treating Recon facts as complete.

    Any group whose constraint could not be resolved to a compatible
    compiler contributes a `compiler_resolution_failed` blocker and forces
    `analysis_status` to `"untrusted"`. This is intentionally not something
    a downstream consumer can quietly ignore alongside a partially-populated
    result -- an incompatible-compiler AST must not be mistaken for a
    complete one.

    Each blocker carries the full structured error: requested_constraint,
    files, resolution_method, attempted_versions, reason.
    """
    blockers = []
    for r in results:
        if not r.compatible:
            blockers.append({
                "type": (
                    r.resolution_method if r.resolution_method in ("missing_import", "invocation_mismatch")
                    else "compiler_resolution_failed"
                ),
                "files": list(r.files),
                "requested_constraint": r.requested_constraint,
                "resolution_method": r.resolution_method,
                "attempted_versions": list(r.attempted_versions),
                "reason": r.reason,
            })
    return {
        "analysis_status": "untrusted" if blockers else "complete",
        "trust_blockers": blockers,
    }


class _TempInput:
    """Writes a standard-json input dict to a temp file for the compiler subprocess."""

    def __init__(self, data: dict):
        self._data = data
        self._path: Path | None = None

    def __enter__(self) -> str:
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".json", prefix="recon-solc-input-")
        self._path = Path(path)
        with open(fd, "w") as f:
            json.dump(self._data, f)
        return str(self._path)

    def __exit__(self, *exc):
        if self._path and self._path.exists():
            self._path.unlink()
