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
_BUNDLED_VERSION = "0.8.24"

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_STRICT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# A single semver clause inside a pragma constraint expression, e.g.
# "^0.8.20", ">=0.8.20", "0.8.24". The operator is optional; a bare version
# is treated the same way solidity treats it -- like `^version`.
_CLAUSE_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+)\.(\d+)\.(\d+)")

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
_KNOWN_SOLC_MINOR_FAMILIES = {
    (0, 4), (0, 5), (0, 6), (0, 7), (0, 8),
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
            (m.group(1) or "^", (int(m.group(2)), int(m.group(3)), int(m.group(4))))
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


def group_sources_by_version(sources: dict[str, str]) -> list[CompileGroup]:
    """Build compiler-compatible compilation units from the *transitive
    import closure*, not from each file's pragma in isolation.

    Pipeline: resolve every `import` in `sources` -> build the import graph
    -> compute weakly-connected components (the transitive dependency
    closure -- if A imports B, directly or transitively, or through a
    cycle, they land in the same component no matter what either one's
    pragma says) -> merge components that need an identical, non-conflicting
    compiler constraint into one solc invocation, purely to cut down on the
    number of subprocess calls for otherwise-unrelated files.

    Compiling import-connected files in isolation (grouping by pragma
    alone) silently breaks: whichever file's group didn't happen to
    include its import partner's content produces a spurious "file not
    found" from solc, even though the file exists in the repo. Grouping by
    connected component fixes that structurally.

    Within one component, every member's pragma constraint must hold
    *simultaneously* -- see `resolve_compiler_for_constraints`, which
    checks each member's constraint independently rather than
    string-concatenating them (naively joining two constraints that each
    contain `||` would parse as the wrong logical expression). A component
    whose members' constraints can't be simultaneously satisfied gets its
    combined constraint_expr as an ` AND `-joined label for reporting, and
    `compile_group()` will report it as unresolved rather than guessing.

    A component with an import that couldn't be resolved to any file in
    `sources` at all (missing dependency) carries that in
    `unresolved_imports`; `compile_group()` fails closed on that
    information before ever invoking solc, since the compile is already
    known to be incomplete.
    """
    graph = import_resolution.build_import_graph(sources)
    components = import_resolution.connected_components(graph, files=sources.keys())
    all_cycles = import_resolution.find_cycles(graph)

    prelim: list[CompileGroup] = []
    for comp_files in components:
        comp_set = set(comp_files)
        member_constraints = {f: extract_pragma_constraint(sources[f]) for f in comp_files}
        distinct = sorted({c for c in member_constraints.values() if c is not None})
        combined_label = " AND ".join(distinct) if distinct else None

        unresolved = [
            {"importing_file": u.importing_file, "raw_path": u.raw_path, "line": u.line}
            for u in graph.unresolved
            if u.importing_file in comp_set
        ]
        cycles = [c for c in all_cycles if set(c) <= comp_set]

        prelim.append(CompileGroup(
            constraint_expr=combined_label,
            files=list(comp_files),
            member_constraints=member_constraints,
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


def _node_modules_for(version: str) -> str:
    if version == _BUNDLED_VERSION and (_BUNDLED_NODE_MODULES / "solc").exists():
        return str(_BUNDLED_NODE_MODULES)
    return str(_version_node_modules_dir(version))


def _cached_versions() -> list[str]:
    """Versions already installed on disk (this run or a previous one)."""
    if not _CACHE_DIR.exists():
        return []
    out = []
    for child in _CACHE_DIR.iterdir():
        if (
            child.is_dir()
            and _STRICT_SEMVER_RE.match(child.name)
            and (child / "node_modules" / "solc").exists()
        ):
            out.append(child.name)
    return out


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

    Returns True iff the install succeeded and solc is present afterwards.
    Does not touch the budget itself beyond the single reservation the
    caller already made via `try_reserve()`.
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
    return proc.returncode == 0 and (node_modules / "solc").exists()


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


# no_pragma_bundled_default: no pragma present -> bundled used by convention
# bundled_compatible:        bundled version itself satisfies the constraint
# cache_compatible:          a previously-installed cached version satisfies it
# installed_compatible:      a fresh npm install of a satisfying version succeeded
# unparseable_constraint:    pragma text didn't parse into any version clause
# unresolved:                no local/installable compiler satisfies the constraint
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
    "missing_import",
})


def _resolve_against_predicate(
    predicate: Callable[[str], bool], budget: InstallBudget
) -> tuple[str | None, str]:
    """Shared version-search logic: bundled -> cached -> npm-install, in
    that preference order, trying each concrete version against
    `predicate` ("would this version satisfy the compilation unit?").

    Returns `(resolved_version, resolution_method)`; `resolved_version` is
    None iff `resolution_method == "unresolved"`. Factored out of
    `resolve_compiler` so both the single-constraint and the multi-file,
    multi-constraint (`resolve_compiler_for_constraints`) resolution paths
    share one implementation of "prefer local, then install within
    budget" -- there is exactly one place that decides which concrete
    version gets used.
    """
    local_candidates = {_BUNDLED_VERSION, *_cached_versions()}
    matching_local = sorted((v for v in local_candidates if predicate(v)), key=_ver_tuple)
    if _BUNDLED_VERSION in matching_local:
        return _BUNDLED_VERSION, "bundled_compatible"
    if matching_local:
        return matching_local[-1], "cache_compatible"

    if budget.offline:
        logger.warning("no local solc satisfies the constraint and offline mode disallows npm; unresolved")
        return None, "unresolved"

    published = _query_npm_available_versions()
    if not published:
        return None, "unresolved"

    satisfying = sorted(
        (v for v in published if _is_installable_version(v) and predicate(v)),
        key=_ver_tuple,
        reverse=True,
    )
    if not satisfying:
        logger.warning("no published/allow-listed solc satisfies the constraint")
        return None, "unresolved"

    best = satisfying[0]
    if not budget.try_reserve():
        logger.warning(
            "solc@%s would satisfy the constraint but the install budget (%s) is exhausted; unresolved",
            best, budget.max_installs,
        )
        return None, "unresolved"

    if _install_version(best, budget):
        return best, "installed_compatible"

    logger.warning("npm install of solc@%s failed; unresolved", best)
    return None, "unresolved"


def resolve_compiler(
    constraint_expr: str | None, budget: InstallBudget | None = None
) -> CompilerRequirement:
    """Resolve a pragma constraint expression to a concrete, *compatible*
    solc version -- or report that none is available.

    This never returns `compatible=True` for a version that doesn't
    actually satisfy the constraint. There is deliberately no "fall back to
    the bundled compiler anyway" path here: an incompatible compiler
    producing an AST that looks like normal output is exactly the failure
    mode this function exists to prevent.
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
        )

    version, method = _resolve_against_predicate(
        lambda v: version_satisfies(v, constraint_expr), budget
    )
    return CompilerRequirement(constraint_expr, version, method, version is not None)


def resolve_compiler_for_constraints(
    constraint_exprs: list[str | None], budget: InstallBudget | None = None
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
        )

    def predicate(v: str) -> bool:
        return all(version_satisfies(v, e) for e in present)

    version, method = _resolve_against_predicate(predicate, budget)
    return CompilerRequirement(label, version, method, version is not None)


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


def compile_group(
    group: CompileGroup, sources: dict[str, str], budget: InstallBudget | None = None
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
        requirement = resolve_compiler_for_constraints(constraint_exprs, budget)
    else:
        requirement = resolve_compiler(group.constraint_expr, budget)

    if not requirement.compatible:
        message = (
            f"no compatible solc available for constraint "
            f"{group.constraint_expr!r} ({requirement.resolution_method})"
        )
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
            }],
            compatible=False,
            resolution_method=requirement.resolution_method,
        )

    resolved_version = requirement.resolved_version
    node_modules = _node_modules_for(resolved_version)

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
        output = json.loads(proc.stdout)
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
    """
    blockers = []
    for r in results:
        if not r.compatible:
            blockers.append({
                "type": r.resolution_method if r.resolution_method == "missing_import" else "compiler_resolution_failed",
                "files": list(r.files),
                "requested_constraint": r.requested_constraint,
                "resolution_method": r.resolution_method,
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
