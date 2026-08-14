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


def group_sources_by_version(sources: dict[str, str]) -> list[CompileGroup]:
    """Group files by their full pragma constraint expression so each solc
    invocation gets a self-consistent set. Files with no resolvable pragma
    form their own group (constraint_expr=None), which resolves to the
    bundled default compiler -- there's no explicit requirement to violate.

    Grouping is by the *whole* constraint expression, not a single version
    token: two files declaring `^0.8.20` and `>=0.8.20 <0.9.0` are
    semantically different constraints (even though they happen to share a
    leading token) and must not be silently merged into one compile unit.
    """
    groups: dict[str, CompileGroup] = {}
    for relpath, content in sources.items():
        constraint_expr = extract_pragma_constraint(content)
        key = constraint_expr if constraint_expr is not None else "\0__no_pragma__"
        groups.setdefault(key, CompileGroup(constraint_expr=constraint_expr)).files.append(relpath)
    return [groups[k] for k in sorted(groups)]


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
RESOLUTION_METHODS = frozenset({
    "no_pragma_bundled_default",
    "bundled_compatible",
    "cache_compatible",
    "installed_compatible",
    "unparseable_constraint",
    "unresolved",
})


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

    # 1. Prefer what's already on disk -- no network, no subprocess.
    local_candidates = {_BUNDLED_VERSION, *_cached_versions()}
    matching_local = sorted(
        (v for v in local_candidates if version_satisfies(v, constraint_expr)),
        key=_ver_tuple,
    )
    if _BUNDLED_VERSION in matching_local:
        return CompilerRequirement(constraint_expr, _BUNDLED_VERSION, "bundled_compatible", True)
    if matching_local:
        return CompilerRequirement(constraint_expr, matching_local[-1], "cache_compatible", True)

    # 2. Nothing local satisfies it -- see if npm has a satisfying,
    #    allow-listed version worth installing.
    if budget.offline:
        logger.warning(
            "no local solc satisfies %r and offline mode disallows npm; unresolved",
            constraint_expr,
        )
        return CompilerRequirement(constraint_expr, None, "unresolved", False)

    published = _query_npm_available_versions()
    if not published:
        return CompilerRequirement(constraint_expr, None, "unresolved", False)

    satisfying = sorted(
        (
            v for v in published
            if _is_installable_version(v) and version_satisfies(v, constraint_expr)
        ),
        key=_ver_tuple,
        reverse=True,
    )
    if not satisfying:
        logger.warning("no published/allow-listed solc satisfies %r", constraint_expr)
        return CompilerRequirement(constraint_expr, None, "unresolved", False)

    best = satisfying[0]
    if not budget.try_reserve():
        logger.warning(
            "solc@%s would satisfy %r but the install budget (%s) is exhausted; unresolved",
            best, constraint_expr, budget.max_installs,
        )
        return CompilerRequirement(constraint_expr, None, "unresolved", False)

    if _install_version(best, budget):
        return CompilerRequirement(constraint_expr, best, "installed_compatible", True)

    logger.warning("npm install of solc@%s failed; %r unresolved", best, constraint_expr)
    return CompilerRequirement(constraint_expr, None, "unresolved", False)


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
    requirement = resolve_compiler(group.constraint_expr, budget)

    if not requirement.compatible:
        return CompileResult(
            version=None,
            requested_constraint=group.constraint_expr,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{
                "type": "compiler_resolution_failed",
                "message": (
                    f"no compatible solc available for constraint "
                    f"{group.constraint_expr!r} ({requirement.resolution_method})"
                ),
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
                "type": "compiler_resolution_failed",
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
