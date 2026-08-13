"""solc acquisition and invocation.

The environment this analyzer runs in can only reach the npm registry (not
the solc binary release servers), so we use `solc-js` (the pure JS/WASM build
of the Solidity compiler, published to npm as `solc`) rather than a native
solc binary or `py-solc-x`. This is a project-agnostic, network-appropriate
substitute for whatever "existing compiler infrastructure" a given repo might
normally use.

This module is explicitly a compiler-invocation shim. It performs no AST
interpretation.
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
_VERSION_TOKEN_RE = re.compile(r"\d+\.\d+\.\d+")
_STRICT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Hard cap on how many *distinct* non-bundled solc versions a single run is
# allowed to trigger `npm install` for. A repo can contain arbitrarily many
# `.sol` files each declaring a different pragma version; without a cap this
# becomes an attacker-controlled loop of subprocess/network calls (DoS via
# untrusted repo content). Any group beyond the cap silently falls back to
# the bundled compiler instead of triggering another install.
_MAX_INSTALLS_PER_RUN = 5

# Known-good published solc-js releases on npm (major.minor families). This
# is an allow-list gate, not just a syntactic regex check: a version string
# extracted from untrusted source content must fall within a family we know
# npm actually publishes before we ever shell out to `npm install`. This
# blocks pragma-crafted version strings that are syntactically valid semver
# but nonsensical/non-existent (which would otherwise still cost a full
# npm-install network round trip before failing).
_KNOWN_SOLC_MINOR_FAMILIES = {
    (0, 4), (0, 5), (0, 6), (0, 7), (0, 8),
}


def _is_installable_version(version: str) -> bool:
    """Allow-list check: strict semver AND within a known-published family."""
    if not _STRICT_SEMVER_RE.match(version):
        return False
    major, minor, _patch = (int(p) for p in version.split("."))
    return (major, minor) in _KNOWN_SOLC_MINOR_FAMILIES


@dataclass
class CompileGroup:
    version: str
    files: list[str] = field(default_factory=list)


@dataclass
class CompileResult:
    version: str
    requested_version: str
    files: list[str]
    ok: bool
    ast_by_file: dict  # relative_path -> ast dict
    errors: list[dict]
    used_fallback: bool


def extract_requested_version(source_text: str) -> str | None:
    """Best-effort extraction of a single representative version token from a
    file's `pragma solidity ...;` statement(s). This is a heuristic used only
    to pick which compiler to run — it is not emitted as a Recon fact about
    program behavior.
    """
    m = _PRAGMA_RE.search(source_text)
    if not m:
        return None
    expr = m.group(1)
    tokens = _VERSION_TOKEN_RE.findall(expr)
    if not tokens:
        return None
    return tokens[0]


def group_sources_by_version(sources: dict[str, str]) -> list[CompileGroup]:
    """Group files by requested compiler version so each solc invocation gets
    a self-consistent set. Files with no resolvable pragma fall back to the
    bundled default version.
    """
    groups: dict[str, CompileGroup] = {}
    for relpath, content in sources.items():
        version = extract_requested_version(content) or _BUNDLED_VERSION
        groups.setdefault(version, CompileGroup(version=version)).files.append(relpath)
    return [groups[k] for k in sorted(groups)]


def _version_node_modules_dir(version: str) -> Path:
    return _CACHE_DIR / version / "node_modules"


@dataclass
class InstallBudget:
    """Tracks/limits `npm install` calls for a single pipeline run.

    Untrusted repo content (pragma statements) chooses which solc versions
    get requested, so the number of *new* npm-install subprocesses per run
    must be bounded regardless of how many distinct versions a repo
    declares. Versions already cached on disk from a previous run (or
    earlier in this run) don't count against the budget — they're a cache
    hit, not a new install. Set `offline=True` to disallow npm installs
    entirely (every non-cached version falls back to the bundled compiler).
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


def ensure_solc_available(version: str, budget: InstallBudget | None = None) -> tuple[str, bool]:
    """Ensure a solc-js install exists for `version`.

    Returns (node_modules_path_to_use, used_fallback). Falls back to the
    bundled default version if the requested version cannot be installed
    (e.g. not published, no network path to the registry, it fails the
    known-version allow-list, or the per-run install budget is exhausted).
    """
    if budget is None:
        budget = InstallBudget()

    if version == _BUNDLED_VERSION and (_BUNDLED_NODE_MODULES / "solc").exists():
        return str(_BUNDLED_NODE_MODULES), False

    target_dir = _CACHE_DIR / version
    node_modules = _version_node_modules_dir(version)
    if (node_modules / "solc").exists():
        # Already installed (this run or a previous one) -- cache hit, no
        # npm invocation and no budget consumed.
        return str(node_modules), False

    if not _is_installable_version(version):
        logger.warning(
            "solc@%s is not a recognized/installable version; falling back to bundled %s",
            version, _BUNDLED_VERSION,
        )
        return str(_BUNDLED_NODE_MODULES), True

    if not budget.try_reserve():
        reason = "offline mode" if budget.offline else f"install budget ({budget.max_installs}) exhausted"
        logger.warning(
            "skipping npm install of solc@%s (%s); falling back to bundled %s",
            version, reason, _BUNDLED_VERSION,
        )
        return str(_BUNDLED_NODE_MODULES), True

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
        proc = None

    if proc is not None and proc.returncode == 0 and (node_modules / "solc").exists():
        return str(node_modules), False

    logger.warning(
        "could not obtain solc@%s (falling back to bundled %s)", version, _BUNDLED_VERSION
    )
    return str(_BUNDLED_NODE_MODULES), True


def compile_group(
    group: CompileGroup, sources: dict[str, str], budget: InstallBudget | None = None
) -> CompileResult:
    node_modules, used_fallback = ensure_solc_available(group.version, budget)
    resolved_version = _BUNDLED_VERSION if used_fallback else group.version

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
                requested_version=group.version,
                files=list(group.files),
                ok=False,
                ast_by_file={},
                errors=[{"message": f"compiler invocation failed: {exc}", "severity": "error"}],
                used_fallback=used_fallback,
            )

    if proc.returncode != 0:
        return CompileResult(
            version=resolved_version,
            requested_version=group.version,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{"message": proc.stderr.strip() or "unknown compiler error", "severity": "error"}],
            used_fallback=used_fallback,
        )

    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return CompileResult(
            version=resolved_version,
            requested_version=group.version,
            files=list(group.files),
            ok=False,
            ast_by_file={},
            errors=[{"message": f"could not parse compiler output: {exc}", "severity": "error"}],
            used_fallback=used_fallback,
        )

    errors = output.get("errors", []) or []
    hard_errors = [e for e in errors if e.get("severity") == "error"]

    ast_by_file = {}
    for relpath, entry in (output.get("sources") or {}).items():
        if "ast" in entry:
            ast_by_file[relpath] = entry["ast"]

    return CompileResult(
        version=resolved_version,
        requested_version=group.version,
        files=list(group.files),
        ok=len(hard_errors) == 0 and len(ast_by_file) > 0,
        ast_by_file=ast_by_file,
        errors=errors,
        used_fallback=used_fallback,
    )


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
