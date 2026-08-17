"""Orchestrates the full recon pipeline (section 33 architecture).

Source Discovery -> Parsing/AST -> Symbol/Type Index -> Contract & Function
Inventory -> Call Analysis -> State Analysis -> Input-Origin Analysis ->
Data-Flow Analysis -> External Interaction Analysis -> Asset/Value Flow
Analysis -> Capability Extraction -> Evidence/Provenance -> Graph
Construction -> Schema Validation -> Recon Output.

(Call/State/Input-Origin/External/Asset analyses are fused into a single
per-function AST walk in expr_analysis.py for efficiency; they remain
independent *stages* in terms of what facts they emit.)

Per-function/per-modifier analysis below is individually wrapped in
``try/except Exception`` so that one bad function does not abort the whole
run. That, by itself, has no ceiling: a large or adversarial repo could keep
the process alive indefinitely (or spin through an unbounded number of
individually-caught exceptions) with no way to stop other than waiting it
out. Two coarse guards sit around those try/except blocks to bound the
*whole* run rather than just each step:

* an overall wall-clock deadline (``timeout_seconds``), checked at each
  file/group/function/modifier boundary; and
* a circuit breaker that aborts the run if too many analyses in a row raise
  an exception, since that indicates a systemic problem rather than
  isolated bad input.

Either one stops remaining work, writes out whatever was already produced
as a partial result, and records the reason via ``ctx.warn`` and
``analysis_status`` in metadata.json instead of letting the process hang or
burn through the whole repo for no benefit.
"""

from __future__ import annotations

import logging
import os
import time

from . import (
    ast_utils,
    capability,
    external_deps,
    expr_analysis,
    inventory,
    inventory_facts,
    output,
    relationships,
    solc_manager,
)
from .context import ProjectContext

# Per-file and total-repo size guards applied before any file is opened for
# reading. Untrusted repo content otherwise controls how much is read into
# memory (each file is held as: raw content str, ctx.files entry, encoded
# ctx.file_bytes entry, plus a LineIndex over it) with no upper bound, which
# is a memory-exhaustion vector for a repo containing very large and/or very
# many `.sol` files. Files over the per-file cap are skipped (warned, not
# analyzed); once the running total exceeds the repo cap, remaining
# discovered files are skipped the same way rather than read.
_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024        # 5 MB per file
_MAX_TOTAL_SOURCE_BYTES = 200 * 1024 * 1024   # 200 MB across the whole repo

# Overall pipeline guards (see module docstring). Both are cooperative: they
# are checked between iterations rather than forcibly interrupting work in
# progress, so a single slow step (e.g. a solc subprocess, which has its own
# timeout in solc_manager) still has to return before the check can fire.
_DEFAULT_TIMEOUT_SECONDS = 30 * 60          # overall wall-clock budget for run()
_MAX_CONSECUTIVE_ANALYSIS_FAILURES = 50     # circuit breaker on repeated exceptions

logger = logging.getLogger("recon.pipeline")


class _PipelineTimeout(Exception):
    """Internal signal: the overall wall-clock budget for run() was exhausted."""


class _CircuitBreakerTripped(Exception):
    """Internal signal: too many consecutive per-function/modifier analyses
    failed in a row, indicating a systemic problem rather than isolated bad
    input in one function."""


def run(
    repo_root: str,
    output_dir: str,
    include_lib: bool = False,
    offline: bool = False,
    max_solc_installs: int | None = None,
    timeout_seconds: float | None = _DEFAULT_TIMEOUT_SECONDS,
) -> ProjectContext:
    from .discovery import discover_sources

    run_start = time.monotonic()
    deadline = (run_start + timeout_seconds) if timeout_seconds and timeout_seconds > 0 else None
    phase_durations: dict[str, float] = {}
    aborted_reason: str | None = None  # "timed_out" | "circuit_breaker_tripped" | None

    repo_root = os.path.abspath(repo_root)
    discovered = discover_sources(repo_root, include_lib=include_lib)

    os.makedirs(output_dir, exist_ok=True)
    snippets_dir = os.path.join(output_dir, "snippets")
    os.makedirs(snippets_dir, exist_ok=True)

    ctx = ProjectContext(repo_root=repo_root, snippets_dir=snippets_dir)

    def _check_deadline() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise _PipelineTimeout()

    def _record_phase(name: str, t0: float) -> None:
        duration = round(time.monotonic() - t0, 3)
        phase_durations[name] = duration
        ctx.warn("phase duration", phase=name, duration_seconds=duration)

    files_failed: list[str] = []
    files_partial: list[str] = []
    files_analyzed: list[str] = []
    compiler_runs = []
    errors_out = []
    file_diagnostics: dict[str, dict] = {}  # per-file failure reasons

    sources: dict[str, str] = {}
    total_bytes_read = 0
    total_cap_hit = False
    per_file_ast: dict[str, tuple[str, dict]] = {}  # relpath -> (group_version, source_unit)
    # Defaults so the partial-output paths (timeout / circuit breaker before
    # these phases ran) can still assemble run_meta below.
    expansion = external_deps.ExpansionResult(sources={})
    compiler_hints: dict = {"by_file": {}, "primary": None, "conflicting": False}

    try:
        # ---- Discovery / read ---------------------------------------------
        t_phase = time.monotonic()
        for d in discovered:
            _check_deadline()
            try:
                file_size = os.path.getsize(d.absolute_path)
            except OSError as exc:
                files_failed.append(d.relative_path)
                ctx.warn(f"could not stat file: {exc}", file=d.relative_path)
                continue

            if file_size > _MAX_FILE_SIZE_BYTES:
                files_failed.append(d.relative_path)
                ctx.warn(
                    "file exceeds per-file size limit; skipped",
                    file=d.relative_path, size_bytes=file_size, limit_bytes=_MAX_FILE_SIZE_BYTES,
                )
                continue

            if total_bytes_read + file_size > _MAX_TOTAL_SOURCE_BYTES:
                if not total_cap_hit:
                    total_cap_hit = True
                    ctx.warn(
                        "total repo source size limit reached; remaining files skipped",
                        limit_bytes=_MAX_TOTAL_SOURCE_BYTES,
                    )
                files_failed.append(d.relative_path)
                continue

            try:
                with open(d.absolute_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError as exc:
                files_failed.append(d.relative_path)
                ctx.warn(f"could not read file: {exc}", file=d.relative_path)
                continue
            total_bytes_read += file_size
            sources[d.relative_path] = content
            ctx.files[d.relative_path] = content
            content_bytes = content.encode("utf-8")
            ctx.file_bytes[d.relative_path] = content_bytes
            ctx.line_indexes[d.relative_path] = ast_utils.LineIndex(content_bytes)

        if not sources:
            ctx.warn("no Solidity source files discovered under repo_root", repo_root=repo_root)
        _record_phase("file_discovery_and_reading", t_phase)

        # ---- External dependency expansion -----------------------------------
        # Discovery intentionally skips dependency directories, but solc
        # needs the full import closure in one sources map. Pull in the
        # on-disk files referenced by unresolved imports (node_modules
        # packages, remapped paths, files in skipped dirs), strictly inside
        # the repo boundary and under the same size caps.
        t_phase = time.monotonic()
        expansion = external_deps.expand_sources(sources, repo_root)
        for note in expansion.notes:
            ctx.warn(f"dependency expansion: {note}")
        for relpath in expansion.added:
            content = expansion.sources[relpath]
            sources[relpath] = content
            ctx.files[relpath] = content
            content_bytes = content.encode("utf-8")
            ctx.file_bytes[relpath] = content_bytes
            ctx.line_indexes[relpath] = ast_utils.LineIndex(content_bytes)
        if expansion.prefix_aliases:
            ctx.warn(
                "import remappings applied",
                remappings={p: t for p, t in sorted(expansion.prefix_aliases.items())},
            )
        if expansion.added:
            ctx.warn(
                "dependency sources added to compilation universe",
                count=len(expansion.added),
                files=expansion.added,
            )
        _record_phase("dependency_expansion", t_phase)

        # ---- Build metadata compiler hints (diagnostics, never override) ----
        compiler_hints = solc_manager.extract_compiler_hints(repo_root)
        if compiler_hints["by_file"]:
            ctx.warn("build metadata compiler hints found", **compiler_hints["by_file"])
        if compiler_hints["conflicting"]:
            ctx.warn(
                "build metadata hints conflict with each other; no hint used",
                hints=compiler_hints["by_file"],
            )

        # ---- Compilation ----------------------------------------------------
        t_phase = time.monotonic()
        groups = solc_manager.group_sources_by_version(
            sources, prefix_aliases=expansion.prefix_aliases
        )

        install_budget = solc_manager.InstallBudget(offline=offline, **(
            {"max_installs": max_solc_installs} if max_solc_installs is not None else {}
        ))

        hint = compiler_hints["primary"]
        for group in groups:
            _check_deadline()

            # A hint that contradicts this unit's pragma constraints is
            # reported, never applied: source pragmas are authoritative.
            if hint is not None and group.constraint_expr is not None:
                members_sat = [
                    solc_manager.version_satisfies(hint, c)
                    for c in (group.member_constraints or {}).values()
                    if c is not None
                ]
                if members_sat and not all(members_sat):
                    ctx.warn(
                        "build metadata hint conflicts with unit pragma constraints; pragma wins",
                        hint=hint,
                        constraint=group.constraint_expr,
                        files=sorted(group.files),
                    )

            result = solc_manager.compile_group(
                group, sources, install_budget,
                hint=hint, remappings=expansion.solc_remappings,
            )
            compiler_runs.append(
                {
                    "requested_version": result.requested_constraint,
                    "resolved_version": result.version,
                    "used_fallback": result.resolution_method in ("cache_compatible", "installed_compatible"),
                    "files": sorted(result.files),
                    "ok": result.ok,
                    "error_count": len([e for e in result.errors if e.get("severity") == "error"]),
                    "resolution_method": result.resolution_method,
                    "invoked_version": result.invoked_version,
                    "version_verified": (
                        result.invoked_version is not None
                        and result.invoked_version == result.version
                    ),
                    "attempted_versions": list(result.attempted_versions),
                    "reason": result.reason,
                    "hint": hint,
                }
            )
            if result.resolution_method in ("cache_compatible", "installed_compatible"):
                ctx.warn(
                    f"constraint {result.requested_constraint} not satisfied by the bundled "
                    f"compiler; resolved compatible solc {result.version} via "
                    f"{result.resolution_method}",
                    files=sorted(result.files),
                )
            for e in result.errors:
                errors_out.append({"severity": e.get("severity"), "message": e.get("message") or e.get("formattedMessage")})

            succeeded_files = set(result.ast_by_file.keys())
            for relpath in result.files:
                if relpath in succeeded_files:
                    # First successful AST for this file wins; later runs that
                    # also compile it (due to overlapping subgroup membership)
                    # are silently skipped to prevent duplicate inventory entries
                    # and graph edge collisions.
                    if relpath not in per_file_ast:
                        per_file_ast[relpath] = (result.version, result.ast_by_file[relpath])
                        files_analyzed.append(relpath)
                        # Clear any earlier failure diagnostic for this file
                        file_diagnostics.pop(relpath, None)
                    # else: already have AST from an earlier compiler run → skip
                elif relpath not in per_file_ast:
                    # Only record failure if the file has not already succeeded
                    # in a previous compiler run (overlap subgroups scenario)
                    files_failed.append(relpath)
                    pragma = solc_manager.extract_pragma_constraint(sources.get(relpath, ""))
                    diag: dict = {
                        "pragma": pragma,
                        "requested_constraint": result.requested_constraint,
                        "resolved_compiler": result.version,
                        "resolution_method": result.resolution_method,
                        "compiler_compatible": result.compatible,
                        "group_size": len(result.files),
                        "has_ast": False,
                    }
                    if not result.compatible:
                        diag["failure_reason"] = (
                            f"compiler resolution failed: {result.resolution_method}"
                        )
                        if result.reason:
                            diag["resolution_failure_detail"] = result.reason[:300]
                    else:
                        # Extract per-file solc error messages when available
                        file_errors = [
                            e for e in result.errors
                            if e.get("severity") == "error"
                            and (relpath in str(e.get("message", ""))
                                 or relpath in str(e.get("formattedMessage", ""))
                                 or not e.get("sourceLocation"))
                        ]
                        if file_errors:
                            diag["failure_reason"] = "compiler error"
                            diag["solc_errors"] = [
                                (e.get("formattedMessage") or e.get("message") or "")[:300]
                                for e in file_errors[:5]
                            ]
                        else:
                            diag["failure_reason"] = (
                                "no AST produced (likely a transitive import error — "
                                "see group-level errors in compiler.runs)"
                            )
                    file_diagnostics[relpath] = diag
                    ctx.warn(
                        "file failed to produce AST",
                        file=relpath,
                        pragma=pragma,
                        compiler_version=result.version,
                        resolution_method=result.resolution_method,
                    )
        _record_phase("compilation", t_phase)

        # ---- Symbol / contract / function inventory --------------------------
        t_phase = time.monotonic()
        per_file_decl_index: dict[str, dict] = {}
        for relpath, (group_version, source_unit) in sorted(per_file_ast.items()):
            _check_deadline()
            contracts, decl_idx = inventory.extract_contracts(relpath, group_version, source_unit)
            for cu in contracts:
                ctx.contracts[cu.key] = cu
            per_file_decl_index[relpath] = decl_idx
            for local_id, info in decl_idx.items():
                ctx.decl_index[(group_version, local_id)] = info

        for cu in ctx.contracts.values():
            ctx.contract_by_group_ast_id[(cu.group, cu.ast_id)] = cu.key
            for fu in cu.functions:
                ctx.function_by_key[fu.key] = fu
            for mu in cu.modifiers:
                ctx.modifier_by_key[mu.key] = mu
            for ev in cu.events:
                ctx.event_by_key[ev.key] = ev

        inventory_facts.resolve_bases(ctx)
        inventory_facts.emit_inventory_facts(ctx)
        _record_phase("inventory", t_phase)

        # ---- Per-function / per-modifier expression-level analysis ------------
        #
        # Modifiers are analyzed with the same expression-level pass as
        # functions: a `require(msg.sender == owner)` written inside a modifier
        # body is just as much an authorization_check as one written inline in a
        # function. See recon/relationships.py for how this feeds the
        # access-controlled / role-privilege layer.

        t_phase = time.monotonic()
        consecutive_failures = 0
        for cu in sorted(ctx.contracts.values(), key=lambda c: c.key):
            for mu in sorted(cu.modifiers, key=lambda m: m.key):
                _check_deadline()
                try:
                    expr_analysis.analyze_modifier(ctx, cu, mu)
                    consecutive_failures = 0
                except Exception as exc:
                    logger.exception("analysis failed for modifier %s", mu.key)
                    ctx.warn(f"modifier analysis failed: {exc}", modifier=mu.key, file=mu.file)
                    files_partial.append(mu.file)
                    consecutive_failures += 1
                    if consecutive_failures >= _MAX_CONSECUTIVE_ANALYSIS_FAILURES:
                        raise _CircuitBreakerTripped(
                            f"{consecutive_failures} consecutive modifier analysis failures"
                        ) from exc
        _record_phase("modifier_analysis", t_phase)

        t_phase = time.monotonic()
        consecutive_failures = 0
        for cu in sorted(ctx.contracts.values(), key=lambda c: c.key):
            for fu in sorted(cu.functions, key=lambda f: f.key):
                _check_deadline()
                try:
                    expr_analysis.analyze_function(ctx, cu, fu)
                    consecutive_failures = 0
                except Exception as exc:  # a single function must not abort the run
                    logger.exception("analysis failed for function %s", fu.key)
                    ctx.warn(f"function analysis failed: {exc}", function=fu.key, file=fu.file)
                    files_partial.append(fu.file)
                    consecutive_failures += 1
                    if consecutive_failures >= _MAX_CONSECUTIVE_ANALYSIS_FAILURES:
                        raise _CircuitBreakerTripped(
                            f"{consecutive_failures} consecutive function analysis failures"
                        ) from exc
        _record_phase("function_analysis", t_phase)

        t_phase = time.monotonic()
        capability.derive_capabilities(ctx)
        relationships.derive_role_privilege_facts(ctx)
        relationships.derive_relationship_chains(ctx)
        relationships.derive_frontrun_vulnerability_facts(ctx)
        _record_phase("capability_and_relationship_derivation", t_phase)

    except _PipelineTimeout:
        aborted_reason = "timed_out"
        elapsed = round(time.monotonic() - run_start, 3)
        ctx.warn(
            "global wall-clock timeout reached; remaining work skipped, partial output written",
            timeout_seconds=timeout_seconds,
            elapsed_seconds=elapsed,
        )
    except _CircuitBreakerTripped as exc:
        aborted_reason = "circuit_breaker_tripped"
        ctx.warn(
            "circuit breaker tripped: too many consecutive analysis failures; "
            "remaining work skipped, partial output written",
            reason=str(exc),
            max_consecutive_failures=_MAX_CONSECUTIVE_ANALYSIS_FAILURES,
        )

    files_analyzed = sorted(set(files_analyzed) - set(files_partial))
    files_partial = sorted(set(files_partial))
    files_failed = sorted(set(files_failed))

    all_files = {d.relative_path for d in discovered}
    accounted = set(files_analyzed) | set(files_partial) | set(files_failed)
    for missing in sorted(all_files - accounted):
        files_failed.append(missing)
    files_failed = sorted(set(files_failed))

    if aborted_reason is not None:
        analysis_status = aborted_reason
    elif files_failed and (files_analyzed or files_partial):
        analysis_status = "partial"
    elif files_failed and not (files_analyzed or files_partial):
        analysis_status = "failed"
    else:
        analysis_status = "complete"

    total_duration = round(time.monotonic() - run_start, 3)
    phase_durations["total"] = total_duration
    ctx.warn("phase duration", phase="total", duration_seconds=total_duration)

    # Compute coverage metrics
    files_discovered_count = len(discovered)
    files_with_ast = len(files_analyzed)
    coverage_percent = round(100.0 * files_with_ast / files_discovered_count, 1) if files_discovered_count > 0 else 0.0

    run_meta = {
        "source_root": repo_root,
        "files_analyzed": files_analyzed,
        "files_partially_analyzed": files_partial,
        "files_failed": files_failed,
        "file_diagnostics": file_diagnostics,
        "coverage": {
            "files_discovered": files_discovered_count,
            "files_with_ast": files_with_ast,
            "files_failed": len(files_failed),
            "files_partial": len(files_partial),
            "coverage_percent": coverage_percent,
        },
        "dependency_files_added": expansion.added,
        "import_prefix_aliases": expansion.prefix_aliases,
        "build_metadata_hints": compiler_hints,
        "compiler": {
            "engine": "solc-js (npm)",
            "bundled_version": solc_manager._BUNDLED_VERSION,
            "runs": compiler_runs,
        },
        "analysis_status": analysis_status,
        "errors": errors_out,
        "phase_durations_seconds": phase_durations,
        "timed_out": aborted_reason == "timed_out",
    }

    output.write_all(ctx, output_dir, run_meta)
    return ctx
