"""Orchestrates the full recon pipeline (section 33 architecture).

Source Discovery -> Parsing/AST -> Symbol/Type Index -> Contract & Function
Inventory -> Call Analysis -> State Analysis -> Input-Origin Analysis ->
Data-Flow Analysis -> External Interaction Analysis -> Asset/Value Flow
Analysis -> Capability Extraction -> Evidence/Provenance -> Graph
Construction -> Schema Validation -> Recon Output.

(Call/State/Input-Origin/External/Asset analyses are fused into a single
per-function AST walk in expr_analysis.py for efficiency; they remain
independent *stages* in terms of what facts they emit.)
"""

from __future__ import annotations

import logging
import os

from . import ast_utils, capability, expr_analysis, inventory, inventory_facts, output, relationships, solc_manager
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

logger = logging.getLogger("recon.pipeline")


def run(
    repo_root: str,
    output_dir: str,
    include_lib: bool = False,
    offline: bool = False,
    max_solc_installs: int | None = None,
) -> ProjectContext:
    from .discovery import discover_sources

    repo_root = os.path.abspath(repo_root)
    discovered = discover_sources(repo_root, include_lib=include_lib)

    os.makedirs(output_dir, exist_ok=True)
    snippets_dir = os.path.join(output_dir, "snippets")
    os.makedirs(snippets_dir, exist_ok=True)

    ctx = ProjectContext(repo_root=repo_root, snippets_dir=snippets_dir)

    files_failed: list[str] = []
    files_partial: list[str] = []
    files_analyzed: list[str] = []
    compiler_runs = []
    errors_out = []

    sources: dict[str, str] = {}
    total_bytes_read = 0
    total_cap_hit = False
    for d in discovered:
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

    groups = solc_manager.group_sources_by_version(sources)
    per_file_ast: dict[str, tuple[str, dict]] = {}  # relpath -> (group_version, source_unit)

    install_budget = solc_manager.InstallBudget(offline=offline, **(
        {"max_installs": max_solc_installs} if max_solc_installs is not None else {}
    ))

    for group in groups:
        result = solc_manager.compile_group(group, sources, install_budget)
        compiler_runs.append(
            {
                "requested_version": result.requested_version,
                "resolved_version": result.version,
                "used_fallback": result.used_fallback,
                "files": sorted(result.files),
                "ok": result.ok,
                "error_count": len([e for e in result.errors if e.get("severity") == "error"]),
            }
        )
        if result.used_fallback:
            ctx.warn(
                f"solc {result.requested_version} unavailable; used fallback {result.version}",
                files=sorted(result.files),
            )
        for e in result.errors:
            errors_out.append({"severity": e.get("severity"), "message": e.get("message") or e.get("formattedMessage")})

        succeeded_files = set(result.ast_by_file.keys())
        for relpath in result.files:
            if relpath in succeeded_files:
                per_file_ast[relpath] = (result.version, result.ast_by_file[relpath])
                files_analyzed.append(relpath)
            else:
                files_failed.append(relpath)
                ctx.warn(f"file failed to produce AST", file=relpath, compiler_version=result.version)

    # ---- Symbol / contract / function inventory --------------------------

    per_file_decl_index: dict[str, dict] = {}
    for relpath, (group_version, source_unit) in sorted(per_file_ast.items()):
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

    # ---- Per-function / per-modifier expression-level analysis ------------
    #
    # Modifiers are analyzed with the same expression-level pass as
    # functions: a `require(msg.sender == owner)` written inside a modifier
    # body is just as much an authorization_check as one written inline in a
    # function. See recon/relationships.py for how this feeds the
    # access-controlled / role-privilege layer.

    for cu in sorted(ctx.contracts.values(), key=lambda c: c.key):
        for mu in sorted(cu.modifiers, key=lambda m: m.key):
            try:
                expr_analysis.analyze_modifier(ctx, cu, mu)
            except Exception as exc:
                logger.exception("analysis failed for modifier %s", mu.key)
                ctx.warn(f"modifier analysis failed: {exc}", modifier=mu.key, file=mu.file)
                files_partial.append(mu.file)

    for cu in sorted(ctx.contracts.values(), key=lambda c: c.key):
        for fu in sorted(cu.functions, key=lambda f: f.key):
            try:
                expr_analysis.analyze_function(ctx, cu, fu)
            except Exception as exc:  # a single function must not abort the run
                logger.exception("analysis failed for function %s", fu.key)
                ctx.warn(f"function analysis failed: {exc}", function=fu.key, file=fu.file)
                files_partial.append(fu.file)

    capability.derive_capabilities(ctx)
    relationships.derive_role_privilege_facts(ctx)
    relationships.derive_relationship_chains(ctx)

    files_analyzed = sorted(set(files_analyzed) - set(files_partial))
    files_partial = sorted(set(files_partial))
    files_failed = sorted(set(files_failed))

    all_files = {d.relative_path for d in discovered}
    accounted = set(files_analyzed) | set(files_partial) | set(files_failed)
    for missing in sorted(all_files - accounted):
        files_failed.append(missing)

    if files_failed and (files_analyzed or files_partial):
        analysis_status = "partial"
    elif files_failed and not (files_analyzed or files_partial):
        analysis_status = "failed"
    else:
        analysis_status = "complete"

    run_meta = {
        "source_root": repo_root,
        "files_analyzed": files_analyzed,
        "files_partially_analyzed": files_partial,
        "files_failed": files_failed,
        "compiler": {"engine": "solc-js (npm)", "runs": compiler_runs},
        "analysis_status": analysis_status,
        "errors": errors_out,
    }

    output.write_all(ctx, output_dir, run_meta)
    return ctx
