"""Deterministic writers for the recon/ output directory."""

from __future__ import annotations

import json
import os
from collections import Counter

from .context import ProjectContext
from .schema import SCHEMA_VERSION, build_schema

ANALYZER_VERSION = "0.1.0"


def _write_json(path: str, data) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def write_facts_jsonl(ctx: ProjectContext, path: str) -> None:
    facts_sorted = sorted(ctx.facts, key=lambda f: f.id)
    with open(path, "w") as f:
        for fact in facts_sorted:
            f.write(json.dumps(fact.to_dict(), sort_keys=True))
            f.write("\n")


def write_graph_json(ctx: ProjectContext, path: str) -> None:
    nodes = sorted((n.to_dict() for n in ctx.graph_nodes.values()), key=lambda n: n["id"])
    edges = sorted((e.to_dict() for e in ctx.graph_edges.values()), key=lambda e: e["id"])
    _write_json(path, {"nodes": nodes, "edges": edges})


def write_schema_json(path: str) -> None:
    _write_json(path, build_schema())


def write_metadata_json(ctx: ProjectContext, path: str, run_meta: dict) -> None:
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "analyzer_version": ANALYZER_VERSION,
        "source_root": run_meta.get("source_root"),
        "files_analyzed": run_meta.get("files_analyzed", []),
        "files_partially_analyzed": run_meta.get("files_partially_analyzed", []),
        "files_failed": run_meta.get("files_failed", []),
        "file_diagnostics": run_meta.get("file_diagnostics", {}),
        "coverage": run_meta.get("coverage", {}),
        "dependency_files_added": run_meta.get("dependency_files_added", []),
        "import_prefix_aliases": run_meta.get("import_prefix_aliases", {}),
        "build_metadata_hints": run_meta.get("build_metadata_hints", {}),
        "compiler": run_meta.get("compiler", {}),
        "analysis_status": run_meta.get("analysis_status", "unknown"),
        "warnings": ctx.warnings,
        "errors": run_meta.get("errors", []),
    }
    _write_json(path, metadata)


def write_summary_json(ctx: ProjectContext, path: str, run_meta: dict) -> None:
    contracts = sorted(ctx.contracts.values(), key=lambda c: c.key)
    interfaces = [c for c in contracts if c.kind == "interface"]
    libraries = [c for c in contracts if c.kind == "library"]

    fact_type_counts = Counter(f.type for f in ctx.facts)
    status_counts = Counter(f.status for f in ctx.facts)

    capability_counts = Counter()
    for f in ctx.facts:
        if f.type == "capability":
            capability_counts[f.subject.get("capability")] += 1

    node_kind_counts = Counter(n.kind for n in ctx.graph_nodes.values())
    edge_type_counts = Counter(e.type for e in ctx.graph_edges.values())

    unresolved = {
        "internal_calls": sum(
            1 for f in ctx.facts if f.type == "internal_call" and f.status != "observed"
        ),
        "inheritance_bases": sum(
            1 for f in ctx.facts if f.type in ("inheritance", "interface_implementation") and f.status != "observed"
        ),
        "event_emissions": sum(
            1 for f in ctx.facts if f.type == "event_emission" and f.status != "observed"
        ),
        "call_argument_dataflows": sum(
            1 for f in ctx.facts if f.type == "call_argument_dataflow" and f.status == "unknown"
        ),
    }

    summary = {
        "contracts": [
            {"key": c.key, "name": c.name, "kind": c.kind, "file": c.file, "is_abstract": c.is_abstract}
            for c in contracts
        ],
        "interfaces": [{"key": c.key, "name": c.name, "file": c.file} for c in interfaces],
        "libraries": [{"key": c.key, "name": c.name, "file": c.file} for c in libraries],
        "function_count": sum(len(c.functions) for c in contracts),
        "state_variable_count": sum(len(c.state_vars) for c in contracts),
        "event_count": sum(len(c.events) for c in contracts),
        "error_count": sum(len(c.errors) for c in contracts),
        "external_call_count": fact_type_counts.get("external_call", 0) + fact_type_counts.get("low_level_call", 0),
        "asset_operation_count": fact_type_counts.get("asset_operation", 0),
        "eth_transfer_count": fact_type_counts.get("eth_transfer", 0),
        "callback_capable_call_count": fact_type_counts.get("callback_capable_call", 0),
        "authorization_check_count": fact_type_counts.get("authorization_check", 0),
        "capabilities": dict(sorted(capability_counts.items())),
        "fact_type_counts": dict(sorted(fact_type_counts.items())),
        "fact_status_counts": dict(sorted(status_counts.items())),
        "graph_statistics": {
            "node_count": len(ctx.graph_nodes),
            "edge_count": len(ctx.graph_edges),
            "nodes_by_kind": dict(sorted(node_kind_counts.items())),
            "edges_by_type": dict(sorted(edge_type_counts.items())),
        },
        "analysis_coverage": {
            "files_analyzed": len(run_meta.get("files_analyzed", [])),
            "files_partially_analyzed": len(run_meta.get("files_partially_analyzed", [])),
            "files_failed": len(run_meta.get("files_failed", [])),
            "unresolved": unresolved,
        },
        "warnings": ctx.warnings,
    }
    _write_json(path, summary)


def write_all(ctx: ProjectContext, output_dir: str, run_meta: dict) -> None:
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "snippets"), exist_ok=True)
    write_schema_json(os.path.join(output_dir, "schema.json"))
    write_metadata_json(ctx, os.path.join(output_dir, "metadata.json"), run_meta)
    write_summary_json(ctx, os.path.join(output_dir, "summary.json"), run_meta)
    write_facts_jsonl(ctx, os.path.join(output_dir, "facts.jsonl"))
    write_graph_json(ctx, os.path.join(output_dir, "graph.json"))
