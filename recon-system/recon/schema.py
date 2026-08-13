"""Versioned schema describing every object shape emitted under `recon/`.

This is descriptive metadata for downstream consumers, not a validator. Bump
SCHEMA_VERSION whenever a field is added, removed, or its meaning changes.
"""

from __future__ import annotations

SCHEMA_VERSION = "1.1.0"


def build_schema() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "description": (
            "Recon-only static analysis output for Solidity/EVM repositories. "
            "Contains atomic, source-traceable facts and a structural graph. "
            "Contains no vulnerability, exploitability, severity, or mitigation "
            "judgments of any kind."
        ),
        "status_values": {
            "observed": "Directly represented by an AST/source node.",
            "derived": "Deterministically inferred from one or more observed facts via disclosed heuristics.",
            "partial": "Some but not all sub-parts of the relationship could be determined.",
            "unknown": "Could not be determined reliably from available information.",
        },
        "certainty_values": {
            "_description": (
                "A second, narrower epistemic label used ONLY inside `properties` for the "
                "security-intelligence fact types (security_relationship_chain, "
                "access_controlled_function, unguarded_capability_hypothesis). It does not "
                "replace `status` — it exists because a single relationship CHAIN can mix "
                "steps of different certainty (e.g. one AST-verified step plus one "
                "co-occurrence-only step), which the base `status` field cannot express."
            ),
            "FACT": "Every step/claim is individually backed by an observed fact.",
            "INFERENCE": "Deterministically combined from multiple observed facts.",
            "HYPOTHESIS": "A structurally-plausible security-relevant question, never a verdict.",
            "UNKNOWN": "Could not be determined.",
        },
        "objects": {
            "Fact": {
                "file": "facts.jsonl (one JSON object per line)",
                "fields": {
                    "id": "string — stable id, sha1-derived from (type, file, ast node id, role)",
                    "type": "string — fact type, e.g. 'state_write', 'internal_call', 'capability'",
                    "status": "one of status_values",
                    "subject": "object — what the fact is about (contract/function/state_variable refs)",
                    "properties": "object — atomic observed attributes for this fact type",
                    "source": "SourceRef|null — file/offset/line provenance",
                    "evidence": "string[] — evidence ids (see Evidence)",
                    "confidence": "'high'|'medium'|'low' — EXTRACTION confidence, not a security rating",
                    "extraction_method": "'ast'|'ast+heuristic'|'regex-fallback'",
                },
            },
            "SourceRef": {
                "fields": {
                    "file": "string — repo-relative path",
                    "start": "int|null — byte offset in file content",
                    "end": "int|null — byte offset (exclusive)",
                    "line_start": "int|null — 1-indexed",
                    "line_end": "int|null — 1-indexed",
                    "ast_node_id": "string|null — solc AST node id (unique within its compile group)",
                }
            },
            "Evidence": {
                "file": "not a separate top-level file; embedded inline in graph.json / referenced by id from facts.jsonl. Snippet bodies live under snippets/.",
                "fields": {
                    "id": "string",
                    "file": "string",
                    "start_line": "int|null",
                    "end_line": "int|null",
                    "start": "int|null",
                    "end": "int|null",
                    "snippet_path": "string|null — path under recon/ to the snippet text file",
                    "fact_ids": "string[] — facts this evidence supports",
                },
            },
            "GraphNode": {
                "fields": {
                    "id": "string",
                    "kind": "'contract'|'function'|'state_variable'|'event'|'error'|'external_target'|'creation_target'",
                    "label": "string — human-readable name",
                    "properties": "object — kind-specific attributes",
                }
            },
            "GraphEdge": {
                "fields": {
                    "id": "string",
                    "type": (
                        "'DECLARES'|'INHERITS'|'IMPLEMENTS'|'CALLS'|'READS'|'WRITES'|'EMITS'|"
                        "'DELEGATES_TO'|'CREATES'|'USES_MODIFIER'"
                    ),
                    "source": "string — GraphNode id",
                    "target": "string — GraphNode id",
                    "status": "one of status_values",
                    "properties": "object — edge-specific attributes",
                    "fact_ids": "string[] — facts backing this edge",
                }
            },
            "SecurityIntelligenceLayer": {
                "_description": (
                    "Fact types introduced to connect otherwise-isolated facts into "
                    "traceable relationships and a lightweight role/privilege map. Built "
                    "entirely by cross-referencing already-extracted facts (recon/relationships.py) "
                    "— no additional AST parsing. See certainty_values above."
                ),
                "modifier_definition": "A `modifier` declaration, inventoried the same way a function is.",
                "access_controlled_function": (
                    "A function with an observed authorization_check, either inline or via a "
                    "modifier it uses. properties.mechanisms lists each mechanism found."
                ),
                "unguarded_capability_hypothesis": (
                    "HYPOTHESIS-level: a function exercises a security-relevant capability "
                    "(can_transfer_token, can_delegatecall, etc.) with no observed authorization_check "
                    "anywhere in scope. An absence-of-evidence signal, not a finding — many functions "
                    "are intentionally permissionless."
                ),
                "security_relationship_chain": (
                    "A short, ordered sequence of {actor, relation, target, certainty, basis_facts} "
                    "steps connecting parameter control -> call target/calldata -> co-occurring asset "
                    "operations, in the shape 'User -> controls -> parameter -> passed_into -> call "
                    "-> co_occurs_with -> asset_operation'. Each step carries its own certainty; "
                    "properties.overall_certainty is the weakest certainty among its steps."
                ),
                "division_operation": (
                    "Structural precursor for rounding/truncation/precision review: every integer "
                    "division site plus its immediate consumer (return value / state write / "
                    "variable initializer / call argument). Recon does not evaluate whether the "
                    "resulting truncation is significant."
                ),
            },
        },
        "files": {
            "schema.json": "this document",
            "metadata.json": "run metadata: versions, coverage inputs, timestamps, warnings/errors",
            "summary.json": "machine-readable index over facts/graph; not authoritative, derived from facts.jsonl+graph.json",
            "facts.jsonl": "authoritative atomic fact database, one Fact per line",
            "graph.json": "{nodes: GraphNode[], edges: GraphEdge[]}",
            "snippets/": "concise source snippets referenced by Evidence.snippet_path",
        },
    }
