"""ReconOutput — a minimal, read-only reader for recon/'s generated artifacts.

This is NOT part of the recon implementation. It simulates what a future
downstream consumer (e.g. a security-reasoning agent) would use: it only
reads the files recon.cli already writes to disk (facts.jsonl, graph.json,
summary.json, metadata.json, snippets/) and offers small, semantic query
helpers over them. It contains no vulnerability/security judgment logic of
its own — it only retrieves and cross-references facts that already exist in
the recon output.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional


class ReconOutput:
    def __init__(self, output_dir: str):
        self.dir = output_dir
        self.facts: list[dict] = [
            json.loads(line) for line in open(os.path.join(output_dir, "facts.jsonl"))
        ]
        self.graph: dict = json.load(open(os.path.join(output_dir, "graph.json")))
        self.summary: dict = json.load(open(os.path.join(output_dir, "summary.json")))
        self.metadata: dict = json.load(open(os.path.join(output_dir, "metadata.json")))

        self._facts_by_id = {f["id"]: f for f in self.facts}
        self._nodes_by_id = {n["id"]: n for n in self.graph["nodes"]}
        self._edges_by_id = {e["id"]: e for e in self.graph["edges"]}

    # ---- fact queries -----------------------------------------------------

    def facts_of_type(self, fact_type: str) -> list[dict]:
        return [f for f in self.facts if f["type"] == fact_type]

    def find_facts(self, fact_type: str, **subject_kv) -> list[dict]:
        """Facts of `fact_type` whose `subject` contains every given key/value."""
        return [
            f for f in self.facts
            if f["type"] == fact_type
            and all(f["subject"].get(k) == v for k, v in subject_kv.items())
        ]

    def find_one_fact(self, fact_type: str, **subject_kv) -> Optional[dict]:
        matches = self.find_facts(fact_type, **subject_kv)
        return matches[0] if matches else None

    def fact(self, fact_id: str) -> Optional[dict]:
        return self._facts_by_id.get(fact_id)

    # ---- semantic key lookup (name -> stable key), no hardcoded ids -------

    def function_key(self, name: str, file_contains: Optional[str] = None) -> str:
        for f in self.facts_of_type("function_exists"):
            if f["subject"]["name"] != name:
                continue
            if file_contains and file_contains not in f["source"]["file"]:
                continue
            return f["subject"]["function"]
        raise LookupError(f"no function_exists fact for name={name!r} file_contains={file_contains!r}")

    def contract_key(self, name: str, file_contains: Optional[str] = None) -> str:
        for f in self.facts_of_type("contract_exists"):
            if f["subject"]["name"] != name:
                continue
            if file_contains and f["source"]["file"] != file_contains and file_contains not in f["source"]["file"]:
                continue
            return f["subject"]["contract"]
        raise LookupError(f"no contract_exists fact for name={name!r} file_contains={file_contains!r}")

    def state_variable_key(self, name: str, contract_key: Optional[str] = None) -> str:
        for f in self.facts_of_type("state_variable"):
            if f["subject"]["name"] != name:
                continue
            if contract_key and f["subject"]["contract"] != contract_key:
                continue
            return f["subject"]["state_variable"]
        raise LookupError(f"no state_variable fact for name={name!r} contract_key={contract_key!r}")

    # ---- graph queries ------------------------------------------------

    def node_by_label(self, label: str, kind: Optional[str] = None) -> dict:
        matches = [
            n for n in self.graph["nodes"]
            if n["label"] == label and (kind is None or n["kind"] == kind)
        ]
        if not matches:
            raise LookupError(f"no graph node with label={label!r} kind={kind!r}")
        if len(matches) > 1:
            raise LookupError(
                f"label={label!r} kind={kind!r} is AMBIGUOUS across this corpus "
                f"({len(matches)} matches) — disambiguate via a DECLARES edge from "
                f"a known contract node instead of a bare label search"
            )
        return matches[0]

    def function_node_via_contract(self, contract_label: str, function_label: str) -> dict:
        """The preferred, non-fragile way to resolve a function's graph node:
        anchor on the (contract-scoped-unique) contract node, then follow its
        DECLARES edges, rather than a bare global label search — several
        function names repeat across this fixture corpus (`deposit`,
        `transfer`, `approve`, ...) and a global label search would silently
        pick whichever one happens to match first, or would raise only if it
        happens to collide. This method fails loudly in both the "not
        declared by this contract" and the "declared more than once" cases.
        """
        contract_node = self.node_by_label(contract_label, kind="contract")
        declared = self.outgoing_edges(contract_node["id"], edge_type="DECLARES")
        candidates = [
            self.node(e["target"]) for e in declared
            if self.node(e["target"]) is not None and self.node(e["target"])["kind"] == "function"
        ]
        matches = [n for n in candidates if n["label"] == function_label]
        if not matches:
            raise LookupError(
                f"contract {contract_label!r} has no DECLARES edge to a function "
                f"labeled {function_label!r}"
            )
        if len(matches) > 1:
            raise LookupError(
                f"contract {contract_label!r} declares {function_label!r} "
                f"{len(matches)} times (overload?) — caller must disambiguate further"
            )
        return matches[0]

    def node(self, node_id: str) -> Optional[dict]:
        return self._nodes_by_id.get(node_id)

    def outgoing_edges(self, node_id: str, edge_type: Optional[str] = None) -> list[dict]:
        return [
            e for e in self.graph["edges"]
            if e["source"] == node_id and (edge_type is None or e["type"] == edge_type)
        ]

    def edge_exists(self, source_id: str, target_id: str, edge_type: str) -> bool:
        return any(
            e["source"] == source_id and e["target"] == target_id and e["type"] == edge_type
            for e in self.graph["edges"]
        )

    # ---- evidence / provenance resolution ----------------------------------

    def resolve_evidence(self, evidence_id: str) -> dict:
        """fact.evidence[i] -> snippet file path + content, entirely from the
        artifact directory (no access to recon's internal Python objects).

        Evidence ids are not indexed in a standalone file; by convention the
        snippet filename is derived from the id's hash segment. This method
        is the ONE place that convention lives, so consumer test code never
        has to know it directly.
        """
        hash_part = evidence_id.split(":", 1)[1] if ":" in evidence_id else evidence_id
        snippet_path = os.path.join(self.dir, "snippets", f"{hash_part}.sol.txt")
        exists = os.path.exists(snippet_path)
        content = open(snippet_path).read() if exists else None
        return {"evidence_id": evidence_id, "snippet_path": snippet_path, "exists": exists, "content": content}

    def raw_source_slice(self, repo_root: str, file: str, start: int, end: int) -> str:
        """Re-slice the ORIGINAL fixture source (ground truth) at the same
        byte offsets a fact claims, for byte-exact cross-checking against the
        snippet recon produced. Uses the fixture file directly — this is the
        one place the smoke test is allowed to touch source-as-ground-truth,
        per the task's evidence-resolution requirement.
        """
        content_bytes = open(os.path.join(repo_root, file), "rb").read()
        return content_bytes[start:end].decode("utf-8", errors="replace")

    # ---- cross-artifact consistency helpers --------------------------------

    def all_evidence_ids(self) -> set:
        ids = set()
        for f in self.facts:
            ids.update(f.get("evidence", []))
        return ids

    def all_fact_ids_referenced_by_edges(self) -> set:
        ids = set()
        for e in self.graph["edges"]:
            ids.update(e.get("fact_ids", []))
        return ids

    def fact_type_count(self, fact_type: str) -> int:
        return len(self.facts_of_type(fact_type))
