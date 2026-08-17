"""Attack-path construction from Threat chain stages + Recon facts.

Converts an abstract Threat chain into the concrete Attack shape required
by for_attack_agent.md:

    A. ENTRY          attacker.attacker/resolve_entry
    B. CONTROL        controlled_inputs   (what the attacker chooses)
    C. PROPAGATION    propagation_path    (source var -> ... -> call args)
    D. SINK           sensitive_sink      (classified, custody-aware)
    E. CONSEQUENCE    consequences.py

Every element is grounded in fact IDs + source locations; statuses are
derived, never upgraded (a dynamic target stays POSSIBLE unless the
recipient traces to attacker-controlled data).
"""

from __future__ import annotations

from typing import Any

from .model import INFERRED, PROVEN, UNKNOWN, POSSIBLE

_TOKEN_RE = None  # imported lazily to keep this module import-light

# --- sink classification (generic token-standard vocabulary) --------------

_APPROVAL_OPS = ("approve", "allowance")
_TRANSFER_OPS = ("transfer",)


def classify_asset_sink(fact: dict[str, Any]) -> tuple[str, str] | None:
    """Map an asset/eth fact to a sensitive sink class.

    Returns (sink_class, custody) or None when the fact is not an asset
    sink. Operation semantics are generic token-standard vocabulary.
    """
    props = fact.get("properties") or {}
    op = str(props.get("operation") or "").lower()
    if fact.get("type") == "eth_transfer":
        return "native_value_transfer", "outbound"
    if fact.get("type") != "asset_operation":
        return None
    if any(a in op for a in _APPROVAL_OPS):
        return "token_approval", "grant"
    if "transferfrom" in op.replace("_", ""):
        return "transfer_from", _transfer_custody(props)
    if any(op.startswith(t) for t in _TRANSFER_OPS):
        return "token_transfer", _transfer_custody(props)
    if "mint" in op:
        return "mint", "inbound"
    if "burn" in op:
        return "burn", "outbound"
    if "withdraw" in op:
        return "withdraw", "outbound"
    return "asset_operation", "unclassified"


def _transfer_custody(props: dict[str, Any]) -> str:
    args = props.get("arguments")
    if isinstance(args, list) and args and isinstance(args[0], str):
        if "this" in args[0].lower():
            return "outbound"
        return "inbound"
    return "unclassified"


def classify_execution_sink(fact: dict[str, Any]) -> str | None:
    """Map an interaction fact to an execution sink class."""
    ftype = fact.get("type", "")
    props = fact.get("properties") or {}
    dynamic = props.get("target_status") == "dynamic"
    if ftype == "low_level_call":
        return "arbitrary_external_call"
    if ftype == "contract_creation":
        return "contract_creation"
    if ftype in ("external_call", "external_call_surface") and dynamic:
        return "dynamic_external_call"
    if ftype in ("external_call", "external_call_surface"):
        return "static_external_call"
    return None


def choose_sink(recon, hypothesis: dict[str, Any], root_fn: str) -> dict[str, Any]:
    """Choose the most security-sensitive sink among the hypothesis's
    observed facts for the root function.

    Priority: asset sinks with protocol custody at risk (grant/outbound)
    > arbitrary/dynamic execution > other asset sinks > state mutation.
    """
    sink_priority = {
        "token_approval": 0, "transfer_from": 1, "native_value_transfer": 1,
        "withdraw": 2, "burn": 2, "token_transfer": 3, "mint": 4,
        "asset_operation": 5,
        "arbitrary_external_call": 1, "contract_creation": 2,
        "dynamic_external_call": 3, "static_external_call": 6,
        "state_mutation": 7,
    }
    best: dict[str, Any] | None = None
    best_rank: tuple[int, int] | None = None
    for fid in hypothesis.get("observed_facts") or []:
        fact = recon.fact(fid)
        if fact is None:
            continue
        subj = fact.get("subject") or {}
        if (subj.get("function") or subj.get("caller")) != root_fn:
            continue
        candidates: list[tuple[str, str, str]] = []  # (class, custody, fact_id)
        asset = classify_asset_sink(fact)
        if asset:
            candidates.append((asset[0], asset[1], fid))
        exec_sink = classify_execution_sink(fact)
        if exec_sink:
            candidates.append((exec_sink, "n/a", fid))
        if fact.get("type") == "state_write":
            candidates.append(("state_mutation", "n/a", fid))
        for cls, custody, cand_id in candidates:
            rank = (sink_priority.get(cls, 9), 0 if custody in ("grant", "outbound") else 1)
            if best_rank is None or rank < best_rank:
                best_rank = rank
                fact_ref = recon.fact(cand_id) or {}
                props = fact_ref.get("properties") or {}
                best = {
                    "class": cls,
                    "custody": custody,
                    "fact_id": cand_id,
                    "location": recon.source_location(cand_id),
                    "operation": props.get("operation", ""),
                    "target_expression": props.get("target_expression", ""),
                    "arguments": props.get("arguments", []),
                    "member": props.get("member", ""),
                }
    if best is None:
        return {"class": "unknown", "custody": "n/a", "fact_id": "",
                "location": "", "status": UNKNOWN}
    best["status"] = PROVEN  # the sink's existence is fact-proven
    return best


def controlled_inputs(recon, hypothesis: dict[str, Any], root_fn: str) -> list[dict[str, Any]]:
    """B. CONTROL -- what the attacker chooses at the entry.

    Derived from the hypothesis's parameter-rooted argument-flow facts on
    the root function (PROVEN), plus caller-controlled input origins.
    Never includes inferred-only shapes without a status downgrade.
    """
    inputs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fid in hypothesis.get("observed_facts") or []:
        fact = recon.fact(fid)
        if fact is None or fact.get("type") not in (
            "call_argument_origin_chain", "call_argument_dataflow", "input_origin",
        ):
            continue
        subj = fact.get("subject") or {}
        if (subj.get("function") or subj.get("caller")) != root_fn:
            continue
        props = fact.get("properties") or {}
        root_kind = str(
            props.get("root_kind") or props.get("origin_kind") or ""
        ).lower()
        expr = str(props.get("argument_expression") or props.get("root_name")
                   or subj.get("origin") or "")
        if not expr or expr in seen:
            continue
        seen.add(expr)
        is_parameter = root_kind == "parameter" or fact.get("type") == "input_origin"
        inputs.append({
            "expression": expr,
            "kind": "parameter" if is_parameter else (root_kind or UNKNOWN),
            "status": PROVEN if is_parameter else INFERRED,
            "fact_id": fid,
            "location": recon.source_location(fid),
        })
    inputs.sort(key=lambda i: i["expression"])
    return inputs


def propagation_path(recon, hypothesis: dict[str, Any], root_fn: str,
                     entry_fn: str) -> list[dict[str, Any]]:
    """C. PROPAGATION -- ordered, fact-grounded path from the controlled
    input to the sink.

    Uses the Threat chain's stage fact IDs (influence -> [internal call
    edge] -> argument propagation -> external execution -> effect), each
    expanded with its source location and expression.
    """
    steps: list[dict[str, Any]] = []
    stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
    order = [
        ("untrusted_influence", "caller-controlled input reaches the function"),
        ("argument_propagation", "input propagates into call arguments"),
        ("external_execution", "arguments reach the external interaction"),
        ("downstream_execution_opportunity", "dynamic recipient may execute code"),
        ("asset_authorization", "spending authority granted over contract assets"),
        ("state_value_effect", "downstream state/value effect"),
        ("validation_gap", "pre/post delta validation brackets the execution"),
        ("invariant_concern", "linked invariant candidate"),
    ]
    stage_by_name = {name: stages.get(name) for name, _ in order}
    root_caller_edge = None
    for fid in (stage_by_name.get("untrusted_influence") or {}).get("fact_ids") or []:
        fact = recon.fact(fid)
        if fact is not None and fact.get("type") == "internal_call":
            root_caller_edge = fact

    for name, description in order:
        stage = stage_by_name.get(name)
        if not stage:
            continue
        entry: dict[str, Any] = {
            "stage": name,
            "description": stage.get("description", description),
            "status": _stage_status(stage),
            "fact_ids": list(stage.get("fact_ids") or []),
        }
        if name == "untrusted_influence" and root_caller_edge is not None:
            callee = (root_caller_edge.get("properties") or {}).get("callee_function", "")
            entry["via_internal_call_edge"] = {
                "from": entry_fn,
                "to": callee or root_fn,
                "fact_id": root_caller_edge.get("id", ""),
            }
            entry["status"] = PROVEN
        locs = [recon.source_location(f) for f in entry["fact_ids"]]
        entry["locations"] = [loc for loc in locs if loc]
        steps.append(entry)
    return steps


def _stage_status(stage: dict[str, Any]) -> str:
    status = str(stage.get("status", "")).upper()
    if "GRADE" in stage and status == "INFERRED":
        # downstream stage with grade STRUCTURALLY_INDICATED stays INFERRED
        return INFERRED
    mapping = {"PROVEN": PROVEN, "INFERRED": INFERRED, "OBSERVED": PROVEN,
               "UNCERTAIN": POSSIBLE}
    return mapping.get(status, UNKNOWN)


def capability_obtained(hypothesis: dict[str, Any], recon, root_fn: str) -> tuple[str, str]:
    """What the attacker obtains, with status. Derived from the sink +
    chain stages, never upgraded."""
    stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
    parts: list[str] = []
    status = UNKNOWN
    if "asset_authorization" in stages:
        parts.append("spender authority over the contract's asset account "
                     "(caller-chosen beneficiary)")
        status = PROVEN
    downstream = stages.get("downstream_execution_opportunity") or {}
    grade = downstream.get("grade", "")
    if grade == "STRUCTURALLY_INDICATED":
        parts.append("control over the recipient of an external execution "
                     "(attacker-directed code path)")
        status = INFERRED if status != PROVEN else status
    elif grade == "PROVEN":
        parts.append("proven callback execution into attacker code")
        status = PROVEN
    sink = stages.get("state_value_effect") or {}
    if sink.get("linkage") == "asset_flow_linked":
        parts.append("influence over a protocol-custody asset flow")
        status = PROVEN
    if not parts:
        # fall back to capability facts
        caps = [
            f for f in recon.facts_for_function(root_fn)
            if f.get("type") == "capability"
        ]
        if caps:
            names = sorted({(f.get("subject") or {}).get("capability", "?") for f in caps})
            parts.append("observed sensitive capabilities: " + ", ".join(names))
            status = INFERRED
    return "; ".join(parts) if parts else "not yet established", status
