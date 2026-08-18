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

import re
from typing import Any

from .model import INFERRED, PROVEN, UNKNOWN, POSSIBLE, STATUS_ORDER

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STOPWORDS = frozenset({
    "address", "this", "msg", "sender", "call", "data", "abi",
    "true", "false", "uint", "uint256", "int", "int256", "bytes",
    "string", "memory", "calldata", "storage",
})

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

    Priority is family-aware. Example: for approval-abuse chains, approval
    sinks stay highest priority; for accounting/front-run/rounding families,
    prefer the sink shape that best matches the bug class instead of always
    grabbing the globally most dangerous primitive.
    """
    category = str(hypothesis.get("category") or "")
    sink_priority = {
        "token_approval": 0, "transfer_from": 1, "native_value_transfer": 1,
        "withdraw": 2, "burn": 2, "token_transfer": 3, "mint": 4,
        "asset_operation": 5,
        "arbitrary_external_call": 1, "contract_creation": 2,
        "dynamic_external_call": 3, "static_external_call": 6,
        "arith_bitshift": 4,
        "arith_division": 5,
        "randomness_source": 5,
        "state_constraint": 5,
        "iteration": 5,
        "state_mutation": 7,
    }
    if category == "accounting_mismatch":
        sink_priority.update({
            "state_mutation": 0,
            "native_value_transfer": 1,
            "withdraw": 1,
            "token_transfer": 1,
            "transfer_from": 2,
            "asset_operation": 3,
            "token_approval": 6,
            "dynamic_external_call": 6,
            "arbitrary_external_call": 6,
        })
    elif category == "rounding_allocation":
        sink_priority.update({
            "arith_division": 0,
            "state_mutation": 1,
            "native_value_transfer": 2,
            "withdraw": 2,
            "token_transfer": 2,
            "token_approval": 7,
        })
    elif category == "frontrun_vulnerability":
        sink_priority.update({
            "state_constraint": 0,
            "state_mutation": 1,
            "dynamic_external_call": 4,
            "arbitrary_external_call": 4,
        })
    elif category == "randomness_manipulation":
        sink_priority.update({
            "randomness_source": 0,
            "state_mutation": 1,
            "native_value_transfer": 2,
            "token_transfer": 2,
        })
    elif category in ("gas_dos", "gas_complexity_dos"):
        sink_priority.update({
            "iteration": 0,
            "state_mutation": 1,
        })
    elif category == "arithmetic_bound_violation":
        sink_priority.update({
            "arith_bitshift": 0,
            "state_mutation": 1,
            "native_value_transfer": 2,
            "token_transfer": 2,
        })
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
        if fact.get("type") == "bitshift_operation":
            candidates.append(("arith_bitshift", "n/a", fid))
        if fact.get("type") == "division_operation":
            candidates.append(("arith_division", "n/a", fid))
        if fact.get("type") == "randomness_source_usage":
            candidates.append(("randomness_source", "n/a", fid))
        if fact.get("type") == "state_dependent_constraint":
            candidates.append(("state_constraint", "n/a", fid))
        if fact.get("type") == "control_flow_structure":
            construct = str((fact.get("properties") or {}).get("construct") or "").lower()
            if construct in {"for_loop", "while_loop", "do_while", "for_statement", "while_statement"}:
                candidates.append(("iteration", "n/a", fid))
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

    Only caller-controlled roots count here. Parameter-rooted values are
    PROVEN-controlled. A small allowlist of environment values that the
    caller directly chooses at invocation time (for example `msg.sender`
    and `msg.value`) also count. Literals, state variables, local
    variables, registry names, and unresolved expressions are *not*
    attacker-controlled merely because they appear in an argument-flow fact.
    """
    inputs: list[dict[str, Any]] = []
    seen: set[str] = set()
    caller_controlled_env = {"msg.sender", "msg.value", "tx.origin"}
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
        root_kind = str(props.get("root_kind") or props.get("origin_kind") or "").lower()
        expr = str(props.get("argument_expression") or props.get("root_name") or subj.get("origin") or "")
        if not expr or expr in seen:
            continue

        status = None
        kind = ""
        if root_kind == "parameter":
            status = PROVEN
            kind = "parameter"
        elif fact.get("type") == "input_origin":
            origin = str((subj.get("origin") or props.get("origin") or expr)).strip()
            if origin in caller_controlled_env:
                status = PROVEN
                kind = "environment"
            else:
                continue
        elif expr in caller_controlled_env:
            status = PROVEN
            kind = "environment"
        else:
            continue

        seen.add(expr)
        inputs.append({
            "expression": expr,
            "kind": kind,
            "status": status,
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


def _tokens(value: Any) -> set[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [v for v in value if isinstance(v, str)]
    else:
        values = []
    out: set[str] = set()
    for item in values:
        out |= {
            tok.lower() for tok in _TOKEN_RE.findall(item)
            if tok.lower() not in _STOPWORDS
        }
    return out



def target_control(recon, hypothesis: dict[str, Any], root_fn: str,
                   controlled: list[dict[str, Any]], sink: dict[str, Any]) -> dict[str, Any]:
    """Whether attacker-controlled input reaches the execution TARGET/recipient.

    For executable attack candidates, POSSIBLE is not enough: STRUCTURALLY_
    INDICATED or stronger is required for attacker-controlled-target claims.
    """
    stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
    downstream = stages.get("downstream_execution_opportunity") or {}
    grade = str(downstream.get("grade") or "")
    if grade == "PROVEN":
        return {
            "status": PROVEN,
            "basis": "downstream_execution_opportunity grade PROVEN",
            "fact_ids": list(downstream.get("fact_ids") or []),
        }
    if grade == "STRUCTURALLY_INDICATED":
        return {
            "status": INFERRED,
            "basis": "downstream_execution_opportunity grade STRUCTURALLY_INDICATED",
            "fact_ids": list(downstream.get("fact_ids") or []),
        }

    target_expr = sink.get("target_expression", "")
    target_tokens = _tokens(target_expr)
    matched = [c for c in controlled if _tokens(c.get("expression", "")) & target_tokens]
    if matched and sink.get("class") in ("dynamic_external_call", "arbitrary_external_call"):
        fact_ids = [c.get("fact_id", "") for c in matched if c.get("fact_id")]
        return {
            "status": INFERRED,
            "basis": "controlled input overlaps the dynamic target expression",
            "fact_ids": fact_ids,
        }
    return {
        "status": POSSIBLE if grade == "POSSIBLE" else UNKNOWN,
        "basis": "no recipient-side control provenance stronger than POSSIBLE was observed",
        "fact_ids": list(downstream.get("fact_ids") or []),
    }



# Sentinel used only inside beneficiary_control's returned dict, never as
# an AttackStep/strategy status value: it means "checked, and the
# beneficiary is PROVABLY NOT attacker-influenced" -- a stronger, more
# specific signal than UNKNOWN ("not checked / cannot determine").
BENEFICIARY_FIXED = "FIXED"

# Sink classes whose argument shape encodes an unambiguous beneficiary/
# spender -- the account that RECEIVES custody or spending authority.
# Generic token-standard vocabulary, never benchmark-specific names.
_BENEFICIARY_ARG_INDEX = {
    "token_approval": 0,   # approve(spender, amount) -> spender
    "transfer_from": 1,    # transferFrom(from, to, amount) -> to
}


def beneficiary_expression(sink: dict[str, Any]) -> str:
    """The argument expression that receives custody/authority for this
    sink, when the sink's own argument shape encodes it unambiguously.
    Returns '' when the sink class has no well-defined beneficiary slot.
    """
    idx = _BENEFICIARY_ARG_INDEX.get(sink.get("class", ""))
    if idx is None:
        return ""
    args = sink.get("arguments") or []
    if not isinstance(args, list) or len(args) <= idx:
        return ""
    val = args[idx]
    return val if isinstance(val, str) else ""


def beneficiary_control(recon, hypothesis: dict[str, Any], root_fn: str,
                        controlled: list[dict[str, Any]], sink: dict[str, Any]) -> dict[str, Any]:
    """Whether the account that RECEIVES spending authority/custody (the
    beneficiary/spender) -- not merely the amount -- is attacker-influenced.

    Evidence discipline: a caller-controlled AMOUNT never proves a
    caller-chosen BENEFICIARY. Approval/transferFrom-abuse claims require
    this specifically: a spender resolved from a fixed/registry expression
    (e.g. a protocol contract resolved via getContractAddress/getAddress)
    must never be described as an attacker-chosen recipient just because
    some OTHER argument on the same call (the amount) is caller-controlled.
    """
    beneficiary = beneficiary_expression(sink)
    if not beneficiary:
        return {
            "status": UNKNOWN,
            "basis": "sink shape does not expose an unambiguous beneficiary argument",
            "beneficiary_expression": "",
            "fact_ids": [],
        }
    beneficiary_tokens = _tokens(beneficiary)
    if not beneficiary_tokens:
        return {
            "status": UNKNOWN,
            "basis": "beneficiary expression carries no resolvable identifier",
            "beneficiary_expression": beneficiary,
            "fact_ids": [],
        }
    matched = [c for c in controlled if _tokens(c.get("expression", "")) & beneficiary_tokens]
    if matched:
        status = PROVEN if any(c.get("status") == PROVEN for c in matched) else INFERRED
        return {
            "status": status,
            "basis": "beneficiary/spender expression overlaps a caller-controlled input",
            "beneficiary_expression": beneficiary,
            "fact_ids": [c.get("fact_id", "") for c in matched if c.get("fact_id")],
        }
    return {
        "status": BENEFICIARY_FIXED,
        "basis": (
            "beneficiary/spender expression does not overlap any "
            "caller-controlled input -- likely fixed or protocol-registry-resolved"
        ),
        "beneficiary_expression": beneficiary,
        "fact_ids": [],
    }



def sink_argument_control(recon, hypothesis: dict[str, Any], root_fn: str,
                          controlled: list[dict[str, Any]], sink: dict[str, Any]) -> dict[str, Any]:
    """Whether controlled inputs overlap the sink's arguments/target expression."""
    sink_tokens = _tokens(sink.get("target_expression", "")) | _tokens(sink.get("arguments", []))
    matched = [c for c in controlled if _tokens(c.get("expression", "")) & sink_tokens]
    if matched:
        status = PROVEN if any(c.get("status") == PROVEN for c in matched) else INFERRED
        return {
            "status": status,
            "basis": "controlled input overlaps sink arguments/target expression",
            "fact_ids": [c.get("fact_id", "") for c in matched if c.get("fact_id")],
            "matched_expressions": [c.get("expression", "") for c in matched],
        }
    return {
        "status": UNKNOWN,
        "basis": "no controlled input was linked to the sink arguments/target expression",
        "fact_ids": [],
        "matched_expressions": [],
    }



def _stage_status(stage: dict[str, Any]) -> str:
    status = str(stage.get("status", "")).upper()
    if "GRADE" in stage and status == "INFERRED":
        # downstream stage with grade STRUCTURALLY_INDICATED stays INFERRED
        return INFERRED
    mapping = {"PROVEN": PROVEN, "INFERRED": INFERRED, "OBSERVED": PROVEN,
               "UNCERTAIN": POSSIBLE}
    return mapping.get(status, UNKNOWN)


def capability_obtained(hypothesis: dict[str, Any], recon, root_fn: str,
                        beneficiary: dict[str, Any] | None = None) -> tuple[str, str]:
    """What the attacker obtains, with status. Derived from the sink +
    chain stages, never upgraded.

    `beneficiary` (see beneficiary_control()) disambiguates "attacker
    controls the amount" from "attacker controls who receives the granted
    authority": only the latter may be described as a caller-chosen
    beneficiary, and only when proven/inferred by beneficiary_control.
    """
    stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
    parts: list[str] = []
    status = UNKNOWN
    if "asset_authorization" in stages:
        ben_status = (beneficiary or {}).get("status", UNKNOWN)
        if ben_status in (PROVEN, INFERRED):
            parts.append("spender authority over the contract's asset account "
                         "(caller-chosen beneficiary)")
            status = PROVEN if ben_status == PROVEN else INFERRED
        elif ben_status == BENEFICIARY_FIXED:
            parts.append(
                "spending authority is granted, but the beneficiary/spender "
                f"('{(beneficiary or {}).get('beneficiary_expression', '')}') "
                "does not overlap any caller-controlled input -- likely fixed "
                "or protocol-registry-resolved, so no attacker-chosen-beneficiary "
                "capability is established by this grant alone"
            )
            status = max(status, POSSIBLE, key=lambda s: STATUS_ORDER.get(s, 0))
        else:
            parts.append(
                "spender authority over the contract's asset account "
                "(beneficiary control not established by Recon; requires verification)"
            )
            status = max(status, INFERRED, key=lambda s: STATUS_ORDER.get(s, 0))
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
