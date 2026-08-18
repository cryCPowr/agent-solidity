"""Attacker model + entry-point resolution.

Answers "who is the attacker?" and "which exact entry point can they
reach?" from Recon visibility/authorization facts, never upgrading
"externally reachable" into "unauthorized" (evidence rule 6).
"""

from __future__ import annotations

from collections import deque
from typing import Any

from . import relevance
from .model import INFERRED, PROVEN, UNKNOWN

_EXTERNALLY_REACHABLE = frozenset({"external", "public"})

# Recon fact types that indicate an observed authorization boundary.
_AUTH_FACT_TYPES = frozenset({
    "access_controlled_function",
    "authorization_check",
    "modifier_usage",
})


def resolve_entry(recon, hypothesis: dict[str, Any]) -> dict[str, Any]:
    """Pick the concrete external entry function for a hypothesis.

    If the root function is internal/private, search Recon's observed
    caller graph for an externally reachable ancestor chain instead of
    assuming the helper itself is directly attacker-callable.
    """
    candidates = list(hypothesis.get("affected_functions") or [])
    if not candidates:
        return {"function": "", "visibility": UNKNOWN, "status": UNKNOWN,
                "required_role": UNKNOWN, "required_role_status": UNKNOWN,
                "location": "", "fact_ids": [], "root_function": "",
                "root_visibility": UNKNOWN, "root_reachable": UNKNOWN,
                "call_chain": [], "externally_reachable": False,
                "privileged_only": False, "notes": ["no affected_functions to resolve entry from"]}

    root_fn = candidates[0]
    root_vis_fact = _visibility_fact(recon, root_fn)
    root_visibility = ((root_vis_fact or {}).get("properties") or {}).get("visibility", UNKNOWN)

    chosen_chain: list[str] = []
    chosen_vis_fact = None
    if root_visibility in _EXTERNALLY_REACHABLE:
        chosen_chain = [root_fn]
        chosen_vis_fact = root_vis_fact
    else:
        chosen_chain = _external_ancestor_chain(recon, root_fn)
        if chosen_chain:
            chosen_vis_fact = _visibility_fact(recon, chosen_chain[0])

    if not chosen_chain:
        for fn in candidates:
            vis_fact = _visibility_fact(recon, fn)
            vis = ((vis_fact or {}).get("properties") or {}).get("visibility", "")
            if vis_fact is None:
                continue
            chosen_chain = [fn] if fn == root_fn else [fn, root_fn]
            chosen_vis_fact = vis_fact
            if vis in _EXTERNALLY_REACHABLE:
                break

    entry_fn = chosen_chain[0] if chosen_chain else candidates[0]
    vis_fact = chosen_vis_fact or _visibility_fact(recon, entry_fn)
    visibility = ((vis_fact or {}).get("properties") or {}).get("visibility", UNKNOWN)
    vis_facts = [vis_fact] if vis_fact is not None else []

    role, role_status, auth_facts = _required_role(recon, entry_fn)
    fact_ids = [f.get("id", "") for f in vis_facts + auth_facts if f.get("id")]
    location = recon.source_location(vis_facts[0].get("id", "")) if vis_facts else ""

    externally_reachable = visibility in _EXTERNALLY_REACHABLE
    notes: list[str] = []
    if root_visibility not in _EXTERNALLY_REACHABLE and chosen_chain and entry_fn != root_fn:
        notes.append("root function is not externally callable; attack must enter via caller chain")
    elif root_visibility not in _EXTERNALLY_REACHABLE:
        notes.append("no externally callable ancestor was found for the root function")
    if role_status == PROVEN:
        notes.append("entry requires observed authorization; executability depends on proving attacker can satisfy or obtain that role")

    if chosen_chain and chosen_chain[-1] != root_fn:
        chosen_chain = chosen_chain + [root_fn]
    elif not chosen_chain:
        chosen_chain = [fn for fn in [entry_fn, root_fn] if fn]

    root_reachable = UNKNOWN
    if root_visibility in _EXTERNALLY_REACHABLE:
        root_reachable = PROVEN
    elif chosen_chain and externally_reachable and chosen_chain[-1] == root_fn and len(chosen_chain) > 1:
        root_reachable = PROVEN

    return {
        "function": entry_fn,
        "visibility": visibility,
        "status": PROVEN if vis_facts else UNKNOWN,
        "required_role": role,
        "required_role_status": role_status,
        "location": location,
        "fact_ids": [fid for fid in fact_ids if fid],
        "root_function": root_fn,
        "root_visibility": root_visibility,
        "root_reachable": root_reachable,
        "call_chain": chosen_chain,
        "externally_reachable": externally_reachable,
        "privileged_only": role_status == PROVEN,
        "notes": notes,
    }


def _visibility_fact(recon, fn_key: str) -> dict[str, Any] | None:
    return next(
        (f for f in recon.facts_for_function(fn_key) if f.get("type") == "function_visibility"),
        None,
    )



def _external_ancestor_chain(recon, root_fn: str) -> list[str]:
    """Shortest observed caller chain from an external/public function to root_fn.

    Prefers unprivileged externally visible callers over privileged ones.
    """
    callers_by_callee: dict[str, list[str]] = {}
    for fact in recon.facts_obj.by_type.get("internal_call", []):
        subject = fact.get("subject") or {}
        caller = subject.get("caller") or subject.get("function") or ""
        callee = ((fact.get("properties") or {}).get("callee_function") or "")
        if caller and callee:
            callers_by_callee.setdefault(callee, []).append(caller)

    best_chain: list[str] = []
    best_score: tuple[int, int, str] | None = None
    queue = deque([(root_fn, [root_fn])])
    seen = {root_fn}
    while queue:
        current, chain_to_root = queue.popleft()
        for caller in callers_by_callee.get(current, []):
            if caller in seen:
                continue
            seen.add(caller)
            chain = [caller] + chain_to_root
            vis_fact = _visibility_fact(recon, caller)
            vis = ((vis_fact or {}).get("properties") or {}).get("visibility", "")
            if vis in _EXTERNALLY_REACHABLE:
                _, role_status, _ = _required_role(recon, caller)
                score = (0 if role_status != PROVEN else 1, len(chain), caller)
                if best_score is None or score < best_score:
                    best_score = score
                    best_chain = chain
                continue
            queue.append((caller, chain))
    return best_chain



def _required_role(recon, fn_key: str) -> tuple[str, str, list[dict[str, Any]]]:
    """Derive the role required to call the entry function.

    PROVEN when an authorization fact is observed (the boundary exists);
    INFERRED-permissive when the function is externally visible and no
    authorization fact was observed -- absence of evidence, stated as
    such, never as proof of being unguarded.
    """
    auth_facts = [
        f for f in recon.facts_for_function(fn_key)
        if f.get("type") in _AUTH_FACT_TYPES
    ]
    if auth_facts:
        names = sorted({
            str((f.get("properties") or {}).get("modifier")
                or (f.get("subject") or {}).get("modifier")
                or f.get("type"))
            for f in auth_facts
        })
        return " / ".join(names), PROVEN, auth_facts
    return "none observed (may still exist)", INFERRED, []


def attacker_model(hypothesis: dict[str, Any], entry: dict[str, Any]) -> str:
    """Describe the attacker for this hypothesis."""
    actor = hypothesis.get("actor", "unknown_actor")
    role = entry.get("required_role", UNKNOWN)
    vis = entry.get("visibility", UNKNOWN)
    if actor in ("external_user", "caller") and vis in ("external", "public"):
        if entry.get("required_role_status") == PROVEN:
            return (
                f"A privileged external caller would be required to reach "
                f"{entry.get('function','')}: observed authorization "
                f"boundary ({role}) is present, and attacker possession of "
                f"that role is not established by Attack Agent."
            )
        return (
            "An unprivileged external caller (any EOA/contract): the entry "
            "is externally visible and no authorization boundary was "
            "observed on it (absence of evidence, not proof)."
        )
    if actor == "external_contract":
        return (
            "An attacker-controlled contract interacting with the protocol "
            "through the identified surface (e.g. as a callback recipient "
            "or token sender)."
        )
    return (
        f"Caller type '{actor}' reaching {entry.get('function','?')}; the "
        f"privileges actually required are not yet established."
    )


def relevance_of(recon, root_fn: str) -> str:
    return relevance.classify_function(recon, root_fn)
