"""Attacker model + entry-point resolution.

Answers "who is the attacker?" and "which exact entry point can they
reach?" from Recon visibility/authorization facts, never upgrading
"externally reachable" into "unauthorized" (evidence rule 6).
"""

from __future__ import annotations

from typing import Any

from . import relevance
from .model import INFERRED, PROVEN, UNKNOWN

# Recon fact types that indicate an observed authorization boundary.
_AUTH_FACT_TYPES = frozenset({
    "access_controlled_function",
    "authorization_check",
    "modifier_usage",
})


def resolve_entry(recon, hypothesis: dict[str, Any]) -> dict[str, Any]:
    """Pick the concrete external entry function for a hypothesis.

    For security chains that span an internal call edge (root function is
    reached through a proven-influenced external caller), the ENTRY is the
    externally visible caller; the root stays the function where the sink
    lives. For everything else the entry is the first affected function
    with external/public visibility, else the primary affected function
    with an explicit visibility status.
    """
    candidates = list(hypothesis.get("affected_functions") or [])
    if not candidates:
        return {"function": "", "visibility": UNKNOWN, "status": UNKNOWN,
                "required_role": UNKNOWN, "location": "", "fact_ids": []}

    entry_fn = ""
    visibility = UNKNOWN
    vis_facts: list[dict[str, Any]] = []
    for fn in candidates:
        fn_facts = recon.facts_for_function(fn)
        vis_fact = next(
            (f for f in fn_facts if f.get("type") == "function_visibility"), None
        )
        if vis_fact is None:
            continue
        vis = (vis_fact.get("properties") or {}).get("visibility", "")
        vis_facts = [vis_fact]
        entry_fn, visibility = fn, vis
        if vis in ("external", "public"):
            break  # first externally reachable function is the entry
    if not entry_fn:
        entry_fn = candidates[0]
        fn_facts = recon.facts_for_function(entry_fn)
        vis_fact = next(
            (f for f in fn_facts if f.get("type") == "function_visibility"), None
        )
        if vis_fact is not None:
            visibility = (vis_fact.get("properties") or {}).get("visibility", UNKNOWN)
            vis_facts = [vis_fact]

    role, role_status, auth_facts = _required_role(recon, entry_fn)
    fact_ids = [f.get("id", "") for f in vis_facts + auth_facts if f.get("id")]
    location = ""
    if vis_facts:
        location = recon.source_location(vis_facts[0].get("id", ""))

    return {
        "function": entry_fn,
        "visibility": visibility,
        "status": PROVEN if vis_facts else UNKNOWN,
        "required_role": role,
        "required_role_status": role_status,
        "location": location,
        "fact_ids": [fid for fid in fact_ids if fid],
    }


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
                f"An external caller holding the required authorization "
                f"({role}) on {entry.get('function','')}."
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
