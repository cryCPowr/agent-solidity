"""Generic multi-stage security-chain composition.

This is the reasoning core the Threat Agent exists for: compose Recon's
low-level facts ("what exists") into hypotheses of the form ("what
combination of these facts could violate a security assumption"):

    untrusted influence
        -> (propagation through arguments/dataflow)
        -> security-relevant external execution
        -> downstream state/value effect
        -> questionable invariant

Composition rules enforced here (see threat-perbaikan.md, both patches):

* Stages are only composed when linked by *meaningful relation evidence*.
  Facts that merely co-occur in one function are classified as
  "adjacent_only" and can never qualify a chain as strong.
* Control provenance (threat/provenance.py) decides how strongly the
  influence stage may be asserted, and influence PROPAGATES ACROSS
  INTERNAL CALL EDGES: a non-entrypoint function whose proven-influenced
  caller feeds it the same parameter-flow identifiers inherits PROVEN
  influence (the "evidence selection + semantic linkage" fix -- the
  security-relevant helper is reachable through its caller's data, not
  its own visibility).
* state_value_effect distinguishes four linkage levels:
      asset_flow_linked    an asset/allowance/value movement whose
                           arguments share the chain's dataflow identity
      dataflow_linked      a state write sharing that identity
      post_call_derived    Recon's derived post-call adjacency only
      adjacent_only        same-function adjacency, no shared identity
  Only asset_flow_linked / dataflow_linked count as a proven consequence;
  adjacent_only must never qualify as strong evidence.
* downstream_execution_opportunity is graded, never a bare "uncertain":
      PROVEN                  fact-level callback evidence
      STRUCTURALLY_INDICATED  the recipient/target of the dynamic
                              interaction is itself attacker-influenced
      POSSIBLE                dynamic target, recipient not tied to the
                              attacker's data (weak signal only)
      (no stage)              no dynamic interaction = NO_EVIDENCE
  A POSSIBLE grade alone can never upgrade a chain to STRONG.
* Composition strength (grade_composition): STRONG_SECURITY_CHAIN
  requires a full semantic chain -- proven attacker influence, proven
  propagation into a sensitive sink, proven sensitive capability or
  security-sensitive execution, a dataflow/asset-flow-linked consequence,
  and a flow-linked invariant or clearly security-sensitive consequence
  (with the callback being at least STRUCTURALLY_INDICATED unless a
  proven asset-flow consequence makes it a mere amplifier).

Everything is derived from fact types/properties -- never from contract,
function, token, or protocol names -- so the engine behaves identically
when every benchmark-specific identifier is renamed.
"""

from __future__ import annotations

import re
from typing import Any

from . import loader
from .evidence import classify_evidence
from .invariants import InvariantCandidate
from .provenance import (
    ControlProvenance,
    FunctionControlProfile,
    build_control_profiles,
)

# Category label for chain hypotheses (generic vocabulary).
CHAIN_CATEGORY = "security_chain"

# Composition-strength classification (threat-perbaikan.md):
#
#   STRUCTURAL            stages co-exist but the linkage is only
#                         structural; may exist, never a high-interest
#                         finding on its own.
#   SECURITY_RELEVANT     proven caller influence + proven propagation
#                         into an external interaction, but not the full
#                         multi-dimensional semantic chain below.
#   STRONG_SECURITY_CHAIN the full semantic chain -- see grade_composition.
COMPOSITION_STRENGTH_STRUCTURAL = "STRUCTURAL"
COMPOSITION_STRENGTH_SECURITY_RELEVANT = "SECURITY_RELEVANT"
COMPOSITION_STRENGTH_STRONG = "STRONG_SECURITY_CHAIN"

# Effect-linkage levels (strongest first).
LINKAGE_ASSET_FLOW = "asset_flow_linked"
LINKAGE_DATAFLOW = "dataflow_linked"
LINKAGE_POST_CALL = "post_call_derived"
LINKAGE_ADJACENT_ONLY = "adjacent_only"
_LINKAGE_RANK = {
    LINKAGE_ASSET_FLOW: 3,
    LINKAGE_DATAFLOW: 2,
    LINKAGE_POST_CALL: 1,
    LINKAGE_ADJACENT_ONLY: 0,
}

# Downstream-execution grades (strongest first).
DOWNSTREAM_PROVEN = "PROVEN"
DOWNSTREAM_STRUCTURALLY_INDICATED = "STRUCTURALLY_INDICATED"
DOWNSTREAM_POSSIBLE = "POSSIBLE"
# NO_EVIDENCE is represented by the stage being absent entirely.

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Solidity/language vocabulary that carries no dataflow identity and must
# never be treated as a shared identifier between two facts.
_IDENTIFIER_STOPWORDS = frozenset({
    "address", "bool", "string", "bytes", "uint", "uint256", "int", "int256",
    "true", "false", "this", "msg", "sender", "call", "callvalue",
    "abi", "data", "require", "return", "returns", "memory", "calldata",
    "storage", "public", "external", "internal", "private", "view", "pure",
    "payable", "new", "type", "contract", "interface", "library", "note",
    "temporal_proximity", "immediate", "nearby", "unknown", "amount_expression",
    # fact-type vocabulary: Recon's own type names are engine vocabulary,
    # never dataflow identity
    "parameter", "parameters", "asset_operation", "external_call",
    "low_level_call", "contract_creation", "external_call_surface",
    "state_write", "post_call_state_effect", "capability",
})


def _fact_identifiers(fact: dict[str, Any]) -> set[str]:
    """Identifier tokens that carry the dataflow identity of a fact.

    Collected from the fact's subject names and the expressions it
    references (call arguments, amount expressions, target expressions,
    flow roots). Purely structural vocabulary (types, keywords) is
    excluded so that two facts never appear "linked" merely because both
    mention e.g. `address` or `call`.
    """
    tokens: set[str] = set()
    subj = fact.get("subject") or {}
    props = fact.get("properties") or {}
    for name in (subj.get("name"), subj.get("origin"), subj.get("capability")):
        if isinstance(name, str):
            tokens.update(t for t in _TOKEN_RE.findall(name) if t.lower() not in _IDENTIFIER_STOPWORDS)
    sv = subj.get("state_variable")
    if isinstance(sv, str):
        # only the variable basename, not the contract/file path noise
        base = sv.rsplit("::", 1)[-1].split("#")[0]
        tokens.update(t for t in _TOKEN_RE.findall(base) if t.lower() not in _IDENTIFIER_STOPWORDS)
    for key in ("arguments", "amount_expression", "argument_expression",
                "root_name", "target_expression"):
        val = props.get(key)
        if isinstance(val, str):
            val = [val]
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    tokens.update(
                        t for t in _TOKEN_RE.findall(item)
                        if t.lower() not in _IDENTIFIER_STOPWORDS
                    )
    # origin-chain hops carry the dataflow root names
    hops = props.get("chain")
    if isinstance(hops, list):
        for hop in hops:
            if isinstance(hop, dict) and isinstance(hop.get("name"), str):
                tokens.update(
                    t for t in _TOKEN_RE.findall(hop["name"])
                    if t.lower() not in _IDENTIFIER_STOPWORDS
                )
    return {t.lower() for t in tokens}


def _recipient_identifiers(fact: dict[str, Any]) -> set[str]:
    """Identity of the RECIPIENT/TARGET side of an interaction only (its
    target expression) -- deliberately excluding call arguments, so that
    'attacker controls the calldata' is never conflated with 'attacker
    chooses who executes'."""
    props = fact.get("properties") or {}
    tokens: set[str] = set()
    tgt = props.get("target_expression")
    if isinstance(tgt, str):
        tokens |= {
            t.lower() for t in _TOKEN_RE.findall(tgt)
            if t.lower() not in _IDENTIFIER_STOPWORDS
        }
    return tokens


def _argument_identifiers(fact: dict[str, Any]) -> set[str]:
    """Identity of the ARGUMENT side of an interaction (call arguments /
    argument expressions)."""
    props = fact.get("properties") or {}
    tokens: set[str] = set()
    for key in ("arguments", "argument_expression"):
        val = props.get(key)
        if isinstance(val, str):
            val = [val]
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    tokens |= {
                        t.lower() for t in _TOKEN_RE.findall(item)
                        if t.lower() not in _IDENTIFIER_STOPWORDS
                    }
    return tokens


def _flow_identity(profile: FunctionControlProfile) -> set[str]:
    """Identifier identity of the ATTACKER-INFLUENCED data: the
    parameter-rooted flows and relationship-chain facts. Only fact-level
    expressions count -- relationship-chain step prose ("parameter(s) of
    transferFrom") mentions call-structure words that must never become
    dataflow identity. This is what downstream identifiers must overlap
    to count as attacker-linked."""
    identity: set[str] = set()
    for fact in profile.parameter_rooted_flows + profile.relationship_chains:
        identity |= _fact_identifiers(fact)
    return identity


def _chain_identity(profile: FunctionControlProfile) -> set[str]:
    """Dataflow identity of the chain's influence/interaction evidence:
    the attacker flows above plus the interaction facts (an effect that
    shares an interaction's arguments is part of the same asset flow,
    e.g. the approval the interaction performs)."""
    return _flow_identity(profile) | {
        t for fact in profile.interaction_facts for t in _fact_identifiers(fact)
    }


# Asset-custody semantics (generic token-standard vocabulary, never
# benchmark identifiers): which side of an asset operation holds custody.
CUSTODY_GRANT = "protocol_grant"      # allowance/authorization granted on
                                      # this contract's own asset account
CUSTODY_OUTBOUND = "protocol_outbound"  # this contract's holdings move out
CUSTODY_SELF_LEDGER = "self_ledger"   # movement on a ledger the analyzed
                                      # contract itself manages
CUSTODY_OTHER = "unclassified"


def _is_authorization_op(fact: dict[str, Any]) -> bool:
    """True for asset operations that GRANT spending authority. The
    grantor of an approve/allowance-family operation is always the calling
    contract's own asset account -- generic token vocabulary, not a
    benchmark name."""
    op = str((fact.get("properties") or {}).get("operation") or "").lower()
    return "approve" in op or "allowance" in op


def _asset_custody(fact: dict[str, Any]) -> str:
    """Classify which custodian an asset operation puts at risk.

    protocol_grant    approve/allowance family: the contract's own account
                      authorizes a spender.
    protocol_outbound value/holdings leave the calling contract (native
                      value transfer, or an explicit transfer whose source
                      side is this contract).
    self_ledger       the movement happens on a ledger the analyzed
                      contract itself manages (self/super target) --
                      attacker moves their own or their chosen parties'
                      entries, not protocol custody.
    unclassified      attacker-funded or unspecified direction.
    """
    props = fact.get("properties") or {}
    if fact.get("type") == "eth_transfer":
        # call{value:} always spends the calling contract's balance
        return CUSTODY_OUTBOUND
    if _is_authorization_op(fact):
        return CUSTODY_GRANT
    target = str(props.get("target_expression") or "").lower()
    if target in ("super", "this") or "address(this)" in target:
        return CUSTODY_SELF_LEDGER
    args = props.get("arguments")
    if isinstance(args, list) and args and isinstance(args[0], str):
        # transfer-family: the first argument is the source side; a
        # this-contract source means protocol holdings move out
        if "this" in args[0].lower():
            return CUSTODY_OUTBOUND
    return CUSTODY_OTHER


def classify_downstream_fact(
    fact: dict[str, Any], identity: set[str]
) -> str:
    """Linkage level of one downstream effect fact against the chain's
    dataflow identity (threat-perbaikan.md #3/#6).

    An asset movement is asset_flow_linked -- the strongest consequence --
    only when the SAME asset/allowance flow is involved AND the movement
    puts the contract's own custody at risk (a granted authorization or an
    outbound transfer). Attacker-funded inflows and movements on a
    self-managed ledger are real dataflow consequences but not protocol
    custody risks, so they grade dataflow_linked at most. Function-level
    asset presence is never a substitute for linked asset flow."""
    ftype = fact.get("type", "")
    if ftype == "post_call_state_effect":
        return LINKAGE_POST_CALL
    shares_identity = bool(_fact_identifiers(fact) & identity)
    if ftype in ("asset_operation", "eth_transfer"):
        if not shares_identity:
            return LINKAGE_ADJACENT_ONLY
        return (
            LINKAGE_ASSET_FLOW
            if _asset_custody(fact) in (CUSTODY_GRANT, CUSTODY_OUTBOUND)
            else LINKAGE_DATAFLOW
        )
    # state_write and any other effect: causal/dataflow linkage required
    return LINKAGE_DATAFLOW if shares_identity else LINKAGE_ADJACENT_ONLY


def _fact_line(fact: dict[str, Any]) -> int | None:
    """Source line of a fact, when Recon recorded one. Used purely for
    sequencing (authorization -> execution -> check), never for matching."""
    line = (fact.get("source") or {}).get("line_start")
    return line if isinstance(line, int) else None


def paired_probe_validation(
    profile: FunctionControlProfile,
) -> tuple[str, list[dict[str, Any]], set[str]] | None:
    """Detect a pre/post delta validation: the SAME probe expression is
    captured into two different locals, the two values are compared
    (delta/equality arithmetic), and a failure path (revert/require)
    consumes the comparison.

    This is the generic "balance/state validation" concept: a check that
    probes one quantity before and after some window and rejects on
    unexpected change. Returns (probe_expression, facts, variable_names)
    or None. Purely structural -- no token/protocol vocabulary involved.
    """
    by_expr: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for origin in profile.local_origin_facts:
        expr = str((origin.get("properties") or {}).get("expression") or "")
        var = str((origin.get("subject") or {}).get("variable") or "")
        if expr and var:
            by_expr.setdefault(expr, []).append((var, origin))
    for expr, pairs in by_expr.items():
        names = {v for v, _f in pairs}
        if len(names) < 2:
            continue  # the same quantity must be probed twice
        for arith in profile.arithmetic_facts:
            props = arith.get("properties") or {}
            text = f"{props.get('left_operand', '')} {props.get('right_operand', '')}"
            mentioned = [n for n in names if n and n in text]
            if len(mentioned) < 2:
                continue  # comparison must span both probe values
            facts = [f for _v, f in pairs] + [arith]
            comp_line = _fact_line(arith)
            if comp_line is not None:
                revert = next(
                    (v for v in profile.validation_facts
                     if (_fact_line(v) or -1) >= comp_line),
                    None,
                )
                if revert is not None:
                    facts.append(revert)
            return expr, facts, names
    return None


def attacker_linked_authorizations(
    profile: FunctionControlProfile, identity: set[str]
) -> list[dict[str, Any]]:
    """Authorization-granting asset operations whose beneficiary/arguments
    share the chain's dataflow identity: the caller chooses who receives
    spending authority over this contract's assets."""
    return [
        f for f in profile.downstream_facts
        if f.get("type") == "asset_operation"
        and _is_authorization_op(f)
        and (_fact_identifiers(f) & identity)
    ]


def linked_downstream_facts(
    profile: FunctionControlProfile,
    identity: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split downstream facts into (linked, post_call, adjacent_only).

    Linked = asset-flow- or dataflow-linked against the given identity
    (defaults to the chain identity). Kept as a public helper for the
    cross-contract lens."""
    if identity is None:
        identity = _chain_identity(profile)
    linked: list[dict[str, Any]] = []
    post_call: list[dict[str, Any]] = []
    adjacent: list[dict[str, Any]] = []
    for fact in profile.downstream_facts:
        level = classify_downstream_fact(fact, identity)
        if level in (LINKAGE_ASSET_FLOW, LINKAGE_DATAFLOW):
            linked.append(fact)
        elif level == LINKAGE_POST_CALL:
            post_call.append(fact)
        else:
            adjacent.append(fact)
    return linked, post_call, adjacent


# Backwards-compatible alias (previous patch name).
_linked_downstream_facts = linked_downstream_facts


def grade_downstream_execution(
    profile: FunctionControlProfile,
    dynamic: list[dict[str, Any]],
    flow_identity: set[str],
) -> str | None:
    """Grade the downstream-execution opportunity (threat-perbaikan.md #4).

    Returns None when there is no dynamic interaction (NO_EVIDENCE --
    no stage is emitted at all).
    """
    if not dynamic:
        return None
    # Fact-level callback evidence: an explicit callback capability or an
    # asserted callback relationship on this function.
    for cap in profile.sensitive_capability_facts:
        if (cap.get("subject") or {}).get("capability") == "can_invoke_external_callback":
            return DOWNSTREAM_PROVEN
    if profile.callback_evidence_facts:
        return DOWNSTREAM_PROVEN
    # The recipient/target itself traces to attacker-influenced
    # expressions: the attacker can point the call at code of their
    # choosing -- structurally indicated downstream execution. Only the
    # target side counts: attacker-controlled calldata to a fixed
    # recipient is a different (weaker) signal.
    for fact in dynamic:
        if _recipient_identifiers(fact) & flow_identity:
            return DOWNSTREAM_STRUCTURALLY_INDICATED
    return DOWNSTREAM_POSSIBLE


def inherited_influence(
    profiles: dict[str, FunctionControlProfile],
) -> dict[str, list[tuple[str, dict[str, Any], set[str]]]]:
    """Propagate PROVEN influence across internal call edges.

    For every non-entrypoint function F with parameter-rooted flows, if a
    caller C (via an internal_call fact) has PROVEN provenance of its own
    and C's attacker-influenced flow identifiers overlap F's, then F's
    parameters are attacker-influenced through C: record
    (caller_fn_key, internal_call_fact, shared_identifiers).

    This is the generic "evidence selection" fix: the security-relevant
    helper inherits influence from its caller's data instead of being
    discarded because its own visibility is private.
    """
    inheritance: dict[str, list[tuple[str, dict[str, Any], set[str]]]] = {}
    for caller_key, caller in profiles.items():
        if caller.provenance is not ControlProvenance.PROVEN:
            continue
        caller_identity = set()
        for fact in caller.parameter_rooted_flows + caller.relationship_chains:
            caller_identity |= _fact_identifiers(fact)
        for edge in caller.internal_call_facts:
            callee_key = (edge.get("properties") or {}).get("callee_function", "")
            callee = profiles.get(callee_key)
            if callee is None or callee.provenance is ControlProvenance.PROVEN:
                continue  # only functions that need inheritance
            if not callee.parameter_rooted_flows:
                continue  # nothing propagates onward without flows
            callee_identity = set()
            for fact in callee.parameter_rooted_flows:
                callee_identity |= _fact_identifiers(fact)
            shared = caller_identity & callee_identity
            if shared:
                inheritance.setdefault(callee_key, []).append(
                    (caller_key, edge, shared)
                )
    return inheritance


def grade_composition(
    provenance: ControlProvenance,
    *,
    propagation: bool,
    sensitive_execution: bool,
    authority: bool,
    effect_linkage: str | None,
    invariant_flow_linked: bool = False,
    downstream_grade: str | None = None,
    validation_gap: bool = False,
) -> str:
    """Canonical composition-strength grading (threat-perbaikan.md #4/#5).

    STRONG_SECURITY_CHAIN requires the full semantic chain:
      1. proven attacker influence,
      2. proven argument/control propagation,
      3. proven sensitive capability/authority OR security-sensitive
         external execution,
      4. a proven linked consequence (asset_flow_linked or
         dataflow_linked -- post-call/adjacent effects never qualify),
      5. a flow-linked invariant, a delta-validation gap around the
         attacker-influenced execution, OR a clearly security-sensitive
         consequence (protocol-custody asset flow, or a dataflow-linked
         consequence wielded through sensitive authority with at least
         structurally-indicated downstream execution),
      6. downstream execution at least STRUCTURALLY_INDICATED -- unless a
         proven protocol-custody asset-flow consequence makes the
         callback a mere optional amplifier.
    """
    influence = provenance is ControlProvenance.PROVEN
    if not (influence and propagation):
        return COMPOSITION_STRENGTH_STRUCTURAL
    linked_consequence = effect_linkage in (LINKAGE_ASSET_FLOW, LINKAGE_DATAFLOW)
    security_sensitive_consequence = (
        effect_linkage == LINKAGE_ASSET_FLOW
        or (
            effect_linkage == LINKAGE_DATAFLOW
            and authority
            and downstream_grade in (DOWNSTREAM_STRUCTURALLY_INDICATED, DOWNSTREAM_PROVEN)
        )
    )
    callback_ok = downstream_grade in (
        DOWNSTREAM_STRUCTURALLY_INDICATED, DOWNSTREAM_PROVEN,
    ) or effect_linkage == LINKAGE_ASSET_FLOW
    if (
        (authority or sensitive_execution)
        and linked_consequence
        and (
            invariant_flow_linked
            or validation_gap
            or security_sensitive_consequence
        )
        and callback_ok
    ):
        return COMPOSITION_STRENGTH_STRONG
    return COMPOSITION_STRENGTH_SECURITY_RELEVANT


def _invariant_flow_linked(
    invariant, linked_fact_ids: set[str]
) -> bool:
    """An invariant candidate may only strengthen the chain when it is
    tied to the SAME dataflow/asset flow: its involved facts must include
    evidence from the chain's linked flow/interaction/effect facts --
    never mere function-level participation in the invariant domain."""
    if invariant is None:
        return False
    return bool(set(invariant.involved_facts) & linked_fact_ids)


def compose_security_chains(
    recon: loader.ReconArtifact,
    invariants: list[InvariantCandidate],
    next_id,
) -> list:
    """Generate multi-stage security hypotheses from control profiles.

    One hypothesis per function whose evidence supports at least
    [influence or proven propagation] + [external interaction], plus the
    downstream-effect / invariant stages when facts support them. The
    bucket layer in composition.py keeps handling unconnected
    co-occurring signals; this layer only ever emits relation-backed
    chains.
    """
    from .hypothesis import ThreatHypothesis  # deferred: avoid import cycle

    profiles = build_control_profiles(recon)
    inheritance = inherited_influence(profiles)
    inv_by_function: dict[str, InvariantCandidate] = {}
    for inv in invariants:
        for fn in inv.involved_functions:
            inv_by_function.setdefault(fn, inv)

    out: list[ThreatHypothesis] = []

    for fn_key in sorted(profiles):
        profile = profiles[fn_key]
        own_provenance = profile.provenance
        inherited = inheritance.get(fn_key, [])
        provenance = (
            ControlProvenance.PROVEN if inherited else own_provenance
        )
        if provenance is ControlProvenance.UNKNOWN:
            continue  # no influence evidence: nothing to compose a chain from
        if not profile.interaction_facts:
            continue  # influence without a downstream interaction is not a chain

        linked = (
            profile.relationship_chains
            or profile.parameter_rooted_flows
            or profile.input_origin_facts
        )
        if not linked:
            continue

        invariant = inv_by_function.get(fn_key)
        chain, observed, uncertainties, grading = _build_chain_steps(
            fn_key, profile, provenance, inherited, invariant
        )
        if len(chain) < 2:
            continue

        strength = grade_composition(provenance, **grading)
        h = _hypothesis_from_chain(
            fn_key, profile, provenance, chain, observed, uncertainties,
            invariant, next_id, recon, strength, inherited,
        )
        out.append(h)

    return out


def _build_chain_steps(
    fn_key: str,
    profile: FunctionControlProfile,
    provenance: ControlProvenance,
    inherited: list[tuple[str, dict[str, Any], set[str]]],
    invariant: InvariantCandidate | None,
):
    """Assemble the ordered chain stages with per-step evidence and
    uncertainty. Returns (steps, observed_fact_ids, uncertainty_parts,
    grading_inputs)."""
    steps: list[dict[str, Any]] = []
    observed: list[str] = []
    uncertainties: list[str] = []

    def _ids(facts: list[dict[str, Any]]) -> list[str]:
        return sorted({f.get("id", "") for f in facts if f.get("id")})

    flow_identity = _flow_identity(profile)
    chain_identity = _chain_identity(profile)

    # --- Stage 1: untrusted influence -----------------------------------
    influence_facts = profile.input_origin_facts + profile.relationship_chains
    if influence_facts or profile.parameter_rooted_flows:
        ids = _ids(influence_facts)
        observed.extend(ids)
        if inherited:
            callers = ", ".join(sorted({c for c, _e, _s in inherited}))
            shared = sorted(set().union(*(s for _c, _e, s in inherited)))
            ids = sorted(set(ids) | {e.get("id", "") for _c, e, _s in inherited if e.get("id")})
            desc = (
                f"Any external caller influences the inputs of {fn_key} "
                f"through an internal call edge from {callers}: the caller "
                f"is externally reachable with proven caller-controlled "
                f"inputs, and the same value identifiers "
                f"({', '.join(shared)}) flow into {fn_key}'s parameters."
            )
            status = "proven"
        elif provenance is ControlProvenance.PROVEN:
            desc = (
                f"Any external caller can choose the inputs of {fn_key} "
                f"(externally reachable function; caller-controlled input "
                f"origins and/or an asserted caller-control relationship)."
            )
            status = "proven"
        else:
            desc = (
                f"The inputs of {fn_key} are plausibly caller-chosen "
                f"(externally reachable), but no fact-level dataflow proof "
                f"was found."
            )
            status = "inferred"
            uncertainties.append(
                "Caller control over the inputs is inferred from external "
                "reachability, not proven by dataflow evidence."
            )
        steps.append({"stage": "untrusted_influence", "description": desc, "fact_ids": ids, "status": status})

    # --- Stage 2: propagation through arguments/dataflow ---------------
    propagation = False
    if profile.parameter_rooted_flows:
        ids = _ids(profile.parameter_rooted_flows)
        observed.extend(ids)
        propagation = True
        steps.append({
            "stage": "argument_propagation",
            "description": (
                "Arguments of calls made in this function trace back to "
                "those caller-chosen parameters (parameter-rooted argument "
                "origin chains)."
            ),
            "fact_ids": ids,
            "status": "proven",
        })

    # --- Stage 3: security-relevant external execution ------------------
    interaction_ids = _ids(profile.interaction_facts)
    observed.extend(interaction_ids)
    dynamic = profile.dynamic_interactions
    # Security-sensitive execution: the attacker-influenced data reaches
    # the RECIPIENT of a dynamic interaction (they choose who executes),
    # or the ARGUMENTS of a low-level/creation call (they choose what it
    # executes with).
    sensitive_execution = any(
        _recipient_identifiers(f) & flow_identity for f in dynamic
    ) or any(
        f.get("type") in ("low_level_call", "contract_creation")
        and (_argument_identifiers(f) & flow_identity)
        for f in profile.interaction_facts
    )
    # effect linkage is judged against the full chain identity (flows +
    # interactions): an effect sharing the interaction's arguments is part
    # of the same asset flow.
    linked_fx, post_call_fx, adjacent_fx = linked_downstream_facts(
        profile, chain_identity
    )
    if provenance is ControlProvenance.PROVEN and dynamic and sensitive_execution:
        desc = (
            "The caller-influenced inputs reach an external interaction "
            "with a dynamically resolved target the caller's data "
            "identifies, giving the caller influence over externally "
            "executed code and/or its arguments."
        )
        status = "proven"
    elif dynamic:
        desc = (
            "An external interaction with a dynamically resolved target "
            "exists in the same function; whether the caller can control "
            "the target or its arguments is not proven."
        )
        status = "inferred"
        uncertainties.append(
            "The external target is resolved dynamically; caller control "
            "over the target/arguments is not established by fact-level "
            "dataflow."
        )
    else:
        desc = (
            "The caller-influenced inputs reach an external interaction "
            "with a statically resolved target (arguments influenced, "
            "target fixed)."
        )
        status = "proven"
    steps.append({
        "stage": "external_execution", "description": desc,
        "fact_ids": interaction_ids, "status": status,
    })

    # --- Stage 3b: downstream execution opportunity (graded) ------------
    downstream_grade = grade_downstream_execution(profile, dynamic, flow_identity)
    if downstream_grade is not None:
        if downstream_grade == DOWNSTREAM_PROVEN:
            cb_status = "proven"
            grade_desc = (
                "Fact-level evidence (callback capability or asserted "
                "callback relationship) shows the recipient can execute "
                "code back into this contract."
            )
        elif downstream_grade == DOWNSTREAM_STRUCTURALLY_INDICATED:
            cb_status = "inferred"
            grade_desc = (
                "The recipient/target of the dynamic interaction is itself "
                "attacker-influenced (it shares the chain's dataflow "
                "identifiers), so the attacker can point the call at code "
                "of their choosing while this function's frame is live. "
                "Runtime dispatch cannot be proven statically."
            )
        else:
            cb_status = "uncertain"
            grade_desc = (
                "Weak signal (POSSIBLE): the recipient/target of a dynamic "
                "external interaction may itself execute code, but nothing "
                "ties the recipient to the attacker's data. Runtime "
                "dispatch cannot be proven statically; this grade alone "
                "can never upgrade the chain to STRONG_SECURITY_CHAIN."
            )
        steps.append({
            "stage": "downstream_execution_opportunity",
            "description": grade_desc,
            "fact_ids": [],
            "status": cb_status,
            "grade": downstream_grade,
            "weak_signal": downstream_grade == DOWNSTREAM_POSSIBLE,
        })
        if downstream_grade != DOWNSTREAM_PROVEN:
            uncertainties.append(
                "Whether the dynamic recipient actually executes code at "
                "runtime (callback/hook) cannot be proven statically; "
                f"downstream-execution grade: {downstream_grade}."
            )

    # --- Stage 3c: asset/token authorization granted to caller data -----
    auth_ops = attacker_linked_authorizations(profile, chain_identity)
    if auth_ops:
        grant_lines = [l for l in (_fact_line(f) for f in auth_ops) if l is not None]
        call_lines = [l for l in (_fact_line(f) for f in dynamic) if l is not None]
        sequenced = bool(
            grant_lines and call_lines and max(grant_lines) <= min(call_lines)
        )
        steps.append({
            "stage": "asset_authorization",
            "description": (
                "An authorization-granting operation gives spending "
                "authority over this contract's own asset account to a "
                "beneficiary chosen through the caller-influenced data"
                + (
                    "; source ordering shows the grant precedes the dynamic "
                    "external execution"
                    if sequenced else ""
                )
                + "."
            ),
            "fact_ids": _ids(auth_ops),
            "status": "observed",
            "linkage": "authorization_grant",
        })
        observed.extend(_ids(auth_ops))

    # --- Stage 4: downstream state/value effect (linkage-graded) --------
    effect_linkage: str | None = None
    if profile.downstream_facts:
        all_fx = linked_fx + post_call_fx + adjacent_fx
        ids = _ids(all_fx)
        observed.extend(ids)
        per_fact = {
            f.get("id"): classify_downstream_fact(f, chain_identity)
            for f in all_fx
        }
        effect_linkage = max(
            (per_fact[f.get("id")] for f in all_fx),
            key=lambda lvl: _LINKAGE_RANK[lvl],
        )
        steps.append({
            "stage": "state_value_effect",
            "description": (
                "Downstream state/value effects, graded by linkage to the "
                f"chain's dataflow identity: strongest={effect_linkage} "
                f"(per fact: {', '.join(sorted(set(per_fact.values())))})."
            ),
            "fact_ids": ids,
            "status": "observed" if linked_fx else "uncertain",
            "linkage": effect_linkage,
        })
        if not linked_fx:
            uncertainties.append(
                "No downstream effect shares the chain's dataflow identity "
                "-- the effects are post-call-derived or same-function "
                "adjacency only, which never qualifies as a proven "
                "consequence."
            )

    # --- Stage 4b: validation that may still pass (delta-check gap) -----
    # Generic composition of the pattern: caller-granted authorization /
    # attacker-influenced dynamic execution sitting INSIDE a pre/post
    # delta-validation window. The check probes one quantity twice and
    # rejects on unexpected change -- it cannot observe authorizations
    # granted to caller-chosen spenders, or movements reconciled before
    # the second probe, so it may still pass.
    validation_gap = False
    probe = paired_probe_validation(profile)
    if (
        probe is not None
        and downstream_grade in (DOWNSTREAM_STRUCTURALLY_INDICATED, DOWNSTREAM_PROVEN)
        and (auth_ops or effect_linkage == LINKAGE_ASSET_FLOW)
    ):
        _expr, probe_facts, _names = probe
        probe_lines = [l for l in (_fact_line(f) for f in probe_facts) if l is not None]
        call_lines = [l for l in (_fact_line(f) for f in dynamic) if l is not None]
        if probe_lines and call_lines and min(probe_lines) <= min(call_lines) <= max(probe_lines):
            validation_gap = True
            ids = _ids(probe_facts)
            observed.extend(ids)
            steps.append({
                "stage": "validation_gap",
                "description": (
                    "A pre/post delta validation brackets the "
                    "attacker-influenced dynamic execution: the same probe "
                    "expression is captured on both sides of the call "
                    "window and compared, with a failure path. Such a "
                    "check validates only the probed quantity at probe "
                    "time; authorizations granted to caller-chosen "
                    "spenders before or during the window are invisible to "
                    "it, so the validation may still pass while the "
                    "granted authority persists."
                ),
                "fact_ids": ids,
                "status": "inferred",
                "linkage": "validation_gap",
            })
            uncertainties.append(
                "Whether the delta validation actually fails to cover the "
                "granted authorization depends on the spender's exercise "
                "timing relative to the probe window."
            )

    # --- Stage 5: invariant concern (flow-linked only) -------------------
    flow_linked_ids = set(
        _ids(profile.parameter_rooted_flows + profile.interaction_facts + linked_fx)
    )
    invariant_attached = False
    if _invariant_flow_linked(invariant, flow_linked_ids):
        invariant_attached = True
        steps.append({
            "stage": "invariant_concern",
            "description": (
                f"Invariant candidate {invariant.id} is tied to the SAME "
                f"dataflow/asset flow (its evidence includes the chain's "
                "linked flow/interaction/effect facts): {invariant.statement}"
            ),
            "fact_ids": sorted(set(invariant.involved_facts) & flow_linked_ids),
            "status": "uncertain",
            "linkage": "flow_linked",
        })
        uncertainties.append(
            f"Invariant {invariant.id} is a candidate, not a confirmed "
            f"protocol invariant: {invariant.uncertainty}"
        )

    grading = {
        "propagation": propagation,
        "sensitive_execution": bool(sensitive_execution),
        "authority": profile.has_sensitive_capability,
        "effect_linkage": effect_linkage,
        "invariant_flow_linked": invariant_attached,
        "downstream_grade": downstream_grade,
        "validation_gap": validation_gap,
    }
    return steps, sorted(set(observed)), uncertainties, grading


def _hypothesis_from_chain(
    fn_key, profile, provenance, chain, observed, uncertainty_parts,
    invariant, next_id, recon, strength, inherited,
):
    from .hypothesis import ThreatHypothesis

    stage_names = [s["stage"] for s in chain]
    invariant_attached = "invariant_concern" in stage_names
    affected_functions = [fn_key] + sorted({c for c, _e, _s in inherited})
    who = (
        "an external caller"
        if profile.is_entrypoint or provenance is ControlProvenance.PROVEN
        else "the function's caller"
    )
    statement = (
        f"Composed security chain in {fn_key} ({provenance.value} control "
        f"provenance, composition strength {strength}): {who} can influence "
        f"the function's inputs"
        f"{', propagated through an internal call edge' if inherited else ''}; "
        f"{'those inputs flow into call arguments; ' if 'argument_propagation' in stage_names else ''}"
        f"the influence reaches an external interaction"
        f"{' with a dynamically resolved target (attacker-influenced execution opportunity)' if profile.dynamic_interactions else ''}"
        f"{'; caller-chosen spending authority is granted over the contract assets' if 'asset_authorization' in stage_names else ''}"
        f"{'; downstream effects are linkage-graded (' + next(s['linkage'] for s in chain if s.get('stage') == 'state_value_effect') + ')' if any(s.get('stage') == 'state_value_effect' for s in chain) else ''}"
        f"{'; a pre/post delta validation brackets the execution window and may still pass' if 'validation_gap' in stage_names else ''}"
        f"{'; a flow-linked invariant candidate may be violated' if invariant_attached else ''}. "
        f"Stages: {' -> '.join(stage_names)}. This composition has not been "
        f"ruled out as security-relevant."
    )
    uncertainty = " ".join(uncertainty_parts) if uncertainty_parts else (
        "The chain stages are individually evidenced; whether they combine "
        "into an exploitable sequence is not yet verified."
    )

    # Asset impact only from asset-flow-LINKED effects: function-level
    # asset presence is never a substitute for linked asset flow.
    asset_linked = any(
        classify_downstream_fact(f, _chain_identity(profile)) == LINKAGE_ASSET_FLOW
        for f in profile.downstream_facts
    )

    h = ThreatHypothesis(
        hypothesis_id=next_id(),
        category=CHAIN_CATEGORY,
        statement=statement,
        actor="external_user" if profile.is_entrypoint else "unknown_actor",
        observed_facts=observed,
        affected_functions=affected_functions,
        affected_assets=["protocol assets"] if asset_linked else [],
        preconditions=[
            "The function is reachable by the influencing caller",
            "The influenced inputs are not constrained by an authorization "
            "check before reaching the interaction",
            *(
                ["The dynamic recipient executes code that interacts back "
                 "with this contract"]
                if profile.dynamic_interactions else []
            ),
        ],
        uncertainty=uncertainty,
        suggested_next_investigation=(
            f"Walk the chain stages for {fn_key} in order and verify each "
            f"step: the control-provenance evidence, the argument "
            f"propagation into the external interaction, the linkage grade "
            f"of the downstream effects, and (if present) the flow-linked "
            f"invariant candidate."
        ),
        invariant_candidate_id=invariant.id if invariant_attached else "",
        priority="medium_interest",  # provisional; prioritize_all re-scores
        priority_rationale=(
            f"Generic security chain ({provenance.value} provenance, "
            f"{len(chain)} stages, composition strength {strength})"
        ),
        evidence_tier=classify_evidence(observed, [], [], recon).value,
        control_provenance=provenance.value,
        composition_strength=strength,
        chain=chain,
    )
    return h
