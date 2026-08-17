"""Control-provenance model for generic security reasoning.

Distinguishes HOW WELL attacker/caller influence over a behavior is
evidenced, independently of what the behavior is:

    PROVEN    Recon fact-level evidence shows the caller controls inputs
              that provably flow into call arguments (parameter-rooted
              origin chains on an externally reachable function, or a
              security_relationship_chain whose steps are asserted as
              FACT).
    INFERRED  The shape suggests caller influence (externally reachable
              function with a dynamic-target interaction) but no dataflow
              proof ties inputs to the interaction.
    UNKNOWN   No influence evidence at all.

The rule this enforces: "dynamic target + unknown control" must never be
treated as equivalent to "proven attacker-controlled target". Unknown or
inferred provenance lowers confidence/priority; it is never silently
promoted to a strong security hypothesis.

This module is protocol-agnostic: it reasons only over Recon fact types
and properties, never over contract/function/token names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import loader

# input_origin subject.origin values that are chosen by the caller at
# transaction time (block.* environment values are NOT caller-controlled).
CALLER_CONTROLLED_INPUT_ORIGINS = frozenset({
    "msg.sender",
    "msg.value",
    "msg.data",
    "tx.origin",
})

# call_argument_dataflow.origin_kind / call_argument_origin_chain.root_kind
# values whose root is ultimately chosen by the caller of the function.
ATTACKER_REACHABLE_ROOT_KINDS = frozenset({"parameter"})

# interaction fact types whose target/arguments constitute the externally
# reachable execution surface of a function.
INTERACTION_FACT_TYPES = frozenset({
    "external_call",
    "external_call_surface",
    "low_level_call",
    "contract_creation",
})

# downstream effect fact types (state/value consequences inside the same
# function, structurally adjacent to the interaction).
DOWNSTREAM_FACT_TYPES = frozenset({
    "post_call_state_effect",
    "state_write",
    "asset_operation",
    "eth_transfer",
})

# capability fact types that assert a sensitive authority/asset power on
# the function (used as an independent security dimension when grading
# composition strength).
SENSITIVE_CAPABILITY_FACT_TYPES = frozenset({
    "capability",
    "unguarded_capability_hypothesis",
})

# capability names that represent sensitive authority or asset power.
SENSITIVE_CAPABILITY_NAMES = frozenset({
    "can_call_arbitrary_target",
    "can_delegatecall",
    "can_invoke_external_callback",
    "can_transfer_token",
    "can_transfer_native_value",
    "can_approve_spender",
    "can_mint",
    "can_burn",
    "can_modify_authorization_state",
    "can_selfdestruct",
    "can_create_contracts",
})


class ControlProvenance(str, Enum):
    PROVEN = "PROVEN"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def coerce(cls, value: str | None) -> "ControlProvenance":
        try:
            return cls(value) if value else cls.UNKNOWN
        except ValueError:
            return cls.UNKNOWN


@dataclass
class FunctionControlProfile:
    """Influence/provenance evidence for one function, derived purely from
    Recon facts (O(1) index lookups; no name-based reasoning)."""

    fn_key: str
    is_entrypoint: bool = False
    proven_control_facts: list[dict[str, Any]] = field(default_factory=list)
    # caller-controlled input origins (msg.sender / msg.value / msg.data)
    input_origin_facts: list[dict[str, Any]] = field(default_factory=list)
    # parameter-rooted argument flows (influence propagation evidence)
    parameter_rooted_flows: list[dict[str, Any]] = field(default_factory=list)
    # relationship chains asserting caller control (pattern-level FACTs)
    relationship_chains: list[dict[str, Any]] = field(default_factory=list)
    interaction_facts: list[dict[str, Any]] = field(default_factory=list)
    dynamic_interactions: list[dict[str, Any]] = field(default_factory=list)
    downstream_facts: list[dict[str, Any]] = field(default_factory=list)
    # sensitive authority/asset capabilities asserted on this function
    sensitive_capability_facts: list[dict[str, Any]] = field(default_factory=list)
    # internal calls ISSUED by this function (subject.caller = this fn,
    # properties.callee_function = the callee) -- used to propagate
    # influence across call edges.
    internal_call_facts: list[dict[str, Any]] = field(default_factory=list)
    # fact-level callback evidence on this function
    callback_evidence_facts: list[dict[str, Any]] = field(default_factory=list)
    # validation/computation facts used to reason about checks that wrap
    # the interactions (paired pre/post probes, delta comparisons, revert
    # sites) -- see security_chains._paired_probe_validation.
    local_origin_facts: list[dict[str, Any]] = field(default_factory=list)
    arithmetic_facts: list[dict[str, Any]] = field(default_factory=list)
    validation_facts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_sensitive_capability(self) -> bool:
        return bool(self.sensitive_capability_facts)

    @property
    def provenance(self) -> ControlProvenance:
        """Strongest evidenced level of caller control over this function's
        interaction surface. See module docstring for the promotion rules;
        note there is deliberately no path from UNKNOWN to PROVEN without
        fact-level evidence."""
        if self._has_proven_control():
            return ControlProvenance.PROVEN
        if self.is_entrypoint and (self.dynamic_interactions or self.input_origin_facts):
            return ControlProvenance.INFERRED
        return ControlProvenance.UNKNOWN

    def _has_proven_control(self) -> bool:
        # A FACT-certainty relationship chain is Recon's own composed proof
        # that the caller controls inputs which reach a dynamic call.
        for rel in self.relationship_chains:
            props = rel.get("properties") or {}
            if props.get("overall_certainty") != "FACT":
                continue
            if any(
                step.get("actor") == "caller" and step.get("certainty") == "FACT"
                for step in props.get("steps", [])
                if isinstance(step, dict)
            ):
                return True
        # Entrypoint + parameter-rooted flows: anyone can call the function
        # and those parameters provably flow into call arguments.
        return self.is_entrypoint and bool(self.parameter_rooted_flows)


def build_control_profiles(recon: loader.ReconArtifact) -> dict[str, FunctionControlProfile]:
    """Derive a control profile for every function that has at least one
    provenance-relevant fact. Pure fact-composition over the loader's
    O(1) indexes; deterministic ordering everywhere."""
    profiles: dict[str, FunctionControlProfile] = {}

    def _profile(fn_key: str) -> FunctionControlProfile:
        if fn_key not in profiles:
            profiles[fn_key] = FunctionControlProfile(fn_key=fn_key)
        return profiles[fn_key]

    for fact in recon.facts_obj.facts:
        ftype = fact.get("type", "")
        subj = fact.get("subject") or {}
        props = fact.get("properties") or {}
        fn_key = subj.get("function") or subj.get("caller")
        if not fn_key:
            continue

        if ftype == "function_visibility":
            if props.get("visibility") in ("external", "public"):
                _profile(fn_key).is_entrypoint = True
        elif ftype == "input_origin":
            if subj.get("origin") in CALLER_CONTROLLED_INPUT_ORIGINS:
                _profile(fn_key).input_origin_facts.append(fact)
        elif ftype in ("call_argument_origin_chain", "call_argument_dataflow"):
            root = props.get("root_kind") or props.get("origin_kind")
            if root in ATTACKER_REACHABLE_ROOT_KINDS:
                _profile(fn_key).parameter_rooted_flows.append(fact)
        elif ftype == "security_relationship_chain":
            _profile(fn_key).relationship_chains.append(fact)
        elif ftype in INTERACTION_FACT_TYPES:
            p = _profile(fn_key)
            p.interaction_facts.append(fact)
            if props.get("target_status") == "dynamic" or ftype in (
                "low_level_call", "contract_creation",
            ):
                p.dynamic_interactions.append(fact)
        elif ftype in DOWNSTREAM_FACT_TYPES:
            _profile(fn_key).downstream_facts.append(fact)
        elif ftype in SENSITIVE_CAPABILITY_FACT_TYPES:
            if subj.get("capability") in SENSITIVE_CAPABILITY_NAMES:
                _profile(fn_key).sensitive_capability_facts.append(fact)
        elif ftype == "internal_call":
            _profile(fn_key).internal_call_facts.append(fact)
        elif ftype == "callback_relationship":
            _profile(fn_key).callback_evidence_facts.append(fact)
        elif ftype == "local_variable_origin":
            _profile(fn_key).local_origin_facts.append(fact)
        elif ftype == "arithmetic_operation":
            _profile(fn_key).arithmetic_facts.append(fact)
        elif ftype in ("revert_site", "require_statement", "assert_statement"):
            _profile(fn_key).validation_facts.append(fact)

    return profiles
