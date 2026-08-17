"""Generic Threat Composition Layer.

This module is the "generic reasoning" half of Threat Agent, as opposed to
the category-specific lenses in hypothesis.py (arbitrary_execution,
callback_reentrancy, etc.).

Problem this solves
--------------------
Category-specific lenses only fire for combinations of facts that someone
already thought to encode as a detector. A new bug class (e.g. share-price
manipulation via a donation-attack on a vault) has no chance of surfacing
until a human writes `_generate_share_price_hypotheses()`.

This module instead:
  1. Classifies every Recon fact type into a small set of broad, semantic
     *signal buckets* (asset_movement, state_mutation, authorization, ...).
     Adding support for a brand-new Recon fact type is a one-line addition
     to FACT_TYPE_BUCKETS / CAPABILITY_BUCKETS -- no new detector required.
  2. Looks for functions where "consequential" buckets co-occur (e.g. a
     function that both does arithmetic AND moves assets), and emits a
     hypothesis for that combination even if it doesn't match any named
     vulnerability class.
  3. Best-effort labels the combination with an existing category name if
     it matches a known pattern (purely for readability), and otherwise
     labels it "novel_composition" so it still surfaces instead of being
     silently dropped.

This module knows nothing about "arbitrary execution" or "rounding" as
concepts. It only knows "these signal buckets showed up together in a
function reachable by some actor" -- the specific vulnerability classes in
hypothesis.py are one interpretation layered on top of this, not the only
one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import loader
from .evidence import classify_evidence, EvidenceTier
from .invariants import InvariantCandidate


# --- Fact type -> signal bucket -------------------------------------------
# To make a new Recon fact type participate in generic composition, add it
# here. That's the entire integration cost -- no detector function needed.
FACT_TYPE_BUCKETS: dict[str, str] = {
    "asset_operation": "asset_movement",
    "eth_transfer": "asset_movement",
    "state_write": "state_mutation",
    "arithmetic_operation": "computation",
    "division_operation": "computation",
    "external_call": "external_interaction",
    "low_level_call": "external_interaction",
    "digest_construction_operation": "data_ingestion",
    "signature_recovery_operation": "data_ingestion",
    "input_origin": "data_ingestion",
    "access_controlled_function": "authorization",
    "contract_creation": "lifecycle",
    "selfdestruct_call": "lifecycle",
    "array_mutation": "control_flow",
    "control_flow_structure": "control_flow",
    # security-intelligence layer (recon/relationships.py): pre-composed
    # caller -> parameter -> dynamic-call chains. Every sampled instance so
    # far is pattern="user_influenced_dynamic_call", i.e. an external
    # interaction whose target/calldata traces back to caller-controlled
    # input -- bucket it accordingly.
    "security_relationship_chain": "external_interaction",
    # New fact types for expanded coverage (gas DoS, arithmetic overflow, frontrun, randomness)
    "loop_nesting_depth": "control_flow_complexity",
    "computational_complexity_indicator": "resource_consumption",
    "bitshift_operation": "arithmetic_boundary",
    "randomness_source_usage": "entropy_source",
    "repeated_randomness_consumer": "entropy_reuse",
    "state_dependent_constraint": "temporal_constraint",
    "mev_exposure_indicator": "temporal_vulnerability",
}

# capability facts carry their bucket in the capability name rather than the
# fact type, so they get their own mapping.
CAPABILITY_BUCKETS: dict[str, str] = {
    "can_call_arbitrary_target": "external_interaction",
    "can_delegatecall": "external_interaction",
    "can_invoke_external_callback": "external_interaction",
    "can_transfer_token": "asset_movement",
    "can_transfer_native_value": "asset_movement",
    "can_approve_spender": "asset_movement",
    "can_mint": "asset_movement",
    "can_burn": "asset_movement",
    "can_modify_authorization_state": "authorization",
    "can_create_contracts": "lifecycle",
    "can_selfdestruct": "lifecycle",
}

# Buckets that represent a *consequence* -- something an attacker would
# actually care about influencing. Buckets like data_ingestion/computation/
# control_flow are only interesting in combination with one of these.
CONSEQUENTIAL_BUCKETS = {
    "asset_movement",
    "state_mutation",
    "authorization",
    "lifecycle",
    "external_interaction",
    "resource_consumption",  # Gas DoS consequence
    "temporal_vulnerability",  # Frontrun/MEV consequence
}

# Best-effort labels for recognizable bucket pairs, purely for readability.
# Unmatched combinations still produce a hypothesis -- see _label_for.
NAMED_COMBINATIONS: dict[frozenset, str] = {
    frozenset({"external_interaction", "asset_movement"}): "arbitrary_execution",
    frozenset({"external_interaction", "state_mutation"}): "callback_reentrancy",
    frozenset({"data_ingestion", "state_mutation"}): "accounting_mismatch",
    frozenset({"data_ingestion", "asset_movement"}): "accounting_mismatch",
    frozenset({"computation", "asset_movement"}): "economic_manipulation",
    frozenset({"authorization", "asset_movement"}): "economic_manipulation",
    frozenset({"authorization", "lifecycle"}): "initialization_vulnerability",
    frozenset({"lifecycle", "asset_movement"}): "initialization_vulnerability",
    frozenset({"control_flow", "external_interaction"}): "DoS_griefing",
    frozenset({"control_flow", "asset_movement"}): "DoS_griefing",
    # New patterns for expanded coverage
    frozenset({"control_flow_complexity", "resource_consumption"}): "gas_complexity_dos",
    frozenset({"arithmetic_boundary", "data_ingestion"}): "arithmetic_bound_violation",
    frozenset({"temporal_constraint", "authorization"}): "frontrun_vulnerability",
    frozenset({"temporal_constraint", "external_interaction"}): "frontrun_vulnerability",
    frozenset({"entropy_reuse", "control_flow"}): "randomness_manipulation",
    frozenset({"entropy_source", "control_flow"}): "randomness_manipulation",
}


@dataclass
class FunctionProfile:
    fn_key: str
    is_entrypoint: bool = False
    buckets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def bucket_fact_ids(self, bucket: str) -> list[str]:
        return [f["id"] for f in self.buckets.get(bucket, [])]


def build_function_profiles(recon: loader.ReconArtifact) -> dict[str, FunctionProfile]:
    """Build a generic, bucket-based signal profile for every function.

    This has no notion of specific vulnerability classes -- it only sorts
    facts into broad semantic buckets so arbitrary combinations of buckets
    can be reasoned about generically in generate_composed_hypotheses().
    """
    profiles: dict[str, FunctionProfile] = {}

    def _profile(fn_key: str) -> FunctionProfile:
        if fn_key not in profiles:
            profiles[fn_key] = FunctionProfile(fn_key=fn_key)
        return profiles[fn_key]

    for fn_fact in loader.functions(recon):
        fn_key = fn_fact["subject"]["function"]
        p = _profile(fn_key)
        fn_facts = loader.facts_for_function(recon, fn_key)
        vis = next((f for f in fn_facts if f["type"] == "function_visibility"), None)
        if vis and vis["properties"].get("visibility") in ("external", "public"):
            p.is_entrypoint = True

    for fact in recon.facts_obj.facts:
        ftype = fact.get("type", "")
        subj = fact.get("subject") or {}
        fn_key = subj.get("function") or subj.get("caller")
        if not fn_key:
            continue

        if ftype in ("capability", "unguarded_capability_hypothesis"):
            # unguarded_capability_hypothesis shares the same subject shape
            # (subject.capability) as capability -- it's the same capability
            # vocabulary, just flagged as lacking an observed auth check.
            bucket = CAPABILITY_BUCKETS.get(subj.get("capability", ""))
        else:
            bucket = FACT_TYPE_BUCKETS.get(ftype)

        if not bucket:
            continue
        _profile(fn_key).buckets.setdefault(bucket, []).append(fact)

    return profiles


def _label_for(buckets_present: set) -> tuple[str, bool]:
    """Best-effort (category_label, is_named_match) for a bucket set."""
    for combo, label in NAMED_COMBINATIONS.items():
        if combo <= buckets_present:
            return label, True
    return "novel_composition", False


def _select_bucket_pairs(profile: FunctionProfile) -> list[set]:
    """Enumerate the bucket pairs worth reporting on for this function.

    Two rules, both generic (no vulnerability-class knowledge):
    - Every pair of co-occurring consequential buckets is interesting on
      its own. Pairs are kept separate (rather than merged into one big
      set) so that an unrecognized pair (e.g. authorization + state
      mutation) doesn't get silently absorbed into a recognized one that
      happens to share the same function (e.g. computation + asset
      movement) and lost during global dedup.
    - A single consequential bucket is interesting on an entrypoint if it
      also has at least one supporting (non-consequential) bucket present,
      since that's a signal the consequence is influenced by something
      (decoded data, arithmetic, iteration) rather than a fixed,
      unconditional effect.
    """
    import itertools

    present = set(profile.buckets.keys())
    consequential = present & CONSEQUENTIAL_BUCKETS
    pairs: list[set] = []

    if len(consequential) >= 2:
        for combo in itertools.combinations(sorted(consequential), 2):
            pairs.append(set(combo))
    elif len(consequential) == 1 and profile.is_entrypoint:
        supporting = present - consequential
        for s in supporting:
            pairs.append(consequential | {s})

    return pairs



def _evidence_tier(profile: FunctionProfile, recon: loader.ReconArtifact) -> EvidenceTier:
    """Classify the evidence backing a function's composed signals.

    Uses the canonical classifier from evidence.py (Bug 4: single source of
    truth). Composition hypotheses are function-scoped, so the tier reflects
    the strongest fact-level evidence attached to the function -- including
    facts that are not bucketed (e.g. call_argument_dataflow), because they
    still prove how the function's signals are wired together. The O(1)
    by_function index provides the candidate facts.
    """
    fact_ids = [f.get("id", "") for f in loader.facts_for_function(recon, profile.fn_key)]
    return classify_evidence(fact_ids, [], [], recon)


def generate_composed_hypotheses(
    recon: loader.ReconArtifact,
    invariants: list[InvariantCandidate],
    next_id,
) -> list:
    """Generate hypotheses purely from generic signal-bucket composition.

    Complements (does not replace) the category-specific lenses in
    hypothesis.py. Anything a lens already finds will typically also be
    found here, labeled with the same best-effort category name, and get
    deduplicated by the caller; anything a lens *doesn't* have a detector
    for still surfaces here under "novel_composition" instead of vanishing.
    """
    from .hypothesis import ThreatHypothesis  # deferred: avoid import cycle

    out: list[ThreatHypothesis] = []
    profiles = build_function_profiles(recon)

    inv_by_function: dict[str, str] = {}
    for inv in invariants:
        for fn in inv.involved_functions:
            inv_by_function.setdefault(fn, inv.id)

    for fn_key, profile in sorted(profiles.items()):
        pairs = _select_bucket_pairs(profile)
        if not pairs:
            continue

        # One tier per function: the strongest evidence among the
        # function's facts (canonical classifier, Bug 4).
        tier = _evidence_tier(profile, recon)

        # Group pairs by their best-effort label, merging bucket sets that
        # land on the same label. This keeps unrecognized combinations
        # ("novel_composition") as their own hypothesis instead of being
        # folded into a recognized combination on the same function.
        grouped: dict[str, set] = {}
        for pair in pairs:
            label, _named = _label_for(pair)
            grouped.setdefault(label, set()).update(pair)

        for label, signature in grouped.items():
            fact_ids = sorted({fid for b in signature for fid in profile.bucket_fact_ids(b)})
            if not fact_ids:
                continue
            ordered_buckets = sorted(signature)
            ops_desc = ", ".join(
                f"{b.replace('_', ' ')} ({len(profile.buckets.get(b, []))} fact(s))"
                for b in ordered_buckets
            )

            # Provisional priority per tier; the final evidence-aware
            # priority is (re)assigned by prioritization.prioritize_all,
            # which enforces the tier ceilings (Bug 3).
            if tier is EvidenceTier.GRAPH_REACHABILITY:
                priority = "high_interest"
                uncertainty = (
                    "Multiple proven dependency relations (argument, control, data) "
                    "connect the signals into a coherent chain. This suggests a "
                    "real security pattern that deserves attention. Whether it "
                    "violates a protocol invariant is not yet confirmed."
                )
                suggested_next = (
                    f"Follow the proven chain from {fn_key} through {', '.join(ordered_buckets)} "
                    f"to determine actual security impact."
                )
            elif tier is EvidenceTier.ARGUMENT_DEPENDENCY:
                priority = "medium_interest"
                uncertainty = (
                    "Verified argument/dataflow evidence (e.g. call_argument_dataflow, "
                    "parameter origin) connects inputs to calls in this function, "
                    "but whether this leads to actual security impact is not yet confirmed."
                )
                suggested = f"Analyze the chain {fn_key} → user-controlled target → asset impact. " if "asset_movement" in signature else ""
                suggested_next = (
                    f"{suggested}Check if the dependency creates a real security concern "
                    f"and whether the caller-controlled parameter reaches a sensitive sink."
                )
            elif tier is EvidenceTier.RELATIONSHIP_GROUNDED:
                priority = "medium_interest"
                uncertainty = (
                    "An explicit Recon relationship chain connects these signals, "
                    "but no argument/dataflow dependency (and no graph path) has "
                    "been verified. Whether the relationship implies causation "
                    "requires deeper analysis."
                )
                suggested_next = (
                    f"Inspect the relationship-chain steps for {fn_key}: do they "
                    f"carry actual argument/dataflow dependencies between "
                    f"{', '.join(ordered_buckets)}, or only co-occurrence?"
                )
            else:  # EvidenceTier.CO_OCCURRENCE
                priority = "low_interest"
                uncertainty = (
                    "Signals co-occur in the same function but there is no proven "
                    "data/argument/control dependency. Whether they cause each other "
                    "requires deeper analysis or proof."
                )
                suggested_next = (
                    f"Verify if {', '.join(ordered_buckets)} are causally connected "
                    f"or merely coincidental. Look for data/argument/control dependency chains."
                )

            chain_clause = {
                EvidenceTier.GRAPH_REACHABILITY: "A verified graph path connects these signals. ",
                EvidenceTier.ARGUMENT_DEPENDENCY: "A proven argument/dataflow dependency connects these signals. ",
                EvidenceTier.RELATIONSHIP_GROUNDED: "An explicit Recon relationship chain connects these signals. ",
                EvidenceTier.CO_OCCURRENCE: "",
            }[tier]

            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category=label,
                statement=(
                    f"Function {fn_key} combines the following signals: {ops_desc}"
                    f"{' and is externally reachable' if profile.is_entrypoint else ''}. "
                    f"{chain_clause}"
                    f"This combination has not been ruled out as security-relevant, "
                    f"whether or not it matches a previously catalogued hypothesis "
                    f"category."
                ),
                actor="external_user" if profile.is_entrypoint else "unknown_actor",
                observed_facts=fact_ids,
                affected_functions=[fn_key],
                affected_assets=["protocol assets"] if "asset_movement" in signature else [],
                preconditions=[
                    "Attacker can reach or influence this function"
                    if profile.is_entrypoint
                    else "Function is reachable through some call path (not verified here)",
                    f"The involved signals ({', '.join(ordered_buckets)}) can be chained "
                    f"in a way that violates an implicit protocol assumption",
                ],
                uncertainty=uncertainty,
                suggested_next_investigation=suggested_next,
                invariant_candidate_id=inv_by_function.get(fn_key, ""),
                priority=priority,
                priority_rationale=f"Generic composition ({tier.value})",
                evidence_tier=tier.value,
            )
            out.append(h)

    return out
