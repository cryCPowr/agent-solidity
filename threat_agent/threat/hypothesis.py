"""Threat Hypothesis Generator.

Combines Recon facts to generate security-relevant hypotheses.
Each hypothesis references:
- observed_facts (fact IDs from facts.jsonl)
- graph_nodes (node IDs from graph.json)
- graph_edges (edge IDs from graph.json)
- affected_functions (function keys)
- affected_assets (asset expressions)
- invariant_candidate_id (if applicable)

Hypothesis categories (named lenses -- see category-specific _generate_*
functions below):
- arbitrary_execution
- callback_reentrancy
- accounting_mismatch
- rounding_allocation
- signature_replay
- cross_contract_trust
- DoS_griefing
- upgrade_risk
- economic_manipulation
- initialization_vulnerability
- flash_loan_sensitivity

Plus two open-set layers:
- the generic composition layer (composition.py) for signal combinations
  that don't match any named lens:
    - novel_composition (bucket co-occurrence observations)
- the generic security-chain layer (security_chains.py) for multi-stage
  influence -> propagation -> external execution -> effect -> invariant
  compositions backed by relation evidence:
    - security_chain

Architecture
------------
generate_hypotheses() is deliberately NOT just "run N detectors". It runs:
  1. Category-specific lenses (the _generate_* functions below) -- these
     encode well-understood vulnerability patterns and produce detailed,
     specific statements/preconditions.
  2. The generic composition layer (composition.generate_composed_hypotheses)
     -- this reasons over broad signal buckets (asset movement, state
     mutation, computation, ...) with no knowledge of named vulnerability
     classes, so a bug pattern nobody has written a lens for yet still has
     a chance to surface (labeled "novel_composition" if it doesn't match
     a known pattern).
Lenses run first so that, when both layers find the same (category,
functions) combination, the lens's richer statement wins during dedup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import loader
from .evidence import classify_evidence
from .invariants import InvariantCandidate
from .composition import generate_composed_hypotheses


HYPOTHESIS_CATEGORIES = [
    "arbitrary_execution",
    "callback_reentrancy",
    "accounting_mismatch",
    "rounding_allocation",
    "signature_replay",
    "cross_contract_trust",
    "DoS_griefing",
    "upgrade_risk",
    "economic_manipulation",
    "initialization_vulnerability",
    "flash_loan_sensitivity",
    "gas_dos",
    "arithmetic_bound_violation",
    "frontrun_vulnerability",
    "randomness_manipulation",
    "novel_composition",
    "security_chain",
]


@dataclass
class ThreatHypothesis:
    hypothesis_id: str
    category: str
    statement: str
    actor: str = "unknown_actor"
    preconditions: list[str] = field(default_factory=list)
    observed_facts: list[str] = field(default_factory=list)
    graph_nodes: list[str] = field(default_factory=list)
    graph_edges: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    invariant_candidate_id: str = ""
    uncertainty: str = ""
    priority: str = "low_interest"
    priority_rationale: str = ""
    suggested_next_investigation: str = ""
    evidence_tier: str = ""  # canonical tier from threat/evidence.py:
    # "CO_OCCURRENCE" | "RELATIONSHIP_GROUNDED" | "ARGUMENT_DEPENDENCY" | "GRAPH_REACHABILITY"
    # Generic security-chain provenance (see provenance.py); empty for
    # non-chain hypotheses.
    control_provenance: str = ""  # "PROVEN" | "INFERRED" | "UNKNOWN" | ""
    # Generic security-chain composition strength (security_chains.py):
    # "STRUCTURAL" | "SECURITY_RELEVANT" | "STRONG_SECURITY_CHAIN" | ""
    composition_strength: str = ""
    # Ordered chain stages (security_chains.py): dicts with stage /
    # description / fact_ids / status. Empty for non-chain hypotheses.
    chain: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "category": self.category,
            "statement": self.statement,
            "actor": self.actor,
            "preconditions": self.preconditions,
            "observed_facts": self.observed_facts,
            "graph_nodes": self.graph_nodes,
            "graph_edges": self.graph_edges,
            "affected_functions": self.affected_functions,
            "affected_assets": self.affected_assets,
            "invariant_candidate_id": self.invariant_candidate_id,
            "uncertainty": self.uncertainty,
            "priority": self.priority,
            "priority_rationale": self.priority_rationale,
            "suggested_next_investigation": self.suggested_next_investigation,
            "evidence_tier": self.evidence_tier,
            "control_provenance": self.control_provenance,
            "composition_strength": self.composition_strength,
            "chain": self.chain,
        }


def generate_hypotheses(
    recon: loader.ReconArtifact,
    invariants: list[InvariantCandidate],
) -> list[ThreatHypothesis]:
    """Generate threat hypotheses from Recon facts.

    Uses combination-based reasoning:
    - Not shallow rules ("external call = vulnerability")
    - But structured combinations of proven facts
    - Each hypothesis references concrete Recon facts

    IDs are deterministic: a content-derived hash over (category, normalized
    statement, sorted fact ids, graph references, invariant). Generation
    order does not influence the final ID.
    """
    import hashlib

    def _deterministic_id(h: ThreatHypothesis) -> str:
        stmt = " ".join(h.statement.strip().lower().split())
        components = [
            h.category,
            stmt,
            "|".join(sorted(h.observed_facts)),
            "|".join(sorted(h.graph_nodes)),
            "|".join(sorted(h.graph_edges)),
            h.invariant_candidate_id or "",
            "|".join(sorted(h.affected_functions)),
        ]
        raw = "\n".join(components).encode("utf-8")
        return f"H-{hashlib.sha256(raw).hexdigest()[:10]}"

    hypotheses: list[ThreatHypothesis] = []
    counter = 0

    def _next_id() -> str:
        # Temporary placeholder ID; overwritten by deterministic ID below.
        nonlocal counter
        counter += 1
        return f"H-TMP-{counter:03d}"

    # --- Category 1: Arbitrary Execution + Token + Callback ---
    _generate_arbitrary_execution(recon, hypotheses, _next_id, invariants)

    # --- Category 2: Callback/Reentrancy ---
    _generate_callback_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 3: Accounting Mismatch ---
    _generate_accounting_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 4: Rounding/Allocation ---
    _generate_rounding_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 5: Signature Replay ---
    _generate_signature_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 6: Cross-Contract Trust ---
    _generate_cross_contract_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 7: DoS/Griefing ---
    _generate_dos_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 8: Economic Manipulation ---
    _generate_economic_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 9: Gas DoS ---
    _generate_gas_dos_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 10: Arithmetic Bound Violation ---
    _generate_arithmetic_overflow_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 11: Frontrun Vulnerability ---
    _generate_frontrun_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 12: Randomness Manipulation ---
    _generate_randomness_bias_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Generic composition layer: catches signal combinations that don't
    # match any named lens above (see composition.py). Runs after the
    # lenses so lens statements win ties during dedup below. ---
    from .composition import generate_composed_hypotheses  # deferred import

    hypotheses.extend(generate_composed_hypotheses(recon, invariants, _next_id))

    # --- Generic security-chain layer (security_chains.py): multi-stage
    # influence -> propagation -> external execution -> effect -> invariant
    # compositions, only where relation evidence links the stages. ---
    from .security_chains import compose_security_chains  # deferred import

    hypotheses.extend(compose_security_chains(recon, invariants, _next_id))

    # --- Assign deterministic content-derived IDs (Problem 4) ---
    for h in hypotheses:
        h.hypothesis_id = _deterministic_id(h)

    # --- Deduplicate on a rich key (Problem 5): not just category +
    # affected functions. Two hypotheses over the same function that mean
    # different things (different statement / facts / edges) must both
    # survive. ---
    seen: set[tuple] = set()
    unique: list[ThreatHypothesis] = []
    for h in hypotheses:
        key = (
            h.category,
            " ".join(h.statement.strip().lower().split()),
            tuple(sorted(h.observed_facts)),
            tuple(sorted(h.graph_edges)),
            h.invariant_candidate_id or "",
        )
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique


def _find_function_facts(recon: loader.ReconArtifact, fn_key: str) -> list[dict[str, Any]]:
    """Helper to get all facts for a function."""
    return loader.facts_for_function(recon, fn_key)


def _generate_arbitrary_execution(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Arbitrary target + approval + callback combination.

    Combinations investigated:
    - Function with can_call_arbitrary_target AND can_transfer_token/can_approve_spender
    - Dynamic call target where caller controls the target parameter
    - Low-level call with user-supplied calldata
    """
    # Find capabilities
    cap_fact_map: dict[str, list[dict]] = {}
    for cap_fact in recon.facts_obj.by_type.get("capability", []):
        fn = cap_fact["subject"].get("function", "")
        cap_name = cap_fact["subject"]["capability"]
        cap_fact_map.setdefault(fn, []).append(cap_fact)

    # Find functions with BOTH arbitrary call AND token capability
    for fn_key, caps in cap_fact_map.items():
        cap_names = {c["subject"]["capability"] for c in caps}
        if "can_call_arbitrary_target" not in cap_names:
            continue

        # Check if it also has token-related capability
        token_caps = cap_names & {"can_transfer_token", "can_approve_spender", "can_transfer_native_value"}
        if not token_caps:
            continue

        # HIGH/VERY_HIGH interest: has arbitrary call + token control
        h = ThreatHypothesis(
            hypothesis_id=next_id(),
            category="arbitrary_execution",
            statement=(
                f"Function {fn_key} can call arbitrary targets while having "
                f"{' '.join(sorted(token_caps))} capability. "
                f"If an attacker can control the call target and calldata, "
                f"they may redirect protocol assets."
            ),
            actor="external_user",
            preconditions=[
                "Attacker controls call target parameter",
                "Attacker controls calldata",
                "Target responds to callback",
            ],
            observed_facts=[c["id"] for c in caps],
            affected_functions=[fn_key],
            affected_assets=["protocol tokens", "protocol ETH"],
            uncertainty=(
                "Whether the target is user-controlled depends on dataflow "
                "from parameters through the function body. Verification "
                "requires examining _src_text values."
            ),
            suggested_next_investigation=(
                f"Trace dataflow from function parameters to call target "
                f"in {fn_key}. Check if target is a direct parameter, "
                f"derived from parameter, or from internal state."
            ),
        )
        # Assign priority
        if "can_call_arbitrary_target" in cap_names and len(token_caps) >= 2:
            h.priority = "very_high_interest"
            h.priority_rationale = (
                "Combines arbitrary execution with multiple token capabilities: "
                "maximum potential for asset redirection"
            )
        else:
            h.priority = "high_interest"
            h.priority_rationale = (
                "Arbitrary call target with token capability creates "
                "potential asset redirection surface"
            )
        h.evidence_tier = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
        out.append(h)

    # Low-level call with dynamic target
    for llc in recon.facts_obj.by_type.get("low_level_call", []):
        fn_key = llc["subject"].get("function") or llc["subject"].get("caller")
        props = llc.get("properties", {})
        if props.get("target_status") == "dynamic":
            fn_facts = _find_function_facts(recon, fn_key) if fn_key else []
            related_caps = [
                f["id"] for f in fn_facts
                if f["type"] == "capability"
            ]
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="arbitrary_execution",
                statement=(
                    f"Low-level call in {fn_key or 'unknown function'} has dynamic target. "
                    f"External calldata flows into call."
                ),
                actor="caller",
                observed_facts=[llc["id"]] + related_caps,
                affected_functions=[fn_key] if fn_key else [],
                uncertainty="Target derivation depends on function dataflow.",
                suggested_next_investigation=(
                    "Trace how the call target expression is constructed: "
                    "is it a direct parameter, state variable, or derived?"
                ),
                priority="high_interest" if related_caps else "medium_interest",
                priority_rationale="Low-level call with dynamic target is a trust boundary crossing",
            )
            h.evidence_tier = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
            out.append(h)


def _generate_callback_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Callback/reentrancy surfaces.

    Focus: functions that call external targets AND have state modifications
    after the call, or functions that are potential callback targets.
    """
    # Functions with external calls + state writes
    ext_calls = recon.facts_obj.by_type.get("external_call", [])
    state_writes = recon.facts_obj.by_type.get("state_write", [])
    write_funcs = {sw["subject"]["function"] for sw in state_writes}

    for ext in ext_calls:
        fn_key = ext["subject"].get("function")
        if fn_key and fn_key in write_funcs:
            fn_facts = _find_function_facts(recon, fn_key)
            observed = [ext["id"]] + [f["id"] for f in fn_facts if f["type"] in ("capability", "arithmetic_operation")]
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="callback_reentrancy",
                statement=(
                    f"Function {fn_key} performs external call AND state writes. "
                    f"If the external call triggers a callback into this function "
                    f"or related functions, reentrancy may allow state modification "
                    f"before the call completes."
                ),
                actor="external_contract",
                observed_facts=observed,
                affected_functions=[fn_key],
                preconditions=[
                    "External target can call back into protocol",
                    "Protocol state is not locked during call",
                    "No reentrancy guard in place",
                ],
                uncertainty="Whether reentrancy is possible depends on state locking mechanism.",
                suggested_next_investigation=(
                    f"Check if {fn_key} has a reentrancy guard (modifier, boolean "
                    f"flag, or state-before-call pattern). Check if callbacks are "
                    f"possible through tokens or other protocol interfaces."
                ),
                priority="medium_interest",
                priority_rationale="External call + state mutation creates reentrancy surface",
            )
            h.evidence_tier = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
            out.append(h)


def _generate_accounting_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Accounting mismatch patterns.

    Focus: functions that decode external data AND perform calculations
    that influence asset distribution.
    """
    # Look for functions with both:
    # - digest/encoding operations (signatures, calldata parsing)
    # - state writes or arithmetic
    digest_ops = recon.facts_obj.by_type.get("digest_construction_operation", [])
    if not digest_ops:
        return

    for do in digest_ops:
        fn_key = do["subject"].get("function")
        if not fn_key:
            continue
        fn_facts = _find_function_facts(recon, fn_key)
        has_arithmetic = any(f["type"] == "arithmetic_operation" for f in fn_facts)
        has_state_write = any(f["type"] == "state_write" for f in fn_facts)
        has_asset = any(f["type"] == "asset_operation" for f in fn_facts)

        if has_arithmetic or has_state_write:
            observed = [do["id"]] + [
                f["id"] for f in fn_facts
                if f["type"] in ("arithmetic_operation", "state_write", "asset_operation")
            ]
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="accounting_mismatch",
                statement=(
                    f"Function {fn_key} constructs digests/signatures AND "
                    f"{'performs arithmetic' if has_arithmetic else ''}"
                    f"{' and modifies state' if has_state_write else ''}"
                    f"{' and moves assets' if has_asset else ''}. "
                    f"If external data is decoded and used in calculations, "
                    f"there may be a semantic mismatch between expected and actual values."
                ),
                actor="external_user",
                observed_facts=observed,
                affected_functions=[fn_key],
                preconditions=[
                    "External data is decoded from calldata or signatures",
                    "Decoded values influence accounting calculations",
                ],
                uncertainty=(
                    "Whether the decoded data flows into accounting depends on "
                    "dataflow analysis of the function body."
                ),
                suggested_next_investigation=(
                    "Trace the decoded values: do they flow into any arithmetic "
                    "operations, state variable assignments, or asset transfers?"
                ),
                priority="high_interest",
                priority_rationale="Digest construction + state/arithmetic is a semantic mismatch surface",
            )
            h.evidence_tier = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
            out.append(h)


def _generate_rounding_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Rounding/truncation allocation.

    Focus: division operations that influence asset allocation or rewards.
    """
    divisions = recon.facts_obj.by_type.get("division_operation", [])
    if not divisions:
        return

    for div in divisions:
        fn_key = div["subject"].get("function")
        props = div.get("properties", {})
        consumer = props.get("immediate_consumer")
        left = props.get("left_operand", "?")
        right = props.get("right_operand", "?")

        fn_facts = _find_function_facts(recon, fn_key) if fn_key else []
        has_asset = any(f["type"] == "asset_operation" for f in fn_facts)
        observed = [div["id"]] + [f["id"] for f in fn_facts if f["type"] == "asset_operation"]

        h = ThreatHypothesis(
            hypothesis_id=next_id(),
            category="rounding_allocation",
            statement=(
                f"Division in {fn_key}: ({left}) / ({right}) with "
                f"consumer={consumer}. Integer division truncates towards zero. "
                f"{'Asset transfer is involved, creating rounding advantage potential.' if has_asset else 'If this calculation influences any allocation, rounding may create advantage.'}"
            ),
            actor="caller",
            observed_facts=observed,
            affected_functions=[fn_key] if fn_key else [],
            affected_assets=["shares", "rewards"] if has_asset else ["calculation results"],
            preconditions=[
                "Division result influences allocation or distribution",
                "Rounding favors the caller",
            ],
            uncertainty=(
                "Whether rounding advantage is realized depends on: "
                "1) The magnitude of the remainder vs. denominator "
                "2) Whether multiple divisions accumulate rounding bias "
                "3) Who receives the truncated remainder"
            ),
            suggested_next_investigation=(
                f"Check if {fn_key}'s division result feeds into any "
                f"state variable, return value, or token transfer. "
                f"If the function distributes assets, check for a "
                f"reconciliation mechanism that accounts for truncated values."
            ),
            priority="high_interest" if has_asset else "medium_interest",
            priority_rationale=(
                "Division in allocation context with asset involvement "
                "creates rounding advantage opportunity" if has_asset else
                "Division affects calculation; potential for rounding bias"
            ),
            evidence_tier=classify_evidence(observed, [], [], recon),
        )
        out.append(h)


def _generate_signature_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Signature replay / authentication.

    Focus: signature recovery operations.
    """
    sig_ops = recon.facts_obj.by_type.get("signature_recovery_operation", [])
    if not sig_ops:
        return

    for sig in sig_ops:
        fn_key = sig["subject"].get("function")
        fn_facts = _find_function_facts(recon, fn_key) if fn_key else []
        observed = [sig["id"]] + [f["id"] for f in fn_facts if f["type"] == "asset_operation"]

        h = ThreatHypothesis(
            hypothesis_id=next_id(),
            category="signature_replay",
            statement=(
                f"Signature recovery in {fn_key}. "
                f"If signatures are not properly bound to a unique nonce, "
                f"chain, or domain, they may be replayed."
            ),
            actor="external_user",
            observed_facts=observed,
            affected_functions=[fn_key] if fn_key else [],
            preconditions=[
                "Signature lacks unique binding (nonce/domain/chain)",
                "No replay protection mechanism in place",
            ],
            uncertainty="Whether replay protection exists depends on function implementation.",
            suggested_next_investigation=(
                f"Check if {fn_key} uses nonces, domains, chain IDs, "
                f"or other mechanisms to bind signatures to unique contexts."
            ),
            priority="high_interest" if observed else "medium_interest",
            priority_rationale="Signature operations are replay-prone without proper binding",
            evidence_tier=classify_evidence(observed, [], [], recon),
        )
        out.append(h)


def _generate_cross_contract_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Cross-contract trust chains.

    Focus: CALLS edges between contracts that form chains.

    Selectivity (threat-perbaikan.md): graph adjacency alone is not
    semantic dependency. A dynamic cross-contract call only stays a
    security-relevant trust hypothesis when fact-level influence evidence
    (parameter-rooted flows, relationship chains, or caller-controlled
    input origins) links the calling function to the interaction;
    otherwise the hypothesis is emitted as a structural observation with
    UNKNOWN control provenance, which the prioritizer keeps out of the
    high-interest bands.
    """
    from .provenance import build_control_profiles, ControlProvenance  # deferred: avoid import cycle
    from .security_chains import (  # deferred: avoid import cycle
        LINKAGE_ASSET_FLOW, LINKAGE_DATAFLOW, linked_downstream_facts,
        grade_composition,
    )

    calls = [e for e in recon.graph.edges if e.get("type") == "CALLS"]
    if not calls:
        return

    control_profiles = build_control_profiles(recon)
    # Recon's composed caller-influence proofs are per interaction fact
    # (a step's basis_facts point at the exact dynamic call), so map each
    # interaction fact to the strongest certainty a relationship chain
    # asserts over it. This is call-specific linkage, not function-level
    # co-occurrence.
    basis_certainty: dict[str, str] = {}
    _cert_rank = {"FACT": 2, "INFERENCE": 1, "HYPOTHESIS": 0}
    for rel in recon.facts_obj.by_type.get("security_relationship_chain", []):
        cert = (rel.get("properties") or {}).get("overall_certainty", "")
        for step in (rel.get("properties") or {}).get("steps", []):
            if not isinstance(step, dict):
                continue
            for fid in step.get("basis_facts") or []:
                prev = basis_certainty.get(fid, "")
                if _cert_rank.get(cert, -1) > _cert_rank.get(prev, -1):
                    basis_certainty[fid] = cert

    for edge in calls:
        src_id = edge.get("source", "")
        tgt_id = edge.get("target", "")
        src_node = recon.graph.nodes_by_id.get(src_id, {})
        tgt_node = recon.graph.nodes_by_id.get(tgt_id, {})

        src_contract = src_node.get("contract") or _contract_for_node(src_id, recon)
        tgt_contract = tgt_node.get("contract") or _contract_for_node(tgt_id, recon)

        if not src_contract or not tgt_contract:
            continue

        props = edge.get("properties") or {}
        if props.get("target_status") == "dynamic":
            observed = edge.get("fact_ids") or []
            # Resolve the calling function from the edge's own facts.
            src_fn = next(
                (
                    (recon.facts_obj.by_id.get(fid) or {}).get("subject", {}).get(
                        "function"
                    ) or (recon.facts_obj.by_id.get(fid) or {}).get("subject", {}).get("caller")
                    for fid in observed
                ),
                "",
            )
            profile = control_profiles.get(src_fn)
            # Call-specific influence evidence: a relationship chain whose
            # basis facts cover THIS interaction.
            edge_cert = max(
                (_cert_rank.get(basis_certainty.get(fid, ""), -1) for fid in observed),
                default=-1,
            )
            if edge_cert >= _cert_rank["FACT"]:
                provenance = ControlProvenance.PROVEN
            elif edge_cert >= _cert_rank["INFERENCE"]:
                provenance = ControlProvenance.INFERRED
            else:
                provenance = (
                    profile.provenance if profile is not None else ControlProvenance.UNKNOWN
                )
            propagation = provenance is ControlProvenance.PROVEN
            linked_fx = (
                linked_downstream_facts(profile)[0] if profile is not None else []
            )
            linked_linkage = None
            if linked_fx:
                from .security_chains import classify_downstream_fact, _chain_identity
                levels = {
                    classify_downstream_fact(f, _chain_identity(profile))
                    for f in linked_fx
                }
                linked_linkage = (
                    LINKAGE_ASSET_FLOW if LINKAGE_ASSET_FLOW in levels
                    else LINKAGE_DATAFLOW
                )
            strength = grade_composition(
                provenance,
                propagation=propagation,
                sensitive_execution=True,  # the edge IS a dynamic execution path
                authority=bool(profile is not None and profile.has_sensitive_capability),
                effect_linkage=linked_linkage,
                # no callback model at edge level: the lens can grade at
                # most SECURITY_RELEVANT; STRONG chains are owned by the
                # chain layer.
                downstream_grade=None,
            )
            if strength != "STRUCTURAL":
                statement = (
                    f"Contract {src_contract} calls dynamic target in {tgt_contract}. "
                    f"Trust chain: {src_contract} -> dynamic -> {tgt_contract}. "
                    f"Recon's relationship evidence over this specific call "
                    f"asserts caller influence at {provenance.value} certainty, "
                    f"so the dynamic target is an unverified execution path "
                    f"(composition strength {strength})."
                )
                uncertainty = (
                    "Whether the target is actually user-controlled depends "
                    "on the dataflow from the function's inputs to the call "
                    "target expression."
                )
                priority = "medium_interest"
                rationale = (
                    f"Dynamic cross-contract call with call-specific "
                    f"influence evidence (composition strength {strength})"
                )
            else:
                statement = (
                    f"Contract {src_contract} calls dynamic target in {tgt_contract}. "
                    f"Trust chain: {src_contract} -> dynamic -> {tgt_contract}. "
                    f"This is structural graph adjacency: no fact-level "
                    f"influence evidence ties any caller to this specific "
                    f"dynamic call, so it is recorded as a structural "
                    f"observation, not a security-relevant composition."
                )
                uncertainty = (
                    "Whether the target is user-controlled is unknown; no "
                    "dataflow or relationship evidence connects caller "
                    "influence to this call."
                )
                priority = "low_interest"
                rationale = "Structural graph adjacency without semantic dependency"
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="cross_contract_trust",
                statement=statement,
                actor="external_user",
                observed_facts=observed,
                graph_nodes=[src_id, tgt_id],
                graph_edges=[edge.get("id", "")],
                affected_functions=[src_fn] if src_fn else [],
                affected_assets=["cross-contract assets"],
                preconditions=[
                    "Target is controlled by untrusted party",
                    "Target has code that can interact with protocol",
                ],
                uncertainty=uncertainty,
                suggested_next_investigation=(
                    "Trace the dataflow to determine who controls the call target."
                ),
                priority=priority,
                priority_rationale=rationale,
                control_provenance=provenance.value,
                composition_strength=strength,
            )
            h.evidence_tier = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
            out.append(h)


def _generate_dos_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Denial of service / griefing surfaces.

    Focus: functions with loops, array mutations, or external calls that
    may cause gas exhaustion.
    """
    array_mutations = recon.facts_obj.by_type.get("array_mutation", [])
    control_flow = recon.facts_obj.by_type.get("control_flow_structure", [])

    # Functions with array mutations (potential loops)
    for am in array_mutations:
        fn_key = am["subject"].get("function")
        if not fn_key:
            continue
        fn_facts = _find_function_facts(recon, fn_key)
        observed = [am["id"]]
        h = ThreatHypothesis(
            hypothesis_id=next_id(),
            category="DoS_griefing",
            statement=(
                f"Function {fn_key} performs array mutation. "
                f"If array size is unbounded or user-controlled, "
                f"iteration may exceed block gas limit."
            ),
            actor="external_user",
            observed_facts=observed,
            affected_functions=[fn_key],
            preconditions=[
                "Array size is unbounded or user-controllable",
                "Iteration is not gas-bounded",
            ],
            uncertainty="Array size bounds depend on state variable tracking.",
            suggested_next_investigation=(
                f"Check if the mutated array has a known maximum size. "
                f"If the array grows based on user input, it may be DoS-prone."
            ),
            priority="medium_interest",
            priority_rationale="Unbounded array operations can cause DoS",
            evidence_tier=classify_evidence(observed, [], [], recon),
        )
        out.append(h)

    # External calls that may fail and block
    for ext in recon.facts_obj.by_type.get("external_call", []):
        props = ext.get("properties", {})
        if props.get("call_type") == "external":
            observed = [ext["id"]]
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="DoS_griefing",
                statement=(
                    f"Function {ext['subject'].get('function', '?')} makes "
                    f"an external call. If the call reverts, "
                    f"the entire transaction reverts."
                ),
                actor="external_user",
                observed_facts=observed,
                affected_functions=[ext["subject"].get("function", "")],
                preconditions=[
                    "External call may revert",
                    "Caller has no error handling (require/check-effects)",
                ],
                uncertainty="Whether the call can revert depends on target contract behavior.",
                suggested_next_investigation=(
                    "Check if the function has error handling for failed calls."
                ),
                priority="low_interest",
                priority_rationale="Standard external call; only concerning if no error handling",
            )
            h.evidence_tier = classify_evidence(h.observed_facts, h.graph_nodes, h.graph_edges, recon)
            out.append(h)


def _generate_economic_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """H-00X: Economic manipulation patterns.

    Focus: functions where price/valuation inputs combine with
    asset transfers.
    """
    # Look for functions that combine:
    # 1) Input from external source (msg.sender, msg.value, parameters)
    # 2) Asset movement
    # 3) Arithmetic
    input_origin = recon.facts_obj.by_type.get("input_origin", [])
    asset_ops = recon.facts_obj.by_type.get("asset_operation", [])
    arithmetic = recon.facts_obj.by_type.get("arithmetic_operation", [])

    # Group functions with both arithmetic AND asset operations
    asset_funcs = {
        ao["subject"]["function"]
        for ao in asset_ops
        if "function" in ao["subject"]
    }
    arith_funcs = {
        a["subject"]["function"]
        for a in arithmetic
        if "function" in a["subject"]
    }
    common = asset_funcs & arith_funcs

    for fn_key in common:
        fn_facts = _find_function_facts(recon, fn_key)
        observed = [f["id"] for f in fn_facts if f["type"] in ("asset_operation", "arithmetic_operation")]
        h = ThreatHypothesis(
            hypothesis_id=next_id(),
            category="economic_manipulation",
            statement=(
                f"Function {fn_key} combines arithmetic operations with "
                f"asset movements. If inputs influence the arithmetic "
                f"(e.g., user-supplied prices or amounts), there may be "
                f"an economic manipulation surface."
            ),
            actor="external_user",
            observed_facts=observed,
            affected_functions=[fn_key],
            affected_assets=["protocol assets"],
            preconditions=[
                "Arithmetic inputs can be influenced by external parties",
                "Results control asset allocation or pricing",
            ],
            uncertainty="Whether inputs are controllable depends on dataflow.",
            suggested_next_investigation=(
                f"Trace input dataflow in {fn_key}: do parameters, "
                f"msg.sender, msg.value, or other external sources "
                f"influence the arithmetic that controls assets?"
            ),
            priority="high_interest" if observed else "medium_interest",
            priority_rationale="Arithmetic + asset movement = economic exposure",
            evidence_tier=classify_evidence(observed, [], [], recon),
        )
        out.append(h)


def _contract_for_node(node_id: str, recon: loader.ReconArtifact) -> str:
    """Resolve a graph node to its enclosing contract name.

    Builds a DECLARES-based lookup:
    - contract node (source) --DECLARES--> child node (target)
    - reverse: child node -> contract label

    This is correct because DECLARES edges go contract -> members.
    """
    # Build contract map from DECLARES edges
    contract_map: dict[str, str] = {}
    for edge in recon.graph.edges:
        if edge.get("type") == "DECLARES":
            src_id = edge.get("source", "")
            tgt_id = edge.get("target", "")
            src_node = recon.graph.nodes_by_id.get(src_id, {})
            if src_node.get("kind") == "contract":
                contract_label = src_node.get("label", "")
                if contract_label:
                    contract_map[tgt_id] = contract_label

    # Direct lookup
    contract = contract_map.get(node_id)
    if contract:
        return contract

    # If node itself is a contract
    node = recon.graph.nodes_by_id.get(node_id, {})
    if node.get("kind") == "contract":
        return node.get("label", node_id)
    # external_target nodes have their own label (e.g., "token", "paymentToken")
    if node.get("kind") == "external_target":
        return node.get("label", node_id)

    # Last resort: return opaque id (nothing to parse from hashes)
    return node_id


def _generate_gas_dos_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Detect unbounded gas consumption patterns (F-59 pattern).
    
    Looks for nested loops with parameter-dependent bounds.
    Unlike other categories, this does NOT filter by visibility because:
    - Private functions with expensive computation can cause DoS via public callers
    - Gas complexity is transitive through call chain
    """
    # Find computational complexity indicators
    complexity_facts = recon.facts_obj.by_type.get("computational_complexity_indicator", [])
    
    for comp_fact in complexity_facts:
        fn_key = comp_fact["subject"].get("function", "")
        if not fn_key:
            continue
        
        # Find related loop facts
        fn_facts = _find_function_facts(recon, fn_key)
        loop_facts = [
            f for f in fn_facts
            if f["type"] == "loop_nesting_depth"
        ]
        
        nesting_level = comp_fact["properties"].get("nesting_level", 1)
        pattern = comp_fact["properties"].get("pattern", "unknown")
        
        # Prioritize based on nesting level
        # Level 3+: very high (matches F-59 _countSubsetMatches)
        # Level 2: high
        # Level 1: medium
        if nesting_level >= 3:
            priority = "very_high_interest"
        elif nesting_level >= 2:
            priority = "high_interest"
        else:
            priority = "medium_interest"
        
        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="gas_dos",
                statement=(
                    f"Function contains {pattern} with nesting level {nesting_level}. "
                    f"Expensive computation could cause gas exhaustion, potentially exceeding "
                    f"block gas limit and causing denial of service. "
                    f"Even private functions are relevant if called by public entry points."
                ),
                actor="external_caller",
                preconditions=[
                    "Function is reachable (directly or via call chain from external entry)",
                    "Loop bounds depend on caller-supplied parameters or unbounded state",
                ],
                observed_facts=[comp_fact["id"]] + [lf["id"] for lf in loop_facts],
                graph_nodes=[],
                graph_edges=[],
                affected_functions=[fn_key],
                affected_assets=[],
                priority=priority,
                priority_rationale=f"Gas DoS through resource exhaustion (nesting level {nesting_level}, pattern: {pattern})",
                evidence_tier=classify_evidence(
                    [comp_fact["id"]] + [lf["id"] for lf in loop_facts],
                    [],
                    [],
                    recon
                ).name,
            )
        )


def _generate_arithmetic_overflow_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Detect bit-shift overflow patterns (F-81 pattern).
    
    Looks for bit-shift operations with non-constant shift amounts.
    """
    # Find bitshift operations
    bitshift_facts = recon.facts_obj.by_type.get("bitshift_operation", [])
    
    for shift_fact in bitshift_facts:
        shift_source = shift_fact["properties"].get("shift_amount_source", "constant")
        if shift_source == "constant":
            continue  # Constants are safe
        
        fn_key = shift_fact["subject"].get("function", "")
        if not fn_key:
            continue
        
        # Check if function is externally callable
        fn_facts = _find_function_facts(recon, fn_key)
        vis_fact = next((f for f in fn_facts if f["type"] == "function_visibility"), None)
        if not vis_fact or vis_fact["properties"].get("visibility") not in ("external", "public"):
            continue
        
        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="arithmetic_bound_violation",
                statement=(
                    f"Function performs bit-shift operation with {shift_source} shift amount. "
                    f"If shift amount exceeds type bounds (255 for uint256), operation will panic. "
                    f"Attacker could trigger overflow causing protocol lock or undefined behavior."
                ),
                actor="external_caller",
                preconditions=[
                    "Function is externally callable",
                    "Shift amount not validated against type bounds",
                ],
                observed_facts=[shift_fact["id"]],
                graph_nodes=[],
                graph_edges=[],
                affected_functions=[fn_key],
                affected_assets=[],
                priority="high_interest",
                priority_rationale="Arithmetic panic can lock protocol state",
                evidence_tier=classify_evidence([shift_fact["id"]], [], [], recon).name,
            )
        )


def _generate_frontrun_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Detect frontrunnable governance patterns (F-112 pattern).
    
    Looks for state-dependent constraints in external functions.
    """
    # Find MEV exposure indicators
    mev_facts = recon.facts_obj.by_type.get("mev_exposure_indicator", [])
    
    for mev_fact in mev_facts:
        fn_key = mev_fact["subject"].get("function", "")
        if not fn_key:
            continue
        
        # Find related state_dependent_constraint facts
        fn_facts = _find_function_facts(recon, fn_key)
        constraint_facts = [
            f for f in fn_facts
            if f["type"] == "state_dependent_constraint"
        ]
        
        constraint_count = mev_fact["properties"].get("constraint_count", 0)
        frontrun_risk = mev_fact["properties"].get("frontrun_risk", "medium")
        
        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="frontrun_vulnerability",
                statement=(
                    f"Function has {constraint_count} state-dependent constraint(s) vulnerable to frontrunning. "
                    f"Attacker can observe pending transaction and frontrun with state manipulation, "
                    f"causing victim transaction to revert or behave unexpectedly (MEV exploitation)."
                ),
                actor="mev_searcher",
                preconditions=[
                    "Function has require/revert conditions that depend on mutable state",
                    "State can be manipulated by other external functions",
                    "Transaction observable in mempool",
                ],
                observed_facts=[mev_fact["id"]] + [cf["id"] for cf in constraint_facts],
                graph_nodes=[],
                graph_edges=[],
                affected_functions=[fn_key],
                affected_assets=[],
                priority="high_interest" if frontrun_risk == "high" else "medium_interest",
                priority_rationale="MEV/frontrunning can DoS governance or manipulate outcomes",
                evidence_tier=classify_evidence(
                    [mev_fact["id"]] + [cf["id"] for cf in constraint_facts],
                    [],
                    [],
                    recon
                ).name,
            )
        )


def _generate_randomness_bias_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Detect randomness reuse patterns (F-262 pattern).
    
    Looks for multiple randomness draws from same source in same function.
    """
    # Find repeated randomness consumers
    reuse_facts = recon.facts_obj.by_type.get("repeated_randomness_consumer", [])
    
    for reuse_fact in reuse_facts:
        fn_key = reuse_fact["subject"].get("function", "")
        if not fn_key:
            continue
        
        # Find related randomness source facts
        fn_facts = _find_function_facts(recon, fn_key)
        source_facts = [
            f for f in fn_facts
            if f["type"] == "randomness_source_usage"
        ]
        
        usage_count = reuse_fact["properties"].get("usage_count", 0)
        
        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="randomness_manipulation",
                statement=(
                    f"Function uses randomness source {usage_count} times. "
                    f"If same seed is reused for multiple independent draws, "
                    f"attacker can exploit correlation to gain statistical advantage."
                ),
                actor="strategic_player",
                preconditions=[
                    "Same randomness seed used for multiple draws",
                    "Draws should be independent but share correlation",
                    "Attacker can choose inputs that exploit correlation",
                ],
                observed_facts=[reuse_fact["id"]] + [sf["id"] for sf in source_facts],
                graph_nodes=[],
                graph_edges=[],
                affected_functions=[fn_key],
                affected_assets=[],
                priority="medium_interest",
                priority_rationale="Statistical bias can provide unfair advantage",
                evidence_tier=classify_evidence(
                    [reuse_fact["id"]] + [sf["id"] for sf in source_facts],
                    [],
                    [],
                    recon
                ).name,
            )
        )
    
    # Also check for single randomness usage (still noteworthy)
    single_rand_facts = recon.facts_obj.by_type.get("randomness_source_usage", [])
    for rand_fact in single_rand_facts:
        fn_key = rand_fact["subject"].get("function", "")
        if not fn_key:
            continue
        
        # Skip if already covered by reuse_facts
        if any(rf["subject"].get("function") == fn_key for rf in reuse_facts):
            continue
        
        source = rand_fact["properties"].get("source", "unknown")
        predictability = rand_fact["properties"].get("predictability", "medium")
        
        if predictability == "high":
            out.append(
                ThreatHypothesis(
                    hypothesis_id=next_id(),
                    category="randomness_manipulation",
                    statement=(
                        f"Function uses predictable randomness source ({source}). "
                        f"On-chain randomness is manipulable by miners/validators."
                    ),
                    actor="miner_validator",
                    preconditions=[
                        "Function relies on on-chain randomness for security-critical decision",
                        "Randomness source is predictable or manipulable",
                    ],
                    observed_facts=[rand_fact["id"]],
                    graph_nodes=[],
                    graph_edges=[],
                    affected_functions=[fn_key],
                    affected_assets=[],
                    priority="low_interest",
                    priority_rationale="Predictable randomness - common knowledge issue",
                    evidence_tier=classify_evidence([rand_fact["id"]], [], [], recon).name,
                )
            )