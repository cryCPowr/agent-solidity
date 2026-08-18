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

    # --- Category 7: Upgradeability ---
    _generate_upgrade_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 8: Initialization ---
    _generate_initialization_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 9: DoS/Griefing ---
    _generate_dos_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 10: Economic Manipulation ---
    _generate_economic_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 11: Gas DoS ---
    _generate_gas_dos_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 12: Arithmetic Bound Violation ---
    _generate_arithmetic_overflow_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 13: Frontrun Vulnerability ---
    _generate_frontrun_hypotheses(recon, hypotheses, _next_id, invariants)

    # --- Category 14: Randomness Manipulation ---
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



def _effectful_callers(recon: loader.ReconArtifact, callee_fn: str) -> list[dict[str, Any]]:
    """Observed callers of `callee_fn` that themselves move assets or mutate
    security-relevant state.

    This lets Threat lift helper/view math into the effectful runtime path
    that actually settles value or state, which is closer to benchmark-style
    findings than reporting the helper in isolation.

    Important: `post_call_state_effect` alone is too weak here because Recon
    can emit it as structural adjacency. Treat explicit asset movement or
    state writes as the primary effect anchors.
    """
    anchors: list[dict[str, Any]] = []
    for fact in recon.facts_obj.by_type.get("internal_call", []):
        props = fact.get("properties") or {}
        if props.get("callee_function") != callee_fn:
            continue
        subject = fact.get("subject") or {}
        caller_fn = subject.get("caller") or subject.get("function") or ""
        if not caller_fn:
            continue
        caller_facts = _find_function_facts(recon, caller_fn)
        has_asset = any(f["type"] in ("asset_operation", "eth_transfer") for f in caller_facts)
        has_state_write = any(f["type"] == "state_write" for f in caller_facts)
        if not (has_asset or has_state_write):
            continue
        anchors.append({
            "caller": caller_fn,
            "internal_call_fact": fact,
            "caller_facts": caller_facts,
            "has_asset": has_asset,
            "has_state_write": has_state_write,
        })
    return anchors



def _find_invariant_id(invariants: list[InvariantCandidate], category: str) -> str:
    for inv in invariants:
        if inv.category == category:
            return inv.id
    return ""


def _analysis_coverage_warning(recon: loader.ReconArtifact) -> str:
    coverage = recon.coverage.raw if isinstance(recon.coverage.raw, dict) else {}
    source_cov = coverage.get("source_coverage")
    analyzed = None
    if isinstance(source_cov, dict):
        analyzed = source_cov.get("analyzed_ratio")
        if not isinstance(analyzed, (int, float)):
            analyzed = source_cov.get("coverage_ratio")
    elif isinstance(source_cov, (int, float)):
        analyzed = source_cov
    if isinstance(analyzed, (int, float)) and analyzed < 0.5:
        return " Recon reported low analysis coverage (<50%), so absence of supporting evidence should be treated as uncertainty, not safety."
    return ""


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

        authority_surfaces = [
            f for f in _find_function_facts(recon, fn_key)
            if f["type"] == "capability_authority_surface"
        ]

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
            observed_facts=[c["id"] for c in caps] + [f["id"] for f in authority_surfaces],
            affected_functions=[fn_key],
            affected_assets=["protocol tokens", "protocol ETH"],
            uncertainty=(
                "Whether the target is user-controlled depends on dataflow "
                "from parameters through the function body. Observed authority "
                "surfaces indicate guarding/no-guarding structure only; they do "
                "not prove caller reachability or privilege acquisition."
                + _analysis_coverage_warning(recon)
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
                if f["type"] in ("capability", "capability_authority_surface")
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
                uncertainty=(
                    "Target derivation depends on function dataflow. Threat stage "
                    "records the dynamic execution surface but does not prove the "
                    "caller can satisfy any required authority boundary."
                    + _analysis_coverage_warning(recon)
                ),
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

    Focus: externally influenced values that are ingested/decoded and then
    drive asset-moving or state-mutating accounting without an obvious
    reconciliation boundary.
    """
    digest_ops = recon.facts_obj.by_type.get("digest_construction_operation", [])
    if not digest_ops:
        return

    for do in digest_ops:
        fn_key = do["subject"].get("function")
        if not fn_key:
            continue
        fn_facts = _find_function_facts(recon, fn_key)
        has_state_write = any(f["type"] == "state_write" for f in fn_facts)
        has_asset = any(f["type"] in ("asset_operation", "eth_transfer") for f in fn_facts)
        has_post_effect = any(f["type"] == "post_call_state_effect" for f in fn_facts)
        has_input_flow = any(f["type"] in ("call_argument_origin_chain", "call_argument_dataflow", "input_origin") for f in fn_facts)
        has_reconciliation_math = any(f["type"] in ("arithmetic_operation", "division_operation") for f in fn_facts)
        mutability = {
            str((f.get("properties") or {}).get("state_mutability") or (f.get("properties") or {}).get("mutability") or "").lower()
            for f in fn_facts if f["type"] == "function_mutability"
        }

        # Benchmark-style accounting mismatches need an observed bookkeeping
        # mutation, not just a computed storage key plus transfers/adjacency.
        if mutability & {"view", "pure"}:
            continue
        if not has_input_flow or not has_state_write:
            continue

        observed = [do["id"]] + [
            f["id"] for f in fn_facts
            if f["type"] in (
                "arithmetic_operation", "division_operation", "state_write",
                "asset_operation", "post_call_state_effect",
                "call_argument_origin_chain", "call_argument_dataflow", "input_origin",
            )
        ]
        h = ThreatHypothesis(
            hypothesis_id=next_id(),
            category="accounting_mismatch",
            statement=(
                f"Function {fn_key} ingests externally influenced data and uses it in "
                f"{'asset-moving' if has_asset else 'state-mutating'} accounting logic"
                f"{' with arithmetic reconciliation' if has_reconciliation_math else ''}. "
                f"If liabilities, netting, or state reconciliation are incomplete, the resulting accounting may diverge from actual value flow."
            ),
            actor="external_user",
            observed_facts=observed,
            affected_functions=[fn_key],
            preconditions=[
                "Externally influenced data reaches accounting-affecting state or asset logic",
                "The protocol does not fully reconcile the updated state against all relevant assets or liabilities",
            ],
            uncertainty=(
                "Threat stage shows externally influenced accounting/state effects, but does not yet prove which asset/liability dimension is omitted or mis-netted."
            ),
            suggested_next_investigation=(
                "Trace the influenced values into state updates, emitted accounting values, and asset transfers. Check whether any liability, debt, fee, or netting dimension is omitted."
            ),
            priority="high_interest" if has_asset else "medium_interest",
            priority_rationale="Externally influenced accounting with state/asset effects can create gross-vs-net or partial-accounting mismatches",
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

    Focus: division operations that feed allocation, reward, state-update,
    or post-condition boundaries -- not arbitrary informational getters.

    If the division sits in a helper/view function, try to lift the
    hypothesis to an observed effectful caller so downstream Attack work is
    anchored to the runtime path that actually settles value or state.
    """
    divisions = recon.facts_obj.by_type.get("division_operation", [])
    if not divisions:
        return

    for div in divisions:
        fn_key = div["subject"].get("function")
        props = div.get("properties", {})
        consumer = str(props.get("immediate_consumer") or "")
        left = props.get("left_operand", "?")
        right = props.get("right_operand", "?")

        fn_facts = _find_function_facts(recon, fn_key) if fn_key else []
        has_asset = any(f["type"] in ("asset_operation", "eth_transfer") for f in fn_facts)
        has_state_write = any(f["type"] == "state_write" for f in fn_facts)
        has_post_state_effect = any(f["type"] == "post_call_state_effect" for f in fn_facts)
        has_input_flow = any(f["type"] in ("call_argument_origin_chain", "call_argument_dataflow", "input_origin") for f in fn_facts)
        has_boundary = any(f["type"] == "require_statement" for f in fn_facts)
        mutability = {
            str((f.get("properties") or {}).get("state_mutability") or (f.get("properties") or {}).get("mutability") or "").lower()
            for f in fn_facts if f["type"] == "function_mutability"
        }
        direct_effectful = has_asset or has_state_write
        lifted_callers = _effectful_callers(recon, fn_key) if fn_key and not direct_effectful else []

        if consumer not in {
            "call_argument", "return_value", "variable_initializer", "tuple_component",
            "ifstatement", "assignment", "binary_op", "return_statement",
        }:
            continue

        if direct_effectful:
            observed = [div["id"]] + [
                f["id"] for f in fn_facts
                if f["type"] in (
                    "asset_operation", "state_write", "post_call_state_effect",
                    "call_argument_origin_chain", "call_argument_dataflow", "input_origin",
                    "require_statement",
                )
            ]
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="rounding_allocation",
                statement=(
                    f"Division in {fn_key}: ({left}) / ({right}) with consumer={consumer}. Integer division truncates towards zero. "
                    f"This result feeds a state/asset effect{' (with nearby post-call structural evidence)' if has_post_state_effect else ''}, so mixed rounding may create allocation skew or flip a boundary condition."
                ),
                actor="caller",
                observed_facts=sorted(set(observed)),
                affected_functions=[fn_key] if fn_key else [],
                affected_assets=["shares", "rewards"] if has_asset else ["calculation results"],
                preconditions=[
                    "Division result influences allocation, reward settlement, or a safety boundary",
                    "Rounding direction or truncation can favor one side or accumulate drift",
                ],
                uncertainty=(
                    "Threat stage shows truncating division in an effectful runtime path, but not yet whether repeated execution, inverse math, or remainder handling creates a material edge or DoS condition."
                ),
                suggested_next_investigation=(
                    f"Check whether {fn_key}'s division result feeds reward splits, share/accounting math, or require boundaries; then compare the rounding direction against any inverse or follow-up calculation."
                ),
                priority="high_interest" if has_asset else "medium_interest",
                priority_rationale=(
                    "Division reaches asset/state settlement logic, making benchmark-style rounding bugs plausible"
                ),
                evidence_tier=classify_evidence(sorted(set(observed)), [], [], recon),
            )
            out.append(h)
            continue

        if mutability & {"view", "pure"} and not lifted_callers:
            continue
        if not lifted_callers:
            continue

        for anchor in lifted_callers:
            caller_fn = anchor["caller"]
            caller_facts = anchor["caller_facts"]
            caller_has_asset = anchor["has_asset"]
            caller_has_state_write = anchor["has_state_write"]
            observed = [div["id"], anchor["internal_call_fact"]["id"]] + [
                f["id"] for f in fn_facts
                if f["type"] in (
                    "call_argument_origin_chain", "call_argument_dataflow", "input_origin",
                    "require_statement",
                )
            ] + [
                f["id"] for f in caller_facts
                if f["type"] in (
                    "asset_operation", "state_write", "post_call_state_effect",
                    "call_argument_origin_chain", "call_argument_dataflow", "input_origin",
                    "require_statement",
                )
            ]
            h = ThreatHypothesis(
                hypothesis_id=next_id(),
                category="rounding_allocation",
                statement=(
                    f"Division in helper {fn_key}: ({left}) / ({right}) with consumer={consumer} feeds effectful caller {caller_fn}. "
                    f"Integer division truncates towards zero, and the helper result flows into caller-side {'asset settlement' if caller_has_asset else 'state transition'} logic where mixed rounding may create allocation skew or flip a boundary condition."
                ),
                actor="caller",
                observed_facts=sorted(set(observed)),
                affected_functions=[caller_fn, fn_key] if fn_key else [caller_fn],
                affected_assets=["shares", "rewards"] if caller_has_asset else ["calculation results"],
                preconditions=[
                    "Division result from the helper feeds a caller that settles value or mutates security-relevant state",
                    "Rounding direction or truncation can favor one side or accumulate drift across the caller's runtime path",
                ],
                uncertainty=(
                    "Threat stage shows a truncating helper feeding an observed effectful caller, but not yet whether repeated execution, inverse math, or remainder handling creates a material edge or DoS condition."
                ),
                suggested_next_investigation=(
                    f"Trace the value returned by {fn_key} into {caller_fn}'s settlement path and compare the rounding direction against any inverse, complementary, or remainder-sensitive calculation."
                ),
                priority="high_interest" if caller_has_asset else "medium_interest",
                priority_rationale=(
                    "Helper division is lifted into an observed effectful caller, matching benchmark-style reward/allocation bug structure"
                ),
                evidence_tier=classify_evidence(sorted(set(observed)), [], [], recon),
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


def _generate_upgrade_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Structural upgradeability hypotheses.

    These hypotheses stay at Threat level: they identify upgrade and
    delegatecall control surfaces plus their observed authority boundary,
    without asserting attacker reachability or privilege acquisition.
    """
    upgrade_functions = recon.facts_obj.by_type.get("upgrade_function", [])
    upgrade_authorities = recon.facts_obj.by_type.get("upgrade_authority", [])
    proxy_paths = recon.facts_obj.by_type.get("proxy_delegatecall_path", [])
    proxy_like = recon.facts_obj.by_type.get("proxy_like_contract", [])
    if not (upgrade_functions or upgrade_authorities or proxy_paths or proxy_like):
        return

    authority_by_function = {
        f["subject"].get("function"): f
        for f in upgrade_authorities
        if f["subject"].get("function")
    }
    proxy_by_contract = {
        f["subject"].get("contract"): f
        for f in proxy_like
        if f["subject"].get("contract")
    }
    delegatecall_by_contract: dict[str, list[dict[str, Any]]] = {}
    for f in proxy_paths:
        contract_key = f["subject"].get("contract")
        if contract_key:
            delegatecall_by_contract.setdefault(contract_key, []).append(f)

    functions_by_contract: dict[str, list[dict[str, Any]]] = {}
    for f in upgrade_functions:
        contract_key = f["subject"].get("contract")
        if contract_key:
            functions_by_contract.setdefault(contract_key, []).append(f)

    inv_id = _find_invariant_id(invariants, "upgrade_authority_coherence")
    for contract_key in sorted(set(functions_by_contract) | set(delegatecall_by_contract) | set(proxy_by_contract)):
        fn_facts = functions_by_contract.get(contract_key, [])
        path_facts = delegatecall_by_contract.get(contract_key, [])
        proxy_fact = proxy_by_contract.get(contract_key)
        observed = [f["id"] for f in fn_facts + path_facts]
        if proxy_fact:
            observed.append(proxy_fact["id"])

        affected_functions = [f["subject"].get("function", "") for f in fn_facts + path_facts]
        affected_functions = [fn for fn in affected_functions if fn]
        authority_facts = [authority_by_function.get(fn) for fn in affected_functions]
        authority_facts = [f for f in authority_facts if f is not None]
        observed.extend(f["id"] for f in authority_facts)

        has_observed_authority = bool(authority_facts)
        has_delegatecall = bool(path_facts)
        actor = "unknown_actor" if has_observed_authority else "external_user"
        priority = "high_interest" if has_delegatecall and not has_observed_authority else "medium_interest"
        rationale = (
            "Proxy/delegatecall execution path exists without an observed upgrade authority boundary"
            if priority == "high_interest"
            else "Upgrade-related execution path exists and requires authority-boundary review"
        )
        contract_label = contract_key.rsplit("/", 1)[-1]
        statement = (
            f"Contract {contract_label} exposes upgrade-related execution surfaces "
            f"through {len(fn_facts)} upgrade function(s)"
            f"{' and delegatecall-backed proxy routing' if has_delegatecall else ''}. "
            f"If the observed authority boundary or implementation source is misaligned "
            f"with intended behavior, logic changes could alter protected state or execution context."
        )
        uncertainty = (
            "Threat stage records only structural upgradeability evidence and observed authorization surfaces. "
            "It does not prove whether any caller can legitimately or illegitimately reach the upgrade path."
            + _analysis_coverage_warning(recon)
        )
        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="upgrade_risk",
                statement=statement,
                actor=actor,
                preconditions=[
                    "Upgrade path remains callable in deployed configuration",
                    "Implementation source or authority boundary is security-relevant for this contract",
                ],
                observed_facts=sorted(set(observed)),
                affected_functions=sorted(set(affected_functions)),
                affected_assets=["implementation_address", "execution_context"],
                invariant_candidate_id=inv_id,
                uncertainty=uncertainty,
                priority=priority,
                priority_rationale=rationale,
                suggested_next_investigation=(
                    "Review who controls the implementation address, whether upgrade authority is intentionally scoped, "
                    "and whether delegatecall routing is constrained to intended code."
                ),
                evidence_tier=classify_evidence(sorted(set(observed)), [], [], recon),
            )
        )



def _generate_initialization_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Structural initialization/lifecycle hypotheses.

    These hypotheses describe initializer reachability/lifecycle surfaces,
    not confirmed initialization bugs.
    """
    initializer_surfaces = recon.facts_obj.by_type.get("initializer_surface", [])
    initializer_lifecycles = recon.facts_obj.by_type.get("initializer_lifecycle", [])
    if not (initializer_surfaces or initializer_lifecycles):
        return

    lifecycle_by_contract = {
        f["subject"].get("contract"): f
        for f in initializer_lifecycles
        if f["subject"].get("contract")
    }
    inv_id = _find_invariant_id(invariants, "initialization_coherence")

    for surface in initializer_surfaces:
        fn_key = surface["subject"].get("function", "")
        contract_key = surface["subject"].get("contract", "")
        if not fn_key:
            continue
        lifecycle = lifecycle_by_contract.get(contract_key)
        props = surface.get("properties", {})
        observed = [surface["id"]]
        if lifecycle:
            observed.append(lifecycle["id"])
        auth_status = props.get("authorization_status")
        writes_initialized = bool(props.get("writes_initialized_flag"))
        actor = "external_user" if auth_status == "none_observed" else "unknown_actor"
        priority = "high_interest" if auth_status == "none_observed" and writes_initialized else "medium_interest"
        rationale = (
            "Initializer mutates observed initialization state without an observed authorization boundary"
            if priority == "high_interest"
            else "Initializer lifecycle should be checked against intended deployment sequencing"
        )
        statement = (
            f"Initializer surface {fn_key} participates in deployment-time state setup"
            f"{' and writes an initialization flag' if writes_initialized else ''}. "
            f"If it remains callable outside the intended lifecycle or sequencing assumptions are wrong, "
            f"configuration state may diverge from intended initialization semantics."
        )
        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="initialization_vulnerability",
                statement=statement,
                actor=actor,
                preconditions=[
                    "Initializer is reachable in deployed configuration",
                    "Deployment sequencing or one-time-use assumptions matter for protocol safety",
                ],
                observed_facts=sorted(set(observed)),
                affected_functions=[fn_key],
                affected_assets=["deployment_state", "configuration_state"],
                invariant_candidate_id=inv_id,
                uncertainty=(
                    "Observed authorization/no-authorization on the initializer is only structural evidence. "
                    "Threat stage does not determine whether post-deployment invocation is actually possible or intended."
                    + _analysis_coverage_warning(recon)
                ),
                priority=priority,
                priority_rationale=rationale,
                suggested_next_investigation=(
                    "Check how deployment and upgrade flows invoke this initializer, whether it is one-shot by design, "
                    "and whether an external/public path can still reach it after setup."
                ),
                evidence_tier=classify_evidence(sorted(set(observed)), [], [], recon),
            )
        )



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
    """Detect benchmark-style live-state frontrun patterns.

    Focus: externally reachable, authorization-sensitive actions whose
    success depends on mutable live state and whose outcome also mutates
    state -- a closer match to config/governance blocking than generic
    stateful require() usage.
    """
    mev_facts = recon.facts_obj.by_type.get("mev_exposure_indicator", [])

    for mev_fact in mev_facts:
        fn_key = mev_fact["subject"].get("function", "")
        if not fn_key:
            continue

        fn_facts = _find_function_facts(recon, fn_key)
        constraint_facts = [f for f in fn_facts if f["type"] == "state_dependent_constraint"]
        auth_facts = [f for f in fn_facts if f["type"] in ("access_controlled_function", "modifier_usage")]
        effect_facts = [f for f in fn_facts if f["type"] in ("state_write", "post_call_state_effect")]
        visibility_facts = [f for f in fn_facts if f["type"] == "function_visibility"]
        mutability_facts = [f for f in fn_facts if f["type"] == "function_mutability"]
        vis = {str((f.get("properties") or {}).get("visibility") or "").lower() for f in visibility_facts}
        mut = {str((f.get("properties") or {}).get("state_mutability") or (f.get("properties") or {}).get("mutability") or "").lower() for f in mutability_facts}

        if not constraint_facts or not auth_facts or not effect_facts:
            continue
        if vis and vis.isdisjoint({"external", "public"}):
            continue
        if mut & {"view", "pure"}:
            continue

        constraint_count = mev_fact["properties"].get("constraint_count", 0)
        frontrun_risk = mev_fact["properties"].get("frontrun_risk", "medium")
        observed = [mev_fact["id"]] + [cf["id"] for cf in constraint_facts] + [af["id"] for af in auth_facts] + [ef["id"] for ef in effect_facts]

        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="frontrun_vulnerability",
                statement=(
                    f"Function {fn_key} combines {constraint_count} mutable-state constraint(s) with an authorization-sensitive state transition. "
                    f"If an attacker can move the live state before execution, the protected action may revert or settle under attacker-favorable timing."
                ),
                actor="mev_searcher",
                preconditions=[
                    "Protected action validates against mutable live state rather than a stable snapshot",
                    "Adversary can change that state through a separate reachable transaction before inclusion order is finalized",
                    "The blocked or altered action is security- or economically relevant",
                ],
                observed_facts=sorted(set(observed)),
                graph_nodes=[],
                graph_edges=[],
                affected_functions=[fn_key],
                affected_assets=[],
                priority="high_interest" if frontrun_risk == "high" else "medium_interest",
                priority_rationale="Authorization-sensitive live-state transition matches benchmark-style governance/MEV blocking pattern",
                uncertainty="Threat stage shows mutable-state gating and protected state effects, but does not yet identify the exact competing transaction that can pre-position the blocking state.",
                evidence_tier=classify_evidence(sorted(set(observed)), [], [], recon).name,
            )
        )


def _generate_randomness_bias_hypotheses(
    recon: loader.ReconArtifact,
    out: list[ThreatHypothesis],
    next_id,
    invariants: list[InvariantCandidate],
) -> None:
    """Detect benchmark-style randomness reuse/correlation patterns.

    Focus: repeated consumption of the same randomness source in a function
    whose inputs are externally influenceable or whose outcome has state/
    asset effects. Single predictable-source usage alone is too weak.
    """
    reuse_facts = recon.facts_obj.by_type.get("repeated_randomness_consumer", [])

    for reuse_fact in reuse_facts:
        fn_key = reuse_fact["subject"].get("function", "")
        if not fn_key:
            continue

        fn_facts = _find_function_facts(recon, fn_key)
        source_facts = [f for f in fn_facts if f["type"] == "randomness_source_usage"]
        input_facts = [f for f in fn_facts if f["type"] in ("call_argument_origin_chain", "call_argument_dataflow", "input_origin")]
        effect_facts = [f for f in fn_facts if f["type"] in ("asset_operation", "eth_transfer", "state_write")]
        mutability = {
            str((f.get("properties") or {}).get("state_mutability") or (f.get("properties") or {}).get("mutability") or "").lower()
            for f in fn_facts if f["type"] == "function_mutability"
        }
        if mutability & {"view", "pure"}:
            continue
        if not input_facts or not effect_facts:
            continue

        meaningful_consumers = {
            "assignment", "variable_initializer", "tuple_component",
            "return_value", "return_statement", "ifstatement", "binary_op",
        }
        has_meaningful_draw = any(
            str((sf.get("properties") or {}).get("immediate_consumer") or "") in meaningful_consumers
            for sf in source_facts
        )
        if not has_meaningful_draw:
            continue

        usage_count = reuse_fact["properties"].get("usage_count", 0)
        observed = [reuse_fact["id"]] + [sf["id"] for sf in source_facts] + [f["id"] for f in input_facts + effect_facts]

        out.append(
            ThreatHypothesis(
                hypothesis_id=next_id(),
                category="randomness_manipulation",
                statement=(
                    f"Function {fn_key} consumes the same randomness source {usage_count} times along an externally influenceable path with state/asset effects. "
                    f"If those draws are expected to be independent, source reuse can create exploitable correlation."
                ),
                actor="strategic_player",
                preconditions=[
                    "Same randomness seed or source is reused for multiple draws",
                    "The draws are expected to be independent for fairness or safety",
                    "Attacker can influence inputs or sequencing to benefit from the correlation",
                ],
                observed_facts=sorted(set(observed)),
                graph_nodes=[],
                graph_edges=[],
                affected_functions=[fn_key],
                affected_assets=[],
                priority="medium_interest",
                priority_rationale="Repeated randomness consumption with attacker influence and state/asset effects can create benchmark-style statistical bias",
                uncertainty="Threat stage shows repeated source consumption, external influence, and state/asset effects, but not yet the exact payout or fairness metric the correlation would bias.",
                evidence_tier=classify_evidence(sorted(set(observed)), [], [], recon).name,
            )
        )
