"""Evidence-gated attack-strategy catalog.

for_attackagent rules (ATTACK STRATEGIES): consider the generic strategy
space, but "choose only strategies supported by the evidence" and "do NOT
force every strategy onto every hypothesis".

Each strategy is a predicate over the normalized AttackContext (Threat
hypothesis + resolved Recon facts). A strategy that fires carries:

    name         generic strategy name (spec vocabulary)
    status       PROVEN / INFERRED / POSSIBLE -- never above the evidence
    assumptions  what must hold for the strategy to work
    basis        which evidence fired it (human-readable, for audit)

Evidence rules enforced here (EVIDENCE DISCIPLINE):
  - a dynamic target is attacker-controlled ONLY with recipient-side
    dataflow overlap (downstream grade >= STRUCTURALLY_INDICATED);
  - an external call is reentrancy only as INFERRED/POSSIBLE;
  - adjacency-only effects never justify a strategy.
"""

from __future__ import annotations

from typing import Any, Callable

from . import paths
from .model import INFERRED, POSSIBLE, PROVEN, UNKNOWN


class AttackContext:
    """Normalized view of one Threat hypothesis + its Recon grounding."""

    def __init__(self, recon, threat, hypothesis: dict[str, Any],
                 root_fn: str, entry_fn: str):
        self.recon = recon
        self.threat = threat
        self.hypothesis = hypothesis
        self.root_fn = root_fn
        self.entry_fn = entry_fn
        self.stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
        self.category = hypothesis.get("category", "")
        self.strength = hypothesis.get("composition_strength", "")
        self.sink = paths.choose_sink(recon, hypothesis, root_fn)

    # --- stage-derived evidence helpers ---------------------------------

    @property
    def downstream_grade(self) -> str:
        return (self.stages.get("downstream_execution_opportunity") or {}).get("grade", "")

    @property
    def effect_linkage(self) -> str:
        return (self.stages.get("state_value_effect") or {}).get("linkage", "")

    def has_stage(self, name: str) -> bool:
        return name in self.stages

    def capabilities(self) -> set[str]:
        return {
            (f.get("subject") or {}).get("capability", "")
            for f in self.recon.facts_for_function(self.root_fn)
            if f.get("type") in ("capability", "unguarded_capability_hypothesis")
        }

    def facts(self, *types: str) -> list[dict[str, Any]]:
        want = set(types)
        return [f for f in self.recon.facts_for_function(self.root_fn) if f.get("type") in want]

    def has_fact(self, *types: str) -> bool:
        return bool(self.facts(*types))

    def unguarded_capability_facts(self) -> list[dict[str, Any]]:
        return [
            f for f in self.recon.facts_for_function(self.root_fn)
            if f.get("type") == "unguarded_capability_hypothesis"
        ]

    def target_control(self) -> dict[str, Any]:
        controlled = paths.controlled_inputs(self.recon, self.hypothesis, self.root_fn)
        return paths.target_control(self.recon, self.hypothesis, self.root_fn, controlled, self.sink)

    def beneficiary_control(self) -> dict[str, Any]:
        controlled = paths.controlled_inputs(self.recon, self.hypothesis, self.root_fn)
        return paths.beneficiary_control(self.recon, self.hypothesis, self.root_fn, controlled, self.sink)

    def sink_argument_control(self) -> dict[str, Any]:
        controlled = paths.controlled_inputs(self.recon, self.hypothesis, self.root_fn)
        return paths.sink_argument_control(self.recon, self.hypothesis, self.root_fn, controlled, self.sink)

    @property
    def text_blob(self) -> str:
        parts = [
            str(self.hypothesis.get("statement") or ""),
            str(self.hypothesis.get("uncertainty") or ""),
            " ".join(str(p) for p in (self.hypothesis.get("preconditions") or [])),
        ]
        return " ".join(parts).lower()

    @property
    def is_constructor(self) -> bool:
        return "::<constructor>#" in self.root_fn

    @property
    def entry_reachable(self) -> bool:
        return bool(self.entry_fn)

    @property
    def mutability(self) -> str:
        fact = next(
            (f for f in self.recon.facts_for_function(self.root_fn) if f.get("type") == "function_mutability"),
            None,
        )
        props = ((fact or {}).get("properties") or {})
        return str(props.get("state_mutability") or props.get("mutability") or "").lower()


StrategyFn = Callable[[AttackContext], dict[str, Any] | None]


def _strategy(name: str, status: str, assumptions: list[str], basis: str) -> dict[str, Any]:
    return {"name": name, "status": status, "assumptions": assumptions, "basis": basis}


# --- chain-stage-driven strategies (security_chain hypotheses) -----------

def _s_attacker_controlled_target(ctx: AttackContext) -> dict[str, Any] | None:
    grade = ctx.downstream_grade
    if grade == "PROVEN":
        return _strategy(
            "attacker-controlled external target", PROVEN,
            ["the recipient contract executes attacker-chosen logic"],
            "downstream_execution_opportunity grade PROVEN (callback evidence)",
        )
    if grade == "STRUCTURALLY_INDICATED":
        return _strategy(
            "attacker-controlled external target", INFERRED,
            ["the recipient contract holds code the attacker chooses or "
             "deploys"],
            "downstream_execution_opportunity grade STRUCTURALLY_INDICATED "
            "(recipient traces to attacker-controlled data)",
        )
    return None


def _s_approval_abuse(ctx: AttackContext) -> dict[str, Any] | None:
    """'Approval abuse' specifically claims a CALLER-CHOSEN beneficiary
    receives spending authority. A caller-controlled AMOUNT on the same
    call never proves that (evidence rule): if the beneficiary/spender
    argument is provably fixed or protocol-registry-resolved (no overlap
    with any controlled input), this is a Mandatory Attack Gate failure
    (Target control) and the strategy must be discarded, not downgraded.
    """
    if not ctx.has_stage("asset_authorization"):
        return None
    beneficiary = ctx.beneficiary_control()
    ben_status = beneficiary.get("status", UNKNOWN)
    if ben_status == paths.BENEFICIARY_FIXED:
        return None  # Mandatory Attack Gate: target control not proven -> discard

    assumptions = [
        "the granted spender allowance is not revoked before the spender "
        "exercises it",
        "the approved account holds enough of the asset for the grant to "
        "matter",
    ]
    if ben_status in (PROVEN, INFERRED):
        status = PROVEN if ben_status == PROVEN else INFERRED
        basis = (
            "asset_authorization stage: the beneficiary/spender "
            f"('{beneficiary.get('beneficiary_expression', '')}') overlaps a "
            "caller-controlled input, so the spender is attacker-chosen"
        )
    else:
        # ben_status == UNKNOWN: Recon did not expose an unambiguous
        # beneficiary argument. Keep the strategy (do not silently drop
        # evidence), but never claim PROVEN attacker-chosen beneficiary.
        status = INFERRED
        basis = (
            "asset_authorization stage: a spending authority grant was "
            "observed, but beneficiary/spender control is not established "
            "by Recon (basis: " + beneficiary.get("basis", "") + ")"
        )
        assumptions.append(
            "Validator must independently confirm the spender/beneficiary "
            "of the granted allowance is attacker-influenced, not a fixed "
            "or protocol-registry-resolved account"
        )
    return _strategy("approval abuse", status, assumptions, basis)


def _s_transfer_from_abuse(ctx: AttackContext) -> dict[str, Any] | None:
    if ctx.sink.get("class") != "token_approval":
        return None
    caps = ctx.capabilities()
    if not (caps & {"can_transfer_token", "can_approve_spender"}):
        return None
    beneficiary = ctx.beneficiary_control()
    if beneficiary.get("status") == paths.BENEFICIARY_FIXED:
        return None  # Mandatory Attack Gate: target control not proven -> discard
    return _strategy(
        "transferFrom abuse", INFERRED,
        ["the token exposes a transfer-from path the spender can invoke",
         "the protocol account still holds the asset when the spender acts"],
        "token-approval sink combined with transfer/approve capabilities on "
        "the same function",
    )


def _s_validation_gap(ctx: AttackContext) -> dict[str, Any] | None:
    if not ctx.has_stage("validation_gap"):
        return None
    return _strategy(
        "stale/incomplete validation (check passes, authority persists)",
        INFERRED,
        ["the granted authorization or reconciled movement survives past "
         "the second probe",
         "the spender can exercise the authority after the checked window"],
        "validation_gap stage: a paired pre/post delta validation brackets "
        "the attacker-influenced execution window",
    )


def _s_callback_reentrancy(ctx: AttackContext) -> dict[str, Any] | None:
    grade = ctx.downstream_grade
    if grade not in ("PROVEN", "STRUCTURALLY_INDICATED"):
        return None  # external call alone is never reentrancy (rule 2/7)
    linked_effect = ctx.effect_linkage in ("asset_flow_linked", "dataflow_linked")
    status = INFERRED if linked_effect else POSSIBLE
    return _strategy(
        "callback/hook reentrancy", status,
        ["the recipient can re-enter the protocol before effects settle"],
        f"dynamic execution with downstream grade {grade}"
        + (" and a linked state/value effect" if linked_effect else ""),
    )


def _s_state_ordering(ctx: AttackContext) -> dict[str, Any] | None:
    if not ctx.has_stage("state_value_effect"):
        return None
    linkage = ctx.effect_linkage
    if linkage not in ("post_call_derived",):
        return None
    if ctx.downstream_grade not in ("PROVEN", "STRUCTURALLY_INDICATED"):
        return None
    return _strategy(
        "state-before-effect / effect-before-state ordering", POSSIBLE,
        ["state updates actually follow the external call in execution "
         "order"],
        "post-call-derived effects adjacent to an attacker-influenced "
        "dynamic execution",
    )


def _s_direct_unauthorized_call(ctx: AttackContext) -> dict[str, Any] | None:
    """Disabled for executable attack candidates.

    Recon's "unguarded" signals are absence-of-evidence heuristics, not
    proof that an unprivileged attacker can reach the sink. Keep this at
    Threat level; do not emit as an Attack strategy.
    """
    return None


def _s_malicious_token_behavior(ctx: AttackContext) -> dict[str, Any] | None:
    sink_class = ctx.sink.get("class", "")
    if sink_class not in ("token_transfer", "transfer_from", "token_approval"):
        return None
    if ctx.downstream_grade not in ("PROVEN", "STRUCTURALLY_INDICATED"):
        return None
    return _strategy(
        "malicious token / receiver callback behavior", INFERRED,
        ["the token (or its receiver hooks) invokes attacker-controlled "
         "code during the interaction"],
        "token interaction whose execution window is attacker-influenced",
    )


# --- category-mapped strategies (named-lens hypotheses) -------------------

_CATEGORY_STRATEGIES: dict[str, tuple[str, str, list[str]]] = {
    "arbitrary_execution": (
        "attacker-controlled external target", INFERRED,
        ["the call target/calldata is attacker-influenced on a reachable "
         "path"]),
    "callback_reentrancy": (
        "callback/hook reentrancy", POSSIBLE,
        ["the external target can call back into the protocol before "
         "effects settle"]),
    "signature_replay": (
        "signature/replay manipulation", INFERRED,
        ["signatures lack nonce/domain/chain binding"]),
    "rounding_allocation": (
        "rounding / precision exploitation", INFERRED,
        ["rounding direction favors the caller across repeated calls"]),
    "economic_manipulation": (
        "economic sequencing / price manipulation", INFERRED,
        ["the manipulated input is not clamped by an oracle or bound"]),
    "accounting_mismatch": (
        "accounting mismatch", INFERRED,
        ["decoded external data drives accounting without reconciliation"]),
    "DoS_griefing": (
        "griefing / denial of service", POSSIBLE,
        ["the attacker can trigger the blocking condition repeatedly"]),
    "initialization_vulnerability": (
        "initialization takeover", INFERRED,
        ["the initializer path is reachable before legitimate setup"]),
    "cross_contract_trust": (
        "cross-contract trust violation", INFERRED,
        ["the dynamic callee is not constrained to a trusted implementation"]),
    "upgrade_risk": (
        "upgrade/initialization abuse", INFERRED,
        ["the upgrade path lacks an authorization or timelock boundary"]),
    "flash_loan_sensitivity": (
        "economic sequencing / price manipulation", POSSIBLE,
        ["a single-transaction manipulation (e.g. flash-loan sized) moves "
         "the sensitive input"]),
}


def _s_category_mapped(ctx: AttackContext) -> dict[str, Any] | None:
    mapped = _CATEGORY_STRATEGIES.get(ctx.category)
    if mapped is None:
        return None

    name, status, assumptions = mapped
    target_control = ctx.target_control()
    sink_control = ctx.sink_argument_control()
    sink_class = ctx.sink.get("class", "")
    evidence_tier = ctx.hypothesis.get("evidence_tier", UNKNOWN)

    if ctx.category == "arbitrary_execution":
        if sink_class not in ("dynamic_external_call", "arbitrary_external_call"):
            return None
        if target_control.get("status") not in (PROVEN, INFERRED):
            return None
        status = target_control.get("status", INFERRED)
    elif ctx.category == "cross_contract_trust":
        if sink_class not in ("dynamic_external_call", "arbitrary_external_call"):
            return None
        if target_control.get("status") not in (PROVEN, INFERRED):
            return None
        status = target_control.get("status", INFERRED)
    elif ctx.category == "callback_reentrancy":
        if not ctx.has_stage("downstream_execution_opportunity"):
            return None
    elif ctx.category == "initialization_vulnerability":
        init_surface = next((f for f in ctx.facts("initializer_surface") if (f.get("subject") or {}).get("function") == ctx.root_fn), None)
        if init_surface is None:
            return None
        if (init_surface.get("properties") or {}).get("authorization_status") != "none_observed":
            return None
        status = INFERRED
    elif ctx.category == "upgrade_risk":
        if not ctx.has_fact("upgrade_function"):
            return None
        if ctx.has_fact("upgrade_authority"):
            return None
        status = INFERRED
    elif ctx.category in ("rounding_allocation", "economic_manipulation", "accounting_mismatch"):
        if sink_control.get("status") not in (PROVEN, INFERRED):
            return None
    elif ctx.category == "signature_replay":
        if not ctx.has_fact("signature_recovery_operation"):
            return None
    elif ctx.category == "DoS_griefing":
        if not ctx.entry_fn or ctx.entry_fn != ctx.root_fn:
            return None
    elif ctx.category == "flash_loan_sensitivity":
        if sink_control.get("status") not in (PROVEN, INFERRED):
            return None

    return _strategy(
        name,
        status,
        assumptions,
        f"threat category '{ctx.category}' with evidence tier {evidence_tier}",
    )


def _s_novel_composition(ctx: AttackContext) -> dict[str, Any] | None:
    if ctx.category not in ("novel_composition", "security_chain"):
        return None
    if ctx.strength != "STRONG_SECURITY_CHAIN" and ctx.category != "novel_composition":
        return None

    # Fallback compositions must still retain at least one exploit anchor.
    # A STRONG security_chain with only a POSSIBLE downstream callback and no
    # proven/inferred attacker control over the target or beneficiary is too
    # weak to surface as an executable Attack candidate; otherwise Attack ends
    # up keeping low-grade "maybe something happens" paths and punts them to
    # Validator as spurious work.
    target_status = ctx.target_control().get("status", UNKNOWN)
    beneficiary_status = ctx.beneficiary_control().get("status", UNKNOWN)
    anchored = (
        ctx.downstream_grade in ("PROVEN", "STRUCTURALLY_INDICATED")
        or target_status in (PROVEN, INFERRED)
        or beneficiary_status in (PROVEN, INFERRED)
    )
    if not anchored:
        return None

    return _strategy(
        "novel composition (protocol-specific path)", INFERRED,
        ["the composed stages combine into an exploitable sequence"],
        "generic composition layer produced this hypothesis; no named "
        "strategy matched the evidence, but an exploit anchor remains "
        "present (dynamic execution or attacker-controlled target/beneficiary)",
    )


def _s_accounting_mismatch_family(ctx: AttackContext) -> dict[str, Any] | None:
    if ctx.category != "accounting_mismatch":
        return None
    if ctx.is_constructor or not ctx.entry_reachable:
        return None
    if not ctx.has_fact("state_write"):
        return None
    if not paths.controlled_inputs(ctx.recon, ctx.hypothesis, ctx.root_fn):
        return None
    text = ctx.text_blob
    if not any(token in text for token in ("data ingestion", "accounting", "liabil", "reconciliation", "state mutation")):
        return None
    return _strategy(
        "accounting mismatch", INFERRED,
        [
            "externally influenced data reaches accounting-affecting state updates",
            "the protocol does not fully reconcile the updated state against assets and liabilities",
        ],
        "accounting-mismatch lens with externally influenced state mutation",
    )


def _s_rounding_precision_family(ctx: AttackContext) -> dict[str, Any] | None:
    if ctx.category != "rounding_allocation":
        return None
    if ctx.is_constructor or not ctx.entry_reachable:
        return None
    if not ctx.has_fact("division_operation"):
        return None
    controlled = paths.controlled_inputs(ctx.recon, ctx.hypothesis, ctx.root_fn)
    text = ctx.text_blob
    allocation_anchor = any(token in text for token in ("allocation", "distribution", "reward", "share"))
    boundary_anchor = any(token in text for token in ("withdraw", "redeem", "preview", "underflow", "revert", "invariant"))
    state_anchor = ctx.has_fact("state_write", "post_call_state_effect")
    control_anchor = any(i.get("status") in (PROVEN, INFERRED) for i in controlled)
    if not (allocation_anchor or boundary_anchor or state_anchor):
        return None
    if not (control_anchor or state_anchor):
        return None
    if ctx.mutability in ("view", "pure") and not control_anchor:
        return None
    return _strategy(
        "rounding / precision exploitation", INFERRED,
        [
            "the rounding direction benefits a caller or breaks an accounting invariant",
            "the truncated remainder can accumulate or flip a boundary condition",
        ],
        "division-based allocation/pricing path with benchmark-style rounding anchors and attacker/state influence",
    )


def _s_gas_dos(ctx: AttackContext) -> dict[str, Any] | None:
    """Gas DoS through unbounded computation."""
    if ctx.category not in ("gas_dos", "gas_complexity_dos"):
        return None
    if ctx.is_constructor or not ctx.entry_reachable:
        return None
    if ctx.mutability in ("view", "pure"):
        return None
    text = ctx.text_blob
    has_iteration = ctx.has_fact("control_flow_structure") or "iteration" in text or "loop" in text
    if not has_iteration:
        return None
    return _strategy(
        "gas_dos", INFERRED,
        [
            "attacker can supply input or reachable state that maximizes iteration count",
            "the must-succeed path exceeds practical gas limits and becomes unusable",
        ],
        "parameter/state-dependent iteration on an externally reachable path",
    )


def _s_arithmetic_overflow(ctx: AttackContext) -> dict[str, Any] | None:
    """Arithmetic bound break through unchecked derived parameters / shifts."""
    if ctx.category != "arithmetic_bound_violation":
        return None
    if ctx.is_constructor or not ctx.entry_reachable:
        return None
    if ctx.mutability in ("view", "pure"):
        return None
    bitshift_facts = ctx.facts("bitshift_operation")
    if not bitshift_facts:
        return None
    if not any(
        str((f.get("properties") or {}).get("shift_amount_source") or "").lower() != "constant"
        for f in bitshift_facts
    ) and "shift amount" not in ctx.text_blob:
        return None
    return _strategy(
        "arithmetic_overflow", INFERRED,
        [
            "a caller-reachable parameter or derived value can exceed the low-level representation bound",
            "the overflow/panic can lock or deny the intended operation",
        ],
        "bit-shift/bound-sensitive arithmetic reachable from attacker-controlled or live protocol inputs",
    )


def _s_frontrun_race(ctx: AttackContext) -> dict[str, Any] | None:
    """Frontrunning governance or time-sensitive operations."""
    if ctx.category != "frontrun_vulnerability":
        return None
    if ctx.is_constructor or not ctx.entry_reachable:
        return None
    if ctx.mutability in ("view", "pure"):
        return None
    text = ctx.text_blob
    if not (ctx.has_fact("state_dependent_constraint") or "temporal constraint" in text or "state-dependent" in text):
        return None
    if not (ctx.has_fact("state_write", "post_call_state_effect") or "mempool" in text or "governance" in text):
        return None
    if not ctx.has_fact("access_controlled_function", "modifier_usage"):
        return None
    return _strategy(
        "frontrun_race", INFERRED,
        [
            "attacker can move live state before the protected action executes",
            "the victim/admin action validates against mutable state instead of an immutable snapshot",
        ],
        "time/state-sensitive externally reachable action with benchmark-style frontrun anchors",
    )


def _s_statistical_exploit(ctx: AttackContext) -> dict[str, Any] | None:
    """Statistical bias through randomness reuse or predictable entropy."""
    if ctx.category != "randomness_manipulation":
        return None
    if ctx.is_constructor or not ctx.entry_reachable:
        return None
    if ctx.mutability in ("view", "pure"):
        return None
    random_facts = ctx.facts("randomness_source_usage")
    if not random_facts:
        return None
    controlled = paths.controlled_inputs(ctx.recon, ctx.hypothesis, ctx.root_fn)
    if not any(i.get("status") in (PROVEN, INFERRED) for i in controlled):
        return None
    text = ctx.text_blob
    reuse_anchor = any(token in text for token in ("reuse", "reused", "independent", "correlat", "multiple draws", "same seed"))
    multi_source = len(random_facts) > 1
    if not (reuse_anchor or multi_source):
        return None
    return _strategy(
        "statistical_exploit", INFERRED,
        [
            "the randomness source is predictable, influenceable, or reused across supposedly independent outcomes",
            "the attacker can gain a measurable allocation or payout edge from that correlation",
        ],
        "predictable/reused randomness source on a caller-reachable path",
    )


# Order matters: the first matching strategy becomes the primary one.
# Category-mapped strategies precede the fact-based direct-call strategy
# so named-lens hypotheses are attributed their specific strategy (they
# carry no chain stages); chain-stage strategies naturally take over for
# security-chain hypotheses because lens categories never match them.
CHAIN_STRATEGIES: list[StrategyFn] = [
    _s_approval_abuse,
    _s_validation_gap,
    _s_attacker_controlled_target,
    _s_transfer_from_abuse,
    _s_callback_reentrancy,
    _s_malicious_token_behavior,
    _s_state_ordering,
    _s_accounting_mismatch_family,
    _s_rounding_precision_family,
    _s_gas_dos,
    _s_arithmetic_overflow,
    _s_frontrun_race,
    _s_statistical_exploit,
    _s_category_mapped,
    _s_direct_unauthorized_call,
    _s_novel_composition,
]


def select_strategies(ctx: AttackContext) -> list[dict[str, Any]]:
    """Select evidence-supported strategies, primary first.

    Never forces a strategy: a hypothesis with only structural evidence
    yields at most one low-status entry, or none.
    """
    selected: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for fn in CHAIN_STRATEGIES:
        result = fn(ctx)
        if result is None:
            continue
        if result["name"] in seen_names:
            continue
        seen_names.add(result["name"])
        selected.append(result)
    return selected


def hypothesis_supported(ctx: AttackContext) -> bool:
    """A hypothesis is attack-supported when at least one strategy fires
    above UNKNOWN, or it is a STRONG chain (which always carries at least
    an inferred novel-composition path)."""
    strategies = select_strategies(ctx)
    if any(s["status"] in (PROVEN, INFERRED, POSSIBLE) for s in strategies):
        return True
    return ctx.strength == "STRONG_SECURITY_CHAIN"
