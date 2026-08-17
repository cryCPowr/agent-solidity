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

    def unguarded_capability_facts(self) -> list[dict[str, Any]]:
        return [
            f for f in self.recon.facts_for_function(self.root_fn)
            if f.get("type") == "unguarded_capability_hypothesis"
        ]


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
    if not ctx.has_stage("asset_authorization"):
        return None
    return _strategy(
        "approval abuse", PROVEN,
        ["the granted spender allowance is not revoked before the spender "
         "exercises it",
         "the approved account holds enough of the asset for the grant to "
         "matter"],
        "asset_authorization stage: a caller-chosen beneficiary receives "
        "spending authority over the contract's asset account",
    )


def _s_transfer_from_abuse(ctx: AttackContext) -> dict[str, Any] | None:
    if ctx.sink.get("class") != "token_approval":
        return None
    caps = ctx.capabilities()
    if not (caps & {"can_transfer_token", "can_approve_spender"}):
        return None
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
    unguarded = ctx.unguarded_capability_facts()
    if not unguarded:
        return None
    caps = sorted(ctx.capabilities() - {""})
    return _strategy(
        "direct unauthorized call", INFERRED,
        ["no authorization boundary exists on a reachable path (absence of "
         "evidence in Recon, not proof)"],
        "unguarded capability hypothesis on the root function"
        + (f" (capabilities: {', '.join(caps)})" if caps else ""),
    )


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
    return _strategy(name, status, assumptions,
                     f"threat category '{ctx.category}' with evidence tier "
                     f"{ctx.hypothesis.get('evidence_tier', UNKNOWN)}")


def _s_novel_composition(ctx: AttackContext) -> dict[str, Any] | None:
    if ctx.category not in ("novel_composition", "security_chain"):
        return None
    if ctx.strength != "STRONG_SECURITY_CHAIN" and ctx.category != "novel_composition":
        return None
    return _strategy(
        "novel composition (protocol-specific path)", INFERRED,
        ["the composed stages combine into an exploitable sequence"],
        "generic composition layer produced this hypothesis; no named "
        "strategy matched the evidence",
    )


def _s_gas_dos(ctx: AttackContext) -> dict[str, Any] | None:
    """Gas DoS through unbounded computation (F-59 pattern)."""
    # Check for gas_dos category from threat
    if ctx.category not in ("gas_dos", "gas_complexity_dos"):
        return None
    
    # Check if function is externally callable
    if ctx.root_fn != ctx.entry_fn:
        return None  # Must be direct entry point
    
    return _strategy(
        "gas_dos", INFERRED,
        [
            "attacker can supply input that maximizes iteration count",
            "gas consumption exceeds block gas limit",
            "transaction reverts with out-of-gas, causing denial of service",
        ],
        "nested loop or unbounded iteration with attacker-controlled bounds in external function"
    )


def _s_arithmetic_overflow(ctx: AttackContext) -> dict[str, Any] | None:
    """Arithmetic overflow through unchecked operations (F-81 pattern)."""
    if ctx.category != "arithmetic_bound_violation":
        return None
    
    # Check if function is externally callable
    if ctx.root_fn != ctx.entry_fn:
        return None
    
    return _strategy(
        "arithmetic_overflow", INFERRED,
        [
            "attacker supplies parameters that exceed type bounds",
            "arithmetic operation (bit-shift) overflows/underflows",
            "system enters undefined state or transaction panics, locking protocol",
        ],
        "unchecked arithmetic or bit-shift with attacker-controlled operands"
    )


def _s_frontrun_race(ctx: AttackContext) -> dict[str, Any] | None:
    """Frontrunning governance or time-sensitive operations (F-112 pattern)."""
    if ctx.category != "frontrun_vulnerability":
        return None
    
    # Check if function has state-dependent constraints
    if not any(ctx.hypothesis.get(k) for k in ["preconditions"] if "state" in str(ctx.hypothesis.get(k, "")).lower()):
        return None
    
    return _strategy(
        "frontrun_race", INFERRED,
        [
            "attacker observes victim transaction in mempool",
            "attacker submits frontrunning transaction with higher gas price",
            "state manipulation causes victim transaction to revert",
            "governance parameter update blocked or MEV extracted",
        ],
        "state-dependent constraint in public function vulnerable to MEV"
    )


def _s_statistical_exploit(ctx: AttackContext) -> dict[str, Any] | None:
    """Statistical bias through randomness reuse (F-262 pattern)."""
    if ctx.category != "randomness_manipulation":
        return None
    
    return _strategy(
        "statistical_exploit", INFERRED,
        [
            "same randomness seed used for multiple independent draws",
            "attacker can choose inputs that correlate draws",
            "attacker gains statistical advantage over expected distribution",
            "expected value becomes positive for attacker through bias exploitation",
        ],
        "repeated randomness consumption from same seed or predictable on-chain source"
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
