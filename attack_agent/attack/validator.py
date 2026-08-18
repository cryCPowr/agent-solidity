"""Validator handoff plan construction.

Every attack hypothesis ends with a plan the Validator can execute. The
Attack Agent never claims confirmation itself; CONFIRM/REJECT conditions
are phrased as observable outcomes.
"""

from __future__ import annotations

from typing import Any

from . import relevance
from .model import INFERRED, PROVEN
from .paths import BENEFICIARY_FIXED


def build_validator_plan(recon, threat, attack) -> dict[str, Any]:
    """Assemble an executable validator handoff plan for one attack candidate."""
    strategy = attack.attack_strategy
    entry = attack.entry_point
    sink = attack.sensitive_sink
    consequence = attack.expected_consequence
    hypothesis = _find_hypothesis(threat, attack.source_hypothesis_id)

    call_chain = list(entry.get("call_chain") or [f for f in [entry.get("function"), attack.root_function] if f])
    plan: dict[str, Any] = {
        "functions_to_test": [f for f in [entry.get("function"), attack.root_function] if f],
        "call_chain": call_chain,
        "attack_gates": attack.attack_gates,
        "attacker_setup": _attacker_setup(attack),
        "initial_state": _initial_state(attack, hypothesis),
        "contracts_mocks_required": _contracts_required(attack),
        "execution_plan": _execution_plan(attack, call_chain),
        "expected_state_transition": _expected_transition(attack, consequence),
        "expected_asset_delta": _expected_asset_delta(attack, consequence),
        "invariant_to_test": _invariant(attack, threat),
        "tooling": _tooling(attack),
        "confirm_if": "",
        "reject_if": "",
    }

    confirm, reject = _confirm_reject(strategy, attack, consequence, hypothesis)
    blind_spot = (consequence.get("cross_asset_blind_spot") or None)
    if blind_spot:
        others = ", ".join(blind_spot["other_assets"])
        confirm += (
            f" Additionally (cross-asset path): the attacker-directed call "
            f"moves at least one contract-held asset the check does not "
            f"measure ({others}) while the probed delta on "
            f"'{blind_spot['probed_asset']}' still balances."
        )
        reject += (
            " Or: every contract-held asset movement is provably outside "
            "the attacker-directed call's reach."
        )
    plan["confirm_if"] = confirm
    plan["reject_if"] = reject
    return plan


def _find_hypothesis(threat, hyp_id: str) -> dict[str, Any]:
    for h in threat.hypotheses:
        if h.get("hypothesis_id") == hyp_id:
            return h
    return {}


def _attacker_setup(attack) -> str:
    sink_class = attack.sensitive_sink.get("class", "")
    needs_contract = (
        attack.attack_strategy in (
            "attacker-controlled external target",
            "callback/hook reentrancy",
            "malicious token / receiver callback behavior",
        )
        or sink_class in ("arbitrary_external_call", "dynamic_external_call")
    )
    ben_status = (attack.beneficiary_control or {}).get("status", "")
    # "Attacker acts as spender" is only a valid setup step when the
    # spender/beneficiary was actually shown to be attacker-influenced --
    # never merely because the sink class is an approval/transferFrom shape
    # (that conflates "attacker controls the amount" with "attacker
    # controls who receives the grant").
    spender = (
        attack.attack_strategy in ("approval abuse", "transferFrom abuse")
        and ben_status in (PROVEN, INFERRED)
    )
    spender_unverified = (
        attack.attack_strategy in ("approval abuse", "transferFrom abuse")
        and ben_status not in (PROVEN, INFERRED)
    ) or (sink_class in ("token_approval", "transfer_from") and ben_status == BENEFICIARY_FIXED)
    call_chain = attack.entry_point.get("call_chain") or []
    prefix = "Deploy an attacker contract (or use an EOA) to call the externally reachable entry."
    if call_chain and len(call_chain) > 1:
        prefix += f" Reachability must be validated through the caller chain: {' -> '.join(call_chain)}."
    parts = [prefix]
    if needs_contract:
        parts.append(
            "The attacker contract must implement whatever code the "
            "attacker-chosen recipient/target would execute during the "
            "dynamic execution window."
        )
    if spender:
        parts.append(
            "The attacker contract must be able to act as the approved "
            "spender (pull funds via the token's transfer-from path)."
        )
    elif spender_unverified:
        ben_expr = (attack.beneficiary_control or {}).get("beneficiary_expression", "")
        parts.append(
            "The spender/beneficiary of the granted allowance "
            f"('{ben_expr}') is not established as attacker-controlled; "
            "Validator must independently confirm whether it is a fixed "
            "protocol contract (in which case this is not an attacker-"
            "controlled grant) or an attacker-influenced account."
        )
    return " ".join(parts)


def _initial_state(attack, hypothesis: dict[str, Any]) -> list[str]:
    state = list(hypothesis.get("preconditions") or [])
    entry = attack.entry_point
    notes = list(entry.get("notes") or [])
    state.extend(notes)
    if entry.get("required_role_status") == PROVEN:
        state.append(
            f"Observed authorization gate on entry: {entry.get('required_role')}. "
            "This is not an executable attack unless Validator can demonstrate a preceding privilege-escalation path."
        )
    if attack.sensitive_sink.get("custody") in ("grant", "outbound"):
        state.append(
            "Protocol account holds a nonzero balance of the affected asset "
            "so the custody effect is observable"
        )
    return state


def _contracts_required(attack) -> list[str]:
    required: list[str] = ["Attacker contract (see attacker_setup)"]
    sink = attack.sensitive_sink
    if sink.get("class", "").startswith("token") or sink.get("class") == "transfer_from":
        target = sink.get("target_expression") or "the token at the sink"
        required.append(
            f"Token interface stub or fork-deployed token for '{target}' "
            f"(sink at {sink.get('location') or 'unknown location'})"
        )
    if attack.production_relevance in (relevance.DEPENDENCY,):
        required.append(
            "Dependency context: the sink lives in dependency code; wire it "
            "as the production code does"
        )
    return required


def _expected_transition(attack, consequence: dict[str, Any]) -> str:
    sink = attack.sensitive_sink
    return (
        f"After the attack sequence, the sink '{sink.get('class', '?')}' at "
        f"{sink.get('location') or 'unknown location'} produces the "
        f"consequence '{consequence.get('class', '?')}' "
        f"(status {consequence.get('status', '?')} -- the attack agent does "
        f"not claim confirmation)."
    )


def _expected_asset_delta(attack, consequence: dict[str, Any]) -> str:
    if not consequence.get("asset_at_risk"):
        return "No direct asset delta asserted; state/consistency change to observe."
    sink_class = attack.sensitive_sink.get("class", "")
    custody = attack.sensitive_sink.get("custody", "")
    ben_status = (attack.beneficiary_control or {}).get("status", "")
    if sink_class in ("token_approval", "transfer_from") and ben_status not in (PROVEN, INFERRED):
        ben_expr = (attack.beneficiary_control or {}).get("beneficiary_expression", "")
        if ben_status == BENEFICIARY_FIXED:
            return (
                f"protocol account grants/moves assets to spender "
                f"'{ben_expr}', which is not attacker-chosen; observe "
                f"whether the AMOUNT or a downstream use creates any "
                f"attacker-relevant impact, since the beneficiary itself "
                f"does not."
            )
        return (
            f"protocol account grants/moves assets to spender '{ben_expr}'; "
            f"whether this beneficiary is attacker-controlled is not "
            f"established and must be verified before asserting an "
            f"attacker-favorable delta."
        )
    direction = {
        "grant": "protocol account grants attacker-controlled allowance",
        "outbound": "protocol account balance decreases",
    }.get(custody, "protocol asset position changes")
    return (
        f"{direction}; attacker position increases by the granted/moved "
        f"amount while any bracketing validation still passes."
    )


def _invariant(attack, threat) -> str:
    hypothesis = _find_hypothesis(threat, attack.source_hypothesis_id)
    blind_spot = (attack.expected_consequence or {}).get("cross_asset_blind_spot")
    inv_id = hypothesis.get("invariant_candidate_id") or ""
    if inv_id:
        inv = threat.invariant(inv_id)
        if inv:
            base = f"{inv.get('id')}: {inv.get('statement', '')}"
            if blind_spot:
                others = ", ".join(blind_spot["other_assets"])
                base += (
                    f" Additionally: holdings of the other contract-held "
                    f"assets ({others}) must stay unchanged despite the "
                    f"attacker-directed call -- any change CONFIRMS the "
                    f"cross-asset path."
                )
            return base
    stages = {s.get("stage") for s in (hypothesis.get("chain") or [])}
    if "validation_gap" in stages:
        base = (
            "The bracketing pre/post delta check equals its expected value "
            "in the same transaction while the granted authority persists."
        )
        if blind_spot:
            others = ", ".join(blind_spot["other_assets"])
            return (
                f"{base} Additionally: ownership/holdings of the other "
                f"contract-held assets ({others}) are unchanged despite the "
                f"attacker-directed call -- or they are NOT unchanged, which "
                f"CONFIRMS the cross-asset path."
            )
        return base
    return "The protocol's implicit accounting/consistency assumption over the sink."


def _tooling(attack) -> str:
    sink = attack.sensitive_sink
    if sink.get("class", "").startswith(("token", "transfer")) or \
            sink.get("class") in ("arbitrary_external_call", "dynamic_external_call"):
        return (
            "Foundry fork test against a live network state (external token "
            "and target contracts involved); fall back to a unit test with "
            "interface stubs if forking is unavailable."
        )
    return "Foundry/Hardhat unit test with minimal mocks."


def _execution_plan(attack, call_chain: list[str]) -> list[str]:
    sink = attack.sensitive_sink
    steps = [
        "Deploy protocol + dependencies or fork target chain state.",
        "Deploy attacker-controlled EOA/contract accounts.",
        f"Seed protocol balance/state so sink '{sink.get('class', '?')}' has observable effect.",
        f"Invoke entry function '{call_chain[0] if call_chain else attack.entry_point.get('function', '?')}' with attacker-controlled inputs.",
    ]
    if len(call_chain) > 1:
        steps.append(f"Assert runtime reaches call chain: {' -> '.join(call_chain)}.")
    steps.extend([
        "Record pre-state snapshots for affected balances/state variables.",
        "Execute attack transaction sequence.",
        "Record post-state snapshots and compare deltas.",
        "Evaluate gate-specific assertions and consequence assertions.",
    ])
    return steps



def _confirm_reject(strategy: str, attack, consequence: dict[str, Any],
                    hypothesis: dict[str, Any]) -> tuple[str, str]:
    sink = attack.sensitive_sink
    loc = sink.get("location") or "the sink"
    stages = {s.get("stage") for s in (hypothesis.get("chain") or [])}

    if strategy in ("approval abuse", "transferFrom abuse"):
        gap = "validation_gap" in stages
        ben_status = (attack.beneficiary_control or {}).get("status", "")
        beneficiary_proven = ben_status in (PROVEN, INFERRED)
        if beneficiary_proven:
            confirm = (
                f"Calling the entry with attacker-chosen inputs results in the "
                f"protocol account granting (or losing) assets to the attacker-"
                f"chosen beneficiary at {loc}"
                + (" while the bracketing delta check still passes"
                   if gap else "")
                + "; the attacker extracts value in the same or a later "
                "transaction."
            )
            reject = (
                "No allowance/asset movement toward the attacker is observable, "
                "or an authorization boundary / allowance reset prevents the "
                "extraction, or the granted allowance is provably zero."
            )
        else:
            confirm = (
                f"Validator independently establishes the spender/beneficiary "
                f"of the grant at {loc} is attacker-influenced (not a fixed "
                f"protocol contract), AND the attacker extracts value via "
                f"that grant"
                + (" while the bracketing delta check still passes" if gap else "")
                + "."
            )
            reject = (
                "The spender/beneficiary is proven fixed or protocol-"
                "registry-resolved (not attacker-influenced), or no "
                "allowance/asset movement toward any attacker-controlled "
                "account is observable."
            )
        return confirm, reject

    if strategy == "stale/incomplete validation (check passes, authority persists)":
        return (
            "The sequence completes without reverting while a granted "
            "authority/movement the check cannot observe persists past the "
            "second probe.",
            "Every grant is revoked (or consumed) before the check, or the "
            "check reverts on the attacker sequence."
        )

    if strategy == "attacker-controlled external target":
        return (
            f"Attacker-supplied input determines the executed recipient/code "
            f"path at {loc} (verify with a target that records the call).",
            "The executed target is provably independent of attacker input "
            "(fixed address/allowlist)."
        )

    if strategy == "callback/hook reentrancy":
        return (
            "Re-entering the protocol from the callback changes state or "
            "asset positions that the outer frame assumed settled.",
            "Re-entrancy is blocked (guard, checks-effects ordering, or "
            "non-reentrant callee) and state is consistent after the call."
        )

    if strategy == "direct unauthorized call":
        chain = attack.entry_point.get("call_chain") or []
        chain_text = f" via caller chain {' -> '.join(chain)}" if chain else ""
        return (
            "An unprivileged caller can invoke the externally reachable entry"
            f"{chain_text} and observe the claimed privileged effect at the sink.",
            "The entry is not externally reachable by an unprivileged caller, "
            "or an authorization check (inline or modifier) reverts before the sink is reached."
        )

    confirm = (
        f"The composed sequence produces the expected consequence "
        f"'{consequence.get('class', '?')}' at {loc}."
    )
    reject = (
        "A required step is impossible (authorization, ordering, value "
        "constraint), or the observed behavior matches the protocol's "
        "documented/intended semantics."
    )
    return confirm, reject
