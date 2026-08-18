"""Consequence classification (for_attack_agent.md section E).

Maps (strategy, sink custody, effect linkage, validation gap) to a
consequence class with an explicit status. Rules enforced:

  - asset movement is not automatically loss (rule 5);
  - the consequence status never exceeds the driving evidence;
  - protocol-custody (grant/outbound) flows may claim asset-loss
    consequences; attacker-funded inflows and self-ledger movements may
    not.
"""

from __future__ import annotations

from typing import Any

from .model import INFERRED, POSSIBLE, PROVEN, UNKNOWN
from .paths import BENEFICIARY_FIXED

# Consequence vocabulary straight from the spec.
CONSEQUENCES = {
    "unauthorized_asset_movement": "unauthorized asset movement",
    "theft": "theft / loss of funds",
    "incorrect_accounting": "incorrect accounting",
    "insolvency": "insolvency",
    "privilege_escalation": "privilege escalation",
    "unauthorized_state_mutation": "unauthorized state mutation",
    "denial_of_service": "denial of service",
    "griefing": "griefing",
    "economic_manipulation": "economic manipulation",
    "unfair_allocation": "unfair allocation",
    "signature_abuse": "signature abuse / replay",
    "reentrancy": "reentrancy-driven state inconsistency",
    "cross_contract_trust_failure": "cross-contract trust failure",
    "initialization_takeover": "initialization takeover",
    "arbitrary_execution": "arbitrary execution",
    "invariant_violation": "invariant violation",
    "novel_consequence": "other novel consequence",
}


def classify_consequence(strategy: dict[str, Any], ctx, beneficiary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a concrete, sink-grounded consequence description.

    `beneficiary` (see attack/paths.py:beneficiary_control) disambiguates
    an attacker-controlled AMOUNT from an attacker-controlled BENEFICIARY:
    consequence phrasing for approval/transferFrom-style sinks must not
    describe a fixed or protocol-registry-resolved spender as if the
    attacker chose it.
    """
    name = strategy.get("name", "")
    status = UNKNOWN
    key = "novel_consequence"
    asset_at_risk = bool(
        ctx.sink.get("custody") in ("grant", "outbound")
        or ctx.effect_linkage == "asset_flow_linked"
    )

    if name == "approval abuse" or name == "transferFrom abuse":
        key = "unauthorized_asset_movement"
        # Never exceed the evidence strength the strategy selector already
        # established (e.g. degraded to INFERRED when beneficiary control
        # is unresolved) -- consequence classification must not re-assert
        # a stronger status than the strategy itself carries.
        status = strategy.get("status", INFERRED)
        if ctx.has_stage("validation_gap"):
            key = "theft"
            # The composed "theft" claim is only as strong as its WEAKEST
            # link: the beneficiary-control status AND the validation_gap
            # stage's own status. A PROVEN beneficiary does not make the
            # gap claim PROVEN if the gap stage itself is only inferred.
            gap_status = str((ctx.stages.get("validation_gap") or {}).get("status", "")).upper()
            gap_is_proven = gap_status in ("PROVEN", "OBSERVED")
            status = status if (status == PROVEN and gap_is_proven) else INFERRED
            description_extra = (
                " the pre/post delta validation can still pass while the "
                "granted spending authority persists"
            )
        else:
            description_extra = ""
        return _result(key, status, asset_at_risk, description_extra, ctx=ctx, beneficiary=beneficiary)

    if name == "stale/incomplete validation (check passes, authority persists)":
        return _result("theft", INFERRED, asset_at_risk,
                       " the check validates the probed quantity only", ctx=ctx)

    if name == "attacker-controlled external target":
        key = "arbitrary_execution" if ctx.sink.get("class") == "arbitrary_external_call" \
            else "unauthorized_state_mutation"
        return _result(key, INFERRED if not asset_at_risk else INFERRED, asset_at_risk, ctx=ctx)

    if name == "callback/hook reentrancy":
        return _result(
            "reentrancy", strategy.get("status", POSSIBLE), asset_at_risk,
            " and possibly inconsistent accounting across the re-entrant "
            "call" if ctx.effect_linkage else "", ctx=ctx,
        )

    if name.startswith("malicious token"):
        return _result("reentrancy", INFERRED, asset_at_risk,
                       " via attacker-controlled token/receiver hooks", ctx=ctx)

    if name.startswith("state-before-effect"):
        return _result("unauthorized_state_mutation", POSSIBLE, False, ctx=ctx)

    if name == "direct unauthorized call":
        return _result("privilege_escalation", INFERRED, asset_at_risk, ctx=ctx)

    if name == "gas_dos":
        return _result(
            "denial_of_service", INFERRED, False,
            " through unbounded computation exceeding the block gas limit", ctx=ctx,
        )

    if name == "arithmetic_overflow":
        return _result(
            "denial_of_service", INFERRED, False,
            " through arithmetic panic (bit-shift/overflow) locking protocol state", ctx=ctx,
        )

    if name == "frontrun_race":
        return _result(
            "denial_of_service", INFERRED, True,
            " of governance/parameter updates via transaction-ordering manipulation", ctx=ctx,
        )

    if name == "statistical_exploit":
        return _result(
            "unfair_allocation", INFERRED, True,
            " through correlated randomness draws granting a statistical edge", ctx=ctx,
        )

    if "rounding" in name:
        return _result("unfair_allocation", INFERRED, False, ctx=ctx)
    if "economic" in name or "price" in name:
        return _result("economic_manipulation", strategy.get("status", POSSIBLE), True, ctx=ctx)
    if "accounting" in name:
        return _result("incorrect_accounting", INFERRED, False, ctx=ctx)
    if "signature" in name:
        return _result("signature_abuse", INFERRED, False, ctx=ctx)
    if "initialization" in name or "upgrade" in name:
        return _result("initialization_takeover", INFERRED, False, ctx=ctx)
    if "griefing" in name or "denial" in name:
        return _result("denial_of_service", POSSIBLE, False, ctx=ctx)
    if "cross-contract" in name:
        return _result("cross_contract_trust_failure", INFERRED, asset_at_risk, ctx=ctx)

    return _result("novel_consequence", strategy.get("status", UNKNOWN), asset_at_risk, ctx=ctx,
                   beneficiary=beneficiary)


def _result(key: str, status: str, asset_at_risk: bool, extra: str = "", *, ctx=None,
           beneficiary: dict[str, Any] | None = None) -> dict[str, Any]:
    sink = (ctx.sink if ctx is not None else {}) if ctx is not None else {}
    sink_class = sink.get("class", "unknown")
    target = sink.get("target_expression") or sink.get("member") or sink_class
    concrete_effect = _concrete_effect(sink, asset_at_risk, beneficiary)
    return {
        "class": CONSEQUENCES[key],
        "status": status,
        "asset_at_risk": asset_at_risk,
        "description": CONSEQUENCES[key] + (extra.rstrip() if extra else ""),
        "sink_class": sink_class,
        "sink_target": target,
        "concrete_effect": concrete_effect,
        "required_observation": f"observe {concrete_effect} through sink '{sink_class}' targeting '{target}'",
    }


def _concrete_effect(sink: dict[str, Any], asset_at_risk: bool,
                    beneficiary: dict[str, Any] | None = None) -> str:
    """Describe the observable effect at the sink.

    For approval/transferFrom-shaped sinks, whether the beneficiary is
    described as "attacker-controlled" depends entirely on
    beneficiary_control's finding -- never on the sink class alone, since
    an attacker-controlled AMOUNT on the same call does not prove a
    caller-chosen beneficiary (see attack/paths.py:beneficiary_control).
    """
    sink_class = sink.get("class", "unknown")
    target = sink.get("target_expression") or sink.get("member") or "the sink target"
    custody = sink.get("custody", "")
    if sink_class in ("token_approval", "transfer_from"):
        ben_status = (beneficiary or {}).get("status", UNKNOWN)
        if ben_status in (PROVEN, INFERRED):
            return f"allowance or spender authority over '{target}' changes in favor of the attacker-controlled beneficiary"
        if ben_status == BENEFICIARY_FIXED:
            ben_expr = (beneficiary or {}).get("beneficiary_expression", "")
            return (
                f"allowance or spender authority over '{target}' changes in "
                f"favor of a fixed/protocol-registry-resolved beneficiary "
                f"('{ben_expr}'), not an attacker-chosen recipient"
            )
        return (
            f"allowance or spender authority over '{target}' changes; "
            f"whether the beneficiary is attacker-chosen is not established by Recon"
        )
    if sink_class in ("token_transfer", "withdraw", "native_value_transfer"):
        if asset_at_risk or custody in ("grant", "outbound"):
            return f"protocol-custody asset movement occurs through '{target}'"
        return f"asset movement occurs through '{target}'"
    if sink_class in ("dynamic_external_call", "arbitrary_external_call"):
        return f"attacker-influenced external execution occurs at '{target}'"
    if sink_class == "state_mutation":
        return "security-relevant protocol state changes"
    if sink_class == "arith_division":
        return "rounding-sensitive division changes allocation or accounting outcomes"
    if sink_class == "arith_bitshift":
        return "bound-sensitive bit-shift or packing logic can panic or mis-encode state"
    if sink_class == "randomness_source":
        return "predictable or reused randomness influences a security-relevant outcome"
    if sink_class == "state_constraint":
        return "mutable live state controls whether a later action succeeds or fails"
    if sink_class == "iteration":
        return "parameter- or state-dependent iteration can exhaust practical gas limits"
    return f"security-relevant behavior occurs at '{target}'"
