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


def classify_consequence(strategy: dict[str, Any], ctx) -> dict[str, Any]:
    """Return {class, description, status, asset_at_risk}."""
    name = strategy.get("name", "")
    status = UNKNOWN
    key = "novel_consequence"
    asset_at_risk = bool(
        ctx.sink.get("custody") in ("grant", "outbound")
        or ctx.effect_linkage == "asset_flow_linked"
    )

    if name == "approval abuse" or name == "transferFrom abuse":
        key = "unauthorized_asset_movement"
        status = PROVEN if name == "approval abuse" else INFERRED
        if ctx.has_stage("validation_gap"):
            key = "theft"
            status = INFERRED
            description_extra = (
                " the pre/post delta validation can still pass while the "
                "granted spending authority persists"
            )
        else:
            description_extra = ""
        return _result(key, status, asset_at_risk, description_extra)

    if name == "stale/incomplete validation (check passes, authority persists)":
        return _result("theft", INFERRED, asset_at_risk,
                       " the check validates the probed quantity only")

    if name == "attacker-controlled external target":
        key = "arbitrary_execution" if ctx.sink.get("class") == "arbitrary_external_call" \
            else "unauthorized_state_mutation"
        return _result(key, INFERRED if not asset_at_risk else INFERRED, asset_at_risk)

    if name == "callback/hook reentrancy":
        return _result(
            "reentrancy", strategy.get("status", POSSIBLE), asset_at_risk,
            " and possibly inconsistent accounting across the re-entrant "
            "call" if ctx.effect_linkage else "",
        )

    if name.startswith("malicious token"):
        return _result("reentrancy", INFERRED, asset_at_risk,
                       " via attacker-controlled token/receiver hooks")

    if name.startswith("state-before-effect"):
        return _result("unauthorized_state_mutation", POSSIBLE, False)

    if name == "direct unauthorized call":
        return _result("privilege_escalation", INFERRED, asset_at_risk)

    if name == "gas_dos":
        return _result(
            "denial_of_service", INFERRED, False,
            " through unbounded computation exceeding the block gas limit",
        )

    if name == "arithmetic_overflow":
        return _result(
            "denial_of_service", INFERRED, False,
            " through arithmetic panic (bit-shift/overflow) locking protocol state",
        )

    if name == "frontrun_race":
        return _result(
            "denial_of_service", INFERRED, True,
            " of governance/parameter updates via transaction-ordering manipulation",
        )

    if name == "statistical_exploit":
        return _result(
            "unfair_allocation", INFERRED, True,
            " through correlated randomness draws granting a statistical edge",
        )

    if "rounding" in name:
        return _result("unfair_allocation", INFERRED, False)
    if "economic" in name or "price" in name:
        return _result("economic_manipulation", strategy.get("status", POSSIBLE), True)
    if "accounting" in name:
        return _result("incorrect_accounting", INFERRED, False)
    if "signature" in name:
        return _result("signature_abuse", INFERRED, False)
    if "initialization" in name or "upgrade" in name:
        return _result("initialization_takeover", INFERRED, False)
    if "griefing" in name or "denial" in name:
        return _result("denial_of_service", POSSIBLE, False)
    if "cross-contract" in name:
        return _result("cross_contract_trust_failure", INFERRED, asset_at_risk)

    return _result("novel_consequence", strategy.get("status", UNKNOWN), asset_at_risk)


def _result(key: str, status: str, asset_at_risk: bool, extra: str = "") -> dict[str, Any]:
    return {
        "class": CONSEQUENCES[key],
        "status": status,
        "asset_at_risk": asset_at_risk,
        "description": CONSEQUENCES[key] + (extra.rstrip() if extra else ""),
    }
