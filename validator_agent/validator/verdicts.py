"""Verdict mapping from executed forge results.

Mapping (strict, evidence-first):
  both tests pass                       -> CONFIRM
  test_attack_call_succeeds fails       -> REJECT (path blocked: the call
                                           reverts / preconditions unmet)
  test_attacker_gains fails             -> REJECT (confirm condition
                                           disproved: check holds / no gain)
  compile error / timeout / no harness  -> INCONCLUSIVE (never REJECT)

Every verdict carries a retry_hint for the ATTACK/THREAT refinement loop.
"""

from __future__ import annotations

from typing import Any

from .model import CONFIRM, INCONCLUSIVE, REJECT, Verdict


def verdict_from_run(attack: dict[str, Any], parsed: dict[str, Any],
                     test_file: str) -> Verdict:
    attack_id = attack.get("attack_id", "?")
    if parsed.get("timed_out"):
        return Verdict(
            attack_id=attack_id, verdict=INCONCLUSIVE,
            reason="forge test timed out",
            test_file=test_file,
            retry_hint="split the harness setup or raise the runner timeout",
        )
    if parsed.get("parse_error"):
        return Verdict(
            attack_id=attack_id, verdict=INCONCLUSIVE,
            reason="forge output could not be parsed",
            test_file=test_file,
            retry_hint="inspect raw forge output; engine version mismatch",
            evidence=[parsed.get("raw", "")[:2000]],
        )
    if not parsed.get("tests"):
        return Verdict(
            attack_id=attack_id, verdict=INCONCLUSIVE,
            reason="no test results (compilation or harness failure)",
            test_file=test_file,
            retry_hint="fix the harness scaffold / compile errors; see raw output",
            evidence=[parsed.get("raw", "")[:2000]],
        )

    call_ok = parsed["tests"].get(
        _find_key(parsed["tests"], "test_attack_call_succeeds"), {}
    ).get("passed")
    gains = parsed["tests"].get(
        _find_key(parsed["tests"], "test_attacker_gains"), {}
    ).get("passed")

    if call_ok and gains:
        return Verdict(
            attack_id=attack_id, verdict=CONFIRM,
            reason=(
                "executed test satisfied the confirm conditions: the attack "
                "sequence completed and the attacker gained the probed "
                "asset or a cross asset"
            ),
            test_file=test_file,
            evidence=_passed_evidence(parsed),
            meta={"tests": parsed["tests"]},
        )
    if call_ok is False:
        return Verdict(
            attack_id=attack_id, verdict=REJECT,
            reason=(
                "executed REJECT: the attack call reverts -- path blocked "
                "or preconditions unmet in this setup"
            ),
            test_file=test_file,
            retry_hint="attack refine: check entry preconditions/roles in "
                       "the assumptions; if the entry needs state the "
                       "harness lacks, fix the harness first",
            evidence=_failure_reason(parsed, "test_attack_call_succeeds"),
            meta={"tests": parsed["tests"]},
        )
    if gains is False:
        return Verdict(
            attack_id=attack_id, verdict=REJECT,
            reason=(
                "executed REJECT: the sequence completes but the attacker "
                "gains nothing -- the confirm condition is disproved "
                "(the bracketing check or an authorization holds)"
            ),
            test_file=test_file,
            retry_hint="attack refine: revisit the gain assumption "
                       "(allowance exercised? cross asset reachable?) or "
                       "downgrade the hypothesis",
            evidence=_failure_reason(parsed, "test_attacker_gains"),
            meta={"tests": parsed["tests"]},
        )
    
    # Check new test patterns for expanded coverage
    gas_test = parsed["tests"].get(
        _find_key(parsed["tests"], "test_gas_consumption_within_limits"), {}
    )
    if gas_test.get("passed") is False:
        return Verdict(
            attack_id=attack_id, verdict=CONFIRM,
            reason="gas consumption exceeded block limit threshold (DoS confirmed)",
            test_file=test_file,
            evidence=_failure_reason(parsed, "test_gas_consumption_within_limits"),
            meta={"tests": parsed["tests"]},
        )
    
    arith_test = parsed["tests"].get(
        _find_key(parsed["tests"], "test_arithmetic_bounds_respected"), {}
    )
    if arith_test.get("passed") is False:
        return Verdict(
            attack_id=attack_id, verdict=CONFIRM,
            reason="arithmetic overflow/underflow panic detected (bounds violated)",
            test_file=test_file,
            evidence=_failure_reason(parsed, "test_arithmetic_bounds_respected"),
            meta={"tests": parsed["tests"]},
        )
    
    race_test = parsed["tests"].get(
        _find_key(parsed["tests"], "test_state_race_protected"), {}
    )
    if race_test.get("passed") is False:
        return Verdict(
            attack_id=attack_id, verdict=CONFIRM,
            reason="frontrun attack successfully blocked victim transaction (MEV confirmed)",
            test_file=test_file,
            evidence=_failure_reason(parsed, "test_state_race_protected"),
            meta={"tests": parsed["tests"]},
        )
    
    rand_test = parsed["tests"].get(
        _find_key(parsed["tests"], "test_randomness_distribution_fair"), {}
    )
    if rand_test.get("passed") is False:
        return Verdict(
            attack_id=attack_id, verdict=CONFIRM,
            reason="statistical bias detected in randomness distribution",
            test_file=test_file,
            evidence=_failure_reason(parsed, "test_randomness_distribution_fair"),
            meta={"tests": parsed["tests"]},
        )
    
    return Verdict(
        attack_id=attack_id, verdict=INCONCLUSIVE,
        reason="test results incomplete: expected driver tests not found",
        test_file=test_file,
        retry_hint="regenerate the test (engine/plan mismatch)",
        evidence=[str(parsed["tests"])[:500]],
        meta={"tests": parsed["tests"]},
    )


def verdict_blocked(attack: dict[str, Any], preflight: dict[str, Any]) -> Verdict:
    return Verdict(
        attack_id=attack.get("attack_id", "?"),
        verdict=INCONCLUSIVE,
        reason="; ".join(preflight.get("reasons", [])) or "blocked before execution",
        readiness=preflight.get("status", "BLOCKED"),
        retry_hint=(
            "supply a setup harness implementing IProtocolHarness "
            "(scaffold written next to the verdicts) and re-run"
        ),
    )


def _find_key(tests: dict[str, Any], suffix: str) -> str:
    for key in tests:
        if key.endswith(suffix) or suffix in key:
            return key
    return suffix


def _failure_reason(parsed: dict[str, Any], suffix: str) -> list[str]:
    key = _find_key(parsed["tests"], suffix)
    entry = parsed["tests"].get(key, {})
    reason = entry.get("reason") or "assertion failed"
    return [f"{key}: {reason}"]


def _passed_evidence(parsed: dict[str, Any]) -> list[str]:
    return [
        f"{name}: passed" if res.get("passed") else f"{name}: {res.get('reason')}"
        for name, res in sorted(parsed["tests"].items())
    ]
