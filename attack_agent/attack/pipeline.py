"""Attack Agent pipeline orchestration.

    Threat hypotheses (high-value)
        -> per-hypothesis attack paths (entry/control/propagation/sink)
        -> evidence-gated strategy selection
        -> consequence classification
        -> exploitability scoring
        -> de-duplication (one attack per root exploit)
        -> validator handoff plans

The agent INCREASES SPECIFICITY, not hypothesis count: hypotheses without
any evidence-supported strategy are skipped, and duplicates are merged.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import attacker as attacker_mod
from . import consequences, crossasset, dedup, paths, prioritize, relevance, strategies, validator
from .model import (AttackHypothesis, AttackStep, INFERRED, PROVEN, UNKNOWN, POSSIBLE)
from .paths import BENEFICIARY_FIXED as BENEFICIARY_FIXED_STATUS

_EXTERNALLY_REACHABLE = frozenset({"external", "public"})

# Which Threat hypotheses are worth attacking (for_attack_agent.md:
# "for each high-value Threat hypothesis").
HIGH_VALUE_PRIORITIES = frozenset({"high_interest", "very_high_interest"})
BENCHMARK_FAMILY_CATEGORIES = frozenset({
    "accounting_mismatch",
    "rounding_allocation",
    "frontrun_vulnerability",
    "gas_dos",
    "gas_complexity_dos",
    "randomness_manipulation",
    "arithmetic_bound_violation",
    "economic_manipulation",
})


def select_high_value(threat) -> list[dict[str, Any]]:
    selected = [
        h for h in threat.hypotheses
        if h.get("priority") in HIGH_VALUE_PRIORITIES
        or h.get("composition_strength") == "STRONG_SECURITY_CHAIN"
        or h.get("category") in BENCHMARK_FAMILY_CATEGORIES
    ]
    return sorted(selected, key=lambda h: h.get("hypothesis_id", ""))


def generate_attacks(recon, threat) -> list[AttackHypothesis]:
    attacks: list[AttackHypothesis] = []
    for hypothesis in select_high_value(threat):
        attack = _build_attack(recon, threat, hypothesis)
        if attack is not None:
            attacks.append(attack)
    scored = _score_all(attacks, threat)
    merged = dedup.deduplicate(scored)
    merged.sort(key=lambda a: (-a.exploitability_score, a.attack_id))
    for attack in merged:
        attack.validator_plan = validator.build_validator_plan(recon, threat, attack)
    return merged


def _build_attack(recon, threat, hypothesis: dict[str, Any]) -> AttackHypothesis | None:
    affected = hypothesis.get("affected_functions") or []
    root_fn = affected[0] if affected else ""
    if not root_fn:
        return None

    entry = attacker_mod.resolve_entry(recon, hypothesis)
    ctx = strategies.AttackContext(recon, threat, hypothesis, root_fn, entry.get("function", ""))
    selected = strategies.select_strategies(ctx)
    if not selected or not strategies.hypothesis_supported(ctx):
        return None  # no evidence-supported attack path; skip, don't force
    primary, *secondary = selected

    model_str = attacker_mod.attacker_model(hypothesis, entry)
    relevance_level = attacker_mod.relevance_of(recon, root_fn)
    inputs = paths.controlled_inputs(recon, hypothesis, root_fn)
    propa = paths.propagation_path(recon, hypothesis, root_fn, ctx.entry_fn)
    sink = ctx.sink
    target_control = paths.target_control(recon, hypothesis, root_fn, inputs, sink)
    sink_control = paths.sink_argument_control(recon, hypothesis, root_fn, inputs, sink)
    beneficiary_control = paths.beneficiary_control(recon, hypothesis, root_fn, inputs, sink)

    gate_eval = _attack_gates(hypothesis, entry, primary, sink, inputs, propa, target_control,
                              sink_control, beneficiary_control)
    if _gate_blocked(gate_eval):
        return None

    capability, cap_status = paths.capability_obtained(hypothesis, recon, root_fn, beneficiary_control)
    consequence = consequences.classify_consequence(primary, ctx, beneficiary_control)
    blind_spot = crossasset.cross_asset_blind_spot(recon, hypothesis, root_fn)
    if blind_spot is not None:
        _enrich_consequence_with_cross_asset(consequence, blind_spot)

    assets = list(hypothesis.get("affected_assets") or [])
    if not assets and sink.get("custody") in ("grant", "outbound"):
        assets = [sink.get("target_expression") or "the protocol's asset at the sink"]
    if blind_spot is not None:
        for other in blind_spot["other_assets"]:
            if other["asset"] not in [a.lower() for a in assets]:
                assets.append(
                    f"{other['asset']} (other contract-held asset reachable by "
                    f"the attacker-directed call)"
                )

    attack = AttackHypothesis(
        attack_id="TMP",
        source_hypothesis_id=hypothesis.get("hypothesis_id", ""),
        root_function=root_fn,
        attacker_model=model_str,
        production_relevance=relevance_level,
        attack_strategy=primary["name"],
        strategy_status=primary["status"],
        entry_point=entry,
        controlled_inputs=inputs,
        propagation_path=propa,
        sensitive_sink=sink,
        beneficiary_control=beneficiary_control,
        capability_obtained=capability,
        affected_assets=assets,
        expected_consequence=consequence,
        attack_steps=_attack_steps(recon, hypothesis, entry, inputs, sink,
                                   consequence, primary, blind_spot, beneficiary_control),
        evidence=_evidence_lines(primary, selected, hypothesis),
        fact_ids=list(hypothesis.get("observed_facts") or []),
        assumptions=list(primary.get("assumptions") or []),
        uncertainty=_uncertainty_lines(hypothesis, selected),
        attack_gates=gate_eval,
        attack_graph=_attack_graph(entry, root_fn, sink, consequence, primary),
    )
    attack.capability_status = cap_status
    attack.attack_id = _deterministic_id(attack)
    return attack


def _enrich_consequence_with_cross_asset(consequence: dict[str, Any],
                                          blind_spot: dict[str, Any]) -> None:
    """Audit-report-style enrichment (generic): the bracketing check measures
    only the probed asset; the attacker-directed call can additionally
    move other contract-held assets the check never measures."""
    others = ", ".join(o["asset"] for o in blind_spot["other_assets"])
    consequence["description"] = (
        f"{consequence['description']}; the bracketing check measures only "
        f"'{blind_spot['probed_asset']}' while the attacker-directed call "
        f"can additionally move other contract-held assets ({others}) -- "
        f"cross-asset blind spot"
    )
    consequence["cross_asset_blind_spot"] = {
        "probed_asset": blind_spot["probed_asset"],
        "other_assets": [o["asset"] for o in blind_spot["other_assets"]],
    }


def _attack_steps(recon, hypothesis, entry, inputs, sink, consequence,
                  primary, blind_spot=None, beneficiary_control=None) -> list[AttackStep]:
    """Concrete, ordered, fact-grounded attack steps. Unsupported critical
    steps are marked UNKNOWN with what Validator must verify."""
    steps: list[AttackStep] = []
    order = 0

    def add(action: str, status: str, fact_ids: list[str] | None = None,
            location: str = "") -> None:
        nonlocal order
        order += 1
        steps.append(AttackStep(order=order, action=action, status=status,
                                fact_ids=fact_ids or [], location=location))

    entry_fn = entry.get("function", "?")
    add(
        f"Attacker calls {entry_fn} "
        f"(visibility: {entry.get('visibility', UNKNOWN)}).",
        PROVEN if entry.get("status") == PROVEN else UNKNOWN,
        entry.get("fact_ids", []),
        entry.get("location", ""),
    )
    root_fn = (hypothesis.get("affected_functions") or ["?"])[0]
    if entry_fn != root_fn:
        add(
            f"The call propagates through an internal call edge into "
            f"{root_fn}, whose parameters the caller's data chooses.",
            PROVEN,
            _internal_edge_ids(hypothesis),
        )

    for controlled in inputs:
        add(
            f"Attacker supplies '{controlled['expression']}' "
            f"({controlled['kind']}), which they control.",
            controlled.get("status", UNKNOWN),
            [controlled.get("fact_id", "")],
            controlled.get("location", ""),
        )

    for stage_entry in hypothesis.get("chain") or []:
        stage = stage_entry.get("stage", "")
        if stage == "argument_propagation":
            add(
                "The controlled input flows into the arguments of the "
                "sensitive interaction (parameter-rooted dataflow).",
                PROVEN,
                stage_entry.get("fact_ids", []),
                _first_location(recon, stage_entry.get("fact_ids", [])),
            )
        elif stage == "external_execution":
            add(
                f"The interaction executes externally: sink "
                f"'{sink.get('class', '?')}'"
                + (f" on '{sink.get('target_expression')}'" if sink.get("target_expression") else "")
                + ".",
                PROVEN,
                [sink.get("fact_id", "")] if sink.get("fact_id") else stage_entry.get("fact_ids", []),
                sink.get("location", ""),
            )
        elif stage == "downstream_execution_opportunity":
            grade = stage_entry.get("grade", "")
            if grade in ("STRUCTURALLY_INDICATED", "PROVEN"):
                add(
                    "The attacker-chosen recipient executes attacker logic "
                    "while the caller's frame is live.",
                    PROVEN if grade == "PROVEN" else INFERRED,
                    stage_entry.get("fact_ids", []),
                )
            else:
                add(
                    "UNKNOWN -- whether the dynamic recipient executes code "
                    "at all: Validator must set the recipient to an "
                    "attacker contract and observe a callback.",
                    UNKNOWN,
                    stage_entry.get("fact_ids", []),
                )
        elif stage == "asset_authorization":
            ben = beneficiary_control or {}
            ben_status = ben.get("status", UNKNOWN)
            if ben_status in (PROVEN, INFERRED):
                action = (
                    "The protocol account grants spending authority over its "
                    "assets to the attacker-chosen beneficiary."
                )
                step_status = PROVEN if ben_status == PROVEN else INFERRED
            elif ben_status == paths.BENEFICIARY_FIXED:
                action = (
                    "The protocol account grants spending authority, but the "
                    f"beneficiary/spender ('{ben.get('beneficiary_expression', '')}') "
                    "does not overlap any caller-controlled input -- this is "
                    "NOT an attacker-chosen beneficiary; any attacker-relevant "
                    "impact must come from the amount or a downstream effect."
                )
                step_status = POSSIBLE
            else:
                action = (
                    "The protocol account grants spending authority; whether "
                    "the beneficiary/spender is attacker-chosen is not "
                    "established by Recon and must be verified by Validator."
                )
                step_status = UNKNOWN
            add(
                action,
                step_status,
                stage_entry.get("fact_ids", []),
                _first_location(recon, stage_entry.get("fact_ids", [])),
            )
        elif stage == "validation_gap":
            add(
                "The bracketing pre/post delta validation still passes: it "
                "probes one quantity and cannot observe the granted "
                "authority.",
                INFERRED,
                stage_entry.get("fact_ids", []),
                _first_location(recon, stage_entry.get("fact_ids", [])),
            )
            if blind_spot is not None:
                others = ", ".join(o["asset"] for o in blind_spot["other_assets"])
                loc = next(
                    (o["location"] for o in blind_spot["other_assets"] if o["location"]),
                    "",
                )
                add(
                    f"Cross-asset blind spot: the check measures only "
                    f"'{blind_spot['probed_asset']}', but the "
                    f"attacker-directed call can additionally move other "
                    f"assets this contract demonstrably holds/controls "
                    f"({others}) -- the check never measures them.",
                    INFERRED,
                    blind_spot["fact_ids"],
                    loc,
                )

    add(
        f"Consequence: {consequence.get('class', '?')} "
        f"(status {consequence.get('status', UNKNOWN)} -- the attack agent "
        f"does not claim confirmation; see validator_plan).",
        UNKNOWN,
        [],
    )
    return steps


def _internal_edge_ids(hypothesis) -> list[str]:
    for stage in hypothesis.get("chain") or []:
        if stage.get("stage") == "untrusted_influence":
            return [
                fid for fid in stage.get("fact_ids", [])
            ]
    return []


def _first_location(recon, fact_ids: list[str]) -> str:
    for fid in fact_ids:
        loc = recon.source_location(fid)
        if loc:
            return loc
    return ""


def _evidence_lines(primary, selected, hypothesis) -> list[str]:
    lines = [
        f"primary strategy: {primary['name']} ({primary['status']}) -- {primary['basis']}"
    ]
    for sec in selected[1:]:
        lines.append(f"secondary: {sec['name']} ({sec['status']}) -- {sec['basis']}")
    tier = hypothesis.get("evidence_tier", "")
    if tier:
        lines.append(f"upstream evidence tier: {tier}")
    strength = hypothesis.get("composition_strength", "")
    if strength:
        lines.append(f"upstream composition strength: {strength}")
    return lines


def _uncertainty_lines(hypothesis, selected) -> list[str]:
    uncertainties: list[str] = []
    hyp_unc = hypothesis.get("uncertainty", "")
    if isinstance(hyp_unc, str) and hyp_unc:
        uncertainties.append(hyp_unc)
    for strategy in selected:
        for assumption in strategy.get("assumptions", []):
            uncertainties.append(f"assumption to verify [{strategy['name']}]: {assumption}")
    return uncertainties


def _score_all(attacks: list[AttackHypothesis], threat) -> list[AttackHypothesis]:
    by_id = {h.get("hypothesis_id", ""): h for h in threat.hypotheses}
    for attack in attacks:
        hypothesis = by_id.get(attack.source_hypothesis_id, {})
        score, band = prioritize.exploitability_score(attack, hypothesis)
        attack.exploitability_score = score
        attack.exploitability_band = band
    return attacks


def _deterministic_id(attack: AttackHypothesis) -> str:
    components = [
        attack.root_function,
        attack.attack_strategy,
        attack.sensitive_sink.get("fact_id", ""),
        attack.sensitive_sink.get("class", ""),
        attack.source_hypothesis_id,
    ]
    raw = "\n".join(components).encode("utf-8")
    return f"A-{hashlib.sha256(raw).hexdigest()[:10]}"



def _is_externally_reachable_attack(entry: dict[str, Any], root_fn: str) -> bool:
    vis = entry.get("visibility", UNKNOWN)
    if vis not in _EXTERNALLY_REACHABLE:
        return False
    chain = list(entry.get("call_chain") or [])
    if not chain:
        return False
    return chain[-1] == root_fn



def _requires_unproven_privilege(entry: dict[str, Any]) -> bool:
    return entry.get("required_role_status") == PROVEN



ASSET_AUTHORIZATION_STRATEGIES = frozenset({"approval abuse", "transferFrom abuse"})



def _strategy_needs_target_control(primary: dict[str, Any], sink: dict[str, Any]) -> bool:
    strategy = primary.get("name", "")
    return strategy in {
        "attacker-controlled external target",
        "cross-contract trust violation",
        "callback/hook reentrancy",
        "malicious token / receiver callback behavior",
    } or strategy in ASSET_AUTHORIZATION_STRATEGIES or sink.get("class") in {"dynamic_external_call", "arbitrary_external_call"}



def _strategy_needs_sink_input_control(primary: dict[str, Any], sink: dict[str, Any]) -> bool:
    strategy = primary.get("name", "")
    return strategy in {
        "approval abuse",
        "transferFrom abuse",
        "stale/incomplete validation (check passes, authority persists)",
    } or sink.get("class") in {"token_approval", "transfer_from", "token_transfer", "native_value_transfer"}



def _known_concrete_consequence_strategy(strategy: str) -> bool:
    return strategy in {
        "approval abuse",
        "transferFrom abuse",
        "stale/incomplete validation (check passes, authority persists)",
        "attacker-controlled external target",
        "callback/hook reentrancy",
        "malicious token / receiver callback behavior",
        "state-before-effect / effect-before-state ordering",
        "signature/replay manipulation",
        "rounding / precision exploitation",
        "economic sequencing / price manipulation",
        "accounting mismatch",
        "griefing / denial of service",
        "initialization takeover",
        "cross-contract trust violation",
        "upgrade/initialization abuse",
        "gas_dos",
        "arithmetic_overflow",
        "frontrun_race",
        "statistical_exploit",
    }



def _attack_gates(hypothesis: dict[str, Any], entry: dict[str, Any], primary: dict[str, Any],
                  sink: dict[str, Any], inputs: list[dict[str, Any]], propa: list[dict[str, Any]],
                  target_control: dict[str, Any], sink_control: dict[str, Any],
                  beneficiary_control: dict[str, Any] | None = None) -> dict[str, Any]:
    def gate(name: str, status: str, reason: str, evidence_fact_ids: list[str] | None = None) -> tuple[str, dict[str, Any]]:
        return name, {
            "status": status,
            "reason": reason,
            "evidence_fact_ids": [f for f in (evidence_fact_ids or []) if f],
        }

    gates: dict[str, Any] = {}

    entry_ok = _is_externally_reachable_attack(entry, entry.get("root_function", ""))
    k, v = gate(
        "entry_reachability",
        "REACHABLE" if entry_ok else "BLOCKED",
        "externally reachable entry with caller chain to root" if entry_ok else "no externally reachable caller chain to root",
        entry.get("fact_ids", []),
    )
    gates[k] = v

    caller_actor = str(hypothesis.get("actor") or "unknown_actor")
    caller_ok = caller_actor not in {"unknown_actor", ""}
    k, v = gate(
        "caller_validity",
        "REACHABLE" if caller_ok else "UNKNOWN",
        "threat actor model is explicit" if caller_ok else "threat actor model is unknown",
        [],
    )
    gates[k] = v

    priv_blocked = _requires_unproven_privilege(entry)
    k, v = gate(
        "privilege_proof",
        "BLOCKED" if priv_blocked else "REACHABLE",
        "entry has observed authorization boundary and no privilege-escalation acquisition path is proven"
        if priv_blocked else "no observed required privileged role on entry",
        entry.get("fact_ids", []),
    )
    gates[k] = v

    cap_status = primary.get("status", UNKNOWN)
    k, v = gate(
        "capability_acquisition",
        "REACHABLE" if cap_status in (PROVEN, INFERRED) else "UNKNOWN",
        f"strategy capability status = {cap_status}",
        [],
    )
    gates[k] = v

    strategy_name = primary.get("name", "")
    if strategy_name in ASSET_AUTHORIZATION_STRATEGIES:
        ben = beneficiary_control or {}
        bc = ben.get("status", UNKNOWN)
        bc_ok = bc in (PROVEN, INFERRED)
        bc_fixed = bc == BENEFICIARY_FIXED_STATUS
        k, v = gate(
            "target_control",
            "REACHABLE" if bc_ok else ("BLOCKED" if bc_fixed else "UNKNOWN"),
            ben.get("basis", "no beneficiary-control evidence"),
            ben.get("fact_ids", []),
        )
    elif _strategy_needs_target_control(primary, sink):
        tc = target_control.get("status", UNKNOWN)
        tc_ok = tc in (PROVEN, INFERRED)
        k, v = gate(
            "target_control",
            "REACHABLE" if tc_ok else ("UNKNOWN" if tc == POSSIBLE else "BLOCKED"),
            target_control.get("basis", "no target-control evidence"),
            target_control.get("fact_ids", []),
        )
    else:
        k, v = gate("target_control", "REACHABLE", "strategy does not require attacker-controlled dynamic target", [])
    gates[k] = v

    has_proven_input = any(i.get("status") == PROVEN for i in inputs)
    if _strategy_needs_sink_input_control(primary, sink):
        sc = sink_control.get("status", UNKNOWN)
        sc_ok = sc in (PROVEN, INFERRED)
        k, v = gate(
            "input_provenance",
            "REACHABLE" if (has_proven_input and sc_ok) else ("UNKNOWN" if sc_ok else "BLOCKED"),
            sink_control.get("basis", "no sink-input control evidence"),
            sink_control.get("fact_ids", []),
        )
    else:
        k, v = gate(
            "input_provenance",
            "REACHABLE" if has_proven_input else "UNKNOWN",
            "at least one proven controlled input" if has_proven_input else "no proven controlled input observed",
            [i.get("fact_id", "") for i in inputs],
        )
    gates[k] = v

    sink_known = sink.get("class") not in ("", "unknown")
    k, v = gate(
        "sink_relevance",
        "REACHABLE" if sink_known else "BLOCKED",
        "security-sensitive sink identified" if sink_known else "no concrete sensitive sink identified",
        [sink.get("fact_id", "")],
    )
    gates[k] = v

    stages = {s.get("stage") for s in propa}
    causal_ok = bool({"argument_propagation", "external_execution"} & stages)
    k, v = gate(
        "causal_connection",
        "REACHABLE" if causal_ok else "UNKNOWN",
        "propagation path links controlled data to sink execution" if causal_ok else "propagation from controlled input to sink not explicit",
        [fid for s in propa for fid in s.get("fact_ids", [])],
    )
    gates[k] = v

    property_ok = bool(hypothesis.get("invariant_candidate_id") or hypothesis.get("category"))
    k, v = gate(
        "property_applicability",
        "REACHABLE" if property_ok else "UNKNOWN",
        "threat hypothesis provides a scoped security property lens" if property_ok else "no scoped security property reference",
        [],
    )
    gates[k] = v

    conc_ok = _known_concrete_consequence_strategy(primary.get("name", ""))
    k, v = gate(
        "concrete_consequence",
        "REACHABLE" if conc_ok else "UNKNOWN",
        "strategy maps to a concrete consequence model" if conc_ok else "strategy does not map to a concrete consequence model",
        [],
    )
    gates[k] = v

    unsupported = any("absence of evidence" in str(a).lower() for a in (primary.get("assumptions") or []))
    k, v = gate(
        "unsupported_assumption",
        "UNKNOWN" if unsupported else "REACHABLE",
        "assumptions include evidence gaps that validator must discharge" if unsupported else "critical assumptions are explicitly enumerated",
        [],
    )
    gates[k] = v

    return gates



def _gate_blocked(gates: dict[str, Any]) -> bool:
    return any((g or {}).get("status") == "BLOCKED" for g in gates.values())



def _attack_graph(entry: dict[str, Any], root_fn: str, sink: dict[str, Any],
                  consequence: dict[str, Any], primary: dict[str, Any]) -> dict[str, Any]:
    chain = list(entry.get("call_chain") or [])
    return {
        "nodes": [
            {"id": "tx1", "kind": "transaction", "actor": "attacker", "entry": entry.get("function", "")},
            {"id": "s1", "kind": "state", "label": "post-entry"},
            {"id": "sink", "kind": "sink", "sink_class": sink.get("class", ""), "location": sink.get("location", "")},
            {"id": "cons", "kind": "consequence", "class": consequence.get("class", "")},
        ],
        "edges": [
            {"from": "tx1", "to": "s1", "label": "entry-call"},
            {"from": "s1", "to": "sink", "label": "propagate-to-sink"},
            {"from": "sink", "to": "cons", "label": "state/value-effect"},
        ],
        "call_chain": chain if chain else [entry.get("function", ""), root_fn],
        "strategy": primary.get("name", ""),
    }
