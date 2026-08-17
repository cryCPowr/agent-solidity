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
from .model import (AttackHypothesis, AttackStep, INFERRED, PROVEN, UNKNOWN)

# Which Threat hypotheses are worth attacking (for_attack_agent.md:
# "for each high-value Threat hypothesis").
HIGH_VALUE_PRIORITIES = frozenset({"high_interest", "very_high_interest"})


def select_high_value(threat) -> list[dict[str, Any]]:
    selected = [
        h for h in threat.hypotheses
        if h.get("priority") in HIGH_VALUE_PRIORITIES
        or h.get("composition_strength") == "STRONG_SECURITY_CHAIN"
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

    ctx = strategies.AttackContext(recon, threat, hypothesis, root_fn, "")
    selected = strategies.select_strategies(ctx)
    if not selected or not strategies.hypothesis_supported(ctx):
        return None  # no evidence-supported attack path; skip, don't force
    primary, *secondary = selected

    entry = attacker_mod.resolve_entry(recon, hypothesis)
    ctx.entry_fn = entry.get("function", "")

    model_str = attacker_mod.attacker_model(hypothesis, entry)
    relevance_level = attacker_mod.relevance_of(recon, root_fn)
    inputs = paths.controlled_inputs(recon, hypothesis, root_fn)
    propa = paths.propagation_path(recon, hypothesis, root_fn, ctx.entry_fn)
    sink = ctx.sink
    capability, cap_status = paths.capability_obtained(hypothesis, recon, root_fn)
    consequence = consequences.classify_consequence(primary, ctx)
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
        capability_obtained=capability,
        affected_assets=assets,
        expected_consequence=consequence,
        attack_steps=_attack_steps(recon, hypothesis, entry, inputs, sink,
                                   consequence, primary, blind_spot),
        evidence=_evidence_lines(primary, selected, hypothesis),
        fact_ids=list(hypothesis.get("observed_facts") or []),
        assumptions=list(primary.get("assumptions") or []),
        uncertainty=_uncertainty_lines(hypothesis, selected),
    )
    attack.capability_status = cap_status  # type: ignore[attr-defined]
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
                  primary, blind_spot=None) -> list[AttackStep]:
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
            add(
                "The protocol account grants spending authority over its "
                "assets to the attacker-chosen beneficiary.",
                PROVEN,
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
