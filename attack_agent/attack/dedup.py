"""De-duplication of attacks that share one root exploit.

for_attack_agent.md: "Different Threat hypotheses may represent the same
root exploit. Prefer one strong attack hypothesis over many duplicate
variants."

Attacks are merged when they share:
  - the same root function, AND
  - the same attack strategy family, AND
  - the same sink fact (or both sinks unclassified).

The strongest variant (highest exploitability score, deterministic
tiebreak) survives; the others are linked, not discarded.
"""

from __future__ import annotations


def dedup_key(attack) -> tuple:
    return (
        attack.root_function,
        _strategy_family(attack.attack_strategy),
        attack.sensitive_sink.get("fact_id", "") or attack.sensitive_sink.get("class", ""),
    )


def _strategy_family(strategy: str) -> str:
    """Coarse strategy families so near-duplicate variants merge."""
    if strategy in ("approval abuse", "transferFrom abuse",
                    "stale/incomplete validation (check passes, authority persists)"):
        return "asset_authorization_abuse"
    if strategy in ("attacker-controlled external target",
                    "novel composition (protocol-specific path)",
                    "cross-contract trust violation"):
        return "attacker_controlled_execution"
    if strategy in ("callback/hook reentrancy",
                    "malicious token / receiver callback behavior",
                    "state-before-effect / effect-before-state ordering"):
        return "reentrancy_ordering"
    return strategy


def deduplicate(attacks: list) -> list:
    """Merge duplicate attacks; keep strongest, link the rest."""
    best: dict[tuple, int] = {}
    order: list[tuple] = []
    for idx, attack in enumerate(attacks):
        key = dedup_key(attack)
        if key not in best:
            best[key] = idx
            order.append(key)
            continue
        keep_idx = best[key]
        keep, drop = attacks[keep_idx], attack
        if (drop.exploitability_score, drop.attack_id) > \
                (keep.exploitability_score, keep.attack_id):
            # swap: the stronger variant becomes the representative
            attacks[keep_idx], attacks[idx] = drop, keep
            keep = drop
        keep.linked_hypothesis_ids.append(drop.source_hypothesis_id)
        keep.linked_hypothesis_ids.extend(drop.linked_hypothesis_ids)
    seen: set[str] = set()
    merged: list = []
    for key in order:
        attack = attacks[best[key]]
        if attack.attack_id in seen:
            continue
        seen.add(attack.attack_id)
        attack.linked_hypothesis_ids = sorted(
            {h for h in attack.linked_hypothesis_ids
             if h != attack.source_hypothesis_id}
        )
        merged.append(attack)
    return merged
