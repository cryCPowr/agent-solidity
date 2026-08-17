"""Attack Agent output writer.

Writes to the output directory:
  schema.json      the output schema
  attacks.jsonl    one attack hypothesis per line (queue order)
  summary.json     counts, bands, strategies, relevance, duplicates
"""

from __future__ import annotations

import json
import os
from typing import Any

from .schema import SCHEMA


def write_attack_output(attacks, output_dir: str) -> dict[str, Any]:
    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "schema.json"), "w", encoding="utf-8") as f:
        json.dump(SCHEMA, f, indent=2)

    with open(os.path.join(output_dir, "attacks.jsonl"), "w", encoding="utf-8") as f:
        for attack in attacks:
            f.write(json.dumps(attack.to_dict()) + "\n")

    summary = build_summary(attacks)
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return summary


def build_summary(attacks) -> dict[str, Any]:
    def count(key_fn) -> dict[str, int]:
        buckets: dict[str, int] = {}
        for attack in attacks:
            buckets[key_fn(attack)] = buckets.get(key_fn(attack), 0) + 1
        return dict(sorted(buckets.items()))

    return {
        "attack_count": len(attacks),
        "attacks_by_band": count(lambda a: a.exploitability_band),
        "attacks_by_strategy": count(lambda a: a.attack_strategy),
        "attacks_by_production_relevance": count(lambda a: a.production_relevance),
        "attacks_by_consequence": count(lambda a: a.expected_consequence.get("class", "?")),
        "merged_duplicate_hypotheses": sum(len(a.linked_hypothesis_ids) for a in attacks),
        "top_attacks": [
            {
                "attack_id": a.attack_id,
                "strategy": a.attack_strategy,
                "root_function": a.root_function,
                "score": a.exploitability_score,
                "band": a.exploitability_band,
                "relevance": a.production_relevance,
            }
            for a in attacks[:10]
        ],
    }
