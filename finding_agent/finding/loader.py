"""Loader: attacks.jsonl + verdicts.jsonl, joined by attack_id."""

from __future__ import annotations

import json
import os
from typing import Any


def _read_jsonl(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not os.path.exists(path):
        return records
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def load_runs(attack_dir: str, validator_dir: str) -> list[tuple[dict, dict]]:
    """Return (attack, verdict) pairs for CONFIRMED attacks, in queue order."""
    attacks = _read_jsonl(os.path.join(attack_dir, "attacks.jsonl"))
    verdicts = {
        v.get("attack_id"): v
        for v in _read_jsonl(os.path.join(validator_dir, "verdicts.jsonl"))
    }
    pairs = []
    for attack in attacks:
        verdict = verdicts.get(attack.get("attack_id"))
        if verdict and verdict.get("verdict") == "CONFIRM":
            pairs.append((attack, verdict))
    return pairs


def load_all_verdicts(validator_dir: str) -> list[dict[str, Any]]:
    return _read_jsonl(os.path.join(validator_dir, "verdicts.jsonl"))
