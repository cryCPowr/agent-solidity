"""Attack-artifact loader for the Validator Agent."""

from __future__ import annotations

import json
import os
from typing import Any


def load_attacks(attack_dir: str) -> list[dict[str, Any]]:
    path = os.path.join(attack_dir, "attacks.jsonl")
    attacks: list[dict[str, Any]] = []
    if not os.path.exists(path):
        return attacks
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                attacks.append(json.loads(line))
    # queue order (highest exploitability first) is already the file order
    return attacks


def load_attack_summary(attack_dir: str) -> dict[str, Any]:
    path = os.path.join(attack_dir, "summary.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)
