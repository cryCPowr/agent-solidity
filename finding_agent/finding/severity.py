"""Severity assessment (an ASSESSMENT, not new evidence).

Derived transparently from what upstream agents + validator established:
  - consequence class (asset theft beats griefing)
  - strategy status (PROVEN beats INFERRED)
  - exploitability score band (from the Attack Agent)
  - production relevance of the affected code

The rationale string always states the inputs so a reader can disagree
with the label using the same data.
"""

from __future__ import annotations

from typing import Any

_CONSEQUENCE_BASE: dict[str, str] = {
    "theft / loss of funds": "critical",
    "unauthorized asset movement": "critical",
    "arbitrary execution": "critical",
    "insolvency": "critical",
    "privilege escalation": "high",
    "incorrect accounting": "medium",
    "accounting mismatch": "medium",
    "unauthorized state mutation": "medium",
    "economic manipulation": "medium",
    "unfair allocation": "medium",
    "reentrancy": "medium",
    "signature abuse": "high",
    "replay": "high",
    "initialization takeover": "high",
    "denial of service": "medium",
    "permanent lock": "medium",
    "griefing": "low",
}

_ORDER = ["informational", "low", "medium", "high", "critical"]


def assess_severity(attack: dict[str, Any]) -> tuple[str, str]:
    consequence = (attack.get("expected_consequence") or {}).get("class", "")
    base = _CONSEQUENCE_BASE.get(consequence.lower(), "medium")
    factors = [f"consequence class {consequence!r} -> base {base}"]

    score = float(attack.get("exploitability_score") or 0)
    if score >= 9 and _rank(base) < _rank("high"):
        base = "high"
        factors.append(f"exploitability {score} raises floor to high")
    elif score <= 4 and _rank(base) > _rank("medium"):
        base = "medium"
        factors.append(f"exploitability {score} caps at medium")
    else:
        factors.append(f"exploitability {score} (no band change)")

    strategy_status = attack.get("strategy_status", "")
    if strategy_status == "PROVEN":
        factors.append("primary strategy PROVEN (no assumption gap)")
    else:
        factors.append(f"primary strategy {strategy_status} (assumptions remain)")

    relevance = attack.get("production_relevance", "UNKNOWN")
    if relevance == "TEST/MOCK":
        factors.append("affected code is TEST/MOCK relevance (informational)")
        base = "informational"

    return base, "; ".join(factors)


def _rank(severity: str) -> int:
    return _ORDER.index(severity) if severity in _ORDER else 0
