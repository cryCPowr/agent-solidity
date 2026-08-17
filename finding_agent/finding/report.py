"""Finding construction: attack + verdict -> Finding (audit-report-style)."""

from __future__ import annotations

import os
import re
from typing import Any

from .model import Finding
from .severity import assess_severity


def build_finding(attack: dict[str, Any], verdict: dict[str, Any],
                  sequence: int = 1,
                  validator_dir: str = "") -> Finding:
    consequence = attack.get("expected_consequence") or {}
    blind = consequence.get("cross_asset_blind_spot") or {}
    severity, rationale = assess_severity(attack)

    root = attack.get("root_function", "?")
    entry = (attack.get("entry_point") or {}).get("function", root)

    title = _title(attack, consequence)
    description = _description(attack, consequence, blind)
    impact = _impact(consequence, blind, attack)

    poc = _resolve_poc(attack, verdict, validator_dir)
    if (verdict.get("meta") or {}).get("harness_scope") == "contract":
        poc["scope_note"] = (
            "validated through a CONTRACT-scoped setup harness: its "
            "performAttack implements one specific path; if this attack's "
            "root function differs from that path, the CONFIRM answers the "
            "harness's path. Prefer a function-scoped harness for "
            "path-precise confirmation."
        )

    return Finding(
        finding_id=f"F-{sequence:03d}",
        attack_id=attack.get("attack_id", "?"),
        title=title,
        severity=severity,
        severity_rationale=rationale,
        description=description,
        impact=impact,
        attack_path=[
            {
                "order": s.get("order"),
                "action": s.get("action"),
                "status": s.get("status"),
                "location": s.get("location", ""),
            }
            for s in attack.get("attack_steps", [])
        ],
        affected_code=_affected_code(attack),
        poc=poc,
        mitigation=_mitigation(attack),
        evidence=list(attack.get("evidence", [])),
        fact_ids=sorted(set(attack.get("fact_ids", []))),
        uncertainty=list(attack.get("uncertainty", [])) +
                     list(attack.get("assumptions", [])),
        meta={
            "root_function": root,
            "entry_point": entry,
            "strategy": attack.get("attack_strategy", ""),
            "strategy_status": attack.get("strategy_status", ""),
            "exploitability_score": attack.get("exploitability_score", 0),
            "production_relevance": attack.get("production_relevance", ""),
        },
    )


def _title(attack: dict[str, Any], consequence: dict[str, Any]) -> str:
    root = attack.get("root_function", "")
    fn = root.split("::")[-1].split("#")[0] if "::" in root else root
    cls = consequence.get("class", "security issue")
    return f"{cls.capitalize()} via {fn} ({attack.get('attack_strategy', 'composition')})"


def _description(attack: dict[str, Any], consequence: dict[str, Any],
                 blind: dict[str, Any]) -> str:
    parts = [
        f"Primary strategy: {attack.get('attack_strategy', '?')} "
        f"({attack.get('strategy_status', '?')}).",
        f"Entry point: {(attack.get('entry_point') or {}).get('function', '?')} "
        f"(visibility: {(attack.get('entry_point') or {}).get('visibility', '?')}).",
        f"Attacker-controlled inputs: "
        + (", ".join(i.get("expression", "?")
                     for i in attack.get("controlled_inputs", [])) or "none recorded"),
        f"Capability obtained: {attack.get('capability_obtained', '?')}",
    ]
    desc = consequence.get("description") or consequence.get("class", "")
    if desc:
        parts.append(f"Consequence: {desc}")
    if blind:
        parts.append(
            f"Cross-asset blind spot: the executed check measures only "
            f"'{blind.get('probed_asset')}' while the attacker-directed call "
            f"additionally moved {', '.join(blind.get('other_assets', []))}."
        )
    return "\n".join(parts)


def _impact(consequence: dict[str, Any], blind: dict[str, Any],
            attack: dict[str, Any]) -> str:
    impact = consequence.get("class", "security impact")
    assets = ", ".join(attack.get("affected_assets", [])) or "protocol assets"
    text = f"{impact.capitalize()} affecting {assets}."
    if blind:
        text += (
            f" The validation in place only observes "
            f"'{blind.get('probed_asset')}', so it passes while other "
            f"protocol-held assets ({', '.join(blind.get('other_assets', []))}) "
            f"are moved by the attacker-directed execution."
        )
    return text


def _affected_code(attack: dict[str, Any]) -> list[str]:
    locations = [attack.get("root_function", "")]
    for step in attack.get("attack_steps", []):
        loc = step.get("location", "")
        if loc and loc not in locations:
            locations.append(loc)
    return [loc for loc in locations if loc]


def _mitigation(attack: dict[str, Any]) -> list[str]:
    """Generic, evidence-derived mitigation patterns (never protocol names)."""
    plan = attack.get("validator_plan") or {}
    consequence = attack.get("expected_consequence") or {}
    blind = consequence.get("cross_asset_blind_spot") or {}
    strategy = (attack.get("attack_strategy") or "").lower()
    items: list[str] = []

    if "approval" in strategy or "transferfrom" in strategy:
        items.append(
            "Do not grant asset allowances to caller-chosen addresses: "
            "restrict the approved spender to a curated allowlist, or move "
            "funds with direct transfers instead of approve+pull."
        )
    if blind:
        items.append(
            f"Cross-asset scope: the bracketing check only measures "
            f"'{blind.get('probed_asset')}'. Either forbid the "
            f"attacker-directed call from touching protocol-held assets "
            f"({', '.join(blind.get('other_assets', []))}) via a target "
            f"allow/deny list, or widen the check to cover every asset the "
            f"call could move."
        )
    if "callback" in strategy or "reentran" in strategy:
        items.append(
            "Treat any attacker-controlled execution window inside the "
            "checked frame as untrusted: effects/checks ordering plus "
            "revoking state before the external call, not after."
        )
    if not items:
        items.append(
            "Remove or constrain the attacker-controlled choice at "
            f"'{attack.get('root_function', 'the entry point')}' so the "
            "confirm conditions of the executed PoC can no longer hold."
        )
    if plan.get("reject_if"):
        items.append(
            f"Regression guard (from the validator plan): the fixed code "
            f"must make the PoC hit its reject condition -- {plan['reject_if']}"
        )
    return items


def _resolve_poc(attack: dict[str, Any], verdict: dict[str, Any],
                 validator_dir: str) -> dict[str, Any]:
    """PoC paths, recomputed from the validator output dir when available.

    Verdicts record absolute workspace paths at run time; those go stale
    the moment artifacts are moved/archived. The workspace layout is
    deterministic (workspace/<attack_id>/test/<basename>), so recompute
    from validator_dir and fall back to the recorded values only when
    the recomputed file does not exist.
    """
    recorded_test = verdict.get("test_file", "")
    recorded_ws = (verdict.get("meta") or {}).get("workspace", "")
    workspace, test_file = recorded_ws, recorded_test
    if validator_dir and recorded_test:
        ws = os.path.join(validator_dir, "workspace",
                          attack.get("attack_id", ""))
        candidate = os.path.join(ws, "test", os.path.basename(recorded_test))
        if os.path.exists(candidate):
            workspace, test_file = ws, candidate

    command = ""
    if workspace and test_file:
        rel = os.path.relpath(test_file, workspace)
        command = f"cd {workspace} && forge test --match-path {rel} -vvvv"
    return {
        "test_file": test_file,
        "workspace": workspace,
        "command": command,
        "meaning": (
            "Both driver tests pass: the attack sequence completes AND the "
            "attacker ends up holding the probed asset or a cross asset. "
            "This is an executed confirmation, not a static claim."
        ),
        "verdict_reason": verdict.get("reason", ""),
    }


def render_markdown(finding: Finding) -> str:
    """Audit-report-style report (structure mirrors real audit reports)."""
    meta = finding.meta
    lines = [
        f"# {finding.title}",
        "",
        f"**Finding ID:** {finding.finding_id} (attack `{finding.attack_id}`)",
        f"**Severity:** {finding.severity.upper()} "
        f"— assessment: {finding.severity_rationale}",
        f"**Affected code:** `{meta.get('root_function', '?')}` "
        f"(entry: `{meta.get('entry_point', '?')}`)",
        f"**Production relevance:** {meta.get('production_relevance', '?')}",
        "",
        "## Finding description and impact",
        "",
        finding.description,
        "",
        finding.impact,
        "",
        "## Attack path (executed and confirmed by the Validator)",
        "",
    ]
    for step in finding.attack_path:
        loc = f" @ `{step['location']}`" if step.get("location") else ""
        lines.append(
            f"{step['order']}. **[{step['status']}]** {step['action']}{loc}"
        )
    lines += [
        "",
        "## Proof of Concept (executable)",
        "",
        f"- Test file: `{finding.poc.get('test_file', '')}`",
        f"- Workspace: `{finding.poc.get('workspace', '')}`",
        f"- Run: `{finding.poc.get('command', '')}`",
        *( [f"- **Scope note:** {finding.poc['scope_note']}"]
           if finding.poc.get("scope_note") else [] ),
        f"- Meaning: {finding.poc.get('meaning', '')}",
        f"- Validator reason: {finding.poc.get('verdict_reason', '')}",
        "",
        "## Recommended mitigation",
        "",
    ]
    for i, item in enumerate(finding.mitigation, 1):
        lines.append(f"{i}. {item}")
    lines += [
        "",
        "## Evidence and traceability",
        "",
    ]
    for ev in finding.evidence:
        lines.append(f"- {ev}")
    if finding.fact_ids:
        shown = ", ".join(finding.fact_ids[:40])
        more = f" (+{len(finding.fact_ids) - 40} more)" if len(finding.fact_ids) > 40 else ""
        lines.append(f"- Fact IDs: {shown}{more}")
    if finding.uncertainty:
        lines += ["", "## Remaining uncertainty (preserved, not resolved)", ""]
        for u in finding.uncertainty:
            lines.append(f"- {u}")
    lines += [
        "",
        "---",
        "",
        "Every status above is repeated verbatim from the upstream agents; "
        "this report upgrades nothing. Confirmation authority belongs to "
        "the executed PoC listed above.",
        "",
    ]
    return "\n".join(lines)
