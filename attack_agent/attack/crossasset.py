"""Cross-asset blind-spot detection.

Distilled from real audit-report reasoning (kept fully generic): a
pre/post delta validation only measures the asset its probe expression
reads. When an attacker-directed execution window exists in the same
frame, the attacker's calldata can additionally move OTHER assets the
contract demonstrably holds or controls -- assets the check never
measures. The classic shape:

    check probes  token A balance delta
    attacker call moves asset B (a different token/NFT) + drains A via a
    granted allowance inside the window
    -> check on A passes while B is stolen

Everything here is derived structurally:

* probe asset: the receiver of the paired probe expression
  (``X.balanceOf(...)`` -- generic token-standard vocabulary);
* other custodied assets: targets that appear as the object of an
  asset operation or native-value transfer ANYWHERE in the same
  contract (so the contract demonstrably moves them), excluding the
  probed asset. Library/error/helper call targets never qualify
  because they are never asset-operation targets.

No protocol, token, or standard names beyond generic EVM/token
vocabulary are used.
"""

from __future__ import annotations

import re
from typing import Any

# generic token-standard probe vocabulary
_PROBE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*balanceOf\s*\(")

# cast wrappers around identifiers: TokenLibrary(address(tokenVar)) -> tokenVar
_CAST_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(\s*(?:address\s*\(\s*)?([A-Za-z_][A-Za-z0-9_.]*)\s*\)?\s*\)$")


def probe_asset(hypothesis: dict[str, Any], recon) -> str:
    """The asset measured by the hypothesis's paired-probe validation
    ('' when not determinable)."""
    for stage in hypothesis.get("chain") or []:
        if stage.get("stage") != "validation_gap":
            continue
        for fid in stage.get("fact_ids") or []:
            fact = recon.fact(fid)
            if fact is None or fact.get("type") != "local_variable_origin":
                continue
            expr = str((fact.get("properties") or {}).get("expression") or "")
            match = _PROBE_RE.search(expr)
            if match:
                return _normalize_target(match.group(1))
    return ""


def other_custodied_assets(recon, root_fn: str, exclude: str) -> list[dict[str, Any]]:
    """Assets the same contract demonstrably moves (asset operations /
    native-value transfers), excluding the probed asset.

    Returns [{asset, fact_ids, location}], deterministic order.
    """
    contract_prefix = root_fn.split("::")[0] if "::" in root_fn else root_fn
    found: dict[str, dict[str, Any]] = {}
    for fact in recon.facts_obj.facts:
        if fact.get("type") not in ("asset_operation", "eth_transfer"):
            continue
        subj = fact.get("subject") or {}
        fn = subj.get("function") or subj.get("caller") or ""
        if not fn.startswith(contract_prefix):
            continue
        target = str((fact.get("properties") or {}).get("target_expression") or "")
        asset = _normalize_target(target)
        if not asset or asset == exclude:
            continue
        entry = found.setdefault(asset, {"asset": asset, "fact_ids": [], "location": ""})
        fid = fact.get("id", "")
        if fid:
            entry["fact_ids"].append(fid)
        if not entry["location"]:
            entry["location"] = recon.source_location(fid)
    for entry in found.values():
        entry["fact_ids"] = sorted(set(entry["fact_ids"]))
    return [found[k] for k in sorted(found)]


def cross_asset_blind_spot(recon, hypothesis: dict[str, Any],
                           root_fn: str) -> dict[str, Any] | None:
    """Full generic pattern: a bracketing delta validation on asset A +
    an attacker-directed execution window that can additionally move
    other contract-held assets B.. (which the check never measures).

    Returns {'probed_asset', 'other_assets': [...], 'fact_ids'} or None
    when the evidence does not support the pattern.
    """
    stages = {s.get("stage"): s for s in (hypothesis.get("chain") or [])}
    downstream = stages.get("downstream_execution_opportunity") or {}
    if stages.get("validation_gap") is None:
        return None
    if downstream.get("grade") not in ("STRUCTURALLY_INDICATED", "PROVEN"):
        return None
    probed = probe_asset(hypothesis, recon)
    if not probed:
        return None
    others = other_custodied_assets(recon, root_fn, exclude=probed)
    if not others:
        return None
    fact_ids = sorted({fid for o in others for fid in o["fact_ids"]})
    return {
        "probed_asset": probed,
        "other_assets": others,
        "fact_ids": fact_ids,
    }


def _normalize_target(target: str) -> str:
    target = target.strip()
    cast = _CAST_RE.match(target)
    if cast:
        target = cast.group(1)
    return target.strip().lower()
