"""Invariant Candidates Generator.

Generates security invariant candidates from observable protocol structure.
These are INVARIANT CANDIDATES, not confirmed guarantees.

Supported Categories:
- asset_conservation
- share_asset_correspondence
- authorization_coherence
- accounting_accuracy
- non_negative_balance
- unbacked_mint_prevention
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import loader


@dataclass
class InvariantCandidate:
    id: str
    category: str
    statement: str
    rationale: str
    involved_facts: list[str] = field(default_factory=list)
    involved_functions: list[str] = field(default_factory=list)
    involved_assets: list[str] = field(default_factory=list)
    uncertainty: str = ""
    confidence: str = "medium"  # low | medium | high


def generate_invariants(recon: loader.ReconArtifact) -> list[InvariantCandidate]:
    """Generate candidate security invariants from Recon facts."""
    candidates: list[InvariantCandidate] = []
    inv_counter = 0

    def _next_id() -> str:
        nonlocal inv_counter
        inv_counter += 1
        return f"INV-{inv_counter:03d}"

    # --- 1. Asset Conservation Invariant ---
    # For every function performing token/ETH transfers
    asset_ops = recon.facts_obj.by_type.get("asset_operation", [])
    eth_transfers = recon.facts_obj.by_type.get("eth_transfer", [])
    if asset_ops or eth_transfers:
        funcs = sorted({
            f["subject"]["function"] for f in asset_ops + eth_transfers
        })
        facts = [f["id"] for f in asset_ops + eth_transfers]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="asset_conservation",
                statement="Total protocol assets must cover liabilities; asset transfers must not exceed authorized amounts.",
                rationale="Protocol performs asset operations (transfer/approve/native transfer).",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=["tokens", "ETH"],
                uncertainty="Exact accounting invariant depends on internal state update logic.",
            )
        )

    # --- 2. Share / Allocation Accuracy Invariant ---
    # For functions with division or arithmetic
    divisions = recon.facts_obj.by_type.get("division_operation", [])
    if divisions:
        funcs = sorted({f["subject"]["function"] for f in divisions})
        facts = [f["id"] for f in divisions]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="share_asset_correspondence",
                statement="Share or reward calculations using integer division must not accumulate precision advantage to unauthorized parties.",
                rationale="Division operations truncate towards zero; rounding direction must favor the protocol or be bounded.",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=["shares", "rewards"],
                uncertainty="Solidity division truncates towards zero; whether rounding direction is safe depends on numerator/denominator order.",
            )
        )

    # --- 3. Authorization Coherence Invariant ---
    # For access_controlled_function facts
    access_controlled = recon.facts_obj.by_type.get("access_controlled_function", [])
    if access_controlled:
        funcs = sorted({f["subject"]["function"] for f in access_controlled})
        facts = [f["id"] for f in access_controlled]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="authorization_coherence",
                statement="Privileged operations must only be callable by authorized actors matching the designated role.",
                rationale="Functions are protected by inline or modifier-based authorization checks.",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=[],
                uncertainty="State variables used for authorization may be mutable by other functions.",
            )
        )

    # --- 4. Dynamic Execution Isolation Invariant ---
    # For arbitrary low-level call or delegatecall capabilities
    caps = recon.facts_obj.by_type.get("capability", [])
    dynamic_caps = [
        c for c in caps
        if c["subject"]["capability"] in ("can_call_arbitrary_target", "can_delegatecall")
    ]
    if dynamic_caps:
        funcs = sorted({c["subject"]["function"] for c in dynamic_caps})
        facts = [c["id"] for c in dynamic_caps]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="execution_isolation",
                statement="Arbitrary external calls or delegatecalls must not allow unverified state mutation or token redirection.",
                rationale="Functions possess arbitrary call or delegatecall capabilities.",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=["protocol_state", "tokens"],
                uncertainty="Caller may restrict target through parameters or state; verification required.",
            )
        )

    return candidates