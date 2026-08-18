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

    # --- 5. Initialization Coherence Invariant ---
    initializer_surfaces = recon.facts_obj.by_type.get("initializer_surface", [])
    initializer_lifecycles = recon.facts_obj.by_type.get("initializer_lifecycle", [])
    if initializer_surfaces or initializer_lifecycles:
        funcs = sorted({
            f["subject"].get("function", "")
            for f in initializer_surfaces
            if f["subject"].get("function")
        })
        facts = [f["id"] for f in initializer_surfaces + initializer_lifecycles]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="initialization_coherence",
                statement="Initialization routines must execute in the intended lifecycle order and must not remain unexpectedly callable after deployment.",
                rationale="Recon observed initializer declarations and/or lifecycle modeling for the contract.",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=["deployment_state", "configuration_state"],
                uncertainty="Recon models initializer structure and observed authorization surfaces, but not deployment sequencing or post-deploy reachability.",
            )
        )

    # --- 6. Upgrade Authority Coherence Invariant ---
    upgrade_functions = recon.facts_obj.by_type.get("upgrade_function", [])
    upgrade_authorities = recon.facts_obj.by_type.get("upgrade_authority", [])
    proxy_paths = recon.facts_obj.by_type.get("proxy_delegatecall_path", [])
    if upgrade_functions or upgrade_authorities or proxy_paths:
        funcs = sorted({
            f["subject"].get("function", "")
            for f in upgrade_functions + upgrade_authorities + proxy_paths
            if f["subject"].get("function")
        })
        facts = [f["id"] for f in upgrade_functions + upgrade_authorities + proxy_paths]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="upgrade_authority_coherence",
                statement="Upgrade and delegatecall-controlled execution paths must remain constrained to the intended authority boundary and implementation source.",
                rationale="Recon observed upgrade-related functions, authorities, or proxy delegatecall paths.",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=["implementation_address", "proxy_storage"],
                uncertainty="Observed authorization on an upgrade path does not by itself prove the authority is immutable, reachable, or semantically correct.",
            )
        )

    # --- 7. Capability / Authority Consistency Invariant ---
    authority_surfaces = recon.facts_obj.by_type.get("capability_authority_surface", [])
    if authority_surfaces:
        funcs = sorted({
            f["subject"].get("function", "")
            for f in authority_surfaces
            if f["subject"].get("function")
        })
        facts = [f["id"] for f in authority_surfaces]
        candidates.append(
            InvariantCandidate(
                id=_next_id(),
                category="capability_authority_consistency",
                statement="Security-sensitive capabilities should remain consistent with their observed authorization boundary and should not unexpectedly rewrite authority state.",
                rationale="Recon linked capability facts to observed authorization surfaces and authorization-state writes.",
                involved_facts=facts,
                involved_functions=funcs,
                involved_assets=["authorization_state", "sensitive_capabilities"],
                uncertainty="Threat significance depends on whether the capability is externally reachable and whether authority state transitions are intended.",
            )
        )

    return candidates
