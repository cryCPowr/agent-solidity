"""MAESTRO — the orchestrator of AGENT FINDER.

Chains all five agents over one target repository and renders a live TUI
so the whole pipeline is visible while it runs automatically:

    RECON -> THREAT -> ATTACK -> VALIDATOR -> FINDING

Non-negotiable rules inherited from konsep.txt:
  - one target = one run directory runs/<target>/ (recon/threat/attack/
    validator/finding inside); refuse to reuse a dirty run dir unless
    --clean-run wipes it first (cross-target contamination guard).
  - repo under test is NEVER modified; forge workspaces live in the run.
  - the LLM assistant hook is OPTIONAL and honest: LLM APIs authenticate
    with an API key (any OpenAI-compatible endpoint), NOT with an email
    address -- there is no such thing as email-only LLM access. Without
    a key the hook stays dormant and the pipeline runs fully
    deterministically.
"""

from .runner import RunResult, StageResult, run_pipeline
from .stages import stage_specs

__all__ = ["run_pipeline", "RunResult", "StageResult", "stage_specs"]
