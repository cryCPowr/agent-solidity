"""Validator Agent: execute attack validator_plans -> CONFIRM / REJECT.

Pipeline position (konsep.txt):

    ATTACK AGENT -> HYPOTHESIS QUEUE -> VALIDATOR
        ├─ CONFIRM -> FINDING AGENT
        └─ REJECT  -> ATTACK retry/refine (REJECT struktural -> THREAT)

The Validator is the ONLY stage allowed to turn a hypothesis into a
verified outcome. It never claims a vulnerability is "real" without an
executed test; infra failures are INCONCLUSIVE, never REJECT.

Architecture (generic; repo specifics live in a SUPPLIED harness):

  planner.py   static pre-flight of the validator_plan vs Recon facts
  codegen.py   Foundry test synthesis: generic attacker contract +
               driver + confirm/reject assertions + harness scaffold
  runner.py    isolated forge workspace (remappings auto-derived),
               forge test execution, output parsing
  verdicts.py  CONFIRM / REJECT / INCONCLUSIVE + retry hints
  harness.py   IProtocolHarness contract interface + harness contract
               management (repo-specific, supplied as DATA, never
               generated with benchmark knowledge)
"""

from .model import Verdict, ValidationRun
from .pipeline import run_validator

__all__ = ["Verdict", "ValidationRun", "run_validator"]
