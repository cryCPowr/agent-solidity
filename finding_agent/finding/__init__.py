"""FINDING AGENT — the report writer of AGENT FINDER.

Pipeline position (konsep.txt):

    VALIDATOR ── CONFIRM ──► FINDING AGENT ──► FINDING (laporan akhir)
                 REJECT ──► (refinement loop, bukan wilayah finding)

Mission: turn ONE confirmed attack into a audit-report-style finding report:
  - what the bug is and its impact
  - the exact attack path (numbered, status-annotated)
  - the executable PoC (where the generated test lives + how to run it)
  - recommended mitigation (generic pattern, evidence-derived)
  - full traceability (fact ids, source locations)

Discipline:
  - ONLY CONFIRM verdicts become findings. REJECT/INCONCLUSIVE never do.
  - The finding agent REPEATS evidence, it never upgrades it: statuses
    stay PROVEN/INFERRED/... exactly as the upstream agents recorded.
  - Severity is an ASSESSMENT derived from consequence class + strategy
    status + score; it is labeled as assessment, not new evidence.
  - Fully generic: no protocol/benchmark identifiers in the engine.
"""

from .model import Finding
from .pipeline import run_finding

__all__ = ["Finding", "run_finding"]
