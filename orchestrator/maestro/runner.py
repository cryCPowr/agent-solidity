"""Sequential pipeline runner with per-stage capture + stats."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable

from .stages import stage_specs


@dataclass
class StageResult:
    name: str
    agent: str
    cmd: list[str]
    ok: bool
    returncode: int
    log: str = ""
    stats: str = ""
    duration_ms: int = 0


@dataclass
class RunResult:
    run_dir: str
    stages: list[StageResult] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return bool(self.stages) and all(s.ok for s in self.stages)


def prepare_run_dir(run_dir: str, clean_run: bool) -> str:
    """Cross-target hygiene (konsep.txt): refuse a dirty run dir unless
    --clean-run wipes it first."""
    if os.path.exists(run_dir):
        if not clean_run:
            raise RuntimeError(
                f"run dir already exists: {run_dir}. A stale run can "
                f"contaminate the next target. Re-run with --clean-run to "
                f"wipe it, or choose another --name."
            )
        shutil.rmtree(run_dir)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


def run_pipeline(repo: str, run_dir: str, harness_dir: str,
                 limit: int = 0, clean_run: bool = False,
                 on_stage_start: Callable[[str], None] | None = None,
                 on_stage_done: Callable[[StageResult], None] | None = None,
                 log_tail: int = 40) -> RunResult:
    """Run all five stages in order; stop at the first hard failure.

    on_stage_start/on_stage_done are TUI hooks (sync). A stage counts as
    failed when its subprocess exits non-zero; the run stops because later
    stages consume the previous stage's artifacts.
    """
    prepare_run_dir(run_dir, clean_run)
    specs = stage_specs(repo, run_dir, harness_dir, limit)
    result = RunResult(run_dir=run_dir)

    for spec in specs:
        if on_stage_start:
            on_stage_start(spec["name"])
        try:
            proc = subprocess.run(
                spec["cmd"], cwd=spec["cwd"], capture_output=True,
                text=True, timeout=3600,
            )
            log = (proc.stdout or "") + (proc.stderr or "")
            rc = proc.returncode
        except subprocess.TimeoutExpired as exc:
            log = (exc.stdout or "") + (exc.stderr or "") + "\n[maestro] stage timed out"
            rc = 124
        ok = rc == 0 and os.path.isdir(spec["out_dir"])
        stage = StageResult(
            name=spec["name"], agent=spec["agent"], cmd=spec["cmd"],
            ok=ok, returncode=rc, log=log[-4000:],
            stats=spec["stats"](spec["out_dir"]) if os.path.isdir(spec["out_dir"]) else "",
        )
        result.stages.append(stage)
        if on_stage_done:
            on_stage_done(stage)
        if not ok:
            break
    return result
