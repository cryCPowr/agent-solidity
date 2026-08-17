"""Rich TUI: live dashboard for the whole AGENT FINDER run."""

from __future__ import annotations

import time

from rich.console import Group, Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import assistant
from .runner import RunResult, StageResult

_STATUS_STYLE = {
    "pending": ("dim", "…"),
    "running": ("bold cyan", "▶"),
    "ok": ("bold green", "✔"),
    "fail": ("bold red", "✘"),
}


class Dashboard:
    """Live layout: header / stage table / live log / verdict footer."""

    def __init__(self, repo: str, run_dir: str, stage_names: list[str]):
        self.repo = repo
        self.run_dir = run_dir
        self.rows = {name: {"status": "pending", "stats": ""} for name in stage_names}
        self.log_lines: list[str] = []
        self.finished: RunResult | None = None
        self._t0 = time.time()

    # -- hooks called by the runner ---------------------------------------

    def on_stage_start(self, name: str) -> None:
        self.rows[name]["status"] = "running"
        self._append(f"▶ {name} running…", style="cyan")

    def on_stage_done(self, stage: StageResult) -> None:
        self.rows[stage.name]["status"] = "ok" if stage.ok else "fail"
        self.rows[stage.name]["stats"] = stage.stats
        mark = "✔" if stage.ok else "✘"
        self._append(f"{mark or '!'} {stage.name} {stage.stats}".strip(),
                     style="green" if stage.ok else "red")
        for line in stage.log.splitlines()[-6:]:
            if line.strip():
                self._append(f"│ {line.strip()[:120]}", style="dim")

    def _append(self, line: str, style: str = "") -> None:
        self.log_lines.append((line, style))
        self.log_lines = self.log_lines[-18:]

    # -- rendering ---------------------------------------------------------

    def render(self) -> Panel:
        elapsed = time.time() - self._t0
        header = Text()
        header.append(" AGENT FINDER ", style="bold white on blue")
        header.append("  recon → threat → attack → validator → finding",
                      style="dim")
        header.append(f"\n target: {self.repo}\n run:    {self.run_dir}"
                      f"   [{elapsed:6.1f}s]")
        header.append(f"\n {assistant.status_line()}", style="yellow")

        table = Table.grid(padding=(0, 2))
        table.add_column(width=3, justify="center")
        table.add_column(width=12)
        table.add_column(width=10, justify="center")
        table.add_column(ratio=1, overflow="ellipsis")
        for name, row in self.rows.items():
            style, glyph = _STATUS_STYLE[row["status"]]
            table.add_row(Text(glyph, style=style), Text(name, style=style),
                          Text(row["status"], style=style),
                          Text(row["stats"], style="dim"))
        log = Text()
        for i, (line, style) in enumerate(self.log_lines[-14:]):
            if i:
                log.append("\n")
            log.append(line, style=style or None)
        body = Group(header, Text(""), table, Text(""), log)
        return Panel(body, border_style="blue",
                     title="maestro — orchestrator", title_align="left")

    def final_panel(self) -> Panel:
        result = self.finished
        assert result is not None
        table = Table(title=f"Run complete — {result.run_dir}",
                      title_style="bold")
        table.add_column("stage", width=12)
        table.add_column("result", width=8, justify="center")
        table.add_column("stats", overflow="fold")
        for stage in result.stages:
            style = "green" if stage.ok else "red"
            table.add_row(stage.name, Text("OK" if stage.ok else "FAIL",
                                           style=style), stage.stats)
        summary_path = None
        finding_stage = [s for s in result.stages if s.name == "FINDING"]
        if finding_stage and finding_stage[0].ok:
            summary_path = f"{result.run_dir}/finding/summary.json"
        note = Text()
        if summary_path:
            note.append(f"\nfindings summary: {summary_path}\n"
                        f"reports: {result.run_dir}/finding/finding-*.md",
                        style="bold green")
        else:
            note.append("\nno finding stage output — see failed stage above",
                        style="yellow")
        return Panel(Group(table, note), border_style="green")


def run_with_tui(repo: str, run_dir: str, harness_dir: str, limit: int,
                 clean_run: bool, console: Console | None = None) -> RunResult:
    console = console or Console()
    dash = Dashboard(repo, run_dir,
                     ["RECON", "THREAT", "ATTACK", "VALIDATOR", "FINDING"])
    from .runner import run_pipeline
    with Live(dash.render(), console=console, refresh_per_second=4) as live:
        result = run_pipeline(
            repo, run_dir, harness_dir, limit=limit, clean_run=clean_run,
            on_stage_start=lambda name: (dash.on_stage_start(name),
                                         live.update(dash.render())),
            on_stage_done=lambda stage: (dash.on_stage_done(stage),
                                         live.update(dash.render())),
        )
        dash.finished = result
        live.update(dash.render())
    console.print(dash.final_panel())
    return result


def run_plain(repo: str, run_dir: str, harness_dir: str, limit: int,
              clean_run: bool, console: Console | None = None) -> RunResult:
    """Non-TUI mode (CI / piping): plain stage lines."""
    console = console or Console()
    console.print(f"[bold blue]AGENT FINDER[/bold blue] target={repo} "
                  f"run={run_dir}")
    console.print(f"[yellow]{assistant.status_line()}[/yellow]")
    from .runner import run_pipeline
    result = run_pipeline(
        repo, run_dir, harness_dir, limit=limit, clean_run=clean_run,
        on_stage_start=lambda name: console.print(f"[cyan]▶ {name}[/cyan]"),
        on_stage_done=lambda s: console.print(
            f"[{'green' if s.ok else 'red'}]"
            f"{'✔' if s.ok else '✘'} {s.name}[/] rc={s.returncode} "
            f"{s.stats}"),
    )
    console.print(dash_final_text(result))
    return result


def dash_final_text(result: RunResult) -> str:
    lines = ["", f"run complete: {result.run_dir}"]
    for s in result.stages:
        mark = "OK  " if s.ok else "FAIL"
        lines.append(f"  [{mark}] {s.name:10} {s.stats}")
    lines.append(f"  findings: {result.run_dir}/finding/finding-*.md")
    return "\n".join(lines)
