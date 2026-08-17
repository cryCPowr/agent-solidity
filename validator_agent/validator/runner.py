"""Foundry runner: isolated workspace, execution, output parsing.

The workspace is fully isolated from the repository under test:
  workspace/
    foundry.toml      (src/test/lib paths + remappings derived from the
                       repo's node_modules layout -- generic package
                       conventions only)
    contracts -> symlink to <repo>/contracts
    node_modules -> symlink to <repo>/node_modules (when present)
    test/...          generated test + harness copy

Nothing in the repository is ever modified.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from .codegen import render_test, test_slug

FORGE_TIMEOUT_DEFAULT = 600  # seconds


def build_workspace(workspace: str, repo_dir: str, attack: dict[str, Any],
                    harness: dict[str, Any]) -> str:
    """Create the isolated forge workspace and write the generated test.
    Returns the test file path."""
    os.makedirs(os.path.join(workspace, "test"), exist_ok=True)
    contracts = _ensure_link(workspace, "contracts", _find_contracts_dir(repo_dir))
    node_modules = os.path.join(repo_dir, "node_modules")
    if os.path.isdir(node_modules):
        _ensure_link(workspace, "node_modules", node_modules)

    remappings = _derive_remappings(workspace)
    with open(os.path.join(workspace, "foundry.toml"), "w", encoding="utf-8") as f:
        f.write(
            "[profile.default]\n"
            'src = "contracts"\n'
            'test = "test"\n'
            'out = "out"\n'
            'libs = ["node_modules"]\n'
            'solc_version = "0.8.28"\n'
            'ffi = false\n'
            'evm_version = "cancun"\n'
            "via_ir = true\n"
            "optimizer = true\n"
            "optimizer_runs = 200\n"
            f"remappings = {json.dumps(remappings)}\n"
        )

    harness_dst = os.path.join(workspace, "test", os.path.basename(harness["path"]))
    shutil.copyfile(harness["path"], harness_dst)

    slug = test_slug(attack.get("attack_id", ""))
    test_path = os.path.join(workspace, "test", f"Validate{slug}.t.sol")
    source = render_test(attack, harness["contract"], os.path.basename(harness["path"]))
    with open(test_path, "w", encoding="utf-8") as f:
        f.write(source)
    return test_path


def _find_contracts_dir(repo_dir: str) -> str:
    for candidate in ("contracts", "src", "."):
        path = os.path.join(repo_dir, candidate)
        if os.path.isdir(path):
            return path
    return repo_dir


def _ensure_link(workspace: str, name: str, target: str) -> str:
    link = os.path.join(workspace, name)
    if os.path.lexists(link):
        os.remove(link)
    os.symlink(os.path.abspath(target), link)
    return link


def _derive_remappings(workspace: str) -> list[str]:
    """Generic package-convention remappings from the linked node_modules
    (scoped packages `@org/pkg/...` and bare packages `pkg/...`)."""
    nm = os.path.join(workspace, "node_modules")
    remappings: list[str] = []
    if not os.path.isdir(nm):
        return remappings
    for entry in sorted(os.listdir(nm)):
        path = os.path.join(nm, entry)
        if entry.startswith("@"):
            if not os.path.isdir(path):
                continue
            for sub in sorted(os.listdir(path)):
                remappings.append(f"{entry}/{sub}/=node_modules/{entry}/{sub}/")
        elif os.path.isdir(path):
            remappings.append(f"{entry}/=node_modules/{entry}/")
    return remappings


def run_forge_test(workspace: str, test_path: str,
                   timeout: int = FORGE_TIMEOUT_DEFAULT) -> dict[str, Any]:
    """Run `forge test --json` limited to the generated file."""
    rel = os.path.relpath(test_path, workspace)
    cmd = ["forge", "test", "--match-path", rel, "--json", "--root", workspace]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=workspace,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stdout": "", "stderr": "forge test timed out"}
    return {
        "status": "done",
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def parse_forge_json(run: dict[str, Any]) -> dict[str, Any]:
    """Parse `forge test --json` output into per-test results.

    Returns {"ok": bool, "tests": {name: {"passed": bool, "reason": str}},
             "raw": stdout}.
    """
    stdout = run.get("stdout", "")
    if run.get("status") == "timeout":
        return {"ok": False, "timed_out": True, "tests": {}, "raw": ""}
    try:
        # forge --json emits one JSON object per line (NDJSON)
        payloads = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    except json.JSONDecodeError:
        return {"ok": False, "parse_error": True, "tests": {}, "raw": stdout}
    tests: dict[str, Any] = {}
    ok = True
    for payload in payloads:
        # forge --json format: {"test/...:ContractName": {"test_results": {...}}}
        for key, suite in payload.items():
            if not isinstance(suite, dict):
                continue
            suite_results = suite.get("test_results") or {}
            for test_name, result in suite_results.items():
                if not isinstance(result, dict):
                    continue
                status = result.get("status", "")
                passed = status == "Success"
                reason = result.get("reason") or ""
                tests[test_name] = {"passed": passed, "reason": reason}
                if not passed:
                    ok = False
    return {"ok": ok, "tests": tests, "raw": stdout}
