"""Shared fixtures for tests/consumer/.

Runs `python -m recon.cli` exactly once per test session (subprocess, exactly
as an external consumer would invoke it) and hands every test module in this
directory the same read-only ReconOutput. No recon internals are imported.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")

# Only the local test-helper directory goes on sys.path (to import
# recon_reader). REPO_ROOT is deliberately NOT added: this module invokes
# recon.cli as a subprocess so tests exercise it the way an external
# consumer would, and never imports recon internals directly (see docstring).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recon_reader import ReconOutput  # noqa: E402


@pytest.fixture(scope="session")
def repo_root() -> str:
    return REPO_ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> str:
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def recon(tmp_path_factory) -> ReconOutput:
    """Generate recon output the way an external consumer would: invoke the
    CLI as a subprocess against the existing fixture corpus, unmodified, then
    read only the resulting artifact directory.
    """
    out_dir = str(tmp_path_factory.mktemp("recon_consumer_out"))
    proc = subprocess.run(
        [sys.executable, "-m", "recon.cli", FIXTURES_DIR, "-o", out_dir],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"recon.cli failed:\n{proc.stdout}\n{proc.stderr}"
    return ReconOutput(out_dir)
