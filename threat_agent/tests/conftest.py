"""Threat Agent test configuration.

Resolves the Recon input directory for tests. Priority order:

1. THREAT_RECON_OUTPUT environment variable (explicit override)
2. THREAT_RECON_OUTPUT / recon.live symlink if present
3. Stable sibling path under tests/fixtures/recon
4. Fails clearly if none are available
"""

from __future__ import annotations

import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_RECON_OUTPUT = os.path.join(_HERE, "fixtures", "recon")


def _resolve_recon_output() -> str:
    """Return the Recon output directory for tests.

    Priority:
    1. THREAT_RECON_OUTPUT env var
    2. THREAT_RECON_OUTPUT_*
    """
    for var in ("THREAT_RECON_OUTPUT", "THREAT_RECON_OUTPUT_PATH", "RECON_OUTPUT"):
        val = os.environ.get(var)
        if val and os.path.isdir(val):
            return val

    # Stable bundled fixture directory (committed with the repo)
    fixtures_recon = os.path.join(_HERE, "fixtures", "recon")
    if os.path.isdir(fixtures_recon):
        return fixtures_recon

    # Fallback: sibling recon-system/recon-sample-output (legacy layout)
    legacy = os.path.join(_HERE, "..", "..", "recon-system", "recon-sample-output")
    legacy = os.path.abspath(legacy)
    if os.path.isdir(legacy):
        return legacy

    raise RuntimeError(
        "No Recon artifact directory found. "
        "Set THREAT_RECON_OUTPUT to a Recon output directory, "
        f"or place artifacts in {fixtures_recon}"
    )


@pytest.fixture(scope="session")
def recon_output_dir() -> str:
    """Resolved Recon output directory for this test session."""
    return _resolve_recon_output()


@pytest.fixture(scope="session")
def recon(recon_output_dir):
    from threat.loader import load_recon

    artifact = load_recon(recon_output_dir)
    # Fail clearly when the fixture directory exists but has no facts
    if not artifact.facts_obj.facts:
        raise RuntimeError(
            f"Recon artifact at {recon_output_dir!r} loaded with 0 facts. "
            "Tests require real Recon 0.24+ output. "
            "Run: python -m recon.cli <fixtures> -o <output_dir>"
        )
    return artifact