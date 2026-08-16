"""Unit tests for `recon.discovery.discover_sources`.

These call `discover_sources` directly against real temp-dir filesystem
layouts. They deliberately do NOT go through `recon.cli` / the
`tests/consumer` subprocess fixture: that fixture exercises the whole
pipeline as an external consumer would, which is the wrong altitude for
pinning down discovery's own boundary logic (and, in this repo, its
conftest.py has unrelated collection bugs). Put this file wherever
recon-level unit tests live, e.g. `tests/unit/test_discovery.py`.
"""

from __future__ import annotations

import os

import pytest

from recon.discovery import discover_sources


def _write(path: str, content: str = "// sol\n") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def _relpaths(repo_root: str, **kwargs) -> set[str]:
    return {f.relative_path for f in discover_sources(repo_root, **kwargs)}


# --------------------------------------------------------------------------
# Baseline behavior (must keep working - regression guard for this change)
# --------------------------------------------------------------------------

def test_normal_sol_accepted(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "Vault.sol"))
    assert _relpaths(str(repo)) == {"Vault.sol"}


def test_nested_sol_accepted(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "contracts" / "core" / "Vault.sol"))
    assert _relpaths(str(repo)) == {"contracts/core/Vault.sol"}


def test_non_sol_files_ignored(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "Vault.sol"))
    _write(str(repo / "README.md"))
    assert _relpaths(str(repo)) == {"Vault.sol"}


def test_skip_dir_names_excluded(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "Vault.sol"))
    _write(str(repo / "node_modules" / "dep" / "Dep.sol"))
    _write(str(repo / "cache" / "Cached.sol"))
    assert _relpaths(str(repo)) == {"Vault.sol"}


def test_lib_skipped_by_default_but_includable(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "Vault.sol"))
    _write(str(repo / "lib" / "forge-std" / "Std.sol"))
    assert _relpaths(str(repo)) == {"Vault.sol"}
    assert _relpaths(str(repo), include_lib=True) == {
        "Vault.sol",
        "lib/forge-std/Std.sol",
    }


def test_nested_lib_dir_is_first_party_and_discovered(tmp_path):
    """Hardhat/Truffle projects keep first-party sources in nested lib/
    directories (contracts/lib/...). Only the *root-level* lib/ is the
    Foundry submodule dir; nested ones must always be discovered, or every
    contract importing from them fails compilation with spurious
    unresolved-import errors."""
    repo = tmp_path / "repo"
    _write(str(repo / "Vault.sol"))
    _write(str(repo / "contracts" / "Vault.sol"))
    _write(str(repo / "contracts" / "lib" / "Combinations.sol"))
    _write(str(repo / "test" / "helpers" / "lib" / "Deep.sol"))
    assert _relpaths(str(repo)) == {
        "Vault.sol",
        "contracts/Vault.sol",
        "contracts/lib/Combinations.sol",
        "test/helpers/lib/Deep.sol",
    }


def test_extra_skip_dirs(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "Vault.sol"))
    _write(str(repo / "vendor" / "Vendored.sol"))
    assert _relpaths(str(repo), extra_skip_dirs=frozenset({"vendor"})) == {"Vault.sol"}


def test_results_sorted_by_relative_path(tmp_path):
    repo = tmp_path / "repo"
    _write(str(repo / "b.sol"))
    _write(str(repo / "a.sol"))
    _write(str(repo / "sub" / "c.sol"))
    result = [f.relative_path for f in discover_sources(str(repo))]
    assert result == sorted(result)
    assert result == ["a.sol", "b.sol", "sub/c.sol"]


# --------------------------------------------------------------------------
# Symlink filesystem-boundary enforcement (the actual bug being fixed)
# --------------------------------------------------------------------------

def test_file_symlink_inside_repo_accepted(tmp_path):
    """A .sol symlink whose target is also inside repo_root is fine -
    nothing has left the boundary."""
    repo = tmp_path / "repo"
    real_target = repo / "contracts" / "Vault.sol"
    _write(str(real_target))

    linked = repo / "contracts" / "VaultAlias.sol"
    os.symlink(str(real_target), str(linked))

    assert _relpaths(str(repo)) == {"contracts/Vault.sol", "contracts/VaultAlias.sol"}


def test_file_symlink_outside_repo_rejected(tmp_path):
    """The core case from the report: a .sol symlink pointing outside the
    repo must not enter the discovered source universe."""
    outside_dir = tmp_path / "outside-secret"
    outside_dir.mkdir()
    outside_target = outside_dir / "Vault.sol"
    _write(str(outside_target))

    repo = tmp_path / "repo"
    linked = repo / "contracts" / "Vault.sol"
    os.makedirs(os.path.dirname(str(linked)), exist_ok=True)
    os.symlink(str(outside_target), str(linked))

    assert _relpaths(str(repo)) == set()


def test_file_symlink_outside_repo_rejected_even_with_sibling_real_file(tmp_path):
    """Boundary rejection is per-candidate: a legit sibling file is still
    discovered even though the escaping symlink next to it is dropped."""
    outside_dir = tmp_path / "outside-secret"
    outside_dir.mkdir()
    _write(str(outside_dir / "Secret.sol"))

    repo = tmp_path / "repo"
    _write(str(repo / "contracts" / "Real.sol"))
    os.symlink(
        str(outside_dir / "Secret.sol"),
        str(repo / "contracts" / "Escaped.sol"),
    )

    assert _relpaths(str(repo)) == {"contracts/Real.sol"}


def test_broken_symlink_rejected(tmp_path):
    """A dangling symlink can't be verified as inside the boundary and
    can't be read anyway - must not be silently included."""
    repo = tmp_path / "repo"
    linked = repo / "contracts" / "Dangling.sol"
    os.makedirs(os.path.dirname(str(linked)), exist_ok=True)
    os.symlink(str(tmp_path / "does-not-exist.sol"), str(linked))

    assert _relpaths(str(repo)) == set()


def test_directory_symlink_pointing_outside_is_deterministic(tmp_path):
    """A symlinked directory pointing outside the repo must never leak its
    contents in, and must behave the same way on repeated calls (no
    dependence on walk order / OS / symlink-loop handling)."""
    outside_dir = tmp_path / "outside-secret"
    outside_dir.mkdir()
    _write(str(outside_dir / "Secret.sol"))

    repo = tmp_path / "repo"
    repo.mkdir()
    _write(str(repo / "Vault.sol"))
    os.symlink(str(outside_dir), str(repo / "linked_dir"), target_is_directory=True)

    first = _relpaths(str(repo))
    second = _relpaths(str(repo))
    assert first == second == {"Vault.sol"}


def test_directory_symlink_pointing_inside_is_deterministic(tmp_path):
    """A symlinked directory whose target is inside the repo also must not
    have its contents double-walked or leak duplicates, and must be
    deterministic across calls."""
    repo = tmp_path / "repo"
    real_dir = repo / "contracts"
    _write(str(real_dir / "Vault.sol"))
    os.symlink(str(real_dir), str(repo / "linked_dir"), target_is_directory=True)

    first = _relpaths(str(repo))
    second = _relpaths(str(repo))
    assert first == second == {"contracts/Vault.sol"}


def test_symlink_chain_outside_repo_rejected(tmp_path):
    """Indirect escape: symlink -> symlink -> file outside repo. realpath
    fully dereferences the chain, so this must still be rejected."""
    outside_dir = tmp_path / "outside-secret"
    outside_dir.mkdir()
    outside_target = outside_dir / "Vault.sol"
    _write(str(outside_target))

    repo = tmp_path / "repo"
    repo.mkdir()
    hop1 = tmp_path / "hop1.sol"
    os.symlink(str(outside_target), str(hop1))
    hop2 = repo / "Vault.sol"
    os.symlink(str(hop1), str(hop2))

    assert _relpaths(str(repo)) == set()


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", *sys.argv[1:]]))
