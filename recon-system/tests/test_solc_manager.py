"""Tests for solc_manager's constraint resolution & trust gating.

All subprocess/filesystem interaction with npm/node is mocked -- these tests
run fully offline and don't touch the real network or a real solc install.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

import solc_manager as sm


# --------------------------------------------------------------------------
# Constraint extraction
# --------------------------------------------------------------------------

class TestExtractPragmaConstraint(unittest.TestCase):
    def test_no_pragma(self):
        self.assertIsNone(sm.extract_pragma_constraint("contract C {}"))

    def test_single_caret(self):
        src = "pragma solidity ^0.8.20;\ncontract C {}"
        self.assertEqual(sm.extract_pragma_constraint(src), "^0.8.20")

    def test_range(self):
        src = "pragma solidity >=0.8.20 <0.9.0;\ncontract C {}"
        self.assertEqual(sm.extract_pragma_constraint(src), ">=0.8.20 <0.9.0")

    def test_multiple_pragma_statements_are_anded(self):
        src = (
            "pragma solidity >=0.7.0;\n"
            "pragma solidity <0.9.0;\n"
            "contract C {}"
        )
        self.assertEqual(sm.extract_pragma_constraint(src), ">=0.7.0 <0.9.0")


# --------------------------------------------------------------------------
# Semver matching
# --------------------------------------------------------------------------

class TestVersionSatisfies(unittest.TestCase):
    def test_caret_same_major_minor_family(self):
        self.assertTrue(sm.version_satisfies("0.8.24", "^0.8.20"))
        self.assertTrue(sm.version_satisfies("0.8.20", "^0.8.20"))
        self.assertFalse(sm.version_satisfies("0.8.19", "^0.8.20"))
        self.assertFalse(sm.version_satisfies("0.9.0", "^0.8.20"))

    def test_bare_version_behaves_like_caret(self):
        self.assertTrue(sm.version_satisfies("0.8.24", "0.8.20"))
        self.assertFalse(sm.version_satisfies("0.9.0", "0.8.20"))

    def test_range_expression(self):
        expr = ">=0.8.20 <0.9.0"
        self.assertTrue(sm.version_satisfies("0.8.24", expr))
        self.assertTrue(sm.version_satisfies("0.8.20", expr))
        self.assertFalse(sm.version_satisfies("0.9.0", expr))
        self.assertFalse(sm.version_satisfies("0.8.19", expr))

    def test_exact_pin(self):
        self.assertTrue(sm.version_satisfies("0.8.24", "=0.8.24"))
        self.assertFalse(sm.version_satisfies("0.8.25", "=0.8.24"))

    def test_or_expression(self):
        expr = "0.7.6 || ^0.8.10"
        self.assertTrue(sm.version_satisfies("0.7.6", expr))
        self.assertTrue(sm.version_satisfies("0.8.15", expr))
        self.assertFalse(sm.version_satisfies("0.7.5", expr))
        self.assertFalse(sm.version_satisfies("0.9.0", expr))

    def test_unparseable_never_matches(self):
        self.assertFalse(sm.version_satisfies("0.8.24", "nonsense"))
        self.assertFalse(sm.version_satisfies("0.8.24", ""))


# --------------------------------------------------------------------------
# Grouping
# --------------------------------------------------------------------------

class TestGrouping(unittest.TestCase):
    def test_groups_by_full_expression_not_first_token(self):
        sources = {
            "A.sol": "pragma solidity ^0.8.20;\ncontract A {}",
            # Same leading token (0.8.20) but a materially different
            # constraint -- must NOT be merged with A.sol's group.
            "B.sol": "pragma solidity >=0.8.20 <0.9.0;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        exprs = {g.constraint_expr for g in groups}
        self.assertEqual(exprs, {"^0.8.20", ">=0.8.20 <0.9.0"})
        self.assertEqual(len(groups), 2)

    def test_no_pragma_gets_its_own_group(self):
        sources = {
            "A.sol": "contract A {}",
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 2)
        no_pragma_group = next(g for g in groups if g.constraint_expr is None)
        self.assertEqual(no_pragma_group.files, ["A.sol"])


# --------------------------------------------------------------------------
# resolve_compiler
# --------------------------------------------------------------------------

class TestResolveCompilerNoPragma(unittest.TestCase):
    def test_no_pragma_uses_bundled_default_and_is_compatible(self):
        req = sm.resolve_compiler(None)
        self.assertEqual(req.resolved_version, sm._BUNDLED_VERSION)
        self.assertEqual(req.resolution_method, "no_pragma_bundled_default")
        self.assertTrue(req.compatible)


class TestResolveCompilerBundledMatches(unittest.TestCase):
    def test_constraint_matching_bundled_resolves_locally(self):
        # Bundled version is 0.8.24, so a range containing it should resolve
        # without ever touching npm/subprocess.
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch("subprocess.run") as run:
            req = sm.resolve_compiler(">=0.8.20 <0.9.0")
        run.assert_not_called()
        self.assertEqual(req.resolved_version, sm._BUNDLED_VERSION)
        self.assertEqual(req.resolution_method, "bundled_compatible")
        self.assertTrue(req.compatible)


class TestResolveCompilerCacheMatches(unittest.TestCase):
    def test_uses_highest_matching_cached_version_over_bundled_mismatch(self):
        # Constraint that bundled (0.8.24) does NOT satisfy, but a cached
        # version does -- should pick the cached one without hitting npm.
        with mock.patch.object(sm, "_cached_versions", return_value=["0.7.6", "0.7.9"]), \
             mock.patch("subprocess.run") as run:
            req = sm.resolve_compiler("^0.7.0")
        run.assert_not_called()
        self.assertEqual(req.resolved_version, "0.7.9")
        self.assertEqual(req.resolution_method, "cache_compatible")
        self.assertTrue(req.compatible)


class TestResolveCompilerMissing(unittest.TestCase):
    """'missing compiler' -- npm has nothing satisfying the constraint."""

    def test_no_published_version_satisfies_constraint_is_unresolved(self):
        published = ["0.4.24", "0.5.17", "0.6.12", "0.7.6", "0.8.24"]
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=published):
            req = sm.resolve_compiler("^0.9.0")  # nothing published matches
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)

    def test_npm_unreachable_is_unresolved_not_bundled_fallback(self):
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=None):
            req = sm.resolve_compiler("^0.7.0")  # bundled (0.8.24) doesn't match
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)
        # Critically: NOT the bundled version standing in as a silent substitute.
        self.assertNotEqual(req.resolved_version, sm._BUNDLED_VERSION)

    def test_offline_budget_skips_npm_entirely(self):
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions") as query:
            req = sm.resolve_compiler("^0.7.0", budget=sm.InstallBudget(offline=True))
        query.assert_not_called()
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)


class TestResolveCompilerWrongVersion(unittest.TestCase):
    """'wrong compiler version' -- constraint pins to something not
    installable/known-published; must not silently substitute bundled."""

    def test_nonexistent_but_syntactically_valid_pin_is_unresolved(self):
        published = ["0.8.24"]
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=published):
            req = sm.resolve_compiler("=9.9.9")
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)

    def test_allow_list_rejects_unknown_minor_family_even_if_published(self):
        # Simulates npm claiming a 1.x release exists; allow-list (known
        # minor families) must still reject it as an install target.
        published = ["1.0.0"]
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=published):
            req = sm.resolve_compiler("^1.0.0")
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)

    def test_unparseable_constraint_is_unresolved(self):
        req = sm.resolve_compiler("not-a-version-constraint")
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unparseable_constraint")
        self.assertFalse(req.compatible)


class TestResolveCompilerInstall(unittest.TestCase):
    def test_installs_highest_satisfying_published_version(self):
        published = ["0.7.4", "0.7.5", "0.7.6"]
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=published), \
             mock.patch.object(sm, "_install_version", return_value=True) as install:
            req = sm.resolve_compiler("^0.7.0")
        install.assert_called_once()
        installed_version = install.call_args[0][0]
        self.assertEqual(installed_version, "0.7.6")
        self.assertEqual(req.resolved_version, "0.7.6")
        self.assertEqual(req.resolution_method, "installed_compatible")
        self.assertTrue(req.compatible)

    def test_install_failure_is_unresolved(self):
        published = ["0.7.6"]
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=published), \
             mock.patch.object(sm, "_install_version", return_value=False):
            req = sm.resolve_compiler("^0.7.0")
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)

    def test_install_budget_exhaustion_is_unresolved(self):
        published = ["0.7.6"]
        budget = sm.InstallBudget(max_installs=1, installs_used=1)  # already exhausted
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=published), \
             mock.patch.object(sm, "_install_version") as install:
            req = sm.resolve_compiler("^0.7.0", budget=budget)
        install.assert_not_called()
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)


# --------------------------------------------------------------------------
# compile_group / trust gating end-to-end (compiler subprocess mocked)
# --------------------------------------------------------------------------

class TestCompileGroupTrustGate(unittest.TestCase):
    def test_incompatible_constraint_never_invokes_compiler(self):
        group = sm.CompileGroup(constraint_expr="^0.9.0", files=["A.sol"])
        sources = {"A.sol": "pragma solidity ^0.9.0;\ncontract A {}"}
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=["0.8.24"]), \
             mock.patch("subprocess.run") as run:
            result = sm.compile_group(group, sources)

        run.assert_not_called()  # never shells out to `node compile.js`
        self.assertFalse(result.ok)
        self.assertFalse(result.compatible)
        self.assertEqual(result.resolution_method, "unresolved")
        self.assertEqual(result.ast_by_file, {})
        self.assertEqual(result.errors[0]["type"], "compiler_resolution_failed")

    def test_compatible_constraint_compiles_and_reports_metadata(self):
        group = sm.CompileGroup(constraint_expr="^0.8.20", files=["A.sol"])
        sources = {"A.sol": "pragma solidity ^0.8.20;\ncontract A {}"}

        fake_output = json.dumps({
            "errors": [],
            "sources": {"A.sol": {"ast": {"nodeType": "SourceUnit"}}},
        })
        fake_proc = mock.Mock(returncode=0, stdout=fake_output, stderr="")

        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch("subprocess.run", return_value=fake_proc) as run:
            result = sm.compile_group(group, sources)

        run.assert_called_once()
        self.assertTrue(result.ok)
        self.assertTrue(result.compatible)
        self.assertEqual(result.version, sm._BUNDLED_VERSION)
        self.assertEqual(result.resolution_method, "bundled_compatible")
        self.assertIn("A.sol", result.ast_by_file)


class TestBuildTrustSummary(unittest.TestCase):
    def test_all_compatible_is_complete(self):
        results = [
            sm.CompileResult(
                version="0.8.24", requested_constraint="^0.8.20", files=["A.sol"],
                ok=True, ast_by_file={"A.sol": {}}, errors=[],
                compatible=True, resolution_method="bundled_compatible",
            ),
        ]
        summary = sm.build_trust_summary(results)
        self.assertEqual(summary["analysis_status"], "complete")
        self.assertEqual(summary["trust_blockers"], [])

    def test_any_incompatible_forces_untrusted(self):
        results = [
            sm.CompileResult(
                version="0.8.24", requested_constraint="^0.8.20", files=["A.sol"],
                ok=True, ast_by_file={"A.sol": {}}, errors=[],
                compatible=True, resolution_method="bundled_compatible",
            ),
            sm.CompileResult(
                version=None, requested_constraint="^0.9.0", files=["B.sol"],
                ok=False, ast_by_file={}, errors=[{"type": "compiler_resolution_failed"}],
                compatible=False, resolution_method="unresolved",
            ),
        ]
        summary = sm.build_trust_summary(results)
        self.assertEqual(summary["analysis_status"], "untrusted")
        self.assertEqual(len(summary["trust_blockers"]), 1)
        self.assertEqual(summary["trust_blockers"][0]["files"], ["B.sol"])
        self.assertEqual(summary["trust_blockers"][0]["requested_constraint"], "^0.9.0")


# --------------------------------------------------------------------------
# group_sources_by_version: import-closure-aware compilation units
#
# The previous implementation grouped files by pragma alone, compiling
# each group in isolation -- which silently broke as soon as two files
# with different (or even identical, but separately-grouped) pragma
# strings imported each other. These tests cover the required scenarios:
# direct import, transitive (nested) import, relative import, duplicate
# import, missing import, cyclic import, and cross-version (differing
# pragma) imports.
# --------------------------------------------------------------------------

def _group_containing(groups, relpath):
    for g in groups:
        if relpath in g.files:
            return g
    raise AssertionError(f"no group contains {relpath!r}; groups={groups}")


class TestGroupingDirectImport(unittest.TestCase):
    def test_a_imports_b_same_pragma_grouped_together(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0].files), ["A.sol", "B.sol"])

    def test_a_imports_b_no_pragma_on_b_still_grouped_together(self):
        """B has no pragma of its own -- must still end up in A's unit
        (previously, B would land in the separate 'no pragma' group and A's
        compile call would be missing B's source entirely)."""
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(sorted(g.files), ["A.sol", "B.sol"])
        self.assertEqual(g.constraint_expr, "^0.8.20")
        self.assertEqual(g.member_constraints, {"A.sol": "^0.8.20", "B.sol": None})

    def test_unrelated_files_sharing_a_pragma_still_merge_for_efficiency(self):
        sources = {
            "A.sol": "pragma solidity ^0.8.20;\ncontract A {}",
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0].files), ["A.sol", "B.sol"])


class TestGroupingTransitiveImport(unittest.TestCase):
    def test_a_imports_b_imports_c_all_grouped_together(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": 'pragma solidity ^0.8.20;\nimport "./C.sol";\ncontract B {}',
            "C.sol": "pragma solidity ^0.8.20;\ncontract C {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0].files), ["A.sol", "B.sol", "C.sol"])

    def test_nested_import_chain_isolated_from_unrelated_file(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": 'pragma solidity ^0.8.20;\nimport "./C.sol";\ncontract B {}',
            "C.sol": "pragma solidity ^0.8.20;\ncontract C {}",
            "D.sol": "pragma solidity ^0.7.0;\ncontract D {}",  # unrelated, different pragma
        }
        groups = sm.group_sources_by_version(sources)
        chain_group = _group_containing(groups, "A.sol")
        self.assertEqual(sorted(chain_group.files), ["A.sol", "B.sol", "C.sol"])
        d_group = _group_containing(groups, "D.sol")
        self.assertNotIn("A.sol", d_group.files)


class TestGroupingRelativeImport(unittest.TestCase):
    def test_relative_import_across_subdirectories_grouped_together(self):
        sources = {
            "contracts/A.sol": (
                'pragma solidity ^0.8.20;\nimport "../interfaces/IB.sol";\ncontract A {}'
            ),
            "interfaces/IB.sol": "pragma solidity ^0.8.20;\ninterface IB {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0].files), ["contracts/A.sol", "interfaces/IB.sol"])

    def test_relative_import_does_not_cross_wire_same_named_sibling_files(self):
        # The decoy deliberately has a *different* pragma from A/B's group:
        # if relative-import resolution ever mis-resolved "./B.sol" to
        # "other/B.sol", that import edge would pull the decoy's
        # incompatible pragma into A's component and this test would see
        # A's group become unresolved/incompatible.
        sources = {
            "contracts/A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "contracts/B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
            "other/B.sol": "pragma solidity ^0.7.0;\ncontract B {}",  # decoy, same basename
        }
        groups = sm.group_sources_by_version(sources)
        a_group = _group_containing(groups, "contracts/A.sol")
        self.assertIn("contracts/B.sol", a_group.files)
        self.assertNotIn("other/B.sol", a_group.files)
        self.assertEqual(a_group.constraint_expr, "^0.8.20")


class TestGroupingDuplicateImport(unittest.TestCase):
    def test_duplicate_import_statement_does_not_duplicate_file_in_group(self):
        sources = {
            "A.sol": (
                'pragma solidity ^0.8.20;\n'
                'import "./B.sol";\n'
                'import {Foo} from "./B.sol";\n'
                'contract A {}'
            ),
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        files = groups[0].files
        self.assertEqual(sorted(files), ["A.sol", "B.sol"])
        self.assertEqual(len(files), len(set(files)))  # no duplicate entries


class TestGroupingMissingImport(unittest.TestCase):
    def test_missing_import_recorded_on_the_group(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./DoesNotExist.sol";\ncontract A {}',
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(g.files, ["A.sol"])
        self.assertEqual(len(g.unresolved_imports), 1)
        self.assertEqual(g.unresolved_imports[0]["raw_path"], "./DoesNotExist.sol")
        self.assertEqual(g.unresolved_imports[0]["importing_file"], "A.sol")

    def test_missing_import_blocks_compile_group_without_invoking_compiler(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./DoesNotExist.sol";\ncontract A {}',
        }
        groups = sm.group_sources_by_version(sources)
        group = _group_containing(groups, "A.sol")
        with mock.patch("subprocess.run") as run:
            result = sm.compile_group(group, sources)
        run.assert_not_called()
        self.assertFalse(result.ok)
        self.assertFalse(result.compatible)
        self.assertEqual(result.resolution_method, "missing_import")
        self.assertEqual(result.ast_by_file, {})
        self.assertEqual(result.errors[0]["type"], "missing_import")
        self.assertIn("DoesNotExist.sol", result.errors[0]["message"])

    def test_missing_import_does_not_block_unrelated_files(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./DoesNotExist.sol";\ncontract A {}',
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        a_group = _group_containing(groups, "A.sol")
        b_group = _group_containing(groups, "B.sol")
        self.assertIsNot(a_group, b_group)
        self.assertEqual(b_group.unresolved_imports, [])


class TestGroupingCyclicImport(unittest.TestCase):
    def test_cyclic_import_terminates_and_groups_together(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": 'pragma solidity ^0.8.20;\nimport "./A.sol";\ncontract B {}',
        }
        groups = sm.group_sources_by_version(sources)  # must terminate
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0].files), ["A.sol", "B.sol"])
        self.assertEqual(len(groups[0].cycles), 1)
        self.assertEqual(set(groups[0].cycles[0]), {"A.sol", "B.sol"})

    def test_cyclic_import_with_compatible_pragma_still_compiles(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": 'pragma solidity ^0.8.20;\nimport "./A.sol";\ncontract B {}',
        }
        groups = sm.group_sources_by_version(sources)
        group = _group_containing(groups, "A.sol")

        fake_output = json.dumps({
            "errors": [],
            "sources": {
                "A.sol": {"ast": {"nodeType": "SourceUnit"}},
                "B.sol": {"ast": {"nodeType": "SourceUnit"}},
            },
        })
        fake_proc = mock.Mock(returncode=0, stdout=fake_output, stderr="")
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch("subprocess.run", return_value=fake_proc) as run:
            result = sm.compile_group(group, sources)

        run.assert_called_once()
        self.assertTrue(result.ok)
        self.assertTrue(result.compatible)
        self.assertIn("A.sol", result.ast_by_file)
        self.assertIn("B.sol", result.ast_by_file)


class TestGroupingCrossVersionImport(unittest.TestCase):
    def test_conflicting_pragma_across_import_edge_forces_incompatible(self):
        """A (^0.8.20) imports B (^0.7.0): they must still be compiled
        together (B's source has to be available to resolve A's import),
        but no single solc version can satisfy both pragmas at once."""
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": "pragma solidity ^0.7.0;\ncontract B {}",
        }
        groups = sm.group_sources_by_version(sources)
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(sorted(group.files), ["A.sol", "B.sol"])
        self.assertEqual(group.member_constraints, {"A.sol": "^0.8.20", "B.sol": "^0.7.0"})

        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=["0.8.24", "0.7.6"]), \
             mock.patch("subprocess.run") as run:
            result = sm.compile_group(group, sources)

        run.assert_not_called()  # never shells out for a doomed-to-fail unit
        self.assertFalse(result.ok)
        self.assertFalse(result.compatible)
        self.assertEqual(result.resolution_method, "unresolved")
        self.assertEqual(result.errors[0]["type"], "compiler_resolution_failed")

    def test_conflicting_pragma_message_names_the_member_constraints(self):
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": "pragma solidity ^0.7.0;\ncontract B {}",
        }
        group = _group_containing(sm.group_sources_by_version(sources), "A.sol")
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=[]):
            result = sm.compile_group(group, sources)
        self.assertIn("A.sol", result.errors[0]["message"])
        self.assertIn("B.sol", result.errors[0]["message"])

    def test_compatible_overlapping_ranges_across_import_edge_do_resolve(self):
        """A requires '>=0.8.0 <0.9.0', B requires '^0.8.20' -- these
        overlap (e.g. 0.8.24 satisfies both), so the unit must resolve
        even though the two pragma strings are not identical."""
        sources = {
            "A.sol": 'pragma solidity >=0.8.0 <0.9.0;\nimport "./B.sol";\ncontract A {}',
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        group = _group_containing(sm.group_sources_by_version(sources), "A.sol")

        fake_output = json.dumps({
            "errors": [],
            "sources": {
                "A.sol": {"ast": {"nodeType": "SourceUnit"}},
                "B.sol": {"ast": {"nodeType": "SourceUnit"}},
            },
        })
        fake_proc = mock.Mock(returncode=0, stdout=fake_output, stderr="")
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch("subprocess.run", return_value=fake_proc) as run:
            result = sm.compile_group(group, sources)

        run.assert_called_once()
        self.assertTrue(result.ok)
        self.assertTrue(result.compatible)
        self.assertEqual(result.version, sm._BUNDLED_VERSION)  # 0.8.24 satisfies both

    def test_or_expression_member_is_not_corrupted_by_naive_string_join(self):
        """Regression guard: A's constraint contains '||'. Naively
        space-joining A's and B's constraint strings before parsing would
        silently change the logical expression (AND vs OR across the
        wrong terms). B's own additional requirement (^0.8.10) must still
        be enforced on top of A's OR-expression.
        """
        sources = {
            "A.sol": 'pragma solidity 0.7.6 || ^0.8.10;\nimport "./B.sol";\ncontract A {}',
            "B.sol": "pragma solidity ^0.8.20;\ncontract B {}",
        }
        group = _group_containing(sm.group_sources_by_version(sources), "A.sol")

        # 0.7.6 satisfies A alone but NOT B (^0.8.20) -- must NOT be chosen.
        # 0.8.24 (bundled) satisfies both (0.7.6||^0.8.10) and ^0.8.20.
        fake_output = json.dumps({
            "errors": [],
            "sources": {
                "A.sol": {"ast": {"nodeType": "SourceUnit"}},
                "B.sol": {"ast": {"nodeType": "SourceUnit"}},
            },
        })
        fake_proc = mock.Mock(returncode=0, stdout=fake_output, stderr="")
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch("subprocess.run", return_value=fake_proc):
            result = sm.compile_group(group, sources)

        self.assertTrue(result.compatible)
        self.assertEqual(result.version, sm._BUNDLED_VERSION)


class TestResolveCompilerForConstraints(unittest.TestCase):
    def test_all_none_uses_bundled_default(self):
        req = sm.resolve_compiler_for_constraints([None, None])
        self.assertEqual(req.resolved_version, sm._BUNDLED_VERSION)
        self.assertEqual(req.resolution_method, "no_pragma_bundled_default")
        self.assertTrue(req.compatible)

    def test_conflicting_caret_constraints_are_unresolved(self):
        with mock.patch.object(sm, "_cached_versions", return_value=[]), \
             mock.patch.object(sm, "_query_npm_available_versions", return_value=["0.8.24", "0.7.6"]), \
             mock.patch("subprocess.run") as run:
            req = sm.resolve_compiler_for_constraints(["^0.8.20", "^0.7.0"])
        run.assert_not_called()
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unresolved")
        self.assertFalse(req.compatible)

    def test_or_expression_distributes_correctly_over_and(self):
        # (0.7.6 || ^0.8.10) AND ^0.8.20  ==  ^0.8.20 restricted further;
        # bundled 0.8.24 satisfies both.
        req = sm.resolve_compiler_for_constraints(["0.7.6 || ^0.8.10", "^0.8.20"])
        self.assertEqual(req.resolved_version, sm._BUNDLED_VERSION)
        self.assertTrue(req.compatible)

    def test_unparseable_member_is_unresolved(self):
        req = sm.resolve_compiler_for_constraints(["^0.8.20", "garbage"])
        self.assertIsNone(req.resolved_version)
        self.assertEqual(req.resolution_method, "unparseable_constraint")
        self.assertFalse(req.compatible)


if __name__ == "__main__":
    unittest.main(verbosity=2)
