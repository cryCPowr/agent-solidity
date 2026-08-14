"""Tests for import_resolution: parsing, resolving, and graphing Solidity
`import` statements.

Fully offline, no compiler/subprocess involved -- these exercise the graph
construction that `solc_manager.group_sources_by_version` builds
compilation units from.
"""

from __future__ import annotations

import unittest

import import_resolution as ir


# --------------------------------------------------------------------------
# parse_imports
# --------------------------------------------------------------------------

class TestParseImports(unittest.TestCase):
    def test_plain_import(self):
        stmts = ir.parse_imports("A.sol", 'import "B.sol";\ncontract A {}')
        self.assertEqual([s.raw_path for s in stmts], ["B.sol"])
        self.assertEqual(stmts[0].line, 1)

    def test_import_with_as_alias(self):
        stmts = ir.parse_imports("A.sol", 'import "./B.sol" as Bee;\ncontract A {}')
        self.assertEqual([s.raw_path for s in stmts], ["./B.sol"])

    def test_named_import_from(self):
        stmts = ir.parse_imports("A.sol", 'import {Foo, Bar as Baz} from "./lib/B.sol";\n')
        self.assertEqual([s.raw_path for s in stmts], ["./lib/B.sol"])

    def test_star_import_from(self):
        stmts = ir.parse_imports("A.sol", 'import * as B from "./B.sol";\n')
        self.assertEqual([s.raw_path for s in stmts], ["./B.sol"])

    def test_multiline_named_import(self):
        src = (
            "import {\n"
            "    Foo,\n"
            "    Bar\n"
            "} from \"./B.sol\";\n"
            "contract A {}\n"
        )
        stmts = ir.parse_imports("A.sol", src)
        self.assertEqual([s.raw_path for s in stmts], ["./B.sol"])

    def test_import_in_line_comment_is_ignored(self):
        src = '// import "B.sol";\ncontract A {}'
        self.assertEqual(ir.parse_imports("A.sol", src), [])

    def test_import_in_block_comment_is_ignored(self):
        src = '/* import "B.sol"; */\ncontract A {}'
        self.assertEqual(ir.parse_imports("A.sol", src), [])

    def test_line_numbers_are_1_indexed_and_accurate(self):
        src = "pragma solidity ^0.8.20;\n\nimport \"./B.sol\";\ncontract A {}"
        stmts = ir.parse_imports("A.sol", src)
        self.assertEqual(stmts[0].line, 3)

    def test_no_imports(self):
        self.assertEqual(ir.parse_imports("A.sol", "contract A {}"), [])

    # ---- duplicate import ----

    def test_duplicate_identical_import_statement_parsed_twice(self):
        """Parsing sees both statements (for provenance); resolving/graph
        building is what collapses them (see TestBuildImportGraph)."""
        src = 'import "./B.sol";\nimport "./B.sol";\ncontract A {}'
        stmts = ir.parse_imports("A.sol", src)
        self.assertEqual([s.raw_path for s in stmts], ["./B.sol", "./B.sol"])

    def test_duplicate_import_via_different_literal_spelling(self):
        src = 'import "./B.sol";\nimport {Foo} from "./B.sol";\ncontract A {}'
        stmts = ir.parse_imports("A.sol", src)
        self.assertEqual(len(stmts), 2)


# --------------------------------------------------------------------------
# resolve_import_path
# --------------------------------------------------------------------------

class TestResolveImportPath(unittest.TestCase):
    def test_direct_import_root_relative(self):
        known = {"A.sol", "B.sol"}
        self.assertEqual(ir.resolve_import_path("A.sol", "B.sol", known), "B.sol")

    def test_relative_import_same_directory(self):
        known = {"contracts/A.sol", "contracts/B.sol"}
        resolved = ir.resolve_import_path("contracts/A.sol", "./B.sol", known)
        self.assertEqual(resolved, "contracts/B.sol")

    def test_relative_import_parent_directory(self):
        known = {"contracts/A.sol", "interfaces/IB.sol"}
        resolved = ir.resolve_import_path("contracts/A.sol", "../interfaces/IB.sol", known)
        self.assertEqual(resolved, "interfaces/IB.sol")

    def test_relative_import_into_subdirectory(self):
        known = {"contracts/A.sol", "contracts/lib/B.sol"}
        resolved = ir.resolve_import_path("contracts/A.sol", "./lib/B.sol", known)
        self.assertEqual(resolved, "contracts/lib/B.sol")

    def test_relative_import_never_matches_same_named_file_elsewhere(self):
        """A relative import must resolve strictly relative to the
        importing file's own directory -- it must NOT fall back to
        matching a same-named file living somewhere else in the repo."""
        known = {"contracts/A.sol", "contracts/lib/B.sol", "other/B.sol"}
        resolved = ir.resolve_import_path("contracts/A.sol", "./B.sol", known)
        self.assertIsNone(resolved)

    def test_relative_import_escaping_repo_root_is_unresolved(self):
        known = {"A.sol"}
        resolved = ir.resolve_import_path("A.sol", "../../outside.sol", known)
        self.assertIsNone(resolved)

    def test_missing_import_returns_none(self):
        known = {"A.sol"}
        self.assertIsNone(ir.resolve_import_path("A.sol", "./NotThere.sol", known))
        self.assertIsNone(ir.resolve_import_path("A.sol", "NotThere.sol", known))

    def test_direct_import_falls_back_to_importer_directory(self):
        known = {"contracts/A.sol", "contracts/B.sol"}
        # Written without "./" but only resolvable next to the importer.
        resolved = ir.resolve_import_path("contracts/A.sol", "B.sol", known)
        self.assertEqual(resolved, "contracts/B.sol")


# --------------------------------------------------------------------------
# build_import_graph
# --------------------------------------------------------------------------

class TestBuildImportGraph(unittest.TestCase):
    def test_direct_import_edge(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        graph = ir.build_import_graph(sources)
        self.assertEqual(graph.edges["A.sol"], {"B.sol"})
        self.assertEqual(graph.reverse_edges["B.sol"], {"A.sol"})
        self.assertEqual(graph.unresolved, [])

    def test_transitive_chain_a_imports_b_imports_c(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./C.sol";\ncontract B {}',
            "C.sol": "contract C {}",
        }
        graph = ir.build_import_graph(sources)
        self.assertEqual(graph.edges["A.sol"], {"B.sol"})
        self.assertEqual(graph.edges["B.sol"], {"C.sol"})
        self.assertEqual(graph.edges["C.sol"], set())
        self.assertEqual(graph.unresolved, [])

    def test_duplicate_import_collapses_to_one_edge(self):
        sources = {
            "A.sol": 'import "./B.sol";\nimport {Foo} from "./B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        graph = ir.build_import_graph(sources)
        self.assertEqual(graph.edges["A.sol"], {"B.sol"})  # a set: one edge, not two

    def test_missing_import_recorded_not_dropped_silently(self):
        sources = {"A.sol": 'import "./NotThere.sol";\ncontract A {}'}
        graph = ir.build_import_graph(sources)
        self.assertEqual(graph.edges["A.sol"], set())
        self.assertEqual(len(graph.unresolved), 1)
        u = graph.unresolved[0]
        self.assertEqual(u.importing_file, "A.sol")
        self.assertEqual(u.raw_path, "./NotThere.sol")
        self.assertEqual(u.line, 1)

    def test_cyclic_import_does_not_hang_and_both_edges_recorded(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./A.sol";\ncontract B {}',
        }
        graph = ir.build_import_graph(sources)  # must terminate
        self.assertEqual(graph.edges["A.sol"], {"B.sol"})
        self.assertEqual(graph.edges["B.sol"], {"A.sol"})

    def test_self_import_is_dropped(self):
        sources = {"A.sol": 'import "./A.sol";\ncontract A {}'}
        graph = ir.build_import_graph(sources)
        self.assertEqual(graph.edges["A.sol"], set())
        self.assertEqual(graph.unresolved, [])


# --------------------------------------------------------------------------
# connected_components
# --------------------------------------------------------------------------

class TestConnectedComponents(unittest.TestCase):
    def test_direct_import_same_component(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        graph = ir.build_import_graph(sources)
        comps = ir.connected_components(graph, files=sources.keys())
        self.assertEqual(comps, [["A.sol", "B.sol"]])

    def test_transitive_chain_all_in_one_component(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./C.sol";\ncontract B {}',
            "C.sol": "contract C {}",
        }
        graph = ir.build_import_graph(sources)
        comps = ir.connected_components(graph, files=sources.keys())
        self.assertEqual(comps, [["A.sol", "B.sol", "C.sol"]])

    def test_unrelated_files_are_separate_components(self):
        sources = {
            "A.sol": "contract A {}",
            "B.sol": "contract B {}",
        }
        graph = ir.build_import_graph(sources)
        comps = ir.connected_components(graph, files=sources.keys())
        self.assertEqual(comps, [["A.sol"], ["B.sol"]])

    def test_cycle_forms_a_single_component(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./A.sol";\ncontract B {}',
        }
        graph = ir.build_import_graph(sources)
        comps = ir.connected_components(graph, files=sources.keys())
        self.assertEqual(comps, [["A.sol", "B.sol"]])

    def test_missing_import_does_not_create_a_phantom_component(self):
        sources = {"A.sol": 'import "./NotThere.sol";\ncontract A {}'}
        graph = ir.build_import_graph(sources)
        comps = ir.connected_components(graph, files=sources.keys())
        self.assertEqual(comps, [["A.sol"]])

    def test_deterministic_across_dict_insertion_order(self):
        sources_a = {
            "Z.sol": 'import "./A.sol";\ncontract Z {}',
            "A.sol": "contract A {}",
        }
        sources_b = {
            "A.sol": "contract A {}",
            "Z.sol": 'import "./A.sol";\ncontract Z {}',
        }
        comps_a = ir.connected_components(ir.build_import_graph(sources_a), files=sources_a.keys())
        comps_b = ir.connected_components(ir.build_import_graph(sources_b), files=sources_b.keys())
        self.assertEqual(comps_a, comps_b)


# --------------------------------------------------------------------------
# find_cycles
# --------------------------------------------------------------------------

class TestFindCycles(unittest.TestCase):
    def test_two_file_cycle_detected(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./A.sol";\ncontract B {}',
        }
        graph = ir.build_import_graph(sources)
        cycles = ir.find_cycles(graph)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0]), {"A.sol", "B.sol"})

    def test_no_cycle_in_acyclic_chain(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./C.sol";\ncontract B {}',
            "C.sol": "contract C {}",
        }
        graph = ir.build_import_graph(sources)
        self.assertEqual(ir.find_cycles(graph), [])

    def test_self_import_is_not_reported_as_a_cycle(self):
        sources = {"A.sol": 'import "./A.sol";\ncontract A {}'}
        graph = ir.build_import_graph(sources)
        self.assertEqual(ir.find_cycles(graph), [])

    def test_three_file_cycle_detected(self):
        sources = {
            "A.sol": 'import "./B.sol";\ncontract A {}',
            "B.sol": 'import "./C.sol";\ncontract B {}',
            "C.sol": 'import "./A.sol";\ncontract C {}',
        }
        graph = ir.build_import_graph(sources)
        cycles = ir.find_cycles(graph)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0]), {"A.sol", "B.sol", "C.sol"})

    def test_large_cyclic_graph_terminates(self):
        """Guards against recursion/hangs on a denser cyclic graph."""
        n = 200
        sources = {}
        for i in range(n):
            nxt = (i + 1) % n
            sources[f"F{i}.sol"] = f'import "./F{nxt}.sol";\ncontract F{i} {{}}'
        graph = ir.build_import_graph(sources)
        cycles = ir.find_cycles(graph)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(len(set(cycles[0])), n)


if __name__ == "__main__":
    unittest.main(verbosity=2)
