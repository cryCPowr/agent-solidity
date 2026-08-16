"""Solidity import parsing, resolution, and dependency-graph construction.

This module is the missing link between `discovery.py` (which only finds
`.sol` files, without looking inside them) and `solc_manager.py` (which
needs to hand solc a Standard JSON `sources` map that is *self-consistent*:
if file A imports file B, solc cannot resolve that import unless B's
content is present in the same `sources` map as A's.

The previous compilation-unit strategy grouped files purely by each file's
*own* `pragma solidity` string and compiled each group in isolation. That
silently broke as soon as two files with different pragma strings imported
each other: B's content simply wasn't included in A's Standard JSON input,
so solc reported a spurious "file not found" for a file that actually
exists in the repo. This module exists so compilation units can instead be
built from the *transitive import closure*, with pragma compatibility
checked (and reported) separately -- see `solc_manager.group_sources_by_version`.

Pipeline through this module:

    parse_imports        -- regex-extract raw `import` statements per file
        -> resolve_import_path   -- resolve each raw path to a known relpath
            -> build_import_graph    -- assemble edges + unresolved imports
                -> connected_components  -- the transitive dependency closure
                -> find_cycles           -- cycle provenance (informational)

Everything here is pure/offline: no filesystem access beyond the in-memory
`sources: dict[relpath, content]` the caller already has, and no subprocess
calls. Traversals are iterative (no recursion), so pathological/adversarial
import graphs (deep chains, dense cycles) cannot cause a stack overflow or
runaway recursion -- they just cost proportionally more iterations.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Iterable

# Matches any Solidity import statement regardless of its exact shape:
#   import "X.sol";
#   import "X.sol" as Y;
#   import * as Y from "X.sol";
#   import {A, B as C} from "X.sol";
# The only structural constant across all forms is: the `import` keyword,
# then (eventually) a quoted path, then a terminating `;`, with no other
# `;` in between. Comments must be stripped first (see `_strip_comments`)
# so a `// import "x.sol";` inside a comment is never mistaken for a real
# import statement.
_IMPORT_RE = re.compile(r"\bimport\b[^;]*?[\'\"]([^\'\"]+)[\'\"][^;]*;")


def _strip_comments(text: str) -> str:
    """Blank out `//...` and `/*...*/` comments, leaving string literals
    alone and preserving newline positions (so line numbers computed from
    the result still match the original source).

    This is intentionally simple (no full Solidity tokenizer) but string-
    literal aware, which is the part that actually matters here: without
    it, a comment containing a quote character could desynchronize the
    in-string tracking and corrupt an unrelated real import elsewhere in
    the file.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_line_comment = False
    in_block_comment = False
    in_string: str | None = None  # the active quote character, or None

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                out.append(c)
            else:
                out.append(" ")
            i += 1
            continue

        if in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
            else:
                out.append(c if c == "\n" else " ")
                i += 1
            continue

        if in_string is not None:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == in_string:
                in_string = None
            i += 1
            continue

        if c in ("'", '"'):
            in_string = c
            out.append(c)
            i += 1
            continue

        if c == "/" and nxt == "/":
            in_line_comment = True
            out.append(" ")
            i += 2
            continue

        if c == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
            continue

        out.append(c)
        i += 1

    return "".join(out)


@dataclass(frozen=True)
class ImportStatement:
    """One `import` statement as written in `importing_file`, before
    resolution."""

    importing_file: str
    raw_path: str
    line: int  # 1-based


def parse_imports(importing_file: str, source_text: str) -> list[ImportStatement]:
    """Extract every `import` statement in `source_text`, in file order."""
    clean = _strip_comments(source_text)
    out: list[ImportStatement] = []
    for m in _IMPORT_RE.finditer(clean):
        raw_path = m.group(1).strip()
        if not raw_path:
            continue
        line = clean.count("\n", 0, m.start()) + 1
        out.append(ImportStatement(importing_file=importing_file, raw_path=raw_path, line=line))
    return out


def resolve_import_path(
    importing_file: str,
    raw_path: str,
    known_files: Iterable[str],
    prefix_aliases: dict[str, str] | None = None,
) -> str | None:
    """Resolve one raw import path to a canonical relpath in `known_files`,
    or None if it cannot be resolved to anything we know about.

    - `./X` and `../X` are relative imports: Solidity always resolves
      these strictly relative to the importing file's own directory, so
      that's the only place we look.
    - Anything else is a "direct" import. Solidity resolves these via
      import remappings / include paths. We accept, in order:
        1. the path repo-root-relative (Hardhat/Foundry-style
           `import "contracts/X.sol"`),
        2. `node_modules/<raw>` (how Hardhat resolves bare package imports
           once external_deps.expand_sources has pulled the dependency's
           file into the source set under its true on-disk relpath),
        3. `prefix_aliases` rewrites (Foundry remappings like
           `@oz/=node_modules/@openzeppelin/contracts/`): the longest
           matching raw-path prefix is replaced by the mapped relpath
           prefix before the known-files lookup,
        4. the importing file's own directory as a best-effort fallback.

    `prefix_aliases` never overrides an exact root-relative match -- a
    repo's own file at the spelled path always wins over a remapping.
    """
    raw_path = raw_path.strip().replace("\\", "/")
    if not raw_path:
        return None

    known = known_files if isinstance(known_files, (set, frozenset)) else set(known_files)
    importing_dir = posixpath.dirname(importing_file)

    if raw_path.startswith("./") or raw_path.startswith("../"):
        candidate = posixpath.normpath(posixpath.join(importing_dir, raw_path))
        candidate = candidate.replace("\\", "/")
        return candidate if candidate in known and candidate != "." else None

    def _try(candidate: str) -> str | None:
        """Known-files lookup with the extensionless fallback."""
        candidate = candidate.replace("\\", "/")
        if candidate in known and candidate != ".":
            return candidate
        if not candidate.endswith(".sol"):
            with_ext = candidate + ".sol"
            if with_ext in known and with_ext != ".":
                return with_ext
        return None

    # 1. Repo-root-relative (exact spelled path wins over any remapping).
    root_hit = _try(posixpath.normpath(raw_path))
    if root_hit:
        return root_hit

    # 2. node_modules convention for bare package imports.
    nm_hit = _try(posixpath.normpath(posixpath.join("node_modules", raw_path)))
    if nm_hit:
        return nm_hit

    # 3. Remapping prefix aliases, longest matching prefix first.
    for prefix, target in sorted((prefix_aliases or {}).items(), key=lambda p: -len(p[0])):
        if raw_path == prefix or raw_path.startswith(prefix + "/"):
            suffix = raw_path[len(prefix):]
            rewritten = _try(posixpath.normpath(posixpath.join(target, suffix)))
            if rewritten:
                return rewritten
            break  # only the longest matching alias applies

    # 4. Importing-file-relative fallback.
    return _try(posixpath.normpath(posixpath.join(importing_dir, raw_path)))


@dataclass(frozen=True)
class UnresolvedImport:
    """An import statement that could not be resolved to any file in the
    analyzed source set (e.g. an un-vendored external dependency, or a
    genuine typo/missing file)."""

    importing_file: str
    raw_path: str
    line: int


@dataclass
class ImportGraph:
    edges: dict[str, set[str]] = field(default_factory=dict)          # file -> files it imports
    reverse_edges: dict[str, set[str]] = field(default_factory=dict)  # file -> files that import it
    unresolved: list[UnresolvedImport] = field(default_factory=list)
    statements: list[ImportStatement] = field(default_factory=list)


def build_import_graph(
    sources: dict[str, str], prefix_aliases: dict[str, str] | None = None
) -> ImportGraph:
    """Parse and resolve every import in `sources`, producing a full
    import dependency graph plus a deterministic list of unresolved
    (missing) imports.

    `prefix_aliases` (raw-path prefix -> relpath prefix, e.g. from a
    Foundry remappings.txt) is threaded through to resolve_import_path so
    remapped bare imports resolve once the target files are part of the
    source set.

    Duplicate imports -- the same file importing the same target more than
    once, whether via an identical literal or two different literals that
    resolve to the same file -- collapse to a single graph edge (edges are
    sets), which is what actually matters for compilation-unit membership.
    A self-import is dropped rather than recorded as an edge or an
    unresolved import, so it can never manufacture a trivial one-node
    "cycle".
    """
    known_files = set(sources.keys())
    edges: dict[str, set[str]] = {relpath: set() for relpath in known_files}
    reverse_edges: dict[str, set[str]] = {relpath: set() for relpath in known_files}
    unresolved: list[UnresolvedImport] = []
    statements: list[ImportStatement] = []

    for relpath in sorted(known_files):
        for stmt in parse_imports(relpath, sources[relpath]):
            statements.append(stmt)
            resolved = resolve_import_path(relpath, stmt.raw_path, known_files, prefix_aliases)
            if resolved is None:
                unresolved.append(UnresolvedImport(relpath, stmt.raw_path, stmt.line))
                continue
            if resolved == relpath:
                continue
            edges[relpath].add(resolved)
            reverse_edges[resolved].add(relpath)

    unresolved.sort(key=lambda u: (u.importing_file, u.line, u.raw_path))
    return ImportGraph(edges=edges, reverse_edges=reverse_edges, unresolved=unresolved, statements=statements)


def connected_components(graph: ImportGraph, files: Iterable[str] | None = None) -> list[list[str]]:
    """Group files into weakly-connected components of the import graph.

    If A imports B (in either direction), A and B MUST end up in the same
    component: solc needs both sources present in one Standard JSON
    `sources` map to resolve the import at all. This naturally absorbs
    cycles without any special-casing -- a cycle is just part of one
    weakly-connected component, discovered like any other edge.

    Deterministic and iterative (explicit stack, no recursion): traversal
    order never depends on dict/set iteration order, and a cyclic or deep
    graph cannot cause unbounded recursion.
    """
    universe = set(files) if files is not None else set(graph.edges) | set(graph.reverse_edges)
    adjacency: dict[str, set[str]] = {}
    for f in universe:
        adjacency[f] = {t for t in graph.edges.get(f, ()) if t in universe} | {
            s for s in graph.reverse_edges.get(f, ()) if s in universe
        }

    seen: set[str] = set()
    components: list[list[str]] = []
    for start in sorted(universe):
        if start in seen:
            continue
        seen.add(start)
        stack = [start]
        comp: list[str] = []
        while stack:
            node = stack.pop()
            comp.append(node)
            for neigh in sorted(adjacency.get(node, ())):
                if neigh not in seen:
                    seen.add(neigh)
                    stack.append(neigh)
        components.append(sorted(comp))

    components.sort(key=lambda c: c[0])
    return components


def find_cycles(graph: ImportGraph) -> list[list[str]]:
    """Deterministically enumerate directed import cycles as file chains,
    e.g. `["A.sol", "B.sol", "A.sol"]`, for provenance/reporting.

    Solidity permits circular imports -- finding one is not itself an
    error, it's just something worth attaching to a compilation unit's
    evidence. Implemented as an iterative DFS with an explicit "on current
    path" set (no recursion, each node fully explored at most once), so it
    terminates deterministically regardless of how cycle-heavy the input
    graph is.
    """
    nodes = sorted(set(graph.edges) | set(graph.reverse_edges))
    state: dict[str, int] = {}  # 1 = on current path, 2 = fully explored
    cycles: list[list[str]] = []
    seen_cycle_keys: set[tuple[str, ...]] = set()

    for start in nodes:
        if state.get(start) == 2:
            continue

        path: list[str] = [start]
        path_set: set[str] = {start}
        state[start] = 1
        call_stack: list[list[str]] = [sorted(graph.edges.get(start, ()))]
        idx_stack: list[int] = [0]

        while call_stack:
            neighbors = call_stack[-1]
            idx = idx_stack[-1]
            if idx >= len(neighbors):
                finished = path.pop()
                path_set.discard(finished)
                state[finished] = 2
                call_stack.pop()
                idx_stack.pop()
                continue

            idx_stack[-1] += 1
            neigh = neighbors[idx]

            if neigh in path_set:
                start_idx = path.index(neigh)
                chain = path[start_idx:] + [neigh]
                key = tuple(chain)
                if key not in seen_cycle_keys:
                    seen_cycle_keys.add(key)
                    cycles.append(chain)
                continue

            if state.get(neigh) == 2:
                continue

            state[neigh] = 1
            path.append(neigh)
            path_set.add(neigh)
            call_stack.append(sorted(graph.edges.get(neigh, ())))
            idx_stack.append(0)

    cycles.sort(key=lambda c: (c[0], len(c)))
    return cycles
