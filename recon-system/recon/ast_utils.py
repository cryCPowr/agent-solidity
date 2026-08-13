"""Generic helpers for walking solc's JSON AST and resolving source locations.

Nothing here is Solidity-semantics-aware beyond "this is a JSON tree with
`nodeType` / `src` / `id` conventions". Semantic interpretation lives in the
analysis modules.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional


class LineIndex:
    """Maps a byte offset within a source file's UTF-8 encoded content to a
    1-indexed line number.

    solc's `src` offsets are byte offsets into the UTF-8 encoding of the
    source, NOT Python character/codepoint offsets. Any non-ASCII character
    (e.g. an em dash in a comment) makes those diverge. This class — and all
    offset-based slicing in this codebase — operates on `bytes`.
    """

    def __init__(self, content_bytes: bytes):
        self._offsets = [0]
        for i, b in enumerate(content_bytes):
            if b == 0x0A:  # '\n'
                self._offsets.append(i + 1)
        self._len = len(content_bytes)

    def line_for_offset(self, offset: int) -> Optional[int]:
        if offset is None or offset < 0 or offset > self._len:
            return None
        lo, hi = 0, len(self._offsets) - 1
        # binary search for the last line-start offset <= offset
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._offsets[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1


def parse_src(src: Optional[str]) -> Optional[tuple[int, int, int]]:
    """Parse a solc `src` string "start:length:fileIndex" -> (start, length, file_index)."""
    if not src:
        return None
    parts = src.split(":")
    if len(parts) != 3:
        return None
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None


def walk(node: Any, parent: Any = None) -> Iterator[tuple[dict, Optional[dict]]]:
    """Depth-first walk over a solc AST (or Yul AST) fragment.

    Yields (node, parent) for every dict that looks like an AST node
    (has a 'nodeType' key), including the root if applicable. Traverses into
    every list/dict value generically, so it is resilient to solc AST schema
    changes across compiler versions.
    """
    if isinstance(node, dict):
        if "nodeType" in node:
            yield node, parent
        for key, value in node.items():
            if key in ("src",):
                continue
            yield from walk(value, node)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item, parent)


def find_all(node: Any, node_type: str) -> list[dict]:
    return [n for n, _ in walk(node) if n.get("nodeType") == node_type]


def direct_children(node: dict) -> list[dict]:
    """Immediate AST-node children of `node` (one level, not recursive)."""
    out = []
    for key, value in node.items():
        if key == "src":
            continue
        if isinstance(value, dict) and "nodeType" in value:
            out.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "nodeType" in item:
                    out.append(item)
    return out


def contains_node_type(node: Any, node_type: str) -> bool:
    for n, _ in walk(node):
        if n.get("nodeType") == node_type:
            return True
    return False
