"""Production-relevance classification (for_attack_agent.md).

Classifies a function's file location into:

    PRODUCTION   first-party runtime code
    TEST/MOCK    test doubles, fixtures, fuzz helpers, scripts
    DEPENDENCY   third-party/vendored libraries
    UNKNOWN      no source location available

The classification uses ONLY path-shape vocabulary that is generic to the
Solidity ecosystem (e.g. a `node_modules` package directory, a `test`/
`mock`/`fixture` folder) -- never project, protocol, or benchmark names.

Mock/test contracts are not discarded: they are kept with lower priority
because they can reveal intended callback behavior or security boundaries;
the scorer reflects that.
"""

from __future__ import annotations

import re
from typing import Any

PRODUCTION = "PRODUCTION"
TEST_MOCK = "TEST/MOCK"
DEPENDENCY = "DEPENDENCY"
UNKNOWN = "UNKNOWN"

# Ecosystem-generic package/dependency directory names.
_DEPENDENCY_SEGMENTS = frozenset({
    "node_modules", "lib", "libs", "vendor", "vendors", "dependencies",
    "dependency", "packages",
})

# Ecosystem-generic test-shape segment names.
_TEST_SEGMENT_RE = re.compile(
    r"^(tests?|mocks?|fixtures?|fuzz|script|scripts|spec|specs|testhelpers?|test-utils)$",
    re.IGNORECASE,
)

# Common test-file prefixes/suffixes that are generic ecosystem style,
# applied to the file basename only when the directory is ambiguous.
_TEST_FILE_RE = re.compile(
    r"^(mock|test|fixture|fuzz|spec)[._-]|(mock|test|fixture|fuzz|spec)\.sol$|"
    r"\.(t|test)\.sol$",
    re.IGNORECASE,
)


def classify_path(path: str) -> str:
    """Classify a source file path (or '' -> UNKNOWN)."""
    if not path:
        return UNKNOWN
    segments = [seg for seg in path.replace("\\", "/").split("/") if seg]
    for seg in segments[:-1]:  # directory segments
        if seg.lower() in _DEPENDENCY_SEGMENTS:
            return DEPENDENCY
    for seg in segments[:-1]:
        if _TEST_SEGMENT_RE.match(seg):
            return TEST_MOCK
    basename = segments[-1] if segments else ""
    if basename and _TEST_FILE_RE.search(basename) and not basename.startswith("I"):
        # Heuristic basename only: never override a PRODUCTION directory
        # signal, so a first-party file merely named e.g. "Tester.sol"
        # stays TEST/MOCK but a lib file stays DEPENDENCY (checked above).
        return TEST_MOCK
    return PRODUCTION


def classify_function(recon, fn_key: str) -> str:
    """Classify a function by the source file of its facts."""
    path = function_file(recon, fn_key)
    return classify_path(path)


def function_file(recon, fn_key: str) -> str:
    """Best-effort source file for a function key (from any of its facts
    that carries a source location)."""
    for fact in recon.facts_for_function(fn_key):
        src = fact.get("source") or {}
        path = src.get("file") or src.get("path")
        if isinstance(path, str) and path:
            return path
    # fn keys themselves carry the path ("dir/File.sol#12::fn#34")
    return fn_key.split("#")[0] if "#" in fn_key else ""


def relevance_note(level: str) -> str:
    return {
        PRODUCTION: "first-party runtime code",
        TEST_MOCK: "test/mock/fixture code: lower confidence unless it "
                   "reveals intended callback or boundary behavior",
        DEPENDENCY: "third-party dependency code: lower confidence unless "
                    "the protocol wires it into a trust boundary",
        UNKNOWN: "no source location available",
    }.get(level, "")
