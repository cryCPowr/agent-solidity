# Recon Agent — Recon-Only Static Analysis for Solidity/EVM Repositories

> **Stage 1 of a planned 5-stage architecture. CURRENT DEVELOPMENT SCOPE = RECON ONLY.**
>
> | Stage | Name | Status |
> |---|---|---|
> | 1 | **Recon Agent** | **This repository. In active development.** |
> | 2 | Threat Agent | Not started. Not designed. Not implemented. |
> | 3 | Attack Agent | Not started. |
> | 4 | Validator | Not started. |
> | 5 | Finding Agent | Not started. |
>
> Stages 2–5 are a long-term target, not a near-term commitment. Nothing in this
> repository implements, simulates, or stubs them out. See
> [Roadmap](#roadmap-5-stage-architecture) below.

Extracts structured, source-traceable **security intelligence** from a
Solidity codebase — not just a code summary. Recon Agent's job is to turn
source code into machine-readable facts and connected relationships (who
controls what, what calls what, what asset moves where) so that a future
Stage-2+ agent can reason about vulnerability classes without re-parsing the
AST itself.

**Recon Agent performs no vulnerability detection, exploit generation, or
final security judgment.** There is no `vulnerability`, `severity`,
`exploit`, `attack`, or `recommendation` field anywhere in its output — see
[Hard scope boundary](#hard-scope-boundary). Where recon does flag something
security-*relevant* (an unguarded capability, a user-influenced call
combined with an asset approval), it is explicitly labeled `HYPOTHESIS`, not
a finding — see [FACT vs HYPOTHESIS](#fact-vs-hypothesis).

## Development / Verification

**After opening this repository (new machine, new session, after any change),
the following MUST be run from the project root before trusting anything
about the current state of Recon:**

```bash
cd recon-system
npm install                 # fetch solc-js (bundled default compiler), once
python3 -m pytest tests/ -q
```

Expected: all tests pass except one intentionally-documented
`xfail(strict=True)` (a known, un-patched recon limitation — see
[Known limitations](#known-limitations-disclosed-not-silently-papered-over)).
If anything else fails, treat Recon's output as untrusted until fixed — do
not delete or weaken a test to make the suite green.

## Quick start

```bash
cd recon-system
npm install                # fetches solc-js (bundled default compiler)
python3 -m recon.cli /path/to/solidity/repo -o recon/
```

Output is written to `recon/`:

```
recon/
├── schema.json      # versioned description of every object shape below
├── metadata.json     # run metadata: compiler versions used, files analyzed/failed, warnings
├── summary.json       # machine-readable index (counts, coverage) — NOT authoritative
├── facts.jsonl          # authoritative atomic fact database, one JSON object per line
├── graph.json             # {nodes: [...], edges: [...]} structural graph
└── snippets/                # concise source snippets referenced by fact evidence
```

A worked example is checked in at `recon-sample-output/`, produced by running
the CLI against `tests/fixtures/`.

## How it works

```
Source Discovery          recon/discovery.py
      ↓
Compiler invocation        recon/solc_manager.py + compile.js
      ↓
AST extraction              recon/inventory.py
      ↓
Contract/Function Inventory  recon/inventory_facts.py
      ↓
Per-function expression walk  recon/expr_analysis.py
  (calls, state r/w, external
   interactions, asset flow,
   authorization, control-flow,
   special EVM features,
   conservative data-flow)
      ↓
Capability Extraction          recon/capability.py
      ↓
Evidence / Provenance           recon/context.py
      ↓
Graph Construction                (accumulated throughout, in recon/context.py)
      ↓
Deterministic Output                recon/output.py + recon/schema.py
```

### Why solc-js instead of a native `solc` binary

This environment's network egress only reaches package registries
(npm/pypi/crates/github), not `binaries.soliditylang.org`, which is where
`py-solc-x`/`solc-select` normally fetch native solc binaries. `solc-js` (the
official pure JS/WASM build of the Solidity compiler) is published to npm as
`solc` and is self-contained, so `recon/solc_manager.py` uses it via a small
Node shim (`compile.js`) instead. This is a network-appropriate substitute,
not a shortcut: it still gets the *real* solc AST and source maps, not a
hand-rolled parser.

`solc_manager.py` reads each file's `pragma solidity` statement and installs
(via `npm install --prefix .solc-cache/<version>`, cached) whichever solc-js
version it asks for, so the analyzer is not pinned to one Solidity version.
Files are grouped by resolved version and compiled together per group; if a
requested version can't be installed, that group falls back to the bundled
default and the fallback is recorded in `metadata.json.warnings` — it is
never silently swallowed.

### Regex use

Regex is used in exactly one place: extracting the version token out of a
`pragma solidity ...;` line to decide *which compiler to run*. It is never
used to extract facts about program behavior — all facts come from the solc
AST.

## Hard scope boundary

The output schema (`schema.json`) and every fact `type` are drawn from a
fixed, security-neutral vocabulary: existence, visibility, mutability, reads,
writes, calls, emissions, capabilities. There is no notion of "this is bad"
anywhere in the pipeline. Concretely:

- `confidence` on a `Fact` means **extraction confidence** ("how sure am I
  this classification is correct"), never a security rating.
- `asset_operation` facts (ERC20/721/1155-style calls) are always emitted
  with `status: "derived"` and a `note` disclosing that they are a
  name-pattern match, not a verified token-standard conformance check.
- `capability` facts (`can_transfer_token`, `can_delegatecall`, etc.)
  describe what a function can technically do, deterministically aggregated
  from already-extracted facts — never framed as exploitable or dangerous.
- `tests/test_pipeline.py::test_no_security_judgment_vocabulary_in_analyzer_output`
  greps the entire fact/edge type vocabulary for banned terms
  (vulnerab-, exploit, attack, severity, mitigat-, recommend) as a regression
  guard.

## Epistemic status on every fact

Every `Fact` and `GraphEdge` carries a `status`:

| status     | meaning                                                              |
|------------|-----------------------------------------------------------------------|
| `observed` | Directly represented by an AST/source node.                          |
| `derived`  | Deterministically inferred from ≥1 observed facts via a disclosed heuristic (e.g. name-pattern token-op matching, `msg.sender`-comparison → authorization_check). |
| `partial`  | Some but not all sub-parts of the relationship could be determined.   |
| `unknown`  | Could not be determined reliably (e.g. an unresolved dynamic call target, an unclassified builtin call). |

`unknown` is never silently turned into `false`, and nothing is fabricated to
fill a gap — see `tests/fixtures/10_negative.sol` and its corresponding tests
in `tests/test_pipeline.py` for concrete examples of what the analyzer
deliberately does *not* infer (a function named `transfer()` that isn't a
token call, a comment claiming behavior the code doesn't have, a
dynamically-derived call target that must stay `dynamic`/unresolved, two
same-named-but-unrelated contracts that must not be merged).

## FACT vs HYPOTHESIS

On top of the base `status` vocabulary above, three fact types
(`security_relationship_chain`, `access_controlled_function`,
`unguarded_capability_hypothesis` — see
[Security intelligence layer](#security-intelligence-layer-role-privilege--relationship-chains))
carry a second, narrower `properties.certainty` label, because a single
*chain* of steps can mix different confidence levels within itself:

| certainty    | meaning                                                              |
|--------------|-----------------------------------------------------------------------|
| `FACT`       | Every step/claim is individually backed by an `observed` fact (e.g. an argument is AST-verified to be a direct reference to a function parameter). |
| `INFERENCE`  | Deterministically combined from multiple observed facts (e.g. a call's target expression textually matches a parameter name). |
| `HYPOTHESIS` | A structurally-plausible security-relevant *question*, never a verdict (e.g. "an approval and a dynamic call co-occur in this function" — recon does not know if they're related). |
| `UNKNOWN`    | Could not be determined.                                             |

Recon never upgrades a `HYPOTHESIS` into a claim of vulnerability. The
`unguarded_capability_hypothesis` fact type, for example, exists specifically
to flag "no authorization mechanism was *observed*" — many legitimate
functions (public mints, permissionless swaps) are correctly unguarded, and
recon has no way to know intent. That judgment is explicitly deferred to a
future stage.

## What's implemented

- **Contract/function/state inventory** (sections 6–7 of the spec): every
  contract-like unit (`contract`/`interface`/`library`/`abstract`), every
  function (including internal/private, constructors, `receive`, `fallback`),
  parameters, returns, modifiers-used, visibility, mutability, canonical
  signature (distinguishing overloads), override flags.
- **Modifiers are independently inventoried and their bodies analyzed**
  (`modifier_definition` facts + a dedicated `modifier` graph node kind): a
  `require(msg.sender == owner)` written inside `modifier onlyOwner()` is
  detected as an `authorization_check` exactly as it would be if written
  inline in a function, and a `USES_MODIFIER` graph edge connects each
  function to the modifiers it uses.
- **Inheritance / interface implementation** resolved across files within a
  compile group, emitted as `INHERITS`/`IMPLEMENTS` graph edges.
- **State read/write** (section 10), including mapping/array/struct member
  writes resolved back to the root state variable, `delete`, `++`/`--`,
  compound assignment (`+=` → read+write), and `array.push()`/`.pop()` (which
  are not `Assignment` nodes and are easy to miss).
- **Call graph** (section 11): internal calls, external/interface calls,
  low-level `.call`/`.delegatecall`/`.staticcall`, `new X(...)` /
  `new X{salt: s}(...)` creation, with `target_status` (`dynamic` /
  `static_immutable` / `unknown`) — dynamic targets are never asserted static.
- **`{value: ..., gas: ..., salt: ...}` call options** unwrapped from
  `FunctionCallOptions` nodes (a common source of missed low-level-call /
  create2 detection if handled naively).
- **External call surface + asset/value flow** (sections 13–14): ETH
  transfers (`.transfer`/`.send`/`.call{value:}`), name-pattern-matched
  ERC20/721/1155-style operations (`transfer`, `transferFrom`, `approve`,
  `safeTransferFrom`, `safeBatchTransferFrom`, `setApprovalForAll`, `mint`,
  `burn`, ...), always `derived` with a disclosed caveat.
- **Authorization surface** (section 15): `require`/`if` conditions
  mentioning `msg.sender`, cross-referenced against which state variables
  they read, feeding into the `can_modify_authorization_state` capability
  AND the role/privilege map below.
- **Signature/authentication structures** (section 16): `ecrecover` →
  `signature_recovery_operation`, `keccak256`/`sha256`/`ripemd160` →
  `digest_construction_operation`.
- **Callback surface** (section 17): calls whose target type matches known
  receiver interfaces (`IERC721Receiver`, `IERC1155Receiver`, `ERC777`).
  *(Currently 0 instances in the fixture corpus — see Known limitations.)*
- **Control-flow structure** (section 18): `if`, loops, `try`/`catch`,
  `unchecked`, ternary.
- **Event/error map** (section 19): event definitions + emission sites
  (`EMITS` edges), custom error definitions + revert sites (both
  `revert CustomError(...)` and `revert("string")`).
- **Special EVM features** (section 20): inline assembly blocks,
  `selfdestruct`, `address.code`/`.codehash`, create2 salt options.
- **Capability map** (section 21): deterministically aggregated from the
  above; each capability fact links back to its supporting fact ids.
  **Enhanced with evidence/attributes**: `target` (fixed/user_controlled),
  `amount` (fixed/user_controlled), `asset` (fixed/variable), and
  `authorization` (guarded/unknown) — answering WHO controls target/amount,
  WHAT asset, and IS authorization present without changing the coarse
  capability name.
- **Conservative data-flow edges** (sections 8–9) for call arguments: origin
  classified as parameter / local variable / state variable / literal /
  environment / unknown, peeling through simple member/index-access chains;
  anything more complex (arithmetic, multi-hop) is left `unknown` rather than
  guessed.
- **Data-flow propagation**: **extended with local def-use propagation**
  through simple, unambiguous local variable assignments, so chains like
  `parameter → local variable → local variable → arithmetic → use` can be
  recovered instead of stopping at the nearest identifier.
  (`a / b`), its operands, and its immediate consumer (return value / state
  write / variable initializer / call argument) — a structural precursor for
  rounding/truncation/precision review. Recon does not evaluate whether a
  given truncation is significant.
- **Full provenance**: every fact carries file/byte-offset/line/AST-node-id,
  and (where applicable) an evidence id pointing to a concise snippet file
  under `snippets/` — never a whole-file dump.
- **Determinism**: all output is sorted by stable, content-derived ids;
  `tests/test_pipeline.py::test_rerun_produces_identical_facts_and_graph`
  verifies bit-identical re-runs.
- **Graceful degradation**: a single file that fails to compile is recorded
  in `metadata.json.files_failed` / `warnings`, and does not abort analysis
  of the rest of the repository (`analysis_status` becomes `"partial"`).

## Security intelligence layer: role/privilege + relationship chains

Built by `recon/relationships.py` — a pure post-processing pass over facts
already emitted by `expr_analysis.py`/`capability.py`. No new AST parsing.

**Role / privilege map:**
- `access_controlled_function` — a function with an observed
  `authorization_check`, either written inline or reachable through a
  modifier it uses. `properties.mechanisms` lists every mechanism found
  (`"inline"` or `"modifier"`), each with its own `basis_facts`.
- `unguarded_capability_hypothesis` — `HYPOTHESIS`-level: a function
  exercises a security-relevant capability (`can_transfer_token`,
  `can_delegatecall`, `can_modify_authorization_state`, ...) with **no**
  observed authorization mechanism anywhere in scope. An absence-of-evidence
  signal, explicitly not a finding.

- **Security relationship chains** (`security_relationship_chain`): connects
per-function facts into an ordered sequence of `{actor, relation, target,
certainty, basis_facts}` steps, with **evidence-based relationship classification**
(`ARGUMENT_DEPENDENCY`, `DATA_DEPENDENCY`, `SAME_BLOCK`, `EXECUTION_ORDER`,
`co_occurs_with`) instead of generic `co_occurs_with`. Every step is
individually labeled `FACT`/`INFERENCE`/`HYPOTHESIS`; `properties.overall_certainty` is
the weakest certainty among a chain's own steps. See
`tests/fixtures/11_relationship_chain.sol` and `tests/test_recon_intelligence.py`.

## Known limitations (disclosed, not silently papered over)

- **Callback surface has zero fixture coverage.** The `callback_capable_call`
  fact type is implemented (`expr_analysis.py`), but no fixture in the
  current corpus contains a call *site* that targets an
  `IERC721Receiver`/`IERC1155Receiver`/`ERC777`-typed expression — existing
  fixtures only *implement* such interfaces, never *call* one. Category F
  from the original spec is currently unverifiable from the fixture corpus,
  not because the code path is missing but because it's untested. Adding a
  fixture that exercises it is the natural next step.
- **`contract_creation.target_type` is `null` for CREATE2.** `new
  X{salt: s}(...)` wraps the `NewExpression` in a `FunctionCallOptions` node
  that `_emit_creation` doesn't unwrap before reading `.typeName`. Plain
  `new X(...)` (no options) is unaffected. Pinned as
  `xfail(strict=True)` in `tests/consumer/test_consumer_smoke.py` —
  deliberately **not patched**, so this stays visible instead of silently
  disappearing.
- **Modifier-body analysis is intentionally scoped down**, not a full
  `analyze_function`-equivalent pass: only `require`/`authorization_check`
  detection and state *reads* are attributed to a modifier's own body (not
  the full call-graph/control-flow/capability extraction a function gets).
  Modifier bodies very rarely contain the kind of general-purpose logic that
  would need the rest of that machinery; this was a deliberate
  effort/value tradeoff, not an oversight.
- **Cross-pragma-version imports** are not resolved: files are grouped by
  their own resolved compiler version, and if file A (version X) imports
  file B declared under a different version, B's source may not be present
  in A's compile input. This surfaces as a per-file compile failure
  (recorded honestly in `files_failed`/`warnings`), not silent data loss.
- **Data-flow is shallow by design.** Only direct identifier references
  (with simple member/index-access peeling) are resolved; arithmetic
  expressions, multi-statement flows, and cross-function flows are left
  `unknown` rather than approximated. This is a deliberate "prefer unknown
  over fabricated" tradeoff, not an oversight — a sound whole-program
  data-flow/SSA engine was out of scope for this pass.
- **Relationship chains are single-function, single-hop.** They connect
  facts *within* one function; a chain that spans `Contract A calls B calls
  C transfers token` (explicitly requested by the long-term spec as
  "cross-contract... Contract → Function → Contract → State → Asset →
  Actor") is not yet built. The call graph itself IS already cross-function
  (`CALLS`/`DELEGATES_TO` edges), so a downstream consumer can walk it
  manually today; recon does not yet pre-synthesize multi-hop chains.
- **No oracle/price-dependency map, no precompile/interface semantic-mismatch
  detection (Class B from the long-term spec), no accounting-variable
  classification, no invariant-candidate extraction, no upgradeability/
  initialization map beyond what `special_evm_feature`
  (delegatecall/create2) already exposes.** These were deliberately left
  unimplemented this pass rather than rushed: several require either
  cross-referencing external dependency source (ABI/interface semantics)
  or a level of type/naming inference that risks violating recon's
  no-naming-assumption principle if built carelessly. Explicitly listed here
  so the gap is visible, not silently absent.
- **Canonical function signatures** are best-effort: struct/enum parameter
  types are rendered using solc's `typeString`, which is not always
  identical to the ABI-encoded selector type; `canonical_signature()` returns
  `None` rather than guess when it can't derive a reliable elementary type.
- **`abi.encode`/`abi.encodePacked`/`abi.decode`** and any other built-in not
  in the small explicit list in `expr_analysis.py` fall through to a generic
  `call_unresolved` (`status: unknown`) fact rather than a dedicated fact
  type — informative (exact source text is preserved) but not specially
  classified.

## Roadmap (5-stage architecture)

This repository is Stage 1 only. The long-term target architecture:

1. **Recon Agent** *(this repo)* — structural + security-intelligence fact
   extraction from source. No vulnerability judgment.
2. **Threat Agent** *(not started)* — reasons over Recon's facts/relationship
   chains to identify candidate vulnerability classes.
3. **Attack Agent** *(not started)* — constructs candidate exploit paths for
   Threat Agent's candidates.
4. **Validator** *(not started)* — verifies candidate attack paths against
   real/simulated execution.
5. **Finding Agent** *(not started)* — produces the final, human-readable
   security finding.

Stages 2–5 are intentionally out of scope until Stage 1 is mature. This
repository does not implement, stub, or scaffold any of them.

## Testing

```bash
cd recon-system
python3 -m pytest tests/ -v
```

100+ tests (including 1 intentional `xfail`), spread across:

- `tests/test_pipeline.py`, `tests/test_ground_truth.py` — recon's own
  correctness: positive fixture coverage (inheritance, interfaces, every
  call type, mappings/arrays/structs, authorization + signature
  verification, ERC20/721/1155 + callbacks, payable/ETH transfer,
  control-flow/assembly/try-catch, proxy-shaped delegatecall + create/
  create2, overloads/overrides) and negative tests (name lookalikes, false
  comments, dynamically derived addresses, colliding contract names) across
  12 fixtures in `tests/fixtures/` plus 12 isolated ground-truth
  micro-fixtures in `tests/fixtures_ground_truth/` — none protocol-specific,
  all generic Solidity patterns. Determinism (bit-identical re-runs),
  provenance, end-to-end CLI invocation.
- `tests/test_recon_intelligence.py` — the security-intelligence layer:
  modifier-body authorization detection, the role/privilege map
  (`access_controlled_function` / `unguarded_capability_hypothesis`),
  **enriched security relationship chains with evidence-based classification**,
  **enriched capability model with evidence/attributes**, division-operation
  tracking, and a banned-vocabulary regression guard scoped to the new fact
  types.
- `tests/test_dataflow_propagation.py` — **data-flow propagation tests**
  covering parameter→local, local→local, parameter→arithmetic→local,
  local→function call argument, branch/condition, and unknown/unresolved
  expression scenarios.
- `tests/consumer/` — a **black-box** consumer contract test suite that
  invokes `recon.cli` as a subprocess and reads only `facts.jsonl` /
  `graph.json` / `summary.json` / `metadata.json` / `snippets/` (never
  recon's internal Python objects), verifying that a downstream agent could
  actually retrieve what it needs: dynamic-call classification,
  parameter-to-calldata dataflow, capability↔supporting-fact context,
  evidence resolution, graph traversal via `DECLARES`/`CALLS`/`WRITES`/
  `CREATES`/`DELEGATES_TO`, and full cross-artifact consistency (no dangling
  fact/evidence/node references; `summary.json` counts independently
  recomputed from `facts.jsonl` and `graph.json`).
- The scope boundary itself (no banned vocabulary in fact/edge types) is
  checked in multiple of the above, not just once.

## Extending

- Add a new fact type: implement it in the relevant `_emit_*` module (or
  `recon/relationships.py` for a cross-fact synthesis), following the
  existing pattern (`_emit_fact(ctx, fu, type, src_ref, evid, subject,
  properties, status, confidence)`), then document its shape in
  `recon/schema.py::build_schema()`.
- Add a new fixture: drop a `.sol` file under `tests/fixtures/`; it's picked
  up automatically by the whole-directory-discovery pytest fixtures used
  across `tests/test_pipeline.py`, `tests/test_recon_intelligence.py`, and
  `tests/consumer/`, no test-file changes required unless you also want
  assertions on it.
- Bump `recon/schema.py::SCHEMA_VERSION` whenever a field's shape or meaning
  changes, so downstream consumers can detect incompatible output.
- Whatever you add, run `python3 -m pytest tests/ -q` before considering it
  done — see [Development / Verification](#development--verification).
