# Threat Agent  — Enrichment & Benchmark Specification

## Purpose

This document is the **source of truth for enriching Threat Agent **.
It is intentionally **not** a request to rewrite Threat Agent immediately.
First use the three real benchmark classes to determine whether each weakness
actually affects the quality of downstream security hypotheses.

Recon 0.26 is considered frozen for this task. Do not modify Recon as part of
Threat enrichment.

---

## Current baseline

Current Threat  architecture:

```text
Recon artifacts
    ↓
loader
    ↓
actor model
trust model
surface model
invariants
    ↓
category-specific lenses
    +
generic composition layer
    ↓
hypotheses
    ↓
prioritization
```

Current engineering baseline:

- Threat tests: **34 passed**
- Threat consumes a real Recon artifact fixture
- Hypothesis IDs are deterministic/content-derived
- Hypothesis deduplication uses more than category + function
- Generic composition exists as an open-set safety net
- Actor model prefers authorization evidence before lexical hints
- Trust model separates `resolution` from `trust`
- Model-provider abstraction exists

These are considered **GREEN foundations**, but they are not proof that the
security reasoning is complete.

---

# Status legend

### GREEN
Capability exists, is structurally sound, and should be **enriched rather
than replaced**.

### YELLOW
Capability exists but is too shallow, too heuristic, or insufficiently
validated for difficult security reasoning.

### RED / MISSING
Capability is absent or not demonstrated. This document does not assume
that every red item must be implemented by Threat; some belong to Attack or
Validator.

---

# GREEN — keep and enrich

## G1. Generic composition layer — GREEN

Current role:

`threat/composition.py` provides an open-set path that combines broad signal
buckets instead of requiring a named vulnerability detector.

Current strength:

```text
asset movement
+ state mutation
+ external interaction
+ computation
+ authorization
        ↓
novel_composition candidate
```

### Enrichment target

Do not replace generic composition with more hardcoded detectors.

Enrich it with:

- stronger evidence grounding
- dataflow-aware composition when available
- graph-aware composition
- distinction between co-occurrence and dependency
- explicit uncertainty
- better explanations of why signals compose

The generic layer should remain an **open-set safety net**.

---

## G2. Deterministic hypothesis identity — GREEN

Current behavior:

Hypothesis IDs are derived from normalized content, facts, graph references,
invariant, and affected functions.

### Enrichment target

Keep deterministic IDs stable.

When adding richer evidence, ensure the ID changes only when the semantic
identity of the hypothesis changes.

Do not return to run-order IDs.

---

## G3. Richer hypothesis deduplication — GREEN

Current deduplication includes:

- category
- normalized statement
- observed fact IDs
- graph edges
- invariant candidate

### Enrichment target

Consider adding, only if justified by benchmarks:

- normalized attack-surface identity
- affected asset/state identity
- semantic actor identity

Do not deduplicate merely because two hypotheses touch the same function.

---

## G4. Trust model separation — GREEN

Current separation:

```text
resolution:
    static / dynamic / unknown

trust:
    trusted / untrusted / partially_trusted / unknown
```

This is correct and must be preserved.

### Enrichment target

Strengthen evidence behind trust classification:

- authorization checks
- registry validation
- allowlists / whitelists
- state-controlled target validation
- modifier evidence
- caller restrictions
- cross-contract trust propagation

Never collapse:

```text
dynamic == untrusted
```

---

## G5. Actor model evidence-first principle — GREEN

Current model prefers authorization evidence before lexical role hints.
Lexical names such as `owner`, `admin`, `operator`, `keeper` are fallback
hints.

### Enrichment target

Make evidence strength explicit:

```text
explicit_authorization
structural_role
state-backed_role
lexical_hint
unknown
```

Downstream hypothesis priority must not treat a lexical hint as authoritative
permission evidence.

---

## G6. Model-provider abstraction — GREEN

The model-provider abstraction is suitable for Hermes + 9router + different
LLMs.

### Enrichment target

Use LLMs for interpretation, not authoritative facts.

Every LLM-derived hypothesis must retain:

- Recon fact IDs
- graph references
- invariant references
- uncertainty

A raw LLM sentence must never become an authoritative security fact.

---

# YELLOW — enrich these before claiming advanced Threat reasoning

## Y1. Generic composition is still too close to co-occurrence

### Current problem

A set of signals appearing inside the same function is not necessarily a
causal relationship.

For example:

```text
external interaction + asset movement
```

does not prove:

```text
external interaction controls asset movement
```

### Enrichment target

Add evidence tiers:

```text
CO_OCCURRENCE
DATA_DEPENDENCY
ARGUMENT_DEPENDENCY
CONTROL_DEPENDENCY
EXECUTION_ORDER
GRAPH_REACHABILITY
```

A hypothesis based only on co-occurrence should be weaker than one backed by
data/argument/control dependency.

---

## Y2. Category-specific lenses are still narrow

Current lenses include patterns such as:

- arbitrary execution
- callback/reentrancy
- accounting mismatch
- rounding/allocation
- signature replay
- cross-contract trust
- DoS/griefing
- economic manipulation

### Current risk

A bug class not represented by a lens may depend heavily on `novel_composition`.

### Enrichment target

Keep lenses, but treat them as **specialized reasoning lenses**, not the entire
Threat brain.

Prefer reusable primitives:

```text
attacker control
+ authority boundary
+ asset/value impact
+ state transition
+ graph/dataflow relation
+ invariant
```

Then compose them into hypotheses.

Do not add a new detector merely because one benchmark contains a new bug.

---

## Y3. Cross-contract graph reasoning is too shallow

### Current risk

Threat can inspect call relationships, but difficult findings need coherent
multi-step chains such as:

```text
A.claim()
  ↓
B.bridge()
  ↓
C.safeTransferFrom()
  ↓
D.onERC721Received()
  ↓
state / asset effect
```

or:

```text
precompile
  ↓
decode
  ↓
accounting
  ↓
distribution
```

### Enrichment target

Use bounded graph traversal and preserve the actual chain in the hypothesis.

Cross-contract hypotheses should contain real graph nodes and edges whenever
those relationships are proven.

If the chain cannot be proven, represent the uncertainty and lower priority.

---

## Y4. Callback + asset reasoning is still shallow

### Current target

The Threat Agent should be able to combine:

```text
attacker/user controlled target
+
approval capability
+
external interaction
+
callback relationship
+
protocol-held asset
+
postcondition/balance check
```

into one coherent hypothesis instead of producing several unrelated
observations.

### Desired hypothesis shape

```text
Untrusted external execution may redirect a protocol-held asset through a
callback-capable execution path while the observed postcondition checks only
balance delta.
```

The exact statement may differ; the important part is that every clause is
grounded in evidence.

Do not call it a confirmed vulnerability.

---

## Y5. Rounding/allocation reasoning is too shallow

### Current level

Threat can see:

```text
division
+
allocation consumer
```

### Desired level

Reason about:

```text
division
  ↓
rounding-sensitive value
  ↓
entitlement/allocation
  ↓
possible economic imbalance
```

The hypothesis should tell Attack Agent what to verify:

- rounding direction
- boundary values
- cumulative effect
- recipient advantage
- whether the result is actually used as an entitlement/allocation

Threat does not need to prove the exact library implementation.

---

## Y6. Accounting reasoning is too shallow

### Current target

Threat should compose:

```text
external/precompile value
  ↓
decode
  ↓
selected field
  ↓
arithmetic/accounting
  ↓
state/value effect
  ↓
distribution / asset sink
```

### Desired hypothesis

Something materially equivalent to:

```text
External value interpretation may create a gross-vs-net accounting mismatch
that distorts backing, debt, entitlement, or distribution.
```

Required evidence should include the actual facts and graph/dataflow chain.

Do not assume protocol-specific field semantics that Recon does not provide.

---

## Y7. Actor and trust propagation needs deeper cross-contract reasoning

Current trust boundaries are useful, but they are still relatively local.

### Enrichment target

Support questions such as:

```text
Who controls the target?
Who validated it?
Where was the validation performed?
Does that trust assumption survive the next external call?
Does a privileged actor pass control to a user-controlled actor?
```

Again: unknown must remain unknown.

---

## Y8. Prioritization is heuristic and not calibrated against validation outcomes

Current priority levels:

```text
very_high_interest
high_interest
medium_interest
low_interest
```

These are **not severities**.

### Current risk

A generic combination can receive a high score merely because it has asset
impact + external actor + cross-contract reach + invariant.

### Enrichment target

Priority should increasingly favor:

- proven attacker control
- real data/control dependency
- protocol asset exposure
- concrete invariant involvement
- credible execution path
- economic impact
- lower uncertainty

Do not award `very_high_interest` from weak co-occurrence alone.

Eventually calibrate priority using Attack/Validator outcomes.

---

## Y9. Hypothesis schema should distinguish evidence strength

Every hypothesis should make it obvious whether a statement is:

```text
OBSERVED
DERIVED
INFERRED
ASSUMED
UNKNOWN
```

At minimum keep uncertainty explicit.

If a hypothesis claims cross-contract reasoning but has no graph evidence,
the reasoning should be considered weaker.

---

# RED / MISSING — do NOT force these into Threat

## R1. Full exploit construction

This belongs to **Attack Agent**.

Threat should output:

```text
what deserves investigation
why
preconditions
unknowns
```

Attack should determine:

```text
how to execute the abuse
```

---

## R2. Runtime exploit proof

This belongs to **Validator**.

Threat does not need to prove:

- state transition actually happens
- callback is actually reachable at runtime
- attacker can actually steal value
- exact economic delta

Those require execution/fork/trace/PoC validation.

---

## R3. Exact external protocol semantics unavailable from source

Examples:

```text
precompile slot 2 == borrow.value
precompile slot 4 == supply.value
```

If Recon cannot know this from Solidity/source artifacts, Threat should not
invent it.

Use a separate semantic/reference knowledge layer later if needed.

---

## R4. Final severity

Threat must not claim:

```text
High
Critical
Medium
Low
```

Those are downstream finding/judging concepts.

Use investigation priority only.

---

# Three benchmark gates

These are the initial regression/quality benchmarks. More Code4rena findings
will be added later.

## Benchmark A — Bridge / callback / asset redirection

Threat must be able to compose:

```text
user-controlled target/data
+
approval
+
external interaction
+
callback relationship
+
protocol-held asset
+
postcondition
```

Expected output:

A coherent candidate threat about asset redirection / untrusted execution,
with real Recon evidence.

It does NOT need to prove ticket theft.

---

## Benchmark B — Rounding / reward allocation

Threat must be able to compose:

```text
division
+
rounding-sensitive context
+
allocation / entitlement consumer
```

Expected output:

A candidate about potential precision/entitlement imbalance, with the exact
operation and consumer identified.

It does NOT need to prove the final reward delta.

---

## Benchmark C — External decode / accounting mismatch

Threat must be able to compose:

```text
external/precompile interaction
+
decode
+
field/value flow
+
accounting
+
value sink/distribution
```

Expected output:

A candidate about possible accounting semantic mismatch, with uncertainty
clearly stated where external semantics are not known.

It does NOT need to prove the economic exploit.

---

# Enrichment rules for Hermes

Before changing code:

1. Run Threat against the latest real Recon 0.26 artifact.
2. Inspect benchmark A/B/C outputs.
3. Identify the exact weakest reasoning component.
4. Patch only the proven bottleneck.
5. Add regression tests.
6. Re-run the complete Threat suite.
7. Re-run the real Recon → Threat integration.

Do NOT:

- add hardcoded rules solely for the three benchmarks
- add more vulnerability labels for the sake of coverage
- turn Threat into Attack/Validator
- change Recon in this task
- treat a larger hypothesis count as progress

Prefer:

```text
fewer
+
more coherent
+
more evidence-grounded
+
more useful for Attack Agent
```

---

# Definition of a successful Threat enrichment

Threat is ready to freeze when it can:

1. Consume real Recon 0.26 output.
2. Produce evidence-grounded hypotheses.
3. Connect facts across functions/contracts when justified.
4. Preserve uncertainty instead of inventing certainty.
5. Produce useful hypotheses for benchmarks A/B/C.
6. Keep generic composition as an open-set capability.
7. Keep specialized lenses as supporting tools, not the entire reasoning
   engine.
8. Keep priority separate from final severity.
9. Produce deterministic, auditable output.
10. Pass the complete Threat test suite.

---

# Final architectural boundary

```text
RECON
    = protocol facts, dataflow, relationships, provenance

THREAT
    = security interpretation, invariants, threat hypotheses, priority

ATTACK
    = concrete attack paths / exploit hypotheses

VALIDATOR
    = execution proof / rejection / trace / PoC

FINDING
    = confirmed finding documentation
```

The objective is **not** to make Threat independently prove every Code4rena
finding.

The objective is to make Threat good enough that Attack Agent receives a
small, coherent, evidence-grounded queue of things that are genuinely worth
trying to prove.
