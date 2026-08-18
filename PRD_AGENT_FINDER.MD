# PRD — Agent Finder
**Version:** 2.0  
**Status:** Draft  
**Last Updated:** 2026-08-17  
**Authors:** Security Platform Team  

---

> **Product Constitution:**  
> Threat kaya → Attack sempit → Validator keras → Finding hanya dari hasil yang benar-benar terbukti.

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Problem Statement](#2-problem-statement)
3. [Users & Personas](#3-users--personas)
4. [Product Interface & Integration](#4-product-interface--integration)
5. [Product Goals & Non-Goals](#5-product-goals--non-goals)
6. [Product Success Definition & Target Metrics](#6-product-success-definition--target-metrics)
7. [Product Funnel](#7-product-funnel)
8. [Epistemic State Model](#8-epistemic-state-model)
9. [Semantic Authority Model](#9-semantic-authority-model)
10. [Trust & Capability Model](#10-trust--capability-model)
11. [Recon Agent](#11-recon-agent)
12. [Coverage Model](#12-coverage-model)
13. [Intended-Behavior Agent](#13-intended-behavior-agent)
14. [Security Property Model](#14-security-property-model)
15. [Inference Rule Engine](#15-inference-rule-engine)
16. [Threat Agent](#16-threat-agent)
17. [Attack Agent](#17-attack-agent)
18. [Mandatory Attack Gates](#18-mandatory-attack-gates)
19. [Reachability Engine](#19-reachability-engine)
20. [Economic Exploit Model](#20-economic-exploit-model)
21. [Validator](#21-validator)
22. [Validator Independence](#22-validator-independence)
23. [Validator Evidence Contract](#23-validator-evidence-contract)
24. [Finding Agent](#24-finding-agent)
25. [Human Review & Disclosure State](#25-human-review--disclosure-state)
26. [Responsible Disclosure Policy](#26-responsible-disclosure-policy)
27. [Severity Rubric](#27-severity-rubric)
28. [Provenance Model](#28-provenance-model)
29. [Untrusted Source Handling](#29-untrusted-source-handling)
30. [Proxy & Upgradeability Model](#30-proxy--upgradeability-model)
31. [Multi-Transaction Attack Model](#31-multi-transaction-attack-model)
32. [Multi-Chain Support](#32-multi-chain-support)
33. [Failure & Degraded Modes](#33-failure--degraded-modes)
34. [SLA & Operational Limits](#34-sla--operational-limits)
35. [Benchmark Framework](#35-benchmark-framework)
36. [Evaluation Metrics](#36-evaluation-metrics)
37. [Regression Strategy](#37-regression-strategy)
38. [Resource Strategy](#38-resource-strategy)
39. [Language Support](#39-language-support)
40. [Security & Operational Risks](#40-security--operational-risks)
41. [Development Roadmap](#41-development-roadmap)
42. [Required Artifact Schemas](#42-required-artifact-schemas)
43. [State Transition Rules](#43-state-transition-rules)
44. [Final Architecture](#44-final-architecture)
45. [Final Product Constitution](#45-final-product-constitution)
46. [Glossary](#46-glossary)

---

## 1. Product Overview

**Core Principle:**

Agent Finder tidak mengoptimalkan jumlah suspicious code yang ditemukan.

Agent Finder mengoptimalkan:

> **jumlah security failure nyata yang dapat dibuktikan / jumlah analisis yang valid**

Agent Finder menerima repository smart contract dan menghasilkan sejumlah kecil security findings yang:

- grounded pada source code;
- memiliki causal path;
- memiliki attacker model eksplisit;
- memiliki trust-boundary model;
- memiliki intended-behavior model;
- memiliki security property yang jelas;
- memiliki reachable attack condition;
- memiliki concrete security/economic consequence;
- mempertahankan provenance dari awal sampai akhir;
- dan hanya dapat mencapai CONFIRMED setelah claim berhasil divalidasi.

**Agent Finder bukan pattern scanner.**

**LLM hanya boleh:**
- mengamati,
- mengusulkan hipotesis,
- menyusun kemungkinan attack,
- menjelaskan evidence.

**LLM tidak boleh** sendirian meng-upgrade status security-critical.

Setiap transisi penting harus didukung oleh:
- source evidence,
- deterministic rule,
- explicit inference rule, atau
- validator evidence.

**Pipeline utama:**

```
CODE
 ↓
FACTS
 ↓
SEMANTIC MODEL
 ↓
TRUST / CAPABILITY MODEL
 ↓
INTENDED BEHAVIOR
 ↓
SECURITY PROPERTIES
 ↓
INFERENCE RULES
 ↓
ATTACK GRAPH
 ↓
REACHABILITY / ECONOMIC CHECK
 ↓
VALIDATOR
 ↓
CONFIRMED
 ↓
HUMAN REVIEW
 ↓
FINDING
```

---

## 2. Problem Statement

Pattern seperti:
- external call, approve, callback, rounding, arithmetic, timestamp, loop, dynamic target, access-control modifier

tidak otomatis merupakan vulnerability.

Masalah sebenarnya adalah menentukan:
- apa yang dilakukan code;
- assumption apa yang digunakan protocol;
- intended behavior apa yang seharusnya berlaku;
- trust boundary dan capability siapa yang relevan;
- bagaimana beberapa behavior berinteraksi;
- security property apa yang dilindungi;
- apakah kondisi pelanggaran benar-benar reachable;
- apakah exploit dapat menghasilkan consequence nyata;
- apakah claim dapat divalidasi secara deterministik/reproducible.

---

## 3. Users & Personas

### 3.1 Persona Utama

| Persona | Deskripsi | Kebutuhan Utama |
|---------|-----------|-----------------|
| **Security Auditor Profesional** | Auditor yang mengerjakan smart contract audit engagement | Presisi tinggi, provenance lengkap, reproducible findings, laporan disclosure-ready |
| **Protocol Security Engineer** | Engineer internal protocol yang melakukan self-audit sebelum deploy | Integrasi CI/CD, umpan balik cepat, findings yang actionable |
| **Bug Bounty Hunter** | Researcher independen yang mencari vulnerability untuk program bug bounty | Temuan baru yang tidak obvious, attack path yang lengkap |
| **Security Tool Developer** | Developer yang mengintegrasikan Agent Finder ke platform atau toolchain lain | API yang stabil, artifact schema yang terdokumentasi, output terstruktur |

### 3.2 User Stories

**Sebagai Security Auditor Profesional, saya ingin:**
- Menerima findings dengan full provenance sehingga saya dapat memverifikasi secara independen tanpa mengulang seluruh analisis.
- Melihat status CONFIRMED atau INCONCLUSIVE secara eksplisit agar tidak ada ambiguitas dalam laporan audit.
- Mengekspor findings dalam format standar (JSON/Markdown) sehingga dapat dimasukkan ke laporan audit saya.

**Sebagai Protocol Security Engineer, saya ingin:**
- Menjalankan Agent Finder dari CI/CD pipeline (GitHub Actions, GitLab CI) sehingga setiap PR secara otomatis diperiksa.
- Menerima hasil dalam waktu yang dapat diprediksi (ada SLA) sehingga pipeline CI tidak blocking.
- Mendapatkan diff analysis antara dua versi contract sehingga saya tahu apakah perubahan memperkenalkan risiko baru.

**Sebagai Bug Bounty Hunter, saya ingin:**
- Menganalisis repository publik tanpa harus setup environment Foundry manual.
- Menerima attack path yang cukup konkret untuk saya jadikan PoC.

**Sebagai Security Tool Developer, saya ingin:**
- Mengakses hasil analisis via REST API atau file artifact sehingga saya dapat mengintegrasikan ke platform saya.
- Mendapatkan schema artifact yang stabil dengan versi eksplisit sehingga integrasi saya tidak break saat update.

---

## 4. Product Interface & Integration

### 4.1 Input Formats yang Didukung

| Format | Keterangan | Status |
|--------|-----------|--------|
| Local directory path | Path ke direktori repository di filesystem | Phase 1 |
| Git remote URL | `https://github.com/org/repo` atau SSH | Phase 1 |
| Git ref (branch/tag/commit) | `--ref main`, `--ref v1.2.3`, `--ref abc1234` | Phase 1 |
| ZIP archive | Upload file ZIP berisi source | Phase 2 |
| Diff / PR mode | Analisis hanya pada changed files antara dua ref | Phase 3 |

**Batasan Input:**
- Ukuran repository maksimum: **500 MB** (source files, tidak termasuk node_modules / dependencies eksternal)
- Jumlah file Solidity maksimum: **2.000 file** per run
- Baris kode maksimum: **500.000 SLOC**

Jika batasan terlampaui, sistem harus mengembalikan error eksplisit dengan petunjuk bagaimana membagi scope analisis.

### 4.2 Interface yang Tersedia

**CLI (Phase 1)**

```bash
agent-finder analyze \
  --repo ./path/to/repo \
  --ref main \
  --out ./results \
  --chain ethereum \
  --timeout 3600 \
  --validator foundry
```

**REST API (Phase 2)**

```
POST /v1/analyses
GET  /v1/analyses/{id}
GET  /v1/analyses/{id}/findings
GET  /v1/analyses/{id}/artifacts/{name}
GET  /v1/analyses/{id}/status
```

**CI/CD Integration (Phase 3)**
- GitHub Actions action: `agent-finder/analyze-action@v1`
- GitLab CI component
- Pre-built Docker image: `agentfinder/cli:latest`

### 4.3 Output Formats

| Format | Keterangan |
|--------|-----------|
| `findings.json` | Machine-readable findings dengan full provenance |
| `findings.md` | Human-readable Markdown report |
| `findings.sarif` | SARIF format untuk integrasi GitHub Code Scanning |
| `artifacts/` | Direktori seluruh intermediate artifacts |
| Exit codes | `0` = sukses (0+ findings), `1` = error sistem, `2` = partial analysis |

---

## 5. Product Goals & Non-Goals

### Primary Goals

Agent Finder harus dapat:
- membangun protocol model;
- membangun trust/capability model;
- membangun intended-behavior model;
- menghasilkan security properties;
- menghasilkan semantic hypotheses;
- membangun concrete attack graph;
- menguji attacker capability;
- menguji reachability;
- menguji state transition;
- menguji invariant violation;
- menguji economic consequence jika relevan;
- mempertahankan provenance;
- membedakan CONFIRMED, REJECTED, dan INCONCLUSIVE.

### Non-Goals (Fitur yang Sengaja Dikecualikan)

Agent Finder **tidak akan** (dalam scope saat ini):

| Non-Goal | Alasan |
|----------|--------|
| Menyediakan UI/Dashboard web | Bukan prioritas Phase 1–3; fokus ke accuracy |
| Analisis bytecode tanpa source | Membutuhkan decompiler berbeda; scope terpisah |
| Auto-generate fix/patch | Risk tinggi menghasilkan patch yang salah |
| Integrasi langsung ke bug bounty platform | Partnership komersial, bukan technical scope |
| Full support untuk semua EVM-compatible chain | Tiap chain perlu validator environment sendiri |
| Analisis runtime / production monitoring | Domain berbeda dari static + dynamic analysis |
| Menyatakan repository aman hanya karena findings = 0 | Fundamental epistemic principle |
| Disclosure otomatis tanpa human review | Policy requirement |
| Klaim full language/toolchain support tanpa validator | Epistemic principle |

---

## 6. Product Success Definition & Target Metrics

### 6.1 Success Bukan

```
more threats
more attacks
more findings
```

### 6.2 Success Adalah

```
high-quality coverage
+
high semantic precision
+
valid attack paths
+
validated security violations
+
complete provenance
```

### 6.3 Primary Metrics dengan Target

| Metric | Target Minimum | Target Ideal | Catatan |
|--------|---------------|--------------|---------|
| **Known-finding Recall** | ≥ 70% | ≥ 85% | Diukur pada closed-world benchmark |
| **Confirmation Precision** | ≥ 90% | ≥ 95% | CONFIRMED findings yang benar-benar valid |
| **Unsupported Confirmation Rate** | < 5% | 0% | CONFIRMED tanpa validator evidence |
| **Evidence Completeness** | ≥ 85% | ≥ 95% | Findings dengan full provenance chain |
| **Attack-path Validity** | ≥ 80% | ≥ 90% | Attack paths yang reproducible |
| **Validator Reproducibility** | ≥ 95% | 100% | CONFIRMED yang dapat di-reproduce |
| **Coverage-adjusted Recall** | Recall × Coverage ≥ 0.60 | ≥ 0.75 | Mempertimbangkan partial coverage |
| **Cost per Repository** | < $50 USD | < $20 USD | Average mid-size DeFi protocol |
| **Runtime per Repository** | < 60 menit | < 30 menit | Average mid-size DeFi protocol |

**Catatan:** Target diukur pada benchmark dataset v1.0. Target akan di-review setiap quarter.

Jangan menggunakan `0% FP` sebagai klaim absolut. Gunakan:
> "0 unsupported confirmations within validated benchmark scope (v1.0, n=X repositories)"

---

## 7. Product Funnel

```
REPOSITORY
   ↓
RECON
   ↓
PROTOCOL MODEL
   ↓
TRUST / CAPABILITY MODEL
   ↓
INTENDED-BEHAVIOR MODEL
   ↓
SECURITY MODEL
   ↓
ATTACK GENERATION
   ↓
ATTACK QUEUE
   ↓
REACHABILITY / ECONOMIC FILTER
   ↓
VALIDATOR
   ↓
REJECT ──────────────┐
   ↓                 │
REFINE / RETRY       │  (max 3 iterasi per attack candidate)
(max 3x per attack)  │
   ↓                 │
CONFIRMED ←──────────┘
   ↓
HUMAN REVIEW
   ↓
FINDING
```

**Pipeline Semantics:**

| Stage | Definisi |
|-------|---------|
| Recon | broad observation — tidak menyimpulkan vulnerability |
| Semantic Model | structured interpretation dari code behavior |
| Threat | rich hypothesis tentang potential violation |
| Attack | selective claim dengan causal path yang eksplisit |
| Reachability | challenge attacker/state assumptions secara deterministik |
| Validator | prove/disprove dengan machine-checkable evidence |
| Human Review | disclosure-quality adjudication oleh manusia |
| Finding | report only validated and reviewable claims |

**Aturan Refine/Retry Loop:**
- Maksimum **3 iterasi** per attack candidate
- Setiap iterasi harus menghasilkan perubahan signifikan pada attack model (bukan hanya re-phrasing)
- Jika setelah 3 iterasi belum CONFIRMED: status menjadi INCONCLUSIVE, bukan CONFIRMED
- Resource cap per loop: mengikuti batas di section 34

---

## 8. Epistemic State Model

Jangan gunakan satu status untuk semua jenis certainty.

Agent Finder menggunakan beberapa dimensi yang harus **dikombinasikan** secara eksplisit.

### 8.1 Evidence Certainty

| Level | Definisi |
|-------|---------|
| `UNKNOWN` | Tidak ada data |
| `OBSERVED` | Ditemukan di source code secara langsung |
| `DERIVED` | Disimpulkan dari kombinasi OBSERVED facts menggunakan inference rule |
| `VALIDATED` | Dikonfirmasi oleh validator (test execution / symbolic check) |

### 8.2 Semantic Certainty

| Level | Definisi |
|-------|---------|
| `UNKNOWN` | Tidak dapat ditentukan |
| `POSSIBLE` | Hipotesis awal, belum ada supporting evidence |
| `INFERRED` | Didukung oleh inference rule yang valid |
| `SUPPORTED` | Dikonfirmasi oleh multiple independent sources |

### 8.3 Reachability Certainty

| Level | Definisi |
|-------|---------|
| `UNKNOWN` | Belum dianalisis |
| `POSSIBLE` | Secara teori bisa dicapai, belum diverifikasi |
| `REACHABLE` | Terbukti reachable oleh reachability engine |
| `BLOCKED` | Terbukti tidak reachable (access control, state constraint, dll) |

### 8.4 Security-Property Certainty

| Level | Definisi |
|-------|---------|
| `UNKNOWN` | Property belum ditentukan |
| `CANDIDATE` | Property diusulkan tapi belum diverifikasi |
| `SUPPORTED` | Property dikonfirmasi dari authority source |
| `VALIDATED` | Property assertion telah dieksekusi oleh validator |

### 8.5 Overall Claim State

| State | Definisi | Prasyarat |
|-------|---------|-----------|
| `HYPOTHESIS` | Observasi awal | Evidence certainty ≥ OBSERVED |
| `ATTACK_CANDIDATE` | Causal path tersedia | Semantic ≥ INFERRED + causal path + attacker model |
| `VALIDATION_PENDING` | Menunggu validator | Validator plan tersedia |
| `CONFIRMED` | Terbukti valid | Lihat Validator Evidence Contract (section 23) |
| `REJECTED` | Terbukti tidak valid | Validator membuktikan kondisi tidak terpenuhi |
| `INCONCLUSIVE` | Tidak dapat ditentukan | Validator tidak tersedia atau loop melebihi batas |

### 8.6 Aturan Komposisi Certainty

Untuk naik ke `ATTACK_CANDIDATE`, semua kondisi berikut harus terpenuhi:

```
evidence_certainty     >= DERIVED
semantic_certainty     >= INFERRED
reachability_certainty >= POSSIBLE
property_certainty     >= CANDIDATE
```

Untuk `CONFIRMED`:

```
evidence_certainty     = VALIDATED
semantic_certainty     = SUPPORTED
reachability_certainty = REACHABLE
property_certainty     = VALIDATED
```

**Tidak boleh:**
```
LLM confidence ↑  →  CONFIRMED
```

Status CONFIRMED hanya dapat dibuat jika validator memenuhi required evidence contract.

### 8.7 Action Path untuk INCONCLUSIVE

Jika claim mencapai `INCONCLUSIVE`:
1. Finding **tidak masuk** ke final report sebagai CONFIRMED
2. Finding **masuk** ke section terpisah: `inconclusive_candidates.json`
3. Human reviewer **dapat** melakukan manual escalation dengan mencatat justifikasi
4. Jika manual escalation disetujui, status berubah ke `HUMAN_ESCALATED` (bukan CONFIRMED)
5. Report harus mencantumkan INCONCLUSIVE count secara eksplisit

---

## 9. Semantic Authority Model

Agent Finder harus menentukan dari mana intended behavior berasal.

### Authority Sources (Urutan Default)

| Priority | Source | Keterangan |
|----------|--------|-----------|
| 1 | Explicit protocol specification / security specification | Dokumen spesifikasi formal |
| 2 | Executable tests / invariant tests | Test suite yang ada di repository |
| 3 | Interface / standard requirements | EIP, ERC, atau interface yang diimplementasikan |
| 4 | Implementation behavior | Kode itu sendiri |
| 5 | Deployment/configuration constraints | Config files, deployment scripts |
| 6 | Comments/documentation | NatSpec, inline comments |
| 7 | Names/descriptions | Nama fungsi, variabel, README |

Jika dua sumber konflik → status `CONFLICT` dan **bukan** otomatis memilih salah satu.
Conflict harus disimpan sebagai evidence di `semantic_conflicts.json`.

### Output

```
intent.json
semantic_conflicts.json
authority.json
```

Setiap intended-behavior claim wajib menyebut:
- `authority_source` — nomor priority dari tabel di atas
- `source_location` — file dan baris
- `confidence` — POSSIBLE / INFERRED / SUPPORTED
- `conflicting_sources` — list source yang berkonflik (kosong jika tidak ada)
- `resolution_rule` — bagaimana konflik diselesaikan (atau `UNRESOLVED`)

---

## 10. Trust & Capability Model

Setiap actor/dependency diberi trust classification.

**Trust Classifications:**

```
USER               — pengguna biasa tanpa privilege khusus
ATTACKER           — aktor dengan hostile intent, tanpa privilege awal
AUTHORIZED_USER    — user yang memiliki specific permission
LOW_PRIVILEGE      — role dengan akses terbatas
GOVERNANCE         — governance contract atau multisig
ADMIN              — admin role
UPGRADER           — role yang dapat upgrade contract
ORACLE             — price/data oracle
EXTERNAL_PROTOCOL  — protokol DeFi eksternal yang di-integrate
TOKEN              — ERC20/ERC721/ERC1155 contract
CALLBACK_TARGET    — contract yang menerima callback
UNKNOWN_EXTERNAL   — external contract dengan identity tidak diketahui
```

Setiap capability harus memiliki:

```json
{
  "capability_id": "upgrade_implementation",
  "required_role": "UPGRADER",
  "acquisition_path": {
    "status": "UNKNOWN | BLOCKED | POSSIBLE | PROVEN",
    "description": "...",
    "evidence_ids": []
  },
  "provenance": "source location"
}
```

**Aturan:** Attack tidak boleh menggunakan capability yang `acquisition_path.status = UNKNOWN` tanpa mencatatnya sebagai unsupported assumption.

---

## 11. Recon Agent

### Purpose

Membangun Protocol Model dari repository. Recon **tidak menyimpulkan vulnerability**.

### Responsibilities

- source discovery
- compilation
- AST extraction
- contract/interface inventory
- function inventory
- parameters/returns
- modifiers
- authorization
- storage
- state reads/writes
- call graph
- dataflow
- capability mapping
- external interactions
- asset/custody flows
- relationship extraction
- source locations
- proxy/implementation relationships
- delegatecall relationships
- dependency graph
- evidence creation

### Output

```
facts.jsonl      — atomic facts dengan source location
graph.json       — call graph dan relationship graph
protocol.json    — contract/function inventory
dependencies.json
coverage.json
metadata.json
snippets/        — potongan source code yang direferensikan
```

### Compilation Failure Handling

Jika kompilasi gagal:
1. Log error eksplisit dengan compiler output
2. Catat di `coverage.json` bagian mana yang tidak ter-compile
3. **Tidak boleh** ada silent zero-fact runs — jika tidak ada facts, harus ada error eksplisit
4. Lanjutkan dengan partial analysis pada bagian yang berhasil di-compile
5. Semua findings dari partial analysis harus mencantumkan flag `partial_source_coverage: true`

---

## 12. Coverage Model

Coverage harus dihitung per dimensi:

| Dimensi | Keterangan |
|---------|-----------|
| `source_coverage` | % file source yang berhasil diproses |
| `compile_coverage` | % contract yang berhasil di-compile |
| `ast_coverage` | % AST nodes yang berhasil diekstrak |
| `contract_coverage` | % contract yang masuk ke model |
| `function_coverage` | % fungsi yang dianalisis |
| `dependency_coverage` | % dependencies yang resolved |
| `call_graph_coverage` | % call edges yang berhasil dibangun |
| `dataflow_coverage` | % dataflow paths yang dianalisis |
| `storage_coverage` | % storage variables yang dimodel |
| `proxy_coverage` | % proxy/implementation pairs yang resolved |
| `validator_coverage` | % attacks yang bisa divalidasi oleh validator |

**Coverage ≠ Confidence.**

Contoh yang **tidak boleh** dipresentasikan:
```
coverage = 42%
claim confidence = 95%
→ "high-confidence repository assessment"  ← SALAH
```

Setiap finding/candidate harus menyimpan:
```json
{
  "analysis_coverage": 0.72,
  "evidence_coverage": 0.85,
  "validator_coverage": 1.0
}
```

Jika `analysis_coverage < 0.5`: tambahkan flag `LOW_COVERAGE_WARNING` di report.

---

## 13. Intended-Behavior Agent

Agent Finder harus membangun model:

```
WHAT CODE DOES
vs
WHAT PROTOCOL INTENDS
```

### Output

```
intent.json
intent_conflicts.json
```

Setiap intended-behavior claim harus menyertakan:

```json
{
  "property": "Only owner can execute upgrade",
  "authority": {
    "source_type": "explicit_specification",
    "location": "docs/security.md:42"
  },
  "implementation_evidence": {
    "function": "ProxyAdmin.upgrade()",
    "location": "contracts/ProxyAdmin.sol:87"
  },
  "test_evidence": {
    "test": "test/ProxyAdmin.t.sol:testOnlyOwnerCanUpgrade",
    "location": "test/ProxyAdmin.t.sol:34"
  },
  "conflict": null
}
```

Jika intended behavior tidak dapat ditentukan → `INTENT_UNKNOWN`.  
Security claim **tidak boleh** dianggap proven hanya dari intuition atau LLM confidence.

---

## 14. Security Property Model

### Property Categories

| Category | Formula | Keterangan |
|----------|---------|-----------|
| **Asset** | `assets_out <= authorized_assets` | Tidak ada asset keluar melebihi yang diotorisasi |
| **Solvency** | `assets >= liabilities` | Protocol selalu solvent |
| **Authorization** | `caller_capability >= required_capability` | Caller memiliki hak yang cukup |
| **Accounting** | `recorded_value == intended_economic_value` | Pencatatan nilai akurat |
| **State Consistency** | `related_state_variables remain consistent` | State internal tidak inkonsisten |
| **Temporal** | `state_selected_at_T == intended_boundary_state` | State snapshot pada waktu yang tepat |
| **Precision** | `effective_precision == protocol_assumed_precision` | Presisi aritmatik sesuai asumsi |
| **Availability** | `valid_operation remains executable` | Operasi valid tidak bisa diblokir |
| **Callback Safety** | `external callback cannot violate active invariant` | Callback tidak bisa break invariant |
| **Integration** | `protocol assumptions == external component semantics` | Asumsi terhadap sistem eksternal terpenuhi |
| **Economic** | `value extraction requires corresponding entitlement` | Nilai hanya bisa diambil oleh yang berhak |

### Property Schema

Setiap security property wajib memiliki:

```json
{
  "property_id": "PROP-001",
  "category": "Authorization",
  "definition": "Only UPGRADER role can call upgrade()",
  "scope": "ProxyAdmin contract",
  "preconditions": ["contract is initialized", "not paused"],
  "protected_asset_or_state": "implementation address",
  "authority_source": "explicit_specification",
  "applicability": ["ProxyAdmin.upgrade()", "ProxyAdmin.upgradeAndCall()"],
  "formal_or_executable_test": "test/ProxyAdmin.t.sol:testOnlyUpgraderCanUpgrade"
}
```

**Property tidak boleh hanya berupa label.**

---

## 15. Inference Rule Engine

Semantic composition harus menggunakan explicit rules.

### Rule Format

```
RULE_ID: <unique identifier>

PREMISES:
  P1: <kondisi yang harus terpenuhi>
  P2: ...

CONDITIONS:
  C1: <kondisi tambahan yang harus diverifikasi>
  C2: ...

CONCLUSION:
  <kesimpulan yang dapat ditarik>

EVIDENCE_REQUIRED:
  E1: <jenis evidence yang harus ada>
  E2: ...

INVALID_IF:
  I1: <kondisi yang membatalkan rule>
  I2: ...
```

### Contoh

```
RULE_ID: ATTACKER_CONTROLLED_TARGET

PREMISES:
  P1: dynamic_call = true
  P2: target_origin = user_input

CONDITIONS:
  C1: user_input_reaches_target_without_sanitization
  C2: no allowlist or whitelist check on target

CONCLUSION:
  target_is_attacker_controlled

EVIDENCE_REQUIRED:
  E1: dataflow trace from user input to call target
  E2: absence of sanitization nodes in dataflow

INVALID_IF:
  I1: target validated against allowlist
  I2: target hardcoded or derived from protocol-controlled storage
```

LLM boleh **mengusulkan** rule application.  
Rule engine **menentukan** apakah rule valid diterapkan — bukan LLM.

---

## 16. Threat Agent

### Purpose

Mengubah Protocol Model menjadi Security Model.  
Threat Agent mencari kombinasi behavior yang berpotensi melanggar property.

### Reasoning Domains

authorization, custody, accounting, solvency, state consistency, temporal semantics, snapshots, rounding, precision, arithmetic, integrations, dynamic calls, callbacks, reentrancy, token approval, signatures/replay, randomness, economic manipulation, MEV, gas/complexity, cross-contract trust, standards compliance, initialization, upgradeability, storage lifecycle.

### Output

```
hypotheses.jsonl    — hypotheses dengan source evidence
invariants.json     — invariant yang diidentifikasi
semantic_rules.json — rules yang diterapkan
summary.json        — ringkasan analisis
```

**Threat hypothesis ≠ Attack.** Hypothesis adalah kandidat yang belum memiliki causal path lengkap.

---

## 17. Attack Agent

Attack Agent mengubah hypothesis menjadi concrete attack claim.

### Attack Representation

Attack harus berupa graph, bukan hanya linear path:

```
TRANSACTION 1 (attacker: setup)
   ↓
STATE S1
   ↓
TRANSACTION 2 (victim: interact)
   ↓
STATE S2
   ↓
TRANSACTION N (attacker: extract)
   ↓
STATE SN
   ↓
SECURITY CONSEQUENCE
```

### Attack Graph Requirements

Attack graph harus mendukung:
- single transaction
- multi-transaction
- multi-user
- temporal ordering
- block boundary
- oracle update
- callback
- flash-loan composition
- front-run/back-run
- cross-contract interaction

### 17.1 Side-Effect Bundling Requirement (Arbitrary-Call / Attacker-Controlled Payload Attacks)

Berlaku setiap kali attack claim melibatkan target function yang mengizinkan attacker menentukan **sebagian atau seluruh parameter dari sebuah external call** yang dieksekusi oleh contract itu sendiri (mis. `to.call(data)`, `delegatecall`, relay/bridge payload, meta-tx execute, dsb).

Untuk attack semacam ini, Attack Agent **wajib**:

1. Melakukan enumerasi **semua check/require/revert/assert lain** yang dieksekusi di dalam function yang sama **setelah** external call tersebut (mis. balance-delta check, allowance check, invariant assertion, nonce check).
2. Untuk setiap check itu, menentukan apakah payload attacker yang diusulkan (single call sederhana) akan **memenuhi** atau **melanggar** check tersebut.
3. Jika payload attacker sederhana akan **melanggar check lain** (menyebabkan revert sebelum consequence tercapai), attack claim **tidak boleh** langsung dianggap sebagai causal path yang valid. Agent wajib salah satu dari:
   - merevisi attack menjadi payload majemuk (mis. lewat intermediary/relay contract attacker-controlled) yang secara simultan memenuhi *semua* check yang di-enumerasi sambil tetap mencapai security consequence yang diklaim; **atau**
   - menurunkan status attack claim menjadi hypothesis dengan catatan eksplisit "blocked by check X unless bundled" dan mengirimkannya balik ke Reachability Engine, **bukan** langsung ke Validator sebagai claim final.
4. Attack claim yang payload-nya diketahui akan revert pada suatu check yang sudah teridentifikasi **tidak boleh** diteruskan ke Validator sebagai "expected to pass" — ini termasuk kategori *Unsupported assumption* di Mandatory Attack Gates (§18).

> Rationale: pada arbitrary-call primitives, causal path ke sink (mis. "call bisa mentransfer aset korban") sering valid secara teknis, tapi postcondition check di fungsi yang sama (mis. balance-delta assertion) bisa membatalkan seluruh efek jika attacker tidak membundel side-effect yang diperlukan untuk lolos check tersebut. Attack yang tidak memperhitungkan ini akan gagal saat validasi (revert), bukan karena root cause-nya salah, melainkan karena PoC-nya tidak lengkap.

---

## 18. Mandatory Attack Gates

Attack **wajib dibuang** jika salah satu kondisi berikut terpenuhi:

| Gate | Kondisi untuk Discard |
|------|----------------------|
| Entry reachability | Entry point tidak reachable |
| Caller validity | Caller tidak bisa menjadi attacker |
| Privilege proof | Privilege yang dibutuhkan tidak terbukti bisa didapat |
| Capability acquisition | Attacker capability tidak memiliki acquisition path |
| Target control | Target tidak terbukti attacker-controlled |
| Input provenance | Input provenance tidak cukup untuk mendukung attack |
| Sink relevance | Sink tidak relevan terhadap security property |
| Causal connection | Hubungan kausal antara action dan consequence tidak terbukti |
| Property applicability | Security property tidak applicable pada konteks ini |
| Concrete consequence | Consequence tidak konkret atau tidak material |
| Unsupported assumption | Critical assumption tidak didukung evidence |
| Postcondition completeness | Payload attacker yang diusulkan diketahui akan trigger revert pada check/require lain di function yang sama (lihat §17.1), dan attack belum direvisi menjadi payload majemuk yang lolos semua check tersebut |

**Tidak boleh ada claim** `"may be vulnerable"` sebagai attack final.

**Tidak boleh ada claim yang lolos ke Validator jika Agent sendiri sudah mengidentifikasi bahwa payload-nya akan revert pada suatu check** — claim seperti ini wajib direvisi dulu (§17.1) atau di-downgrade ke hypothesis, bukan dikirim ke Validator dengan asumsi "biar validator yang nemuin".

---

## 19. Reachability Engine

Sebelum Validator, gunakan dedicated reachability analysis.

### Checks

| Check | Keterangan |
|-------|-----------|
| `entry_reachability` | Apakah entry function bisa dipanggil? |
| `caller_reachability` | Apakah caller yang dimodelkan valid? |
| `authorization_reachability` | Apakah attacker bisa memenuhi auth requirement? |
| `input_reachability` | Apakah input yang diperlukan bisa disuplai? |
| `state_precondition_reachability` | Apakah state precondition bisa dicapai? |
| `cross_contract_reachability` | Apakah call chain cross-contract valid? |
| `temporal_reachability` | Apakah timing constraints bisa dipenuhi? |

### Output Values

```
REACHABLE — terbukti reachable
BLOCKED   — terbukti tidak reachable
UNKNOWN   — tidak dapat ditentukan
```

`UNKNOWN` **tidak boleh** diubah menjadi `REACHABLE` berdasarkan LLM confidence.

---

## 20. Economic Exploit Model

Untuk vulnerability ekonomi, Agent Finder harus memodelkan:

| Parameter | Keterangan |
|-----------|-----------|
| `attacker_capital` | Modal minimum yang dibutuhkan attacker |
| `required_liquidity` | Likuiditas yang diperlukan (misal untuk flash loan) |
| `gas_cost` | Estimasi gas untuk eksekusi attack |
| `execution_cost` | Total biaya eksekusi termasuk slippage |
| `expected_gain` | Keuntungan expected dari attack |
| `victim_loss` | Kerugian yang diderita korban |
| `maximum_extractable_value` | MEV maksimum yang bisa diekstrak |
| `repeatability` | Apakah attack bisa diulang? |
| `slippage` | Dampak slippage pada profitabilitas |
| `external_dependency` | Dependency ke kondisi eksternal (price, liquidity) |

### Distingsi Penting

```
technical_exploitability  ≠  economic_exploitability
```

Contoh: `technical_violation = true` + `economic_profit = negative` → **tidak otomatis** berarti critical economic vulnerability. Harus dilaporkan sebagai technical finding dengan economic context.

---

## 21. Validator

Validator adalah **adjudicator** — bukan hanya checker.

### Validator Test Types

Validator harus menguji:
- exact entry point
- exact caller identity
- caller privilege
- attacker capability acquisition
- exact inputs
- state preconditions
- transaction sequence
- call chain
- sink behavior
- state transition
- asset delta
- invariant assertion
- temporal assumptions
- external behavior (mock atau fork)
- economic consequence (jika applicable)
- **full-function postcondition survival**: transaksi PoC harus dieksekusi end-to-end sampai selesai *tanpa revert yang tidak diklaim*. Jika transaksi revert pada check manapun (termasuk check yang terjadi setelah sink tercapai secara internal, mis. balance-delta assertion), hasil default adalah `REJECTED` (jika revert itu deterministik/dijelaskan oleh code) atau `INCONCLUSIVE` (jika penyebab revert belum jelas) — **bukan** `CONFIRMED` dengan asumsi "sink-nya sempat kena, jadi valid". Reaching the sink internally is not sufficient; the transaction must actually commit.

### Result States

| State | Keterangan |
|-------|-----------|
| `CONFIRMED` | Attack terbukti valid, semua evidence contract terpenuhi |
| `REJECTED` | Attack terbukti tidak valid |
| `INCONCLUSIVE` | Tidak dapat ditentukan (validator tidak tersedia, environment tidak cukup) |

### CONFIRMED Contract

`CONFIRMED` hanya jika **semua** kondisi berikut terpenuhi:

```
valid entry
+ valid attacker model
+ reachable preconditions
+ expected execution path
+ expected sink reached
+ expected state/asset transition
+ security property applicable
+ property violation observed
+ required consequence observed
[+ economic consequence validated  ← wajib untuk economic findings]
```

---

## 22. Validator Independence

Validator tidak boleh hanya mengulang reasoning Agent.

```
Agent:     proposes attack
             ↓
Validator: executes / checks attack independently
```

### Validator Methods

Validator harus menggunakan **salah satu atau kombinasi** dari:

| Method | Keterangan |
|--------|-----------|
| Foundry unit tests | Test fungsi spesifik |
| Foundry fork tests | Test dengan state on-chain nyata |
| Symbolic checks (Halmos, Certora, Echidna) | Formal verification |
| Invariant assertions | Property-based testing |
| Trace analysis | Analisis execution trace |
| State snapshots | Perbandingan state sebelum/sesudah |
| Deterministic scripts | Script reproducible tanpa LLM |

Jika environment tidak cukup → `INCONCLUSIVE`, **bukan** `CONFIRMED`.

### Validator Environment Requirements

| Requirement | Keterangan |
|-------------|-----------|
| Foundry version | ≥ 0.2.0 (pinned di `foundry.toml`) |
| RPC endpoint (fork tests) | Wajib disediakan user via `--rpc-url` atau env `ETH_RPC_URL` |
| RPC timeout | 30 detik per request, maksimum 3 retry |
| Block number | Harus eksplisit; bukan "latest" untuk reproducibility |
| Compiler version | Harus match dengan repository `pragma` |

Jika RPC endpoint tidak tersedia dan attack membutuhkan fork → `VALIDATOR_UNAVAILABLE`, bukan error.

---

## 23. Validator Evidence Contract

Setiap `CONFIRMED` harus menyimpan **semua** field berikut:

```json
{
  "validator_id": "val-20260817-001",
  "environment": {
    "tool": "foundry",
    "version": "0.2.0",
    "type": "fork | unit | symbolic"
  },
  "compiler_version": "0.8.20",
  "dependency_versions": {
    "openzeppelin-contracts": "5.0.1"
  },
  "chain_state": {
    "chain_id": 1,
    "block_number": 20000000,
    "rpc_endpoint_hash": "sha256:abc..."
  },
  "transaction_sequence": ["tx1_calldata", "tx2_calldata"],
  "caller_accounts": {
    "attacker": "0xABCD...",
    "victim": "0xEFGH..."
  },
  "initial_state": { "...": "..." },
  "final_state": { "...": "..." },
  "trace": "foundry_trace_output_or_path",
  "sink_observation": "Transfer(attacker, 1000e18)",
  "asset_delta": {
    "attacker_gain": "1000e18",
    "victim_loss": "1000e18"
  },
  "property_assertion": "PROP-001 violated",
  "reproduction_command": "forge test --fork-url $ETH_RPC_URL --fork-block-number 20000000 -vvvv --match-test testAttack001"
}
```

**Tujuan:** reviewer lain harus dapat mengulang validation hanya dengan menjalankan `reproduction_command`.

---

## 24. Finding Agent

Finding hanya menerima input dengan status `CONFIRMED`.

### Finding Schema

```json
{
  "finding_id": "FIND-001",
  "title": "Reentrancy in withdraw() allows attacker to drain pool",
  "severity": {
    "overall": "CRITICAL",
    "impact": "critical_asset_loss",
    "exploitability": "permissionless",
    "scope": "protocol",
    "recoverability": "permanent"
  },
  "root_cause": "...",
  "affected_code": [
    { "file": "contracts/Pool.sol", "lines": "142-157" }
  ],
  "attack_path": "...",
  "broken_security_property": "PROP-003",
  "concrete_impact": "Attacker dapat menguras seluruh ETH dalam pool (~$5M pada block 20000000)",
  "evidence": ["fact-042", "fact-099"],
  "mitigation": "...",
  "assumptions": ["attacker has ETH for gas", "contract not paused"],
  "scope_notes": "...",
  "validation_reproduction": "forge test ... (lihat validator_results.json:val-001)",
  "provenance": {
    "validator_result_id": "val-001",
    "attack_id": "atk-007",
    "hypothesis_id": "hyp-012",
    "property_id": "PROP-003",
    "evidence_ids": ["fact-042", "fact-099"],
    "source_locations": ["contracts/Pool.sol:142"]
  }
}
```

---

## 25. Human Review & Disclosure State

### State Machine

```
CONFIRMED
    ↓
REVIEW_REQUIRED
    ↓
REVIEWED  ──── (reviewer rejects) ──→  REJECTED_BY_REVIEW
    ↓
DISCLOSURE_READY
```

### Human Review Wajib untuk

- high-impact finding (severity CRITICAL atau HIGH)
- ambiguous intent (ada SEMANTIC_CONFLICT yang belum resolved)
- external dependency yang tidak dapat divalidasi otomatis
- economic severity di atas threshold ($10,000 estimated impact)
- protocol-wide impact (bukan single-user)
- semua disclosure decisions

### Human Review Workflow

| Step | Actor | SLA | Output |
|------|-------|-----|--------|
| Review assignment | System | Otomatis saat CONFIRMED | Reviewer ditugaskan |
| Technical review | Security Reviewer | 48 jam (HIGH/CRITICAL), 5 hari (lainnya) | REVIEWED atau REJECTED_BY_REVIEW |
| Severity adjudication | Senior Reviewer | 24 jam setelah REVIEWED | Severity final dikonfirmasi |
| Disclosure decision | Disclosure Team | 24 jam setelah severity final | DISCLOSURE_READY atau HOLD |

**Proof of exploit tidak otomatis berarti permission to disclose.**

---

## 26. Responsible Disclosure Policy

### Disclosure Process

```
FINDING
    ↓
DISCLOSURE_READY (internal)
    ↓
NOTIFICATION ke protocol team  (T+0)
    ↓
EMBARGO PERIOD                 (T+0 hingga T+90 hari)
    ↓
RESPONSE dari protocol team    (SLA: 7 hari untuk acknowledge)
    ↓
FIX DEPLOYED                   (target: dalam embargo period)
    ↓
PUBLIC DISCLOSURE              (setelah fix + koordinasi)
```

### Embargo Period

| Severity | Embargo Default | Minimum | Maximum |
|----------|----------------|---------|---------|
| CRITICAL | 90 hari | 7 hari (jika fix sudah live) | 90 hari |
| HIGH | 60 hari | 7 hari | 90 hari |
| MEDIUM | 30 hari | 14 hari | 60 hari |
| LOW | 14 hari | 7 hari | 30 hari |

### Non-Responsif Protocol

Jika protocol team tidak acknowledge dalam 7 hari:
1. Kirim reminder ke semua known contact (T+7)
2. Coba jalur alternatif (on-chain message, public contact) (T+14)
3. Koordinasi dengan CERT/koordinator keamanan ekosistem (T+21)
4. Pertimbangkan limited public disclosure dengan mitigasi untuk user (T+30+)

Semua keputusan disclosure melibatkan human review — tidak ada disclosure otomatis.

### Koordinasi Bug Bounty

Jika repository memiliki active bug bounty program:
1. Submit ke platform bug bounty terlebih dahulu
2. Ikuti policy platform tersebut
3. Agent Finder tidak mengklaim reward atas nama user secara otomatis

---

## 27. Severity Rubric

**Severity rubric ini bersifat deterministik dan versioned (v1.0).**

### 27.1 Impact Score

| Level | Deskripsi | Score |
|-------|-----------|-------|
| `critical_asset_loss` | Kehilangan asset permanen skala protocol | 5 |
| `protocol_insolvency` | Protocol menjadi insolvent | 5 |
| `unauthorized_privilege` | Attacker mendapat privilege kritis (upgrade, drain) | 4 |
| `permanent_dos` | Denial of service permanen pada fungsi kritis | 4 |
| `economic_corruption` | Manipulasi ekonomi berskala besar | 4 |
| `user_asset_loss` | Kehilangan asset individual user | 3 |
| `temporary_dos` | Denial of service sementara | 2 |
| `integrity_issue` | Masalah integritas data tanpa asset loss langsung | 1 |

### 27.2 Exploitability Score

| Level | Deskripsi | Score |
|-------|-----------|-------|
| `permissionless` | Siapa saja bisa mengeksekusi | 5 |
| `low_privilege` | Hanya butuh privilege rendah (user biasa) | 4 |
| `known_privileged_role` | Hanya role spesifik yang ada | 3 |
| `state_dependent` | Butuh state tertentu yang tidak selalu ada | 2 |
| `timing_dependent` | Butuh window waktu sempit | 2 |
| `external_dependency` | Butuh kondisi eksternal (oracle, MEV) | 1 |

### 27.3 Overall Severity Matrix

```
Impact Score × Exploitability Score → Overall Severity

Score ≥ 20    → CRITICAL
Score 12–19   → HIGH
Score 6–11    → MEDIUM
Score 1–5     → LOW
Score = 0     → INFORMATIONAL
```

### 27.4 Economic Modifiers

- Jika `estimated_loss < $1,000` dan impact ≤ user_asset_loss → turunkan severity satu level
- Jika `estimated_loss > $10M` dan exploitability = permissionless → naikkan severity satu level (max CRITICAL)
- Jika `economic_profit < 0` (attack tidak profitable) → turunkan exploitability score satu level

### 27.5 Recoverability Modifier

| Recoverability | Modifier |
|----------------|---------|
| `reversible` | -1 level severity |
| `recoverable_by_admin` | no change |
| `recoverable_by_governance` | no change |
| `permanent` | +1 level severity (max CRITICAL) |

---

## 28. Provenance Model

Setiap claim wajib traceable ke:

```json
{
  "claim_id": "atk-007",
  "provenance": {
    "fact_ids": ["fact-042", "fact-099"],
    "graph_nodes": ["node-112", "node-203"],
    "graph_edges": ["edge-055"],
    "source_locations": ["contracts/Pool.sol:142-157"],
    "call_chain": ["Pool.withdraw()", "Pool._transfer()"],
    "state_transition": ["balance[attacker] -= amount", "transfer called", "balance[attacker] -= amount (again)"],
    "inference_rules": ["RULE:REENTRANCY_PATTERN", "RULE:STATE_MODIFIED_AFTER_CALL"],
    "validator_observations": ["val-001:trace:line-42"]
  }
}
```

### Provenance Graph

```
SOURCE
 ↓
FACT
 ↓
RELATIONSHIP
 ↓
INFERENCE
 ↓
HYPOTHESIS
 ↓
ATTACK
 ↓
VALIDATION
 ↓
FINDING
```

**Tidak boleh ada orphan claim** — setiap claim harus traceable ke source.

---

## 29. Untrusted Source Handling

Repository adalah **UNTRUSTED INPUT**.

Komentar, README, strings, variable names, function names, dan source text **tidak boleh** menjadi system instruction.

```
SOURCE DATA  ≠  AGENT INSTRUCTIONS
```

### Requirements

| Requirement | Implementasi |
|-------------|-------------|
| Sandbox source | Source code diproses dalam isolated context |
| Delimiter | Source text selalu dibalut dalam delimiter eksplisit sebelum dikirim ke LLM |
| Parser isolation | Parser source code tidak mengeksekusi string sebagai instruksi |
| Prompt injection detection | Deteksi pola `"ignore previous instructions"`, `"system:"`, dll dalam source |
| No execution of source as instruction | Source hanya dibaca sebagai data, tidak diinterpretasi sebagai command |
| Provenance of doc-derived claims | Claims yang berasal dari comments/README harus di-tag sebagai low-authority source |

Jika prompt injection terdeteksi dalam source: log event, skip file tersebut, catat di `coverage.json` sebagai `INJECTION_DETECTED`.

---

## 30. Proxy & Upgradeability Model

Proxy harus menjadi first-class graph:

```
PROXY
 ↓
IMPLEMENTATION
 ↓
DELEGATECALL CONTEXT
 ↓
STORAGE LAYOUT
 ↓
UPGRADE AUTHORITY
 ↓
INITIALIZER
 ↓
LIFECYCLE
```

### Validator Requirements untuk Proxy

Validator harus mampu menguji:
- implementation address (current dan historical)
- upgrade authority (siapa yang bisa upgrade)
- initialization state (sudah diinisialisasi atau belum)
- storage collision (antara proxy dan implementation)
- delegatecall context (msg.sender, msg.value preservation)
- upgrade path (apakah ada timelock, governance vote, dll)
- implementation lifecycle (deprecated implementations)

---

## 31. Multi-Transaction Attack Model

Attack schema harus mendukung:

```json
{
  "attack_id": "atk-007",
  "transactions": [
    {
      "tx_id": "tx-1",
      "actor": "attacker",
      "action": "manipulate state via flashloan",
      "calldata": "0x..."
    },
    {
      "tx_id": "tx-2",
      "actor": "victim",
      "action": "interact with manipulated state",
      "calldata": "0x..."
    },
    {
      "tx_id": "tx-3",
      "actor": "attacker",
      "action": "extract value",
      "calldata": "0x..."
    }
  ],
  "state_snapshots": ["snapshot-0", "snapshot-1", "snapshot-2", "snapshot-3"],
  "actors": ["attacker", "victim"],
  "dependencies": ["flashloan provider available"],
  "ordering_constraints": ["tx-1 before tx-2", "tx-2 before tx-3"],
  "temporal_constraints": ["tx-1 and tx-3 in same block"],
  "profit_model": { "gain": "1000e18", "cost": "gas + flashloan_fee" },
  "security_property": "PROP-003"
}
```

Attack **tidak dianggap invalid** hanya karena consequence tidak muncul dalam satu transaction.

---

## 32. Multi-Chain Support

### Chain Support Matrix

| Chain | Phase | Validator Support | Notes |
|-------|-------|------------------|-------|
| Ethereum Mainnet | Phase 1 | Full (Foundry fork) | Primary target |
| Ethereum testnets (Sepolia, Holesky) | Phase 1 | Full (Foundry fork) | |
| Arbitrum One | Phase 2 | Partial (fork, tidak semua precompile) | L2 sequencer assumptions |
| Optimism | Phase 2 | Partial | L2 sequencer assumptions |
| Base | Phase 2 | Partial | |
| Polygon PoS | Phase 3 | Partial | |
| Avalanche C-Chain | Phase 3 | Conditional | |
| BNB Chain | Phase 3 | Conditional | |
| Vyper contracts (any chain) | Phase 2+ | Conditional | Lihat section 39 |

### Chain-Specific Considerations

Setiap chain yang didukung harus mendokumentasikan:

| Consideration | Keterangan |
|---------------|-----------|
| L2 sequencer trust model | Apakah sequencer dapat disalahgunakan? |
| Chain-specific precompiles | Precompile yang tidak ada di Foundry default |
| Block time dan finality | Perbedaan dari Ethereum mainnet |
| Native token behavior | ETH vs MATIC vs BNB, dll |
| Cross-chain bridge assumptions | Jika contract berinteraksi dengan bridge |
| MEV landscape | Apakah MEV bisa dieksekusi? Oleh siapa? |

Jika validator belum tersedia untuk suatu chain, semua findings untuk chain tersebut otomatis `INCONCLUSIVE`.

---

## 33. Failure & Degraded Modes

System tidak boleh menganggap `0 findings = 0 vulnerabilities`.

### System States

| State | Keterangan | Action |
|-------|-----------|--------|
| `FULL_SUCCESS` | Semua tahap berjalan normal | Report normal |
| `PARTIAL_RECON` | Recon tidak lengkap | Flag LOW_COVERAGE_WARNING, report dengan caveat |
| `SEMANTIC_CONFLICT` | Konflik dalam semantic model | Report konflik, findings tetap dilanjutkan dengan caveats |
| `THREAT_EMPTY` | Tidak ada hypothesis yang dihasilkan | Report diagnostic, jangan klaim "aman" |
| `ATTACK_EMPTY` | Semua hypothesis di-gate | Report, mungkin ada false negatives |
| `REACHABILITY_UNKNOWN` | Reachability tidak dapat ditentukan | Flag sebagai INCONCLUSIVE |
| `VALIDATOR_UNAVAILABLE` | Validator tidak bisa dijalankan | Semua attacks → INCONCLUSIVE, bukan CONFIRMED |
| `VALIDATION_INCONCLUSIVE` | Validator jalan tapi tidak konklusi | INCONCLUSIVE, catat di `inconclusive_candidates.json` |
| `SYSTEM_FAILURE` | Error fatal | Exit code 1, log diagnostics |

Jika `analysis_coverage < 0.5`:
```
NO_SECURITY_CONCLUSION
```

Jika validator unavailable:
```
UNVALIDATED  ←  bukan CONFIRMED
```

---

## 34. SLA & Operational Limits

### Runtime Limits

| Parameter | Default | Max | Catatan |
|-----------|---------|-----|---------|
| Total analysis time | 30 menit | 60 menit | Per repository |
| Recon time | 5 menit | 15 menit | |
| Semantic model time | 5 menit | 15 menit | |
| Attack generation time | 10 menit | 20 menit | |
| Validator time (per attack) | 2 menit | 10 menit | |
| Total validator time | 15 menit | 30 menit | |
| Retry loop iterations | 3 | 3 | Per attack candidate |

### Resource Limits

| Parameter | Default | Max |
|-----------|---------|-----|
| LLM calls per repository | 100 | 500 |
| LLM tokens per repository | 2M | 10M |
| Memory usage | 4 GB | 16 GB |
| Validator processes (parallel) | 4 | 8 |
| Fork RPC requests | 1.000 | 5.000 |

### Input Limits

| Parameter | Limit |
|-----------|-------|
| Repository size | 500 MB |
| Solidity files | 2.000 |
| SLOC | 500.000 |
| Dependencies (npm/git) | 50 |

Jika limit terlampaui: error eksplisit + saran bagaimana membagi scope.

---

## 35. Benchmark Framework

### 35.1 Closed-World Benchmark

Dataset memiliki:
- known finding (dengan ground truth)
- source revision (git commit hash)
- relevant code locations
- expected root cause
- expected consequence
- validation oracle (reproduction command)

**Dataset v1.0 (target untuk Phase 5 exit):**

| Category | Jumlah Repositories |
|----------|-------------------|
| Known reentrancy exploits (historical) | 10 |
| Known oracle manipulation exploits | 10 |
| Known access control failures | 10 |
| Known integer overflow/underflow | 10 |
| Known flash loan attacks | 10 |
| False positive controls (tidak ada vuln) | 20 |
| **Total** | **70** |

Sumber dataset: Damn Vulnerable DeFi, real historical exploits (post-mortem), manually curated test cases.

### 35.2 Open-World Benchmark

- Repository dipilih tanpa memberi model daftar expected findings
- Hasil dinilai oleh **independent security reviewers** (bukan tim yang membuat sistem)
- Reviewer tidak boleh melihat Agent Finder output sebelum independent review mereka selesai
- Target: 20 repository per quarter

### 35.3 Benchmark Governance

- Dataset di-maintain oleh dedicated benchmark team
- Update dataset saat ada exploit baru yang significant
- Benchmark runs dilakukan setelah setiap major release
- Hasil benchmark dipublikasikan internal secara transparan

---

## 36. Evaluation Metrics

### Detection

| Metric | Formula | Target |
|--------|---------|--------|
| Precision | TP / (TP + FP) | ≥ 90% |
| Recall | TP / (TP + FN) | ≥ 70% |
| False Positive Rate | FP / (FP + TN) | < 10% |
| False Negative Rate | FN / (FN + TP) | < 30% |

### Confirmation Quality

| Metric | Formula | Target |
|--------|---------|--------|
| Confirmation Precision | Valid CONFIRMED / All CONFIRMED | ≥ 90% |
| Unsupported Confirmation Rate | CONFIRMED without full evidence / All CONFIRMED | < 5% |
| Inconclusive Rate | INCONCLUSIVE / All validated | < 20% |
| Validator Reproducibility | Reproducible CONFIRMED / All CONFIRMED | ≥ 95% |

### Evidence Quality

| Metric | Target |
|--------|--------|
| Evidence Coverage | ≥ 85% of findings have full provenance |
| Provenance Completeness | 0 orphan claims |
| Unsupported Assumption Rate | < 10% of attack assumptions unsupported |

### Coverage-Adjusted

```
Coverage-Adjusted Recall = Recall × Analysis Coverage ≥ 0.60
```

### Operational

| Metric | Target |
|--------|--------|
| Runtime / repository | < 30 menit (average) |
| Memory | < 4 GB (average) |
| LLM calls / repository | < 100 (average) |
| Token usage / repository | < 2M tokens (average) |
| Cost / repository | < $20 USD (average) |
| Validator execution time / attack | < 2 menit (average) |

---

## 37. Regression Strategy

Setiap security capability baru membutuhkan:

- unit tests
- schema tests
- inference-rule tests
- validator tests
- regression benchmark
- known false-positive tests
- known true-positive tests
- coverage degradation tests
- prompt-injection tests
- malformed repository tests

### Regression Thresholds

Perubahan **tidak boleh** dianggap improvement hanya karena `attack_count ↑` atau `threat_count ↑`.

Improvement harus memenuhi semua kondisi:
1. Benchmark recall tidak turun lebih dari 2%
2. Benchmark precision tidak turun lebih dari 5%
3. Tidak ada regresi pada known true-positive test cases
4. Tidak ada false positive baru pada false-positive test cases

---

## 38. Resource Strategy

Deterministic computation diprioritaskan. LLM digunakan hanya jika deterministic computation tidak cukup.

| Tier | Operations | Prioritas LLM |
|------|-----------|--------------|
| LOW | artifact serialization, schema validation, deduplication, ranking, coverage | Tidak |
| MEDIUM | recon, dataflow, graph analysis | Minimal (hanya untuk ambiguous cases) |
| HIGH | semantic threat reasoning, attack generation, economic reasoning | Ya, dengan grounding |
| VERY HIGH | dynamic validator / fork test | Tidak (deterministic execution) |

---

## 39. Language Support

### Phase 1: Solidity

Full support:

| Stage | Status |
|-------|--------|
| Recon | Full |
| Threat | Full |
| Attack | Full |
| Reachability | Full |
| Validator | Full (Foundry) |
| Finding | Full |

### Vyper

Support harus eksplisit. Jika validator belum tersedia:

| Stage | Status |
|-------|--------|
| Recon | Partial |
| Threat | Conditional |
| Attack | Conditional |
| Validator | Unsupported |
| Finding | Conditional (tidak ada CONFIRMED tanpa validator) |

**Jangan klaim full support untuk Vyper** sampai validator tersedia.

### Bahasa Lain (Future)

Untuk bahasa lain (Rust/Move untuk Solana/Aptos, Ink! untuk Substrate):
- Perlu validator environment terpisah
- Perlu threat model yang berbeda
- Perlu inference rules yang di-porting
- Klaim support hanya setelah validator ter-implement

---

## 40. Security & Operational Risks

### False Positive
**Risk:** Auditor membuang waktu menginvestigasi finding tidak valid.  
**Mitigation:** inference rules, attack gates, reachability engine, strict validator contract, human review.

### False Negative
**Risk:** Vulnerability nyata tidak terdeteksi.  
**Mitigation:** semantic reasoning breadth, open-world benchmark, validator feedback loop, coverage diagnostics, multi-transaction model support.

### LLM Hallucination
**Risk:** LLM mengklaim sesuatu yang tidak ada dalam source code.  
**Mitigation:** source grounding wajib, provenance requirement, machine-checkable inference rules, validator barrier sebelum CONFIRMED.

### Prompt Injection
**Risk:** Source code berisi instruksi yang memanipulasi behavior LLM.  
**Mitigation:** untrusted source handling (section 29), sandbox, delimiters, instruction/data separation, injection detection.

### Compilation Failure
**Risk:** Code tidak bisa dianalisis → silent false negative.  
**Mitigation:** partial analysis dengan explicit coverage, diagnostics, no silent zero-fact runs.

### Validator Unavailable
**Risk:** Attack tidak bisa divalidasi → tidak ada CONFIRMED padahal ada vuln.  
**Mitigation:** INCONCLUSIVE (tidak CONFIRMED), catat sebagai UNVALIDATED, human escalation path tersedia.

### Economic Model Error
**Risk:** Economic impact diestimasi salah → severity salah.  
**Mitigation:** explicit assumptions dalam economic model, sensitivity analysis, reproducible simulation, human review untuk material impact (>$10,000).

### Benchmark Overfitting
**Risk:** Sistem di-tune untuk benchmark dataset, performa buruk di real-world.  
**Mitigation:** open-world benchmark dengan independent reviewer, frequent benchmark dataset updates, cross-validation.

---

## 41. Development Roadmap

### Phase 1 — Recon Reliability
**Estimasi:** 6–8 minggu, 2 engineers

| Goal | Deliverable |
|------|------------|
| Compiler coverage | Stable compilation untuk semua supported Solidity versions |
| AST coverage | Full AST extraction |
| Dependency expansion | npm + git dependency resolution |
| Graph integrity | Call graph dan dataflow graph valid |
| Deterministic IDs | Stable fact/node IDs across runs |
| Coverage diagnostics | `coverage.json` lengkap |
| Proxy mapping | Basic proxy/implementation detection |

**Exit Criteria:**
- Stable artifacts untuk 70 benchmark repositories
- Explicit compilation failures (tidak ada silent zero-fact)
- No silent zero-fact runs

---

### Phase 2 — Semantic Model
**Estimasi:** 6–8 minggu, 2–3 engineers

| Goal | Deliverable |
|------|------------|
| Trust model | `trust_model.json` untuk semua actors |
| Capability model | `capabilities.json` dengan acquisition paths |
| Intended behavior | `intent.json` dengan authority sources |
| Authority hierarchy | Resolusi konflik authority |
| Semantic conflicts | `semantic_conflicts.json` |

**Exit Criteria:**
- Benchmark repositories memiliki deterministic semantic artifacts across 3 runs
- Semantic conflict detection rate ≥ 80% pada conflict test cases

---

### Phase 3 — Security Model
**Estimasi:** 8–10 minggu, 2–3 engineers

| Goal | Deliverable |
|------|------------|
| Invariant derivation | `security_properties.json` |
| Property applicability | Mapping property ke function scope |
| Inference rules | `inference_rules.json` dengan test coverage |
| Accounting properties | Modeling khusus untuk accounting |
| Temporal properties | Snapshot dan temporal semantics |
| Precision properties | Arithmetic precision analysis |
| Integration properties | External protocol assumptions |
| Economic properties | Economic invariant modeling |

**Exit Criteria:**
- False composition rate bounded by regression tests (< 20% false composition)
- Inference rule test coverage ≥ 90%

---

### Phase 4 — Attack Hardening
**Estimasi:** 6–8 minggu, 2–3 engineers

| Goal | Deliverable |
|------|------------|
| Attacker capability verification | Acquisition path validation |
| Caller chain analysis | Full caller reachability |
| Target control verification | Attacker-controlled target proof |
| Multi-transaction attacks | Multi-tx attack schema |
| Reachability engine | Dedicated reachability analysis |
| Economic filtering | Economic viability check |

**Exit Criteria:**
- Zero unsupported privilege assumptions in benchmark
- Attack quality score (precision × recall) improves ≥ 10% vs Phase 3

---

### Phase 5 — Validator
**Estimasi:** 10–12 minggu, 2–4 engineers

| Goal | Deliverable |
|------|------------|
| Foundry unit tests | Basic validator |
| Mock framework | Mock external dependencies |
| Fork tests | On-chain state validation |
| Invariant assertions | Property-based validator |
| State deltas | Before/after state comparison |
| Trace analysis | Execution trace validation |
| Reproducibility | `reproduction_command` untuk semua CONFIRMED |

**Exit Criteria:**
- Deterministic CONFIRMED / REJECTED / INCONCLUSIVE pada semua benchmark
- Zero unsupported confirmations
- Validator reproducibility ≥ 95%

---

### Phase 6 — Finding & Review
**Estimasi:** 4–6 minggu, 1–2 engineers

| Goal | Deliverable |
|------|------------|
| Normalized report | `findings.json`, `findings.md`, `findings.sarif` |
| Severity rubric v1.0 | Deterministic severity calculation |
| Evidence package | Full provenance per finding |
| Mitigation suggestions | Template-based mitigation |
| Human-review workflow | Review assignment dan SLA tracking |
| Disclosure state machine | DISCLOSURE_READY flow |

**Exit Criteria:**
- Every finding maps to exactly one validated result
- Disclosure status explicit untuk semua findings
- SARIF output valid untuk GitHub Code Scanning

---

## 42. Required Artifact Schemas

Semua artifacts harus menyertakan field `schema_version` dan `generated_at`.

| Artifact | Schema Version | Description |
|----------|---------------|-------------|
| `protocol.json` | v1 | Contract/function inventory |
| `facts.jsonl` | v1 | Atomic facts dengan source locations |
| `graph.json` | v1 | Call graph dan relationship graph |
| `coverage.json` | v1 | Coverage per dimensi |
| `trust_model.json` | v1 | Actor trust classifications |
| `capabilities.json` | v1 | Capability dengan acquisition paths |
| `intent.json` | v1 | Intended behavior model |
| `semantic_conflicts.json` | v1 | Semantic conflicts yang ditemukan |
| `authority.json` | v1 | Authority hierarchy |
| `security_properties.json` | v1 | Security properties dengan formal definitions |
| `inference_rules.json` | v1 | Inference rules yang diterapkan |
| `hypotheses.jsonl` | v1 | Security hypotheses |
| `attacks.jsonl` | v1 | Attack candidates dengan causal paths |
| `reachability.json` | v1 | Reachability analysis results |
| `validator_results.json` | v1 | Validator evidence contracts |
| `findings.json` | v1 | Final validated findings |
| `provenance.json` | v1 | Full provenance graph |
| `inconclusive_candidates.json` | v1 | INCONCLUSIVE attacks untuk human review |

**No security-critical stage should rely exclusively on free-form prose.**

### Schema Versioning Policy

- Schema changes yang breaking membutuhkan major version bump (v1 → v2)
- Backward compatibility dipertahankan untuk satu major version
- Migration tooling disediakan untuk setiap major version bump

---

## 43. State Transition Rules

### Hypothesis
```
FACTS → HYPOTHESIS
requires: source evidence (evidence_certainty ≥ OBSERVED)
```

### Attack Candidate
```
HYPOTHESIS → ATTACK_CANDIDATE
requires:
  - causal path (explicit, grounded in source)
  - attacker model (actor + capability with acquisition path)
  - security property (applicable to scope)
  - consequence candidate (concrete)
```

### Validation
```
ATTACK_CANDIDATE → VALIDATION_PENDING
requires: validator plan (tool + method + expected checks)
```

### Confirmation
```
VALIDATION_PENDING → CONFIRMED
requires: full validator evidence contract (section 23)
```

```
VALIDATION_PENDING → REJECTED
requires: validator proof that condition cannot be met
```

```
VALIDATION_PENDING → INCONCLUSIVE
requires: validator ran but cannot determine (OR max retry exceeded)
```

### Finding
```
CONFIRMED → FINDING
requires: normalized finding schema (section 24)
```

### Disclosure
```
FINDING → REVIEW_REQUIRED
REVIEW_REQUIRED → REVIEWED
REVIEW_REQUIRED → REJECTED_BY_REVIEW (jika reviewer menolak)
REVIEWED → DISCLOSURE_READY
requires: human adjudication according to policy (section 26)
```

---

## 44. Final Architecture

```
                  REPOSITORY
                      │
                      ▼
                   RECON
              (facts, graph, protocol)
                      │
                      ▼
              PROTOCOL MODEL
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        TRUST      INTENT      SEMANTICS
        MODEL       MODEL        MODEL
          └───────────┼───────────┘
                      ▼
             SECURITY PROPERTIES
                      │
                      ▼
              INFERENCE RULES
                      │
                      ▼
               THREAT ENGINE
               (hypotheses)
                      │
                      ▼
                ATTACK GRAPH
              (attack candidates)
                      │
                      ▼
             REACHABILITY ENGINE
                      │
                      ▼
             ECONOMIC FILTER
                      │
                      ▼
                 VALIDATOR ─────── (max 3 retries per attack)
                 /       \
             REJECT     CONFIRM
               │     (evidence contract)
               ▼           │
           REJECTED     HUMAN REVIEW
                        (SLA: 48h/5d)
                            │
                            ▼
                     DISCLOSURE FLOW
                     (section 26)
                            │
                            ▼
                         FINDING
```

---

## 45. Final Product Constitution

Agent Finder harus selalu mengikuti aturan:

1. **Observe before interpreting.** Facts dulu, inference kemudian.
2. **Separate facts from inference.** Jangan campur source evidence dengan LLM reasoning.
3. **Separate implementation behavior from intended behavior.** Apa yang code lakukan vs apa yang protocol maksudkan adalah dua hal berbeda.
4. **Never assume attacker capability.** Capability harus memiliki acquisition path yang terbukti.
5. **Never assume trust.** Trust harus dideklarasikan eksplisit.
6. **Never treat LLM confidence as proof.** Confidence bukan evidence.
7. **Never compose PROVEN facts without an explicit inference rule.** Setiap komposisi butuh rule yang terdokumentasi.
8. **Treat multi-transaction attacks as first-class.** Jangan discard hanya karena butuh lebih dari satu tx.
9. **Separate technical exploitability from economic exploitability.** Keduanya perlu dianalisis terpisah.
10. **Treat incomplete coverage as uncertainty, not safety.** Coverage rendah → uncertainty tinggi, bukan keamanan tinggi.
11. **Validator must independently challenge the attack claim.** Bukan hanya konfirmasi ulang reasoning yang sama.
12. **INCONCLUSIVE is a valid result.** Lebih baik INCONCLUSIVE daripada CONFIRMED yang salah.
13. **CONFIRMED requires machine-checkable evidence.** Bukan hanya LLM reasoning yang kuat.
14. **Finding is not automatically disclosure-ready.** Human review wajib untuk semua high-impact findings.
15. **Optimize for true security failures, not suspicious code volume.**
16. **Retry loops must terminate.** Maksimum 3 iterasi per attack candidate.
17. **Resources must be bounded.** Setiap run memiliki SLA dan resource cap yang eksplisit.

**Ultimate Goal:**

```
SOURCE CODE
    ↓
FACTS
    ↓
UNDERSTANDING
    ↓
INTENDED BEHAVIOR
    ↓
SECURITY PROPERTY
    ↓
ATTACK CLAIM
    ↓
REACHABILITY
    ↓
PROOF
    ↓
HUMAN REVIEW
    ↓
TRUTHFUL FINDING
```

> If a candidate cannot survive this chain, it is not a confirmed finding.

---

## 46. Glossary

| Term | Definisi |
|------|---------|
| **Acquisition Path** | Cara attacker mendapatkan suatu capability; harus memiliki bukti yang terdokumentasi |
| **Attack Candidate** | Hypothesis yang sudah memiliki causal path, attacker model, dan security property, tapi belum divalidasi |
| **Attack Gate** | Filter wajib yang membuang attack candidate yang tidak memenuhi syarat minimum |
| **Authority Source** | Sumber yang mendefinisikan intended behavior (spec, test, interface, dll) — diurutkan berdasarkan priority |
| **Causal Path** | Jalur eksplisit dari kondisi attacker-controlled hingga security consequence |
| **Capability** | Aksi yang bisa dilakukan oleh suatu actor; memiliki required_role dan acquisition_path |
| **Closed-World Benchmark** | Dataset dengan known findings dan validation oracle untuk mengukur recall/precision |
| **CONFIRMED** | Status claim yang telah divalidasi oleh machine-checkable validator evidence contract |
| **Coverage** | Persentase bagian repository yang berhasil dianalisis di tiap dimensi |
| **Dataflow** | Aliran data dari source (input) ke sink (penggunaan) melalui code |
| **Delegatecall Context** | Konteks eksekusi saat `delegatecall` digunakan; msg.sender dan storage milik caller |
| **Disclosure** | Proses mengungkapkan vulnerability ke pihak yang relevan (protocol team, publik) |
| **Economic Exploitability** | Apakah attack menghasilkan keuntungan finansial setelah memperhitungkan biaya |
| **Embargo Period** | Periode waktu sebelum public disclosure untuk memberi waktu fix |
| **Evidence Certainty** | Level keyakinan terhadap suatu bukti: UNKNOWN, OBSERVED, DERIVED, VALIDATED |
| **Fact** | Unit informasi atomic yang di-observasi langsung dari source code, dengan source location |
| **Finding** | Vulnerability yang telah CONFIRMED + REVIEWED, siap untuk disclosure |
| **Fork Test** | Validator test yang menggunakan state on-chain nyata via RPC endpoint |
| **Hypothesis** | Observasi awal tentang potential security issue; belum memiliki causal path lengkap |
| **INCONCLUSIVE** | Status claim di mana validator tidak dapat menentukan valid atau tidak |
| **Inference Rule** | Aturan eksplisit dengan premises dan conditions yang menghasilkan conclusion |
| **Intended Behavior** | Apa yang protocol bermaksud untuk lakukan, bukan apa yang code sebenarnya lakukan |
| **Invariant** | Property yang harus selalu benar sepanjang lifetime contract |
| **MEV (Maximal Extractable Value)** | Nilai yang bisa diekstrak melalui manipulasi ordering transaksi |
| **Open-World Benchmark** | Repository real yang dievaluasi tanpa expected findings, dinilai independent reviewer |
| **Orphan Claim** | Claim yang tidak memiliki traceable provenance ke source code |
| **Protocol Model** | Representasi terstruktur dari code: contracts, functions, storage, call graph, dll |
| **Provenance** | Jejak lengkap dari source code → facts → inference → attack → validation → finding |
| **Prompt Injection** | Teknik di mana source code berisi instruksi untuk memanipulasi behavior LLM |
| **Reachability** | Kemampuan untuk mencapai suatu state atau eksekusi suatu path dalam kondisi yang dimodelkan |
| **Recon** | Tahap awal ekstraksi informasi dari repository; tidak menyimpulkan vulnerability |
| **REJECTED** | Status claim yang terbukti tidak valid oleh validator |
| **Semantic Certainty** | Level keyakinan terhadap interpretasi makna code: UNKNOWN, POSSIBLE, INFERRED, SUPPORTED |
| **Semantic Conflict** | Situasi di mana dua authority sources memberikan definisi intended behavior yang berbeda |
| **Severity** | Tingkat keparahan finding: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| **Sink** | Titik di code di mana operasi security-sensitive terjadi (transfer, call, storage write, dll) |
| **SLOC** | Source Lines of Code — metrik ukuran codebase |
| **Technical Exploitability** | Apakah attack secara teknis mungkin, terlepas dari apakah menguntungkan atau tidak |
| **Trust Classification** | Label yang diberikan kepada actor berdasarkan asumsi privilege dan intent |
| **Validator** | Komponen yang menguji attack claim secara independen menggunakan machine-checkable methods |
| **Validator Evidence Contract** | Kumpulan data wajib yang harus disimpan untuk setiap CONFIRMED finding |

---

*PRD v2.0 — Agent Finder | Schema v1.0 artifacts | Roadmap target Phase 6 exit: Q2 2027*
