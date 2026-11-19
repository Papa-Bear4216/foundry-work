# Foundry roadmap

Status: draft for build, 2026-11-19. This file turns the specifications into work packages
a builder can pick up one at a time. Nothing here is built yet.

## How to use this file

1. Pick the lowest-numbered package whose "Needs" column is satisfied and that nobody has claimed.
2. Read the sections named in "Spec". They are the requirement; this file only orders the work.
3. A package is done when every line of its "Done when" cell is true **and** the gates
   listed for its phase pass in CI on Windows and Linux.
4. If a requirement cannot be met as written, stop and record a decision in
   [DECISIONS.md](DECISIONS.md) before writing code against a different requirement.
5. From package Z-8 on, record what you verified with `facts add` and start each session
   from the digest.

Sizes are planning estimates for one builder working alone, not commitments:
**S** = up to half a day, **M** = one to two days, **L** = three to five days.

Items marked **Owner** need the project owner and cannot be completed by a builder alone.

## Phase overview

| Phase | Outcome | Packages | Rough total |
|---|---|---|---|
| 0. Step Zero | A facts ledger agents use to cite or abstain, with both proof deliverables green | Z-0 to Z-8 | 2 to 3 weeks |
| 1. Thin slice | Synthetic Takeout archive in, encrypted vault, search out, from the command line | V-0 to V-8 | 4 to 6 weeks |
| 2. Product v1 (Tier 0) | Wizard, profiles and erasure, offline second copy, restore drill, installers, first public release | P-1 to P-8 | 6 to 8 weeks |
| 3. Growth (Data & Ask) | More sources, places, semantic search, cited answers, relationship map, always-on second device | X-1 to X-7 | Open-ended |
| 4. Remember Live Stack (Opt-in Tier 1+) | Opt-in `exocortexd`, event bus, local memory, write-time recap cards, encrypted channel vaults, `llama.cpp` role runner, Tauri desktop shell, Android companion | E-1 to E-6 | 6 to 8 weeks |
| 5. Act — World Model & Earned Autonomy (Opt-in Tier 1–2) | Living Life Graph (`GraphStore`), Cognitive Mode Gate, Pre-Cognitive Wake, Active Inference, 14-day shadow calibration (`SHADOW=1` default), WYSIWYS biometric approvals, Agent Mesh & Advisory Triad, Morphogenetic self-healing ladder | W-1 to W-5 | 6 to 8 weeks |
| 6. Adoption | The private predecessor consumes Foundry as a package | Planned separately | Not public |

Phases 0 and 1 may overlap once Z-2 is merged: V-0 and V-1 do not depend on the ledger.

## Phase 0: Step Zero (facts ledger)

Spec for the whole phase: [STEP_ZERO_FACTS_LEDGER.md](STEP_ZERO_FACTS_LEDGER.md).

| Id | Package | Spec | Needs | Done when | Size |
|---|---|---|---|---|---|
| Z-0 | Repository skeleton and CI | Architecture 2, 15 | Nothing | Workspace with `packages/facts-ledger` builds to plain JavaScript. CI runs on Windows and Linux with the pinned Node 24. The identifier scan, the licence check and the "no runtime dependency" check run on every push. `docs/DEPENDENCIES.md` exists. | S |
| Z-1 | Measure first | Step Zero 10.4, 13 | Z-0 | A committed report gives peak memory and time for cold start, append, worst-case rebuild, query and digest on a 10,000-block fixture log, on both platforms, with the pinned runtime, measured from inside and from outside the process. FTS5 availability in `node:sqlite` is confirmed on both. If 96 MiB cannot hold, a decision is recorded before Z-2 starts. | S |
| Z-2 | Log format, writer, lock, reader | Step Zero 3.1, 9 | Z-1 | Blocks written by this tool are read by the existing Python tool and the reverse. The lock is held across parent lookup and append. The last-byte check works. The two-writer interop test passes with no lost block and no shared parent. Bad lines are skipped, counted and reported. | M |
| Z-3 | Index and lookup | Step Zero 4, 5 | Z-2 | `facts rebuild` and incremental update give the same index. Lookup stages return `match`, `related` and `not_found` as specified. Output marks ledger content as data. All ordering is bytewise. | M |
| Z-4 | Facts, evidence, predicates, freshness | Step Zero 3.2 to 3.5, 6 | Z-3 | `facts add` rejects a fact without evidence and a `secret` fact. Checked facts are generated from predicates. Command evidence runs only the fixed templates, by absolute path, with the read-only git settings, never through a shell. `facts verify` reports `supported`, `moved`, `stale`, `unverifiable`, `expired`. Free text is never printed as `VERIFIED`. | L |
| Z-5 | Digest | Step Zero 7 | Z-4 | `facts digest` writes a complete file of at most 6,000 bytes in the specified order. The offline calibration script reports the token count for the reference tokenizers and blocks a release above 2,000. | S |
| Z-6 | Deterministic gates | Step Zero 10.1, 10.2, 10.4 | Z-5 | The 50-case gate matches its committed expected output exactly. The citation checker passes its 20 fixture answers. Memory, time, digest size and dependency checks fail the build when broken. | M |
| Z-7 | Model harness and usage report | Step Zero 10.3, 8 | Z-6 | `facts eval --model-cmd` runs all cases against any local command, appends the result as a block, and `facts usage` reports tokens per agent and task. | S |
| Z-8 | Adoption | Step Zero 11, 9 item 5 | Z-6 | The agent rules text is in the project's agent instruction files. The first real digest exists for this repository. The matching lock and last-byte change is proposed as a separate change to the existing Python tool. | S |

Phase exit: both deliverables in Step Zero section 10 are green in CI on both platforms,
and one harness run against at least one model is committed.

## Phase 1: thin slice

Spec for the whole phase: [ARCHITECTURE.md](ARCHITECTURE.md), plus
[PRODUCT_SPEC.md](PRODUCT_SPEC.md) section 6.1.

| Id | Package | Spec | Needs | Done when | Size |
|---|---|---|---|---|---|
| V-0 | Measure first | Architecture 5.2, 5.5, 9, 13 | Z-0 | A committed report covers, on both platforms with the pinned runtime: peak memory and time of the passphrase KDF at the specified parameters; streaming encryption throughput; whether the SQLCipher addon builds in CI, loads, and has FTS5 and R-tree; whether a clean Windows 11 image with Smart App Control on loads the unsigned addon. Ceilings in Architecture section 9 are confirmed or changed by recorded decision. | M |
| V-1 | Format freeze | Architecture 4.2, 4.5, 5.4, 4.7 | V-0 | Record, manifest and keyring formats are frozen as version 1 with committed test vectors. A Python reference reader under 200 lines decrypts every vector. "Draft v0" is removed from the architecture document. | M |
| V-2 | Keys | Architecture 5.1 to 5.4 | V-1 | Keyring create, unlock by passphrase, unlock by recovery key, passphrase change, `rekey --all`. KDF parameters outside the bounds are rejected before the KDF runs. A wrap moved to another slot or vault fails. Secrets are refused on the command line and in the environment. | M |
| V-3 | Vault writer and reader | Architecture 4.1 to 4.6 | V-2 | Append, close, signed manifest, chain, `vault verify` without any secret, `vault verify --deep`. The tamper suite and the crash suite pass. | L |
| V-4 | Index | Architecture 5.5, 6 | V-3 | `SqlDriver` port with the `sqlcipher` and `plain` adapters. The cipher configuration is pinned in code. Fail-closed test, wrong-key test, modified-page test, crash-with-log test and planted-marker test pass on the shipped binary. Two-pass rebuild equals the incremental index. | L |
| V-5 | Archive reader and three importers | Architecture 7; Product 6.1, 6.3 | V-3 | Zip with zip64 and multi-part archives read as streams. Contacts, calendar and mail importers with scripted synthetic fixtures. Re-import adds nothing. A 1 GiB synthetic mail file imports inside the memory ceiling. | L |
| V-6 | Key cache spike | Architecture 5.6 | V-2 | A written finding says whether `os-session` and `os-protected` can be done without a daemon and without a new dependency on each platform. `none` works regardless. No commitment to ship either. | S |
| V-7 | Command line | Architecture 1, 9, 15 | V-4, V-5 | `foundry init`, `import`, `search`, `vault verify`, `index rebuild` work end to end. The offline test shows zero packets during import and search. Every command stays under its ceiling. | M |
| V-8 | Early package for testers | Architecture 13 | V-7 | An npm package installs on an existing Node 24 on both platforms, with addon binaries built by this project's CI and provenance attached. Marked pre-release. | S |

Phase exit: on a Tier 0 machine, a synthetic 1 GiB Takeout archive goes from `foundry init`
to a search result using only the command line, and every gate in Architecture section 15
that applies to these packages is green.

## Phase 2: product v1

| Id | Package | Spec | Needs | Done when | Size |
|---|---|---|---|---|---|
| P-1 | Profiles, collections, sensitivity, consent | Product 9; Architecture 5.4 | V-7 | Generic profiles only. Collections default to profile, source and year. Shipped sensitivity rules are generic. Consent notes are events. `child`-tier data is kept out of model prompts unless switched on per collection. | M |
| P-2 | Erasure | Architecture 5.7, 6.2 | P-1 | Erase profile, collection and item. The ordered steps resume after interruption. The three states are reported separately. Tombstones block re-import. The restore rule holds. The register of keyring copies lists what still holds an old key. Erasure and withdrawal-on-restore gates pass. | L |
| P-3 | Offline second copy | Architecture 8.1, 8.2; Product 8 | V-7 | Vault session steps 1 to 9. FAT32 refused. Rollback and tamper warnings. Printed anchor as text and QR. Scheduler reminders on both platforms. `vault export-iso`. | L |
| P-4 | Restore drill | Architecture 8.3 | P-2, P-3 | The drill restores onto a clean machine from the drive plus passphrase or recovery key. All six failure cases are caught. No plaintext is written to a temp directory. | M |
| P-5 | Wizard | Product 5; Architecture 10 | P-1, P-3 | Six steps, each resumable, each with a command-line equivalent. Loopback only, random port, one-time token. The server exits when the wizard closes. Hardware check picks the tier and shows why. | L |
| P-6 | Installers | Architecture 13; Product 10 | V-8 | Directory bundle with the official unmodified runtime binary. `install.ps1` and `install.sh` verify the published hash and install per user. Each advertised platform is tested on a clean image. Release assets carry build provenance. A WinGet manifest is prepared. | M |
| P-7 | Release hygiene | Architecture 15; Product 11 | P-4, P-5, P-6 | The identifier scan passes on the tree and on every release archive. The limits text from Architecture 5.7, 8.2 and 10 is in the user documentation. Every success measure in Product section 11 is measured and recorded. | S |
| P-8 | **Owner:** publish | Decisions, open questions | P-7 | Product name and package scope chosen. Public repository created with a single first commit made from a clean export of the tree, with no earlier history. Decision recorded on code signing. Version 0.1.0 tagged. | S |

Phase exit: every success measure in Product section 11 is met and recorded.

## Phase 3: growth

Order is by value per unit of work and can change. Each package brings its own synthetic
fixtures and its own measured memory ceiling.

| Id | Package | Spec | Needs |
|---|---|---|---|
| X-1 | Location history, both export formats, and the places table | Architecture 6.1, 7 | Phase 2 |
| X-2 | More importers: photo metadata, activity history, chat exports, call and message exports, health exports | Product 6.2 | Phase 2 |
| X-3 | Model catalog, on-demand embeddings, semantic search | Architecture 6.3, 12 | Phase 2 |
| X-4 | Ask with citations; answer verifier at Tier 2 | Product 7; Architecture 12 | X-3 |
| X-5 | Relationship map with recorded positions | Architecture 11 | X-1 or X-2 |
| X-6 | Always-on second device: home network first, then private overlay network | Architecture 8.4; Product 8 | Phase 2 |
| X-7 | Reach: `.deb`, macOS, Linux arm64, a compact command that starts a new chain epoch | Architecture 4.5, 13 | Phase 2 |

## Phase 4: Remember Live Stack (Opt-in Tier 1+, D-20, D-21)

| Id | Package | Spec | Needs | Done when | Size |
|---|---|---|---|---|---|
| E-1 | Core event bus & local memory | Decisions D-20, D-21; Extraction plan | V-7 | `packages/core` and `packages/memory` pass the scrub gate, store events cleanly without personal identifiers, and pass all unit tests under CI. | M |
| E-2 | `exocortexd` gateway, enrollment & attestation | Decisions D-20, D-21; Architecture 5, 8.4 | V-7, E-1 | `apps/daemon` starts without mandatory external home-proxy lock-in, enforces JWT device enrollment and attestation checks, appends hash-chained events, and stops cleanly when disabled. | L |
| E-3 | Recap cards, encrypted channels & autonomic archival | Decisions D-20, D-21 | V-4, E-1, E-2 | Write-time session recap cards pass anti-empty-card, anti-junk-tag, and anti-hallucinated-next-step tests; Obsidian/Notion/Gmail `ChannelVault` adapters encrypt content via `FVR1`/SQLCipher and shred keys cleanly on disconnect. | L |
| E-4 | Local `llama.cpp` role runner | Decisions D-2, D-6, D-21 | E-2 | Triage, embedding, and vision local role servers launch only on opt-in, enforce explicit memory/concurrency bounds, log calls to `model_calls`, and tear down cleanly on exit. | M |
| E-5 | Tauri desktop shell | Decisions D-20, D-21 | E-2, E-3 | `apps/desktop` builds with generic branding, discovers local `exocortexd` on opt-in, and renders the local dashboard without leaving Tier 0 users needing desktop runtime dependencies. | M |
| E-6 | Android companion (`apps/mobile`) | Decisions D-20, D-21 | E-2 | Capacitor Android companion builds with generic IDs/strings, completes QR pairing, verifies Android Keystore `BiometricPrompt` WYSIWYS signatures, and passes the mobile test suite with zero hardcoded URLs or real device IDs. | L |

Phase exit: opt-in Remember live stack builds cleanly, runs synthetic end-to-end capture -> recap -> channel vault -> desktop/mobile companion tests, and keeps Tier 0 zero-daemon when disabled.

## Phase 5: Act — World Model, Shadow Calibration & Earned Autonomy (Opt-in Tier 1–2, D-20, D-21)

| Id | Package | Spec | Needs | Done when | Size |
|---|---|---|---|---|---|
| W-1 | Living Life Graph (`GraphStore`) | Decisions D-20, A-11; Extraction plan | E-2, E-3 | `packages/world-model` rebuilds deterministic generic entity/edge graphs with spreading/decaying activation from the event log in SQLite/in-process store (no Neo4j). | M |
| W-2 | Cognitive Mode Gate, Dynamic Wake & Active Inference | Decisions D-20, D-21 | W-1 | Five-state Cognitive Mode Gate, `p20` Pre-Cognitive Wake calibration, discrete A/B/C/D Active Inference scoring, and next-action prediction logging pass deterministic synthetic evaluation against a frequency baseline. | L |
| W-3 | Shadow calibration (`SHADOW=1`) & attested actuation | Decisions D-20, D-21 | E-6, W-2 | `SHADOW=1` blocks live execution by default, `wanted`/`not_wanted` tap labels and `InferredOutcomeScheduler` measure `Precision@surface >= 0.90` over 14 days / 50+ labels before any tier gate opens, and single-use biometric WYSIWYS tickets fail closed on replay/mismatch. | L |
| W-4 | Agent Mesh & Advisory Triad | Decisions D-20, D-21 | W-3 | `packages/mesh` and `packages/triad` enforce per-action default-deny capability allowlists on `/network/delegate`, strip secrets/MCP bloat on $0 subscription CLI bridges, and contain zero personal config paths. | L |
| W-5 | Morphogenetic self-healing patch ladder | Decisions D-20, D-21 | W-4 | Disabled by default (`TRIAD_MORPHOGENETIC=0`), runs repairs only inside no-network sandboxed worktrees within strict line/file caps, excludes safety/tests/CI/engine code permanently, and requires biometric patch approval before any earned auto-merge progression. | M |

Phase exit: opt-in Act stack stays fail-closed under `SHADOW=1` by default, passes biometric WYSIWYS replay/deny gates, passes identifier/license scans across all new workspaces, and verifies Morphogenetic exclusions.

## Phase 6: Adoption by the predecessor

The private project that Foundry was extracted from replaces its own storage code with
Foundry packages. That migration is planned outside this repository. The only requirement
it places on Foundry is the one in Architecture section 14: Foundry is a clean extraction
with its own formats, and nothing in it depends on the predecessor.

## What can run in parallel

| After | These can proceed side by side |
|---|---|
| Z-0 | Z-1 and V-0 |
| Z-2 | Z-3 onward, and V-1 |
| V-3 | V-4 and V-5; V-6 any time after V-2 |
| V-7 | P-1, P-3 and V-8 |
| P-1 | P-2 and P-5 |

## Standing rules for every package

1. No fixture is copied from a real account. Fixtures come from scripts in the repository.
2. No personal name, hostname, home path, token or key enters the tree. The scan is a gate.
3. A new runtime dependency needs a line in `docs/DEPENDENCIES.md` and a recorded decision.
4. A memory ceiling is raised only by a recorded decision, never by editing the number.
5. No package adds a process that stays running after its command ends.
