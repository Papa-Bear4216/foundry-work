# Build assignments (internal)

Status: 2026-11-19. **This directory is not part of the public repository** (see
[EXTRACTION_PLAN.md](EXTRACTION_PLAN.md), section 7). This file assigns every package in
[ROADMAP.md](../ROADMAP.md) to a builder. It is written for the orchestration agent that
dispatches the work. The planner wrote it and does not implement.

The roadmap orders the work and states "Done when". The specifications state the
requirement. This file adds only: who writes, who reviews, where they may write, in what
order, and what the owner must supply. Where this file and a specification disagree, the
specification wins and the disagreement is recorded in [DECISIONS.md](../DECISIONS.md).

## 1. Start here

Z-0 can be written now, but no package can be called done until owner item O-1
(section 4) exists: every package needs CI on Windows and Linux and the repository has no
remote.

1. Ask the owner for O-1 and O-2. Start O-3 in parallel.
2. Dispatch **Z-0 to Codex** using the brief in section 8.
3. When Z-0 is merged, dispatch **Z-1 to Codex** and **V-0 to Antigravity** side by side.
4. From then on, follow the two queues in section 6.

## 2. Roster

Checked on 2026-11-19 by asking each provider. Re-check at every dispatch; do not trust
this table after that date.

| Agent | Role here | State on 2026-11-19 |
|---|---|---|
| Codex CLI | Builder | Installed, signed in on a subscription. Configured model `gpt-6.1-sol`; the provider's default is `gpt-6.2-sol`. |
| Antigravity CLI (`agy`) | Builder | Installed, signed in (it lists models). Offers Gemini 4 and Gemini 3.8 Flash families and also Claude models. An earlier Antigravity session on this project stalled; see the reassignment rule in section 3. |
| Claude | Planner and reviewer. **Not a builder.** | Installed, signed in on a subscription. |
| Grok CLI | None | Not installed. |
| Cursor agent | None | Executable not found. The mesh policy names it as root orchestrator; it cannot be used until installed. |
| Mesh workers | None | None registered. |
| Owner | Owner items only | See section 4. |

Model names written in older policy text and instruction files do not match what the
providers report. Use what the provider reports at dispatch and record the model in the
ledger block.

When Antigravity writes a package, run it on a Gemini model, so that a Claude review of
that package is a review by a different provider.

## 3. Assignment rules

1. **One writer per package.** One branch and one worktree per package. Nobody else
   writes in it.
2. **One active package per builder.** Two builders means at most two packages in flight.
3. **The reviewer is never the writer's provider.** Review 1 is always the other builder.
   A planner review by Claude is added for the packages marked in section 5: formats,
   keys, locks, command execution, erasure, the chain and release hygiene.
4. **Reviews are blind.** The reviewer gets the diff, the specification sections and the
   "Done when" lines. It does not get the writer's own report.
5. **Split by kind of work.** Codex: formats, cryptography, locks, the vault and the index.
   Antigravity: measurement, the ledger above the storage layer, importers, the wizard,
   packaging and installers. The split also keeps the roadmap's parallel pairs on
   different builders.
6. **Reassignment.** If a builder is not signed in, out of quota, fails the model bar
   (rule 7), or makes no verifiable progress on a package in two consecutive sessions,
   give the package to the other builder. Record a ledger block that says why. The review
   then comes from Claude, and the package waits if Claude is unavailable.
7. **Model bar (D-15).** As soon as Z-7 is merged, run `facts eval --model-cmd` twice for
   each builder model. A model with any unsupported claim in either run gets no new
   package. Until Z-7 exists there is no harness and work proceeds without the bar. If no
   builder model passes, stop and ask the owner.
8. **Cost.** Only subscription command-line tools. No metered API. If any step would
   incur a charge, stop and ask the owner.

## 4. Owner items

A builder cannot complete these. Ask early; each one blocks the packages named.

| Id | What the owner supplies | Blocks |
|---|---|---|
| O-1 | A **private** working repository on the code host, set as this repository's remote, with CI enabled. It is not the public repository: that is created at P-8 from a clean export. Before the first push, check the current free CI allowance for private repositories and how Windows minutes are counted. | Z-0 "done", so everything |
| O-2 | A clean Windows 11 install with Smart App Control switched on, which a builder can run a test on (a local virtual machine is enough). | P-6 (D-22: no longer blocks V-0) |
| O-3 | The application for free open-source code signing (D-16). Check the programme's terms first: if it requires a public repository, the application waits for P-8 and that is recorded as a decision. | P-8 |
| O-4 | The private pattern scan (names, hostnames, account identifiers), run locally with the Markdown allowlist removed, against the tree and every archive. The pattern file stays outside every repository. | V-8 before anyone outside receives a package; P-7 |
| O-5 | Approval of the change Z-8 proposes to the existing Python log tool. That tool lives in another repository. | Done 2026-11-21 (autonomous-triad #8). R-7 closed. |
| O-6 | A ruling on conflict K-2 (section 9). | V-8 |
| O-7 | P-8 in full: name, package scope, hosting organisation, the public repository, the single first commit, the 0.1.0 tag. | Release |

## 5. Assignments

"Review" lists who reviews besides the CI gates. "Writes in" is the write boundary; shared
files are covered in section 7. Needs, specification sections and "Done when" are in
[ROADMAP.md](../ROADMAP.md) and are not repeated here.

### Phase 0: Step Zero

| Id | Writer | Review | Writes in | Notes |
|---|---|---|---|---|
| Z-0 | Codex | Antigravity | Workspace root, CI workflow, check scripts, `packages/facts-ledger` skeleton, `docs/DEPENDENCIES.md` | Needs O-1. Sets conventions every later package follows. |
| Z-1 | Codex | Antigravity | `packages/facts-ledger` (fixture generator, measurement scripts), one report under `docs/` | Describe machines by class, never by hostname. If 96 MiB cannot hold, record a decision before Z-2. |
| Z-2 | Codex | Antigravity, Claude | `packages/facts-ledger` | The lock and the two-language interop test. Reads the existing Python tool; does not edit it. |
| Z-3 | Antigravity | Codex | `packages/facts-ledger` | Starts when Z-2 is merged. |
| Z-4 | Antigravity | Codex, Claude | `packages/facts-ledger` | Command evidence is the security-critical part: fixed templates only, never stored text, never a shell. |
| Z-5 | Antigravity | Codex | `packages/facts-ledger` | |
| Z-6 | Antigravity | Codex | `packages/facts-ledger`, CI workflow | Expected outputs are committed and matched exactly. |
| Z-7 | Antigravity | Codex | `packages/facts-ledger` | After merge the orchestrator runs rule 7 for both builder models and commits the results. |
| Z-8 | Codex (D-23; was Antigravity) | Antigravity, Claude | Agent instruction files at the root, the first digest; a proposed change in the other repository, **not merged** | Needs a claim in that other project too. O-5 approves the proposal. |

### Phase 1: thin slice

| Id | Writer | Review | Writes in | Notes |
|---|---|---|---|---|
| V-0 | Antigravity | Codex | Throwaway measurement scripts outside `packages/facts-ledger`, its own CI job, one report under `docs/` | Needs O-2 for the Smart App Control line. Adds the SQLCipher addon: line in `docs/DEPENDENCIES.md` (D-10 already decides it). |
| V-1 | Codex | Antigravity, Claude | `packages/vault`, the Python reference reader, `docs/ARCHITECTURE.md` (remove "Draft v0") | Highest reversal cost in the plan (A-4). Do not start before V-0's report is merged. |
| V-2 | Codex | Antigravity, Claude | `packages/vault` | |
| V-3 | Codex | Antigravity, Claude | `packages/vault` | Tamper suite and crash suite. |
| V-4 | Codex | Antigravity, Claude | `packages/index` | Ports the generic tables through the scrub gate (Extraction plan, section 4). |
| V-5 | Antigravity | Codex | `packages/importers` | Ports the contacts parser through the scrub gate. Calendar and mail are written new. Fixtures come from scripts only. |
| V-6 | Antigravity | Codex | A written finding under `docs/`; spike code stays on its branch | Does not edit `packages/vault`. A code change it calls for goes to Codex by recorded decision. |
| V-7 | Codex | Antigravity | `packages/cli` | Offline test: zero packets. |
| V-8 | Antigravity | Codex | Package manifest fields, release workflow | Blocked by K-2 until O-6. Needs O-4 before a package leaves the machine. |

### Phase 2: product v1

| Id | Writer | Review | Writes in | Notes |
|---|---|---|---|---|
| P-1 | Antigravity | Codex | `packages/profiles`, its command modules in `packages/cli` | Ports only the generic sensitivity rules through the scrub gate. Codex's review is also its preparation for P-2. |
| P-2 | Codex | Antigravity, Claude | `packages/vault`, `packages/index`, `packages/profiles` | Starts after P-3, because both write in `packages/vault`. |
| P-3 | Codex | Antigravity, Claude | `packages/vault`, scheduler integration, its command modules | |
| P-4 | Codex | Antigravity, Claude | `packages/vault` (drill), CI job | All six failure cases. No plaintext in a temp directory. |
| P-5 | Antigravity | Codex | `packages/wizard` | Loopback only, random port, one-time token, exits on close. |
| P-6 | Antigravity | Codex | Installers, release workflow, WinGet manifest | Needs O-2. Provenance line is subject to K-2. |
| P-7 | Codex | Antigravity, Claude | User documentation, the archive scan, the record of measured success measures | Needs O-4. |
| P-8 | **Owner** | Claude checks the export against the Extraction plan, section 7 | The public repository | O-7. No agent pushes to a public remote. |

### Phase 3: growth

Provisional. Confirm these at the Phase 2 exit: the roster and the order may have changed.

| Id | Writer | Review | Writes in | Notes |
|---|---|---|---|---|
| X-1 | Antigravity | Codex | `packages/importers`, places table in `packages/index` | Ports the location parser through the scrub gate. |
| X-2 | Antigravity | Codex | `packages/importers` | One importer at a time, each with its own fixture script and measured ceiling. Serial with X-1. |
| X-3 | Codex | Antigravity | `packages/index`, model catalog | Starts after X-1's places table is merged, or before X-1 begins. |
| X-4 | Codex | Antigravity, Claude | Ask and verifier | Needs X-3. Question sets are synthetic. |
| X-5 | Antigravity | Codex | Relationship map | Needs X-1 or X-2. The predecessor's map page is not ported. |
| X-6 | Codex | Antigravity, Claude | `packages/vault` (Mode A), pairing | Home network first. |
| X-7 | Antigravity (packaging: `.deb`, macOS, Linux arm64); Codex (the compact command) | Each reviews the other's half; Claude reviews the compact command | Packaging files; `packages/vault` | Two halves, two branches. X-7 is done when both are merged. |

### Phase 4: Remember Live Stack (Opt-in Tier 1+)

| Id | Writer | Review | Writes in | Notes |
|---|---|---|---|---|
| E-1 | Codex | Antigravity | `packages/core`, `packages/memory` | Event bus, pattern analyzer, speculative dry-run cache, local token/vector memory. Scrub gate mandatory. |
| E-2 | Codex | Antigravity, Claude | `apps/daemon` (`exocortexd` core) | Hash-chained event log, device enrollment, JWT auth, attestation, strict local-host default without home-proxy lock-in. |
| E-3 | Antigravity | Codex | `packages/core`, `apps/daemon` | Write-time session recap cards (anti-trust-breaker tests), encrypted `ChannelVault` adapters (Obsidian/Notion/Gmail), autonomic `FVR1`/SQLCipher archival. |
| E-4 | Antigravity | Codex | `apps/daemon` (`llama.cpp` role runner) | Bounded optional local `llama.cpp` role launcher (`triage`, `embed`, `vision`) with explicit opt-in toggle and stop-on-disable. |
| E-5 | Antigravity | Codex | `apps/desktop` | Tauri tray shell, daemon discovery, generic Command Center UI. |
| E-6 | Antigravity | Codex, Claude | `apps/mobile` | Capacitor Android companion: accessibility capture, Recent tab + widget, `AnticipationRing`, QR pairing, Android Keystore `BiometricPrompt` WYSIWYS approval, Ambient Living Graph HUD. Zero real device IDs or hardcoded URLs. |

### Phase 5: Act — World Model, Shadow Calibration & Earned Autonomy (Opt-in Tier 1–2)

| Id | Writer | Review | Writes in | Notes |
|---|---|---|---|---|
| W-1 | Codex | Antigravity | `packages/world-model` | Living Life Graph (`GraphStore`) with spreading/decaying activation and generic replay from event log (no Neo4j). |
| W-2 | Codex | Antigravity, Claude | `packages/world-model` | Cognitive Mode Gate (5 states), Pre-Cognitive Dynamic Wake (`p20` quantile), Active Inference (`A/B/C/D`), next-action prediction log. |
| W-3 | Antigravity | Codex, Claude | `packages/core`, `apps/daemon`, `packages/world-model` | Shadow recorder, `wanted`/`not_wanted` + `InferredOutcomeScheduler`, `Precision@surface >= 0.90` / 14-day / 50-label gate, fail-closed `SHADOW=1` default & single-use attested WYSIWYS actuation. |
| W-4 | Codex | Antigravity, Claude | `packages/mesh`, `packages/triad` | Agent Mesh MCP router, playbooks, swarms, Advisory Triad bridge, capability-scoped `/network/delegate` default-deny allowlist. |
| W-5 | Codex | Antigravity, Claude | `packages/triad`, `packages/mesh` | Morphogenetic self-healing patch ladder (disabled by default; no-network container tests, diff cap, `morpho/<id>` branch -> biometric approval -> earned auto-merge excluding safety/tests/CI/engine). |

Phase 6 (the predecessor adopts Foundry) is not assigned. It needs the owner's approval and
its own plan.

## 6. Dispatch order

Two queues. A package starts when its "Needs" are merged and its builder is free. A
builder waiting on the other queue stays idle; it does not start a package out of order.

| Step | Codex | Antigravity |
|---|---|---|
| 1 | Z-0 | waits |
| 2 | Z-1 | V-0 |
| 3 | Z-2 | V-0 continues |
| 4 | V-1 | Z-3 |
| 5 | V-2 | Z-4 |
| 6 | V-3 | Z-5, Z-6, Z-7, Z-8 |
| 7 | V-4 | V-6, then V-5 |
| 8 | V-7 (after V-4 and V-5 are both merged) | finishes V-5, then reviews |
| 9 | P-3 | V-8, then P-1, then P-6 |
| 10 | P-2 | P-5 |
| 11 | P-4, then P-7 | reviews |
| 12 | Owner: P-8 (public release of Tiers 0–3 foundation) | |
| 13 | Phase 3 (`X-3`, `X-4`, `X-6`) + Phase 4 (`E-1`, `E-2`) | Phase 3 (`X-1`, `X-2`, `X-5`, `X-7`) + Phase 4 (`E-3`, `E-4`, `E-5`, `E-6`) |
| 14 | Phase 5 (`W-1`, `W-2`, `W-4`, `W-5`) | Phase 5 (`W-3`, reviews & integration gates) |

Phase exits are checked by the orchestrator and reviewed by Claude before the next phase's
first package is merged:

- Phase 0: both Step Zero deliverables green in CI on both platforms, one harness run committed.
- Phase 1: the 1 GiB synthetic archive goes from `foundry init` to a search result on a Tier 0 machine.
- Phase 2: every success measure in Product section 11 is measured and recorded.
- Phase 3: multi-source importers, local embeddings/ask/verifier, relational map, and Mode A sync verified with synthetic fixtures.
- Phase 4: opt-in Remember live stack (`exocortexd`, recap cards, encrypted channels, desktop shell, Android companion) builds and passes synthetic end-to-end tests with zero personal identifiers.
- Phase 5: opt-in Act stack stays fail-closed in `SHADOW=1` by default, passes biometric WYSIWYS + capability deny gates, and verifies Morphogenetic ladder safety exclusions.

Sizes in the roadmap add up to roughly 30 working days per queue. They are estimates for
planning, not commitments, and they exclude review time.

## 7. Protocol for every package

1. **Claim.** `python -m triad.claims claim --task "<id> <name>" --touching "<paths>" --project Foundry`,
   run from the orchestrator project. On a conflict, stop and coordinate; do not proceed.
2. **Read first.** `python -m triad.decision_log tail -n 10 --project Foundry`. From Z-8
   on, start from the digest instead and use `facts add` (same log file, superset format).
3. **Branch and worktree.** Branch `pkg/<id>` (for example `pkg/z-2`) from `main`, in its
   own worktree. Remove the worktree and the branch after the merge.
4. **Build to the specification.** If a requirement cannot be met as written, stop and add
   a dated entry to DECISIONS.md first. A builder may change an **A** entry this way. Only
   the owner changes a **D** entry.
5. **Gates.** Type check clean, tests green, the package's "Done when" lines true, the
   phase gates green in CI on Windows and Linux. The orchestrator re-runs the gates; a
   builder's statement that they pass is not evidence.
6. **Review.** Blind, by the reviewers in section 5. Findings are `blocker`, `should fix`
   or `note`. A merge needs zero blockers from every listed reviewer.
7. **Merge.** The orchestrator merges to `main` and pushes to the private remote. No force
   push. No push to any public remote. No automatic third-party review requests.
8. **Record.** One ledger block per package with intent, reasoning, touches, verification,
   model used and commit. The commit message carries `Decision-Ledger: <block-id>`.
   Nothing secret, no personal name and no home path goes into the ledger.
9. **Release the claim.**

Shared files (workspace manifest, lock file, CI workflows, `docs/DEPENDENCIES.md`,
`docs/DECISIONS.md`, and `packages/cli` after V-7): a package adds its own lines, jobs or
command modules and changes nobody else's. The second of two parallel packages to merge
rebases onto the first.

Standing rules from the roadmap apply to every package: synthetic fixtures only; no
personal name, hostname, home path, token or key in the tree; a new runtime dependency
needs a line in `docs/DEPENDENCIES.md` and a recorded decision; a memory ceiling changes
only by recorded decision; no process outlives its command.

Porting from the predecessor is allowed only for the files and at the steps the Extraction
plan names (V-4, V-5, P-1, X-1), file by file through its scrub gate. The predecessor is
read, never edited. The private pattern file is run in place and never copied, quoted or logged.

## 8. Brief to give a builder

Fill the brackets from ROADMAP.md and section 5. Send nothing else.

```
Package: <id> <name>
Requirement: <specification sections from the roadmap's Spec column>. Read them first.
Done when: <the roadmap's "Done when" cell, copied word for word>
Needs (already merged): <ids>
You may write only in: <"Writes in" from section 5>, on branch pkg/<id>.
Rules: the five standing rules in ROADMAP.md; the protocol in
  docs/internal/BUILD_ASSIGNMENTS.md section 7.
If a requirement cannot be met as written: stop, add a dated DECISIONS.md entry, report.
Report back: commits, the commands you ran and their output, each "Done when" line with
  its evidence, any DECISIONS.md entry you added, and anything you could not verify.
```

## 9. Known conflicts and blockers

| Id | Problem | What to do |
|---|---|---|
| K-1 | The repository has no remote, so "CI on Windows and Linux" cannot be true for any package. | O-1. |
| K-2 | V-8 and P-6 ask for a registry package and build provenance before the public repository and the final name exist (D-14 leaves the name open until P-8). As the planner recalls, the package registry refuses provenance from a private source repository and the code host's build attestations for private repositories need a paid plan; **not verified on this date**. | The V-8 writer verifies both first. If true, the planner recommends: V-8 delivers a CI-built package tarball handed to testers directly, and provenance attaches at the first public release. This changes "Done when" for V-8 and P-6 and touches D-17, so the owner rules (O-6) and the ruling is recorded before V-8 is built. |
| K-3 | CI cost. The gates generate large fixtures (a 10,000-block log, a 1 GiB mail file) on two platforms, and Windows minutes may count more than once against a free allowance. | Measure minutes used after Z-1 and V-0. If the free allowance would be exceeded, stop and ask the owner. Moving a gate off "every push" needs a recorded decision. |
| K-4 | The Smart App Control test needs a machine no CI runner provides. | O-2. D-22 moves this test to P-6; V-0 merges without it. |
| K-5 | Z-8 proposes a change in another repository. | Deliver it as an unmerged branch or patch there, with a claim in that project. O-5. |
| K-6 | Only two builders exist. Grok and Cursor are absent, so every review that is not from the other builder comes from Claude. | Rule 6. If the owner installs another agent, add it as a reviewer first and as a builder only after it passes rule 7. |
| K-7 | The mesh policy requires a plan to have an approving review before execution. | If the work runs through the mesh, register this file as the plan and get that review from a provider other than Claude, since Claude wrote it. |

## 10. Change log

| Date | Entry |
|---|---|
| 2026-11-19 | First version. Every roadmap package assigned. Nothing dispatched, nothing built. |
| 2026-11-19 | Expanded for D-20 and D-21: added Phase 4 (`E-1`..`E-6`) and Phase 5 (`W-1`..`W-5`) full public Sovereign Exocortex assignments and phase exits; renumbered Predecessor Adoption to Phase 6. |
