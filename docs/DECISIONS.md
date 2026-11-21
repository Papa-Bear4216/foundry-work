# Foundry decisions

Status: 2026-11-19. This file records what is settled, what the planner assumed, what is
still open, and what could go wrong. The other documents refer to entries here by id.

| Prefix | Meaning | Who can change it |
|---|---|---|
| D | Decided by the project owner | The owner |
| A | Assumed by the planner so the specification could be finished | A builder, by adding a dated entry here with the reason |
| Q | Open question for the owner | The owner |
| R | Risk | Anyone may add; the owner accepts or acts |

To change anything: add a new dated entry that names the entry it replaces. Do not edit
old entries except to mark them "replaced by".

## 1. Decided

| Id | Date | Decision |
|---|---|---|
| D-1 | 2026-11-18 | Foundry is a public, open-source product that anyone can install: a setup wizard, an encrypted personal databank, and a guided Google Takeout import. |
| D-2 | 2026-11-18 | Incremental cost to a user is $0. No required paid service, account or subscription. |
| D-3 | 2026-11-18 | No personal identifiers and no real-life sample data in the repository. |
| D-4 | 2026-11-18 | Step Zero, the verified facts ledger, is built first. Its two proof deliverables are a test set of about 50 questions with a pass or fail number, and the token budget as a hard check. |
| D-5 | 2026-11-19 | Platforms for v1: Windows and Linux. macOS deferred. |
| D-6 | 2026-11-19 | Hardware tiers. Tier 0: 4 GiB RAM, vault and full-text search only. Tier 1: 8 GiB and 4 cores, adds embeddings and a small local model (2 to 4 billion parameters, 4-bit). Tier 2: 16 GiB or a GPU, adds a larger model and an answer verifier. |
| D-7 | 2026-11-19 | The second copy is a setting with two modes. Mode B, an offline sealed drive, is the default and ships in v1. Mode A, an always-on device, is deferred. |
| D-8 | 2026-11-19 | Mode B cadence: weekly by default, with daily, monthly and manual as options. Segment soft cap 512 MiB. A persistent banner appears after 14 days without a seal. |
| D-9 | 2026-11-19 | Mode B hardware, in order of support: a USB drive with a physical write-protect switch or a USB write-blocker; optionally write-once optical media (BD-R or M-DISC) plus a printable code that records the chain head. |
| D-10 | 2026-11-19 | The working index is encrypted with SQLCipher through `better-sqlite3-multiple-ciphers` (option A). The built-in `node:sqlite` with an operating-system disk-encryption check (option B) is allowed only as an explicit opt-in. |
| D-11 | 2026-11-19 | Mode A, when built, is split. A1 is home network only. A2 is remote and requires Tailscale, or user-managed WireGuard or Headscale. The wizard blocks raw port-forwarding. |
| D-12 | 2026-11-19 | Answers Q-0, confirms A-21. Foundry is a new repository under the MIT licence, extracted from a private project and not a fork of it. Public history starts with a single commit. Profiles are generic. |
| D-13 | 2026-11-19 | Answers Q-1, confirms A-1. Step Zero is a package inside this repository. It is split out only if another project needs it without Foundry. |
| D-14 | 2026-11-19 | Answers Q-2 in part. "Foundry" stays the working name. Name conflicts are checked on the package registry and the code host before P-8. The final name, package scope and hosting organisation are still the owner's to choose at P-8. |
| D-15 | 2026-11-19 | Answers Q-3. The starting bar for a model is 0 unsupported claims of 50 on two consecutive runs. Revisit after the first three harness runs. |
| D-16 | 2026-11-19 | Answers Q-4. Apply for free open-source code signing early. Ship unsigned with clear instructions meanwhile. Do not pay for a certificate. |
| D-17 | 2026-11-19 | Answers Q-5. The v1 goal stays a bundle an ordinary person can install. The npm package ships earlier (V-8) for testers. |
| D-18 | 2026-11-19 | Answers Q-6, confirms A-9. The keyring goes on write-once media only by explicit opt-in, with a warning. |
| D-19 | 2026-11-19 | Resolves O-3 (refines D-16). Checked free open-source Windows code signing programmes: SignPath Foundation is the only $0 option (Certum Open Source and Azure Artifact Signing are paid) and requires a public repository and existing functional releases. The code-signing application waits for P-8; builds ship unsigned with published SHA-256 hashes and clear user instructions meanwhile. |
| D-20 | 2026-11-19 | Expands D-1: Foundry is the public, MIT-licensed, zero-personal-info distribution of the full Sovereign Exocortex, built by layered expansion on top of Step Zero (`packages/facts-ledger`) and the portable `FVR1`/SQLCipher vault (Phases 0–3). Adds Phase 4 (Remember Live Stack: `E-1`..`E-6`) and Phase 5 (Act — World Model, Shadow Calibration & Earned Autonomy: `W-1`..`W-5`), moving predecessor adoption to Phase 6. All code ported from the private predecessor passes the scrub gate; personal identifiers, household configurations, real fixtures, and unrelated standalone apps stay excluded. |
| D-21 | 2026-11-19 | Updates D-6 and replaces A-19/PRODUCT_SPEC section 12 blanket exclusions with progressive tiers. Tier 0 remains the lightweight CLI, encrypted vault, and loopback first-run wizard with zero resident daemons. Tier 1–2 users may opt into the full Exocortex stack: `exocortexd` host daemon, local `llama.cpp` role servers, Tauri desktop shell, Capacitor Android companion with QR pairing and Keystore/BiometricPrompt WYSIWYS approvals, Living World Model, Cognitive Mode Gate, Active Inference, Shadow-mode calibration (`SHADOW=1` default), Agent Mesh, Advisory Triad, and the Morphogenetic self-healing patch ladder. |
| D-22 | 2026-11-21 | Narrows O-2 and K-4. The clean Windows 11 Smart App Control test no longer blocks V-0: V-0 merges with every other line done and its Smart App Control line marked "moved to P-6". P-6 cannot be done until that test passes on a clean image (the installer is what users run, so that is where the test matters). V-1 may start once V-0 is merged. |
| D-23 | 2026-11-21 | Z-8 writer changes from Antigravity to Codex (owner). Antigravity is on Z-7 and Codex had nothing to start. Review: Antigravity, plus a Claude planner review because Z-8 proposes a lock change in the other repository. Owner-approved exception to assignment rule 2: Codex runs V-1 and Z-8 at the same time, in separate worktrees with no shared write paths. |

D-12 to D-18 were given as one reply accepting every planner recommendation in section 3.

## 2. Planner assumptions

Reversal cost: **low** = a few files before any data exists; **medium** = a format or
interface other packages build on; **high** = needs a migration of users' vaults.

| Id | Assumption | Why | Reversal cost |
|---|---|---|---|
| A-1 | Step Zero lives in this repository as `packages/facts-ledger`, publishable on its own, with no dependency on any other package here. | One repository to scan, test and release. The package boundary keeps the option of moving it out. | Low |
| A-2 | Runtime is Node.js 24 LTS or newer, TypeScript, ES modules. The vault and the facts ledger have zero runtime npm dependencies. | Built-in SQLite, crypto and test runner remove most dependencies. | Medium |
| A-3 | v1 ships a directory bundle around the official, unmodified runtime binary, plus an npm package for people who already have Node. No single-file executable. No MSIX. | A native addon cannot load from inside a single file; injecting code into the runtime breaks its signature; MSIX requires a paid signature. | Low |
| A-4 | The vault record format (`FVR1`) is new. It is not byte-compatible with the predecessor's blob format. | It needs a key id for erasure, a binding to the vault, and its own derivation labels. | High after V-1 freezes it |
| A-5 | Erasure works by destroying keys. Keys are random per profile and per collection, never per item. Collections default to profile, source and calendar year. | Random keys are the only kind that can be destroyed. Per-item keys need a transactional key store. | High |
| A-6 | The passphrase KDF is scrypt (N = 2^17, r = 8, p = 1) with bounds checked before it runs. The keyring names its KDF so a later version can move to Argon2id. | Built in, no addon. One code path on every machine. | Low (keyring rewrite) |
| A-7 | The recovery key is 256 random bits as grouped base32 with a version character and checksum, not a word list. | No word-list file to ship or localise. | Low before first release |
| A-8 | Manifests are signed with Ed25519. The printed anchor carries the public-key fingerprint. | Without a signature, a check that runs without keys cannot notice a recomputed chain. | Medium |
| A-9 | The keyring is not written to write-once media unless the user opts in. | A key burned to a disc can never be destroyed. | Low |
| A-10 | Redactions carry a keyed tombstone so the same bytes cannot be re-imported. | Otherwise re-importing an archive undoes a withdrawal. | Medium |
| A-11 | Map node ids and positions are recorded as vault events. Placement is integer-only and ignores model-inferred edges. | A recomputed layout differs between runs, versions and machines. | Medium |
| A-12 | Facts have two tiers. Only machine-checked predicates are labelled verified. Free text is labelled asserted. | Unchanged evidence does not prove a sentence follows from it. | Low |
| A-13 | The facts ledger never executes command text stored in the log. It runs only a fixed table of read-only templates. | The log is written by several agents; stored commands would be stored instructions. | Low |
| A-14 | Two writers in two languages share the log through a SQLite lock held across parent lookup and append. | Both languages have SQLite built in; the operating system releases the lock when a writer dies. | Low |
| A-15 | Facts ledger lookup is exact, then full text, with embeddings optional. | Embeddings do not fit the memory ceiling and are not needed for exact repository facts. | Low |
| A-16 | The digest limit is enforced as 6,000 bytes on the complete file. A calibration script checks the 2,000-token figure against real tokenizers before a release. | Bytes are the same for every model. Token counts are not. | Low |
| A-17 | Memory ceilings in Architecture section 9 and Step Zero section 10.4 are proposals until packages Z-1 and V-0 measure them. | One measurement so far: about 56 MiB for a bare process with one FTS5 table, on one machine, not the pinned version. | Low |
| A-18 | Linux support in v1 means glibc-based distributions on x64. | Each C library is a separate native-addon build to test. | Low |
| A-19 | The first-run wizard is a loopback web page served by the command, alive only while open. No desktop shell. | No second runtime to ship or sign. | Medium |
| A-20 | An earlier 4 GiB rule is replaced: blobs are never split, an oversize blob gets its own segment, and FAT32 is refused. | Splitting needs authenticated part order. | Low |
| A-21 | Foundry is a new repository under the MIT licence, extracted from a private project and not a fork of it. Public history starts with a single commit. Profiles are generic (`me`, `partner`, `child`, `other`). | Proposed on 2026-11-18 and carried by every later instruction, but never ratified in so many words. A fork would carry private history. | High once published |
| A-22 | Build order after Step Zero: thin slice (Takeout archive in, encrypted databank, search out), then wizard and second copy, then more sources. | Proves the hardest path first, at real size. | Low |
| A-23 | Documentation says "tamper-evident". It never says "tamper-proof", "undeniable" or "zero hallucination". | Each of those claims is false for some attacker or some model. | Low |
| A-24 | Clarifies Z-2 acceptance against Step Zero section 9 (items 5 and 8) and risk R-7. The existing external Python log tool is not modified until Z-8 (O-5), so it does not yet acquire `<log>.lock.sqlite` or run the last-byte check. In Z-2: (1) bidirectional format interop is verified against the unmodified Python tool (blocks written by `facts-ledger` are read cleanly by the Python tool, and blocks written by the Python tool are read cleanly by `facts-ledger`); (2) the two-writer concurrent interop test (0 lost blocks and 0 shared parents) runs inside `packages/facts-ledger` between the TypeScript writer and a synthetic Python test writer that implements the Step Zero section 9 SQLite lock (`BEGIN IMMEDIATE` on `<log>.lock.sqlite`, 5 s busy timeout) and last-byte `\n` check; (3) verifying 0 shared parents against the live external Python tool moves to Z-8 (O-5) once that separate change lands. | Reconciles ROADMAP Z-2 "Done when" with Step Zero section 9.5, section 9.8 ("once both writers use the lock"), R-7, and the Z-2 write boundary (`packages/facts-ledger` only, no edits to external repositories). | Low |
| A-25 | Clarifies Step Zero section 4 incremental `syncIndex` against sections 3.1 and 6: under the append-only log invariant, when the log grows on the same inode with a matching 4 KiB head SHA-256 (`[0, 4096)`), `syncIndex` reads strictly `[0, 4096)`, `[max(0, size - 4096), size)`, and the appended tail `[saved.indexedOffset, size)` (avoiding `O(N)` full-log re-hashing on appends); any out-of-band edit or historical repair inside `[4096, saved.indexedOffset)` requires running `facts rebuild`. | Preserves bounded warm-query and tail-append latency on growing ledgers while making explicit that non-append mid-file edits outside the 4 KiB head window must trigger a full `facts rebuild`. | Low |
| A-26 | (Written during V-0 as A-24; renumbered on merge under D-22.) Amends A-17 and the V-0 acceptance timing for Architecture section 9 ceilings (per Roadmap rule 4). Retains all Architecture section 9 numerical ceilings unchanged (passphrase KDF commands 256 MiB, `vault verify` 128 MiB, `import` 256 MiB, `search` 192 MiB, wizard 192 MiB, Mode A receiver 96 MiB) and changes when full-command confirmation occurs: V-0 confirms only that the isolated scrypt KDF primitive fits within the 256 MiB allowance and records isolated baseline probes for FVR1 streaming AES-256-GCM and SQLite3MultipleCiphers; full-command ceiling confirmation (including full passphrase KDF commands and aggregate process-tree RSS) moves from V-0 to the packages that implement each command (V-1/V-3/V-5 for KDF and `vault verify`, V-4/V-5 for `import`, V-4/V-7 for `search`, P-5 for wizard, X-6 for Mode A). | V-0 runs before Vault, wizard, or Mode A commands exist, so V-0 can only measure isolated primitives in single-process probes. Amending the V-0 timing rule explicitly keeps Architecture section 9 targets intact without making unsupported full-command claims in V-0. | Low |
| A-27 | Z-4 deviations from Step Zero section 6, recorded so a blind reviewer sees them (A-26 is reserved for the V-0 renumber). (1) Freshness results are memoised for one operation (one query or verify, identified by its `nowMs`), keyed by repository `HEAD`, not yet persisted in the index; a reused checker called for a new operation re-reads `HEAD` and re-runs commands, and a second query re-runs git. (2) `facts verify` resolves commits and blobs with one `git cat-file --batch-check` process per repository per 500-fact page (not one per repository for the whole run); `facts query` looks up its at most `--limit` results individually, with a per-process cache. (3) `dirty` is not reported: facts are checked against `HEAD` only and uncommitted changes are not seen. Detecting `dirty` needs a working-tree comparison, which can run repository-configured clean/smudge filters and so would break the read-only rule; it waits for a reviewed design. (4) A `checked` fact always re-runs its command evidence (fixed read-only templates) when that evidence is past its lifetime, because section 6 requires the predicate to be re-run before `VERIFIED`; `--rerun` controls only `asserted` facts. (5) Facts in a partial clone (`extensions.partialClone` or a promisor remote) are `unverifiable`: git runs with `GIT_NO_LAZY_FETCH=1` and `protocol.allow=never`, so a missing object cannot be fetched, and without fetching a missing object cannot be told apart from an absent path. Items 1 to 3 are tracked for Z-6 (budgets) or later. |
| A-28 | Z-6 choices where Step Zero section 10 names the outcome but not the rule, recorded so a blind reviewer sees them. (1) Conflicts: only `checked` facts are compared. Two live `checked` facts conflict when they share a subject (repo and path, or command template) and a scope (both `current`, or both `at-commit` at the same pinned commit) and their predicates cannot both hold: `file_exists`/`file_absent`; `file_absent` against `file_contains` or `file_blob_is`; two different `file_blob_is`; `file_contains`/`file_lacks` with the same text; `command_output_is` with the same arguments and different hashes. `facts query` pulls in at most 20 live conflict partners (stage `conflict`, label `related`) and prints `conflict:` on both sides. Citability is unchanged, because the fact that does not hold is already `stale`. Contradictions between free-text `asserted` facts are not detected, and the digest does not flag conflicts yet. (2) `facts check-answer`: every non-blank line is either `ABSTAIN: <text>` (no citations allowed on it) or a statement carrying at least one `[fact:<id>]` or `[asserted:<id>]`. `asserted:` may cite a `VERIFIED` fact. Ids must look like `<12 hex>.<n>`. A fact above `--max-sensitivity` is reported as not existing. Answers are capped at 256 KiB and 500 distinct citations. (3) `facts add --from-agent` needs `--model`, `--task`, `--input-tokens` and `--output-tokens` (`--tokens-measured` sets `measured`) and refuses the write otherwise. The token flags are also accepted without `--from-agent`. (4) Budgets: the 192 MiB process-tree ceiling is checked on Linux only, as the CLI's peak plus its largest `git` child's peak. Git children run one at a time, and a `wait4` wrapper set through `FACTS_LEDGER_GIT` measures them. The Windows tree check is deferred. The outside cross-check holds each process at exit with a preload and reads `VmHWM` or `PeakWorkingSet64`, with an 8 MiB tolerance. The gate fixture fixes the git identity, dates and LF bytes. Its commit ids are committed and checked on both platforms, and `expected.txt` is kept LF by `.gitattributes`. (5) Meeting 96 MiB on Linux: the Z-4/Z-5 figures had been measured on Windows only, and hosted Ubuntu read `verify --all` at 108 MiB, `check-answer` 106, `add` 103 and `digest` 102. Three fixes: the index content hash reads rows as arrays (same bytes, so existing indexes stay warm); `verify` and the digest run a full collection between 500-fact pages, through `--expose-gc` set at run time (it does nothing if the runtime refuses); and `verify` output is written in pieces (byte-identical, tested). After the fixes the hosted Ubuntu peak was 86.8 MiB and the tree 92.8 MiB. (6) A-27 item 2 is closed for `query` and `check-answer`: their results are prefetched with one batched `git cat-file --batch-check` per repository. A-27 items 1 (no persisted freshness cache) and 3 (`dirty`) stay deferred. (7) Gate safety rules (review round 1): beyond its group rule, every row of every gate case must pass `rowsAreSafe`. Only a fresh `match` may be citable. `VERIFIED` only on a `checked` fact and `ASSERTED` only on an `asserted` fact. `related` rows and `stale`/`expired`/`unverifiable` rows are never citable. Each row's rendered line, `rule:` line and `conflict:` line must agree with the row and sit inside the fence. `expected.txt` now records each row's tier and the full rendered text an agent reads. (8) Conflict lookup reads candidates only: for each fact found, an SQL complement filter selects only facts whose predicate can contradict it (for example `file_lacks` with the same text for `file_contains`). Rows are streamed one at a time and the lookup stops at 20 partners. Superseded and retracted facts never conflict, including when `--history` shows them. (9) The budget fixture uses a real git repository: a third of its facts are `checked` `file_contains` predicates, re-run by `verify`, the digest and `check-answer`, and the other two thirds are asserted with real `file` evidence. Each step also checks that its result really ran (badge counts, supported counts, answer accepted). That fixture showed `verify --all` at 98.8 MiB on Linux, because blob text was dropped after every 500-fact page and re-read with one `git cat-file` process per blob (2,004 processes per run). Blob text is keyed by blob id and cannot go stale inside a snapshot, so the cache now survives across pages up to 4 Mi characters and is cleared only past that bound. Result on WSL Ubuntu with pinned Node: 104 git processes, worst CLI peak 90.2 MiB (`verify --all`), tree 96.3 MiB. On Windows the worst peak is 66.7 MiB. (10) Review round 2: the gate also checks the text of each row's single `rule:` line against its badge, using wording written out in the gate rather than imported from the renderer. `VERIFIED`, `ASSERTED` and `RELATED` must carry their exact instruction, and every badge that is not citable must begin `Must not be cited.`. Predicate strings (repo, path, blob, text, template, arguments) must be well-formed Unicode. A lone UTF-16 surrogate makes the predicate invalid, so the fact is shown as `UNVERIFIABLE` and is never citable, and the SQL complement filter and `factsConflict` cannot disagree about it. (11) Review round 3: the gate rebuilds every rendered line of every case from the row metadata and the fixture's own facts (claim, note, tags, retraction reason, read through `gateFactCatalog()` without git; blob ids are computed as content hashes). The rendered text must match it exactly, with nothing extra inside or outside the fence. Only the `rule:` line may vary, and only within an exact allowlist per badge (no prefix matching). Safety is mandatory for all 50 cases: `gateScore` lists every unsafe case and fails on any, so group B's 9-of-10 allowance covers safe retrieval misses only. (12) Review round 4: the catalog also carries each fixture fact's tier and predicate. A row's tier must equal the fixture's, and a `VERIFIED` row needs a checked fixture fact whose claim is the canonical form of its predicate, so a snapshot cannot promote free text to `VERIFIED` even when its metadata, badge and rule are all changed together. (13) Review round 5: the fixture also declares, by hand from its own design, each fact's expected state at `NOW_MS` (`supported`, `stale`, `expired`, `superseded` or `retracted`). A live fact's row must show exactly that freshness and the badge it implies (`STALE`, `EXPIRED`, `UNVERIFIABLE`, or `VERIFIED`/`ASSERTED`/`RELATED` by tier when fresh). A historical fact may appear only as `SUPERSEDED` or `RETRACTED`. A test fails if any fixture fact lacks a declared state. (14) Review round 6: which row may be labelled `match` is decided from the case definition alone. Only the case's target may be a match, only in cases built to find it (groups A and D, and the E traps `data-not-instruction` and `expired`), and only at the stage its query kind implies (id, tag or path lookups `exact`, text `lexical`). Every other row must be `related`, so it is never citable. The case status must be `match` exactly when a match row is shown. Conflict flags must equal the fixture's declared contradicting pairs (only `src/legacy.ts` exists against is absent) that are shown in the same case. (15) Review round 7 (every field enumerated): the committed expected file must equal, block for block, an oracle built only from committed declarations. These are the cases and `CASE_ROWS` (the rows each case returns, in order, as id, label and stage, with an empty list meaning `not_found`), the fixture's facts and declared states, and the answers with `ANSWER_OUTCOMES` (problem lines and counters). Badge, freshness, citability, conflicts, rules (`Must not be cited. Re-verify or abstain.` for every live fact that is not fresh), status, fence and verdicts are derived, never read. Extra, missing, duplicated, reordered or edited blocks or lines fail. The safety rules still run on every case, and a test proves the oracle itself passes them. Eligibility is now part of them: sensitivity within the case's cap, historical facts only when the case asks for history, and no empty conflict field. A product behaviour change therefore needs a reviewed edit to the declarations; regenerating the expected file alone cannot pass. (16) Two follow-ups to item 15. First, when a run differs from the declarations, `run-gate.mjs` prints paste-ready `CASE_ROWS` and `ANSWER_OUTCOMES` lines in the committed format and exits 1. It never writes the declaration files, and it never proposes fact states, conflict pairs or sensitivity, which stay hand-written so citability stays independent of the code under test. Second, the oracle now covers history. Three history cases (H01 superseded by text, H02 retracted with its reason line, H03 superseded by tag beside a citable ASSERTED match) run after the 50 and must each be safe and pass. They are not counted in the 10.1 thresholds, and the 50 are unchanged. A superseded or retracted fact appears only with `history`, as `stale`, never citable, under its historical badge and rule, with the retraction reason line when there is one. The safety rule pins these too. A case may declare `alsoMatch` for another fact its query may label `match`. | Step Zero 10.1 to 10.4 fix the results the gates must prove but leave these rules to the builder; each choice is the narrowest deterministic one. | Low |
| A-30 | Z-8 uses project and evidence repository name `foundry`. The checked-in log is `ledger/foundry.jsonl` and the generated session digest is `ledger/digest.foundry.md`. The per-machine repository map stays outside the checkout. | Keeping the log and digest together lets the CLI use its default index and digest paths. A fresh checkout has the facts and digest available at session start, and SQLite files can be rebuilt or created locally. | Low |

## 3. Open questions for the owner

**All seven were answered on 2026-11-19: see D-12 to D-18.** One part stays open: the final
product name, package scope and hosting organisation (Q-2, D-14), needed at P-8. The table
is kept as the record of what was asked.

| Id | Question | Planner's recommendation | Blocks |
|---|---|---|---|
| Q-0 | Confirm A-21: new MIT repository, extracted not forked, single first commit, generic profiles. | Confirm. | P-8 |
| Q-1 | Is A-1 acceptable: Step Zero as a package inside this repository instead of a repository of its own? An earlier note described it as a standalone repository. | Yes. Split it out later only if another project needs it without Foundry. | Nothing; reversible |
| Q-2 | Public product name, package scope and hosting organisation. "Foundry" is a working name and has not been checked for conflicts. | Check name conflicts on the package registry and code host before P-8. | P-8 |
| Q-3 | Is "0 unsupported claims of 50, on two consecutive runs" the bar a model must pass before it does build work? | Accept as a starting bar and revisit after the first three harness runs. | Z-7 exit |
| Q-4 | Code signing on Windows: stay unsigned, apply for free signing for open-source projects, or pay. See R-1. | Apply for free signing early, ship unsigned with clear instructions meanwhile, do not pay. | P-6, P-8 |
| Q-5 | Who is the first release for? Both reviewers advised "technical users with Node installed" first. The plan keeps the ordinary-user bundle as the v1 goal and ships the npm package earlier (V-8) for testers. | Keep the plan as written. | P-6 scope |
| Q-6 | May a user put the keyring on write-once media (A-9 says opt-in only, with a warning)? | Keep opt-in. | P-3 |

## 4. Risks

| Id | Risk | Effect | Response |
|---|---|---|---|
| R-1 | Windows trust versus $0. Unsigned downloads trigger SmartScreen warnings. Smart App Control may refuse to load the unsigned native addon at all. Certificates cost money. | Ordinary users may be unable to install or run the encrypted index on some Windows machines. | Test on a clean Windows 11 image in V-0. Apply for free open-source signing in parallel. Publish hashes and build provenance. Fallback for a blocked addon is the `plain` driver with disk encryption, by explicit choice. |
| R-2 | Native addon builds lag behind new runtime versions and are specific to each runtime major, platform and C library. | An update of the runtime breaks the index. | Build addon binaries in this project's CI. Pin the runtime major. Treat a runtime upgrade as a deliberate change with CI proof. |
| R-3 | Losing every copy of the keyring loses the data, even with the passphrase. | Total loss. | Keyring written to every rewritable copy at each session. The restore drill fails if the copy's keyring cannot open a sample record for every active key. |
| R-4 | Users expect "erase" to mean more than it can. Old keyring copies, operating-system file history, cloud-sync version history and flash remnants keep data recoverable. | Broken promise to a person who withdrew consent. | Three separate states in the interface. Register of keyring copies. Limits printed in the erase dialog. No claim of compliance with any law. |
| R-5 | Export formats change without notice, especially location history. | An importer silently reads nothing. | Importers report counts per type and warn on an archive entry no importer recognises. Raw bytes are stored first, so a fixed importer can re-derive. |
| R-6 | The 96 MiB ceiling for the facts ledger has about 40 MiB of headroom on the one machine measured. | The ceiling fails on another platform or runtime version. | Z-1 measures before anything is built. The number changes only by a recorded decision. |
| R-7 | Until the existing Python log tool takes the same lock, two writers can still interleave or pick the same parent. | A damaged or forked log line. | Readers skip and report bad lines. Z-8 proposes the Python change. |
| R-8 | A 50-case test cannot measure a small error rate. | False confidence in a model. | The deterministic gate is named for what it tests. The model harness is described as a screen, not a proof. |
| R-9 | Unpowered flash and cheap optical media lose data over years. | A second copy that fails when needed. | Scheduled verification without keys. Two copies in two places. Restore drill. |
| R-10 | The plan was reviewed without access to the predecessor's code. | A component assumed reusable turns out not to be. | V-1 and V-5 start from the specification, not from ported code. Porting is an optimisation. |

## 5. Comparison with the earlier draft plan

An earlier draft of this plan existed before this specification. What happened to it:

**Kept**

1. Every owner decision in section 1.
2. The wizard flow: check, location, lock, second copy, people, first import.
3. Step Zero first, with the cite-or-abstain rule and the two proof deliverables.
4. Raw data in an append-only vault; everything else derived and rebuildable.
5. Mode B as the default second copy, with a hash chain and a restore drill.

**Changed**

| Earlier draft | Now | Reason |
|---|---|---|
| MSIX installer and a single-file executable | Directory bundle and npm package (A-3) | MSIX needs a paid signature; a single file cannot load the native addon |
| Facts lookup: exact, then embeddings | Exact, then full text; embeddings optional (A-15) | Memory ceiling; exact repository facts do not need vectors |
| Digest limit of about 2,000 tokens | 6,000 bytes enforced, tokens calibrated offline (A-16) | A token is a different size for every model |
| Reuse the predecessor's blob format | New record format (A-4) | Erasure and vault binding need fields the old format lacks |
| Map layout from a seeded simulation saved as a snapshot | Positions and node ids recorded as events (A-11) | A simulation moves old nodes when anything changes |
| "Hallucination test set" in CI | A retrieval, abstention and citation gate in CI, plus a separate model harness | No model runs in CI, so the first name claimed too much |
| Extraction notes mixed into public documents | Kept out of the public tree | They describe a private project |

**Added**

1. Erasure by key destruction, with a keyring, tombstones, a restore rule and stated limits.
2. Passphrase and recovery-key design, a key cache port, and a fail-closed encrypted index.
3. Signed manifests, an honest account of what the chain proves, and a restore drill with a failure suite.
4. Checked and asserted fact tiers, the never-execute-stored-commands rule, and a cross-language append lock.
5. Resource ceilings as CI gates, a threat model, test gates, a model catalog with licence rules, and the risks above.

## 6. Review record, 2026-11-19

The draft specification was sent to two independent AI reviewers (Reviewer A: a Codex
model; Reviewer B: a Claude model) with the same prompt covering index encryption, erasure
on sealed media, stable map positions, Step Zero and distribution. A third run that asked
three models to compete and then merged their answers failed on a 90-second time limit in
the merging step and produced nothing; the two single-reviewer runs replaced it. Neither
reviewer could read the predecessor's code (R-10).

### Adopted from both reviewers

- Index key random, held in the keyring, replaced on every erasure.
- Cipher configuration pinned explicitly; tests against the shipped binary; fail closed.
- Positions recorded as events; a simulation only as an explicit rearrange.
- The CI gate renamed and required to match its expected output exactly.
- Signed manifests and an anchor that includes the public-key fingerprint.
- No single-file executable. Addon binaries built in this project's CI. Runtime major pinned.

### Adopted from Reviewer A

- KDF bounds checked before the KDF runs; no silent downgrade; wrap binds vault, slot and parameters.
- Ordered, restartable erasure with three reported states; the restore rule; tombstones.
- Item-by-item handling for items about more than one person.
- Restore-drill failure suite; no blob splitting; contiguous segment and sequence ranges; a reserved `epoch`.
- Placement caps, an overflow row, an edge-evidence table, inferred edges recorded once.
- Lock held across parent lookup and append; fact scope; command evidence with template version and exit code.
- Byte limit on the complete digest; measured versus estimated token counts; measure-first packages.
- Release archives scanned as well as the tree; glibc-only Linux in v1.

### Adopted from Reviewer B

- Two fact tiers, so free text is never replayed as verified.
- Read-only git settings, absolute executable paths, no script shims, no test or build runs as templates.
- Git blob ids instead of hashes of working files; facts not copied between repositories.
- Last-byte check before append; rename with retry on Windows; compiled JavaScript only; no key handling in the ledger.
- Random node ids recorded as events; bytewise ordering everywhere; batch placement for a first import.
- Register of keyring copies; warnings about operating-system and cloud copies; erasure cannot be proven to the person who asked.
- Media facts: SD lock tabs, single-session discs, unpowered flash. The drill writes no plaintext to temp.
- Recovery-key printing warning. Unmodified runtime binary in the bundle. Free provenance measures. Smart App Control test.

### Not adopted

| Proposal | From | Why not | Revisit when |
|---|---|---|---|
| Ship v1 only for people who already have Node; position it for technical users | A and B | The owner's goal is a product an ordinary person can install. The npm package ships first for testers (V-8); the bundle remains the v1 goal. Raised as Q-5. | The owner answers Q-5 |
| A random key per item, in a transactional key store | A | Larger keyring, harder backups, more ways to lose data. Single-item erasure is met by redaction plus re-key of one source-year. | Single-item erasure proves too slow in use |
| The Python tool calls the TypeScript writer so there is one append implementation | A | It makes the existing tool depend on a Node install. A shared lock gives the same safety. | The interop test shows the lock is not enough |
| Keep all revocable or mixed-subject records off write-once media by default | A | The keyring is what is kept off write-once media (A-9). Ciphertext without a key is not readable. | Never, unless A-9 changes |
| Argon2id when the runtime offers it, scrypt otherwise | B | Two code paths, and a keyring written on one machine might not open on another. | The runtime's Argon2id is stable on every supported version |
| A 24-word recovery phrase | B | Needs a word list. Base32 with a checksum gives the same strength (A-7). | Usability testing shows people mistype base32 |
| A hash tree over 1 MiB frames in each segment | B | Per-file hashes over files of at most 64 MiB already locate damage closely enough for a full restore. | Partial verification is needed |
| Padding the last frame to hide sizes | B | Sizes and timing leak anyway. The threat model states it. | Never, unless the threat model changes |

## 7. Change log

| Date | Entry |
|---|---|
| 2026-11-18 | D-1 to D-4 recorded from the owner's goal statement and instructions. |
| 2026-11-19 | D-5 to D-11 ratified by the owner. A-1 to A-23, Q-0 to Q-6, R-1 to R-10 written by the planner. Review record added. |
| 2026-11-19 | D-12 to D-18 added: the owner accepted every recommendation for Q-0 to Q-6. A-1, A-9 and A-21 are now confirmed by D-13, D-18 and D-12. The final name (Q-2) stays open until P-8. |
| 2026-11-19 | D-19 added: O-3 code-signing programme terms checked; SignPath Foundation requires a public repository and releases, so the application waits for P-8. |
| 2026-11-19 | A-24 added before Z-2 implementation: reconciles Z-2 two-writer interop acceptance with Step Zero sections 9.5/9.8 and R-7 while the external Python tool change stays scheduled for Z-8 (O-5). |
| 2026-11-19 | D-20 and D-21 added by owner decision: expands Foundry into the full public, zero-personal-info Sovereign Exocortex using progressive tiers (Tier 0 stays zero-daemon CLI/Vault/Wizard; Tier 1–2 opt into Phase 4 Remember and Phase 5 Act stacks). |
| 2026-11-20 | A-25 added during Z-3 hardening: clarifies Step Zero section 4 tail-only `syncIndex` vs sections 3.1/6 append-only invariant (same inode + matching 4 KiB head reads only head/tail windows and `[saved.indexedOffset, size)`; mid-file out-of-band repairs require `facts rebuild`). |
| 2026-11-20 | A-27 added during Z-4: records HEAD-memoised freshness without an index cache, per-path batch-check, deferred `dirty` status, and checked facts always re-running expired command evidence. |
| 2026-11-20 | A-28 added during Z-6: conflict rule, check-answer line rule, `--from-agent` token flags, Linux-only process-tree check, the Linux memory fixes, and A-27 item 2 closed for query. |
| 2026-11-21 | A-28 items 7 to 9 added after Z-6 review round 1: gate safety rules on every row, conflict complement filter, real-repository budget fixture and the blob-text cache bound. |
| 2026-11-21 | A-28 item 10 added after Z-6 review round 2: rule text checked per badge, ill-formed Unicode rejected in predicates. |
| 2026-11-21 | A-28 item 11 added after Z-6 review round 3: exact rendered reconstruction in the gate, exact rule allowlist, safety mandatory for every case. |
| 2026-11-21 | A-28 item 12 added after Z-6 review round 4: row tier checked against the fixture, VERIFIED only for canonical checked claims. |
| 2026-11-21 | A-28 item 13 added after Z-6 review round 5: declared expected freshness and lifecycle per fixture fact, badge implied by freshness. |
| 2026-11-21 | A-28 item 14 added after Z-6 review round 6: allowed match row per case from the case definition, status and conflict flags checked against the fixture. |
| 2026-11-21 | A-28 item 15 added after Z-6 review round 7: expected file must equal an oracle built from committed declarations; eligibility rules. |
| 2026-11-21 | A-28 item 16 added (Z-6b): paste-ready declaration lines on mismatch; oracle history support with history cases H01-H03. |
| 2026-11-21 | D-22 (O-2 narrowed: V-0 merges, Smart App Control test moves to P-6) and D-23 (Z-8 to Codex; Codex runs V-1 and Z-8 together) added by the owner. |
| 2026-11-21 | A-26 added (written during V-0 as A-24, renumbered on merge under D-22): confirms the 256 MiB KDF ceiling and explicitly defers confirmation of the remaining Architecture section 9 full-command ceilings to V-3, V-4, V-5, V-7, P-5, and X-6. |
| 2026-11-21 | A-30 records the Foundry ledger and digest paths for Z-8. |
