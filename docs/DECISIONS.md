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
