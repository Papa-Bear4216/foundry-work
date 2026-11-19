# Foundry product specification

Status: draft for build, 2026-11-19. Settled items are marked **Decided** and listed with
dates in [DECISIONS.md](DECISIONS.md). Everything else is the planner's proposal.

## 1. Goal

Foundry is the public, MIT-licensed, zero-personal-info distribution of the Sovereign Exocortex. A person with one ordinary computer installs Foundry, answers a short wizard, and starts with a portable, encrypted, searchable databank of their digital history plus a second offline copy on hardware they control (Tier 0, zero resident daemons). Users on capable hardware (Tier 1–2) can optionally enable the live **Remember** and **Act** layers — local capture, write-time recap synthesis, local `llama.cpp` inference, desktop tray shell, Android companion with biometric WYSIWYS approval, Living World Model, and shadow-calibrated automation. Incremental cost is $0: no required subscription, no cloud account, no paid API.

The product helps people by helping them use what they already have: data they are
entitled to export or capture locally, and hardware they already own.

## 2. Who it is for

| User | Has | Wants |
|---|---|---|
| Primary | One Windows or Linux PC, a spare USB drive, a Google account | Their data out of the cloud and searchable, without learning encryption |
| Household | Same, plus a partner's or child's exports | One place for the household's records, with clear rules about whose data is whose |
| Tinkerer | A spare PC, Pi or NAS | The same, plus a continuously synced second copy |

Not a target in v1: teams, businesses, multi-user servers, phones as the main device.

## 3. Principles

1. **Local only.** No network traffic except downloads the user starts (installer, models)
   and, later, sync to the user's own second device. This is enforced by a test that runs
   the product with networking disabled, not by a statement in a README.
2. **$0 incremental.** Every required component is free and runs on the user's hardware.
   Anything that costs money (code-signing certificates, hosted services) is optional or absent.
3. **Raw data is never edited.** The vault stores originals. Indexes, tags, maps and
   summaries are derived and can be rebuilt. Corrections are new records, not edits.
4. **Cite or abstain.** Any generated answer points at stored records or says it found nothing.
5. **Honest limits.** The docs and the wizard say what the product cannot guarantee.
6. **Runs lean.** Tier 0 runs zero always-on helper processes: work happens in short-lived commands and scheduled tasks, and memory use is measured in CI with fixed ceilings. Tier 1–2 users who explicitly opt into Phase 4–5 live capabilities may enable `exocortexd` and local `llama.cpp` role servers on demand, still bounded and measurable, and disabled cleanly when turned off.
7. **No real-life sample data.** Every fixture in the repository is synthetic.

## 4. Platforms and hardware (Decided, updated by D-21)

- Windows 10/11 x64 and Linux x64 in v1, plus opt-in Android companion client in Phase 4 (`E-6`). macOS deferred. Linux arm64 is a stretch target for the always-on second device.
- Hardware tiers, chosen by the wizard from measured RAM, cores and GPU:

| Tier | Minimum | Enabled |
|---|---|---|
| 0 | 4 GiB RAM | Vault, import, full-text search, second copy, restore drill, loopback wizard (zero resident daemons) |
| 1 | 8 GiB RAM, 4 CPU cores | Tier 0 + on-demand embeddings, small local model (2–4 B parameters, 4-bit), and optional opt-in Phase 4 (`exocortexd`, write-time recap cards, channel vaults, Tauri desktop shell, Android companion) |
| 2 | 16 GiB RAM or a discrete GPU | Tier 1 + larger local `llama.cpp` role servers, answer verifier, and optional opt-in Phase 5 (Living World Model, Cognitive Mode Gate, Active Inference, Shadow-calibrated WYSIWYS biometric actuation, Agent Mesh/Triad, Morphogenetic self-healing ladder) |

The wizard never enables a feature whose measured peak memory exceeds half of the
machine's free RAM at check time. A user can lower a tier; raising one requires re-running the check.

## 5. First-run wizard

The wizard is a local web page served on the loopback interface by the `foundry` command.
It exists only while the wizard is open; closing it stops the server.

| Step | Asks | Result |
|---|---|---|
| 1. Check | Nothing | RAM, CPU, GPU, free disk, disk health where readable. Tier shown with the reason. |
| 2. Location | Where the databank lives | Vault and index folders created. Warning if the folder is inside a cloud-sync directory. |
| 3. Lock | Passphrase | Keys created. Recovery key shown once, with a type-back check before continuing. Writing it down by hand is offered first; printing comes with a warning that "print to PDF" and network printers keep a copy. |
| 4. Second copy | Offline drive (default) or always-on device | Drive initialised and first vault session scheduled. Warning if both copies sit on one physical disk. |
| 5. People | Whose data will be stored | Profiles created (`me`, plus optional partner, child, other). Consent notes recorded for anyone who is not the user. |
| 6. First import | Google Takeout walkthrough | Export requested with the right settings; import runs when the archive is on disk. |

Rules:

- Every step can be resumed. Closing the wizard halfway loses nothing.
- Every step has a command-line equivalent, so the product is scriptable and testable.
- The wizard refuses to continue past step 3 until the recovery key check passes. Losing
  both passphrase and recovery key means the data is unrecoverable, and the wizard says so plainly.

## 6. Importing

### 6.1 Thin slice (first working version)

Google Takeout, zip format, three products:

| Product | Format in the archive | Why first |
|---|---|---|
| Contacts | vCard | Small, gives names that make everything else readable |
| Calendar | iCalendar | Small, gives dated events |
| Mail | mbox | Large, proves streaming import and search at real size |

The walkthrough tells the user exactly which boxes to tick, to choose `.zip`, and what
part size to pick. The importer accepts a folder of parts and treats them as one archive.
It reads entries straight from the zip; it never unpacks the whole archive to disk.

### 6.2 After the thin slice

Ordered by value per unit of work: location history (both the older Takeout formats and
the newer on-device Timeline export), photo metadata, My Activity (JSON), chat exports
from other services, phone call and message exports, health exports. Each importer is a
small module with a synthetic fixture and a declared output shape.

### 6.3 Importer rules

1. Store the original bytes first, then derive. An importer that crashes halfway leaves
   raw data that the next run can finish from.
2. Re-importing the same archive adds nothing (content-addressed).
3. Each imported item is assigned a profile, a collection and a sensitivity tier at write time.
4. Parsers never call a network service or a model.

## 7. Search and answers

- **Search (Tier 0):** full-text with filters for date range, source, profile and tier.
  Results show the stored record, its source file and its import date.
- **Semantic search (Tier 1+):** optional embeddings, computed on demand by a process that
  exits when idle.
- **Ask (Tier 1+, later phase):** a local model answers from retrieved records and must
  cite them. An answer with no supporting record is replaced by "not found in your
  databank". At Tier 2 a verifier model checks each answer against its citations.
- **Map of relationships (later phase):** people, places and topics as nodes; every link
  points at the record that justifies it; model-inferred links are marked as inferred with
  a confidence value. Node positions are stored, so the map looks the same every time.

## 8. Second copy

The wizard asks which the user wants. It is a setting and can be changed later.

### Mode B: offline sealed drive (default, v1)

1. A scheduled reminder says a vault session is due (weekly by default; daily, monthly or
   manual are options).
2. The user connects the drive and starts the session.
3. Foundry verifies the drive's existing hash chain, copies new segments, verifies them,
   marks them sealed, and records the new chain head on the working device.
4. The user disconnects the drive. Between sessions nothing can reach it.

The home screen always shows the age of the last seal. Past 14 days unsealed it becomes a
persistent banner.

Supported hardware, in order: a USB drive with a physical write-protect switch or a USB
write-blocker; optionally an export to write-once optical media (BD-R or M-DISC) plus a
printable code that records the chain head.

- The drive must use a file system without a 4 GiB file limit (exFAT, NTFS, ext4). The
  wizard refuses FAT32.
- The lock tab on an SD card does not count as write protection: the card reader may ignore it.
- Flash drives left unpowered for years can lose data. The scheduled check exists to catch
  that while the other copy is still good.

### Mode A: always-on device (later phase)

A second PC, Pi or NAS receives new segments continuously. Because it is reachable over a
network, the docs treat it like a private cloud: data is encrypted before it leaves the
main device, the pairing credential can only append, and the receiver runs only for the
length of a transfer.

- **A1, home network only:** pinned-fingerprint connection, no third-party account.
- **A2, remote:** requires a private overlay network (Tailscale, or user-managed WireGuard
  or Headscale). The wizard blocks raw port-forwarding.

### What the second copy does and does not give you

| Claim | True? |
|---|---|
| A changed, removed or reordered record in a sealed segment is detected | Yes |
| A whole drive swapped for an older copy is detected | Only by comparing against a chain head stored elsewhere (working device, the other copy, or the printed code) |
| Software read-only flags stop an administrator on the same machine | No. Hardware write-protect or write-once media does |
| The drive survives fire, loss or wear | No. Keep the second copy in a different place and let the scheduled check run |

## 9. People, consent and erasure

- Profiles are generic: `me`, `partner`, `child`, `other`. Display names are stored in the
  user's vault and never in code, tests or documentation.
- When data belongs to or is mainly about someone other than the user, the wizard records
  a consent note in plain words: who, on what basis ("they exported it and gave it to me",
  "I am their parent or guardian", "my own copy of a shared conversation"), and when.
- Sensitivity tiers: `public`, `personal`, `private`, `secret`, `clinical`, `child`.
  Shipped rules are generic (credentials, national identity numbers, tax and insurance
  documents). Household-specific rules are user configuration stored in the vault.
- `child`-tier data is excluded from model prompts unless the user turns that on per collection.
- **Withdrawal:** a person's data can be erased even though the vault is append-only. Each
  profile and collection is encrypted under its own key; erasing destroys the key, which
  makes every copy of that data unreadable, including sealed copies. See the limits in
  [ARCHITECTURE.md](ARCHITECTURE.md#57-erasure-and-its-limits).
- The erase screen reports three separate states and never merges them into "deleted":
  hidden, removed from the index, and key destroyed on N of M copies. It lists the copies
  that still need a vault session.
- Restoring an older copy never brings withdrawn data back into view, and re-importing the
  same archive does not restore a redacted item.
- The person who asked cannot check the erasure themselves: the vault's owner holds the
  keys. Foundry provides a technical property, not proof to a third party.
- The product gives no legal advice. The docs point out that recording calls and storing
  other people's messages is regulated differently in different places, and that the user
  is responsible for their own use.

## 10. Installation and updates

- Per-user install, no administrator rights.
- Windows: a zip bundle plus a small install script that verifies a published SHA-256, and
  a WinGet manifest. Linux (glibc-based distributions): a tarball plus install script; a
  `.deb` later.
- For people who already have Node.js 24: the same code as an npm package.
- Scheduled work uses the operating system's own scheduler (Task Scheduler, `systemd --user`
  timers). Scheduled jobs never hold decryption keys: they remind, and they check integrity
  of ciphertext.
- Updates are manual and hash-verified. No background updater.
- Known cost conflict: unsigned Windows binaries trigger SmartScreen warnings, some
  Windows policies block them, and code-signing certificates cost money. See open risk
  R-1 in [DECISIONS.md](DECISIONS.md).

## 11. Success measures for v1

| Measure | Target |
|---|---|
| Fresh install to first search result, synthetic 1 GB Takeout, Tier 0 machine | Under 30 minutes, no terminal needed |
| Restore drill from the second copy onto a clean machine | Passes using only the drive, the passphrase or recovery key, and the installer |
| Network traffic during import and search | Zero packets (tested) |
| Idle resource use | Zero resident processes |
| Peak memory per command | Within the ceilings in [ARCHITECTURE.md](ARCHITECTURE.md#9-resource-budgets), measured in CI |
| Personal identifiers in the repository | Zero (scanned on every push) |

## 12. Scope boundaries and progressive tiers (D-20, D-21)

- **Tier 0 (core v1 foundation):** offline vault, archived imports, full-text search, Mode B offline second copy, restore drill, and loopback setup wizard with zero resident daemons.
- **Opt-in Phases 4–5 (Tier 1–2):** `exocortexd`, local capture, write-time recap cards, encrypted channels (`ChannelVault`), local `llama.cpp` role runner, Tauri desktop shell, Android companion with Keystore/BiometricPrompt WYSIWYS approvals, Living World Model, Shadow-calibrated actuation (`SHADOW=1` default), Agent Mesh, Advisory Triad, and Morphogenetic self-healing ladder (disabled by default).
- **Permanently excluded:** cloud-hosted core state, sharing between households, macOS in initial releases (deferred), hosted demos, any feature requiring a paid subscription/API, personal identifiers/real fixtures, and unrelated external consumer apps.
