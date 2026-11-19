# V-0 Measurement Report

Date: 2026-11-19
Commit measured: `bfd3af3` (`pkg/v-0`)
Hosted CI run: `44636722389` (`ubuntu-latest` and `windows-latest`, Node `24.22.3`)

## 1. Scope and Measurement Methodology

V-0 evaluates the three isolated runtime primitives and cross-platform packaging assumptions required before Vault implementation begins:

1. Passphrase KDF (`scrypt` at `N = 2^17`, `r = 8`, `p = 1`, `32`-byte derived key).
2. Streaming record framing and authenticated encryption (`FVR1` header + `1 MiB` frames + `AES-256-GCM` + `HKDF-SHA256`).
3. Encrypted index addon build, loading, extensions (`FTS5`, `R-tree`), SQLCipher pragma pinning, tamper/wrong-key fail-closed behavior, and plaintext marker absence (`better-sqlite3-multiple-ciphers` `12.6.1`).

**Measurement scope note:** In `benchmarks/v0/run-all.mjs`, internal (`process.resourceUsage().maxRSS`) and external OS peak counters (`VmHWM` from `/proc/<pid>/status` on Linux; Job/process `PeakWorkingSetSize` on Windows) measure **each isolated benchmark Node child process individually**. They do not measure an aggregate launcher + helper process tree, nor do they execute full Vault commands (end-to-end archive import, full index search over real corpus data, interactive wizard flows, or Mode A daemon pipelines).

### Test Environments

| Environment | OS / Arch | Node.js | CPU Cores | RAM | Libc / SQLCipher Binary |
|---|---|---|---|---|---|
| Hosted CI Linux (`ubuntu-latest`) | `linux` / `x64` | `24.22.3` | 2 | 7.7 GiB | GLIBC `2.43` / `built-from-source` |
| Hosted CI Windows (`windows-latest`) | `win32` / `x64` | `24.22.3` | 2 | 8.0 GiB | Win32 / `built-from-source` |
| Local Windows verification | `win32` / `x64` | `24.22.3` | 16 | 15.7 GiB | Win32 / `default-resolution` (prebuild) |

---

## 2. Passphrase KDF (`benchmarks/v0/measure-kdf.mjs`)

Parameters match `docs/ARCHITECTURE.md` section 5.2: `scryptSync` with `N = 131072` (`2^17`), `r = 8`, `p = 1`, `keylen = 32`, `maxmem = 268435456` (`256 MiB`), executed across `3` sequential iterations per child run.

| Metric | Hosted Linux CI | Hosted Windows CI | Local Windows (16c) |
|---|---|---|---|
| Timings (ms) | `407.02`, `387.05`, `357.69` | `426.72`, `343.96`, `366.51` | `203.56`, `202.42`, `214.73` |
| Min / Median / Max (ms) | `357.69` / `387.05` / `407.02` | `343.96` / `366.51` / `426.72` | `202.42` / `203.56` / `214.73` |
| Child external wall (ms) | `1197.36` | `1219.93` | `692.36` |
| Internal `maxRSS` | `177.45 MiB` (`181704 KiB`) | `165.36 MiB` (`169324 KiB`) | `165.84 MiB` (`169816 KiB`) |
| External OS peak | `177.45 MiB` (`186064896 B`) | `165.36 MiB` (`173387776 B`) | `165.84 MiB` (`173891584 B`) |
| Against `256 MiB` budget | Pass (`kdfWithinBudget: true`) | Pass (`kdfWithinBudget: true`) | Pass (`kdfWithinBudget: true`) |

**Result:** Single-passphrase derivation fits cleanly around ~367–387 ms on 2-core CI runners and ~204 ms on 16-core hardware, with peak RSS at `177.45 MiB` (Linux) and `165.36 MiB` (Windows), well under the `256 MiB` ceiling.

---

## 3. Streaming AES-256-GCM Framing (`benchmarks/v0/measure-encrypt.mjs`)

Constructs the `69`-byte `FVR1` header (`total_len = 134220288`), derives the `32`-byte record key via `hkdfSync('sha256', collectionKey, salt, 'foundry/record-key/v1', 32)`, and encrypts/decrypts `128` frames x `1 MiB` (`128 MiB` plaintext; `134220288` encoded body bytes) using `64 KiB` streaming cipher slices into reusable buffers, followed by SHA-256 round-trip equality and a 1-frame tamper check.

- **Timing & peak scope note:** `encryptMs` and `decryptMs` exclude SHA-256 plain/round-trip hashing (decrypted bytes are copied into a reusable `decryptedFrame` buffer inside `decryptMs`, and `roundtripHash.update(...)` runs afterward). `totalWallMs` and the reported process peak RSS cover the full `128 MiB` payload loop plus the single-frame tamper rejection check.

| Metric | Hosted Linux CI | Hosted Windows CI | Local Windows (16c) |
|---|---|---|---|
| Payload / Frame / Slice | `128 MiB` / `1024 KiB` / `64 KiB` | `128 MiB` / `1024 KiB` / `64 KiB` | `128 MiB` / `1024 KiB` / `64 KiB` |
| Encrypt time / throughput | `79.10 ms` / `1618.21 MiB/s` | `148.01 ms` / `864.79 MiB/s` | `92.67 ms` / `1381.26 MiB/s` |
| Decrypt time / throughput | `77.27 ms` / `1656.49 MiB/s` | `157.24 ms` / `814.04 MiB/s` | `78.89 ms` / `1622.56 MiB/s` |
| Probe wall / external child wall | `328.02 ms` / `378.29 ms` | `535.72 ms` / `624.75 ms` | `301.95 ms` / `382.93 ms` |
| Observed peak for `128 MiB` payload (`maxRSS` / OS) | `125.23 MiB` / `125.73 MiB` | `108.42 MiB` / `108.42 MiB` | `111.21 MiB` / `111.21 MiB` |
| Round-trip + tamper rejected | `true` / `true` | `true` / `true` | `true` / `true` |
| Against `128 MiB` probe budget | Pass (`streamProbeWithinBudget: true`) | Pass (`streamProbeWithinBudget: true`) | Pass (`streamProbeWithinBudget: true`) |

**Result:** Using `64 KiB` streaming slices keeps V8 external buffer churn bounded so the isolated `128 MiB` framing probe stays under `128 MiB` peak (`125.73 MiB` Linux, `108.42 MiB` Windows) at `814–1656 MiB/s`.

---

## 4. SQLCipher Native Addon (`benchmarks/v0/measure-sqlcipher.mjs`)

Tests `better-sqlite3-multiple-ciphers` `12.6.1` built from source in CI (SQLite `3.54.1`, `SQLite3 Multiple Ciphers 2.7.1`) and prebuild fallback locally on Windows.

- **Pinned SQLCipher compatibility & page authentication parameters verified via pragma readback:**
  - `cipher = 'sqlcipher'`
  - `legacy = 4`
  - `legacy_page_size = 4096`
  - `kdf_iter = 256000`
  - `fast_kdf_iter = 2`
  - `hmac_use = 1`
  - `hmac_check = 1`
  - `hmac_pgno = 1`
  - `hmac_salt_mask = 58`
  - `hmac_algorithm = 2`
  - `kdf_algorithm = 2`
  - `plaintext_header_size = 0`
  - `temp_store = 2` (`MEMORY`)
  - `secure_delete = 1` (`ON`)

| Metric | Hosted Linux CI | Hosted Windows CI | Local Windows (16c) |
|---|---|---|---|
| Addon variant loaded | `built-from-source` | `built-from-source` | `default-resolution` (prebuild) |
| `FTS5` & `R-tree` available | `true` & `true` | `true` & `true` | `true` & `true` |
| All 14 pinned pragmas match | Pass | Pass | Pass |
| Wrong key rejected | `true` (`SQLITE_NOTADB`) | `true` (`SQLITE_NOTADB`) | `true` (`SQLITE_NOTADB`) |
| Modified page rejected (`hmac_check=1`) | `true` (`SQLITE_CORRUPT`) | `true` (`SQLITE_CORRUPT`) | `true` (`SQLITE_CORRUPT`) |
| Control read (`hmac_check=0`) | `true` (bypassed as control) | `true` (bypassed as control) | `true` (bypassed as control) |
| Live `-wal` scan (`745752 B`) | `markerLeakFound: false` | `markerLeakFound: false` | `markerLeakFound: false` |
| Post-close `.db` scan (`57344 B`) | `markerLeakFound: false` | `markerLeakFound: false` | `markerLeakFound: false` |
| Elapsed / external wall (ms) | `21.12` / `71.47` | `127.25` / `243.30` | `61.04` / `131.44` |
| Internal `maxRSS` / External OS peak | `58.48 MiB` / `58.73 MiB` | `43.75 MiB` / `44.09 MiB` | `44.28 MiB` / `44.54 MiB` |

- **Leak-scan scope note:** V-0 scans the live `-wal` file while open and the post-close `.db` file for planted UTF-8 and UTF-16LE markers. Tests covering rollback journals (`DELETE`/`TRUNCATE`), SQLite temp/spill files under large transactions, and crash recovery with an uncheckpointed `-wal` remain in scope for `V-4` (encrypted index & WAL handling).

---

## 5. Open External Dependency: Windows 11 Smart App Control (`O-2` / `K-4`)

V-0 includes the native addon `better-sqlite3.node` inside `better-sqlite3-multiple-ciphers`. Under Windows 11 Smart App Control (**SAC**), unsigned native binaries/DLLs loaded via `dlopen` (`process.dlopen`) may be blocked unless signed or exempted, whereas development hosts with SAC disabled (`VerifiedAndReputablePolicyState = 0`) cannot prove SAC compatibility.

- **Status:** **OPEN (`O-2` / `K-4`)** — Not yet tested on a clean Windows 11 environment with Smart App Control in Enforced mode (`VerifiedAndReputablePolicyState = 1`).
- **Implication:** Per `docs/ROADMAP.md` (V-0 "Done when") and `docs/internal/BUILD_ASSIGNMENTS.md` (`K-4`), `pkg/v-0` cannot be marked `done` or merged to `main` until `O-2` executes `benchmarks/v0/run-all.mjs` on a clean Windows 11 image with SAC enabled and the unsigned/signed native addon behavior is recorded here (and in `docs/DECISIONS.md` if signing is required beyond `D-19`).

---

## 6. Architecture Section 9 Ceiling Decisions (`A-24`)

Per `docs/DECISIONS.md` entry **`A-24`** (updating `A-17`):

1. **Passphrase KDF commands (`256 MiB`):** **Confirmed.** Observed KDF peak (`177.45 MiB` Linux, `165.36 MiB` Windows) sits comfortably below `256 MiB`.
2. **Remaining Architecture section 9 full-command ceilings:** **Retained unchanged as provisional targets and explicitly deferred** to the packages implementing those workloads:
   - `vault verify` (`128 MiB`) -> `V-3` / `V-5`
   - `import` (`256 MiB`) -> `V-4` / `V-5`
   - `search` (`192 MiB`) -> `V-4` / `V-7`
   - `wizard` (`192 MiB`) -> `P-5`
   - `Mode A` receiver (`96 MiB`) -> `X-6`

V-0 makes no feasibility claim for full-command `wizard`, `Mode A`, 1 GiB `import`, full `vault verify`, or corpus-scale `search` workloads because those code paths do not exist yet in V-0; each downstream package must verify its own aggregate process-tree RSS against section 9 ceilings.

---

## 7. Summary and Next Action

| Gate | Status | Evidence |
|---|---|---|
| CI `check` (`ubuntu-latest`, `windows-latest`) | Pass | Run `44636722389` |
| CI `v0-measure` (`ubuntu-latest`, `windows-latest`) | Pass | Run `44636722389` |
| KDF `256 MiB` ceiling confirmed (`A-24`) | Pass | `177.45 MiB` Linux / `165.36 MiB` Windows |
| Isolated `128 MiB` stream probe (`128 MiB`) & SQLCipher probe (`192 MiB`) | Pass | `125.73 MiB` / `108.42 MiB`; `58.73 MiB` / `44.09 MiB` |
| Clean Windows 11 with Smart App Control ON (`O-2`) | **Open** | Parked on `pkg/v-0` pending `O-2` / `K-4` VM verification |
