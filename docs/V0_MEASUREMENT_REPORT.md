# V-0 Measurement Report

Date: 2026-11-19
Commit measured: `596417f` (`596417fdc80d6b4714a1c7697475c935883639bf`, `pkg/v-0`)
Hosted CI run: `44638009731` (`ubuntu-latest` and `windows-latest`, Node `24.22.3`)

Note on revision provenance: the final documentation commit updates **only** `docs/V0_MEASUREMENT_REPORT.md` to record the metrics from hosted CI run `44638009731`. All benchmark code (`benchmarks/v0/*.mjs`), manifests (`benchmarks/v0/package.json`, `benchmarks/v0/package-lock.json`), CI workflow (`.github/workflows/ci.yml`), `docs/DEPENDENCIES.md`, and `docs/DECISIONS.md` remain byte-identical to measured commit `596417f`.

---

## 1. Scope and Measurement Methodology

V-0 evaluates three isolated runtime primitives and cross-platform native-addon assumptions before Vault implementation begins:

1. Passphrase KDF (`scrypt` at `N = 2^17`, `r = 8`, `p = 1`, `32`-byte derived key).
2. Streaming record framing and authenticated encryption (`FVR1` header + `1 MiB` frames + `AES-256-GCM` + `HKDF-SHA256`).
3. Encrypted index addon build, loading, extensions (`FTS5`, `R-tree`), SQLCipher pragma pinning, wrong-key and tampered-page fail-closed behavior, and plaintext marker absence (`better-sqlite3-multiple-ciphers` `13.2.0`, transitive `node-addon-api` `8.9.2`).

### Peak-Memory Counters and Process Scope

In `benchmarks/v0/run-all.mjs`, each benchmark executes in its own isolated Node child process:

- **Internal counter:** `process.resourceUsage().maxRSS` (KiB), read inside each child process after benchmark workload completion (covering child-process lifetime from startup through measurement).
- **External Linux OS counter:** `os.wait4()` `rusage.ru_maxrss` (KiB), read by the Python wrapper upon child exit.
- **External Windows OS counter:** Win32 `GetProcessMemoryInfo` `PeakWorkingSetSize` (bytes), read on the exited child process handle.

**Scope note:** Both internal and external counters measure each isolated benchmark child process individually across its lifetime from startup through measurement/exit. They do not measure aggregate launcher + helper process trees, nor do they exercise full end-to-end Vault commands (archive import, full-corpus index search, interactive wizard, or Mode A daemon pipelines).

### Test Environments

| Environment | OS / Arch | Node.js | CPU Cores | RAM | Libc / SQLCipher Binary |
|---|---|---|---|---|---|
| Hosted CI Linux (`ubuntu-latest`) | `linux` / `x64` | `24.22.3` | 2 | 7.7 GiB | GLIBC `2.43` (`2.43-2ubuntu2.4`) / `built-from-source` (`13.2.0`) |
| Hosted CI Windows (`windows-latest`) | `win32` / `x64` | `24.22.3` | 2 | 8.0 GiB | Win32 / `built-from-source` (`13.2.0`) |
| Local Windows verification | `win32` / `x64` | `24.22.3` | 16 | 15.7 GiB | Win32 / `default-resolution` prebuild (`13.2.0`) |

---

## 2. Passphrase KDF (`benchmarks/v0/measure-kdf.mjs`)

Parameters match `docs/ARCHITECTURE.md` section 5.2: `scryptSync` with `N = 131072` (`2^17`), `r = 8`, `p = 1`, `keylen = 32`, `maxmem = 268435456` (`256 MiB`), executed across `3` sequential iterations per child run.

| Metric | Hosted Linux CI (`44638009731`) | Hosted Windows CI (`44638009731`) | Local Windows (16c) |
|---|---|---|---|
| Iteration timings (ms) | `386.99`, `377.94`, `348.13` | `347.99`, `344.86`, `333.41` | `206.79`, `199.24`, `204.42` |
| Min / Median / Max (ms) | `348.13` / `377.94` / `386.99` | `333.41` / `344.86` / `347.99` | `199.24` / `204.42` / `206.79` |
| Child external wall (ms) | `1152.20` | `1103.37` | `674.81` |
| Internal `maxRSS` | `177.56 MiB` (`181824 KiB`) | `165.24 MiB` (`169208 KiB`) | `165.84 MiB` (`169820 KiB`) |
| External OS peak | `177.56 MiB` (`186187776 B`) | `165.24 MiB` (`173268992 B`) | `165.84 MiB` (`173895680 B`) |
| `256 MiB` KDF allowance | Pass (`kdfWithinBudget: true`) | Pass (`kdfWithinBudget: true`) | Pass (`kdfWithinBudget: true`) |

**Result:** The isolated `scrypt` primitive stays well below `256 MiB` on both platforms (`177.56 MiB` Linux, `165.24 MiB` Windows; `~345–378 ms` median on 2-core CI runners and `204.42 ms` on 16-core Windows). Full passphrase-command budgets remain to be verified in the packages implementing those commands per `A-24`.

---

## 3. Streaming AES-256-GCM Framing (`benchmarks/v0/measure-encrypt.mjs`)

Constructs the `69`-byte `FVR1` header (`headerTotalLen = 134220288`), derives the `32`-byte record key via `hkdfSync('sha256', collectionKey, salt, 'foundry/record-key/v1', 32)`, and encrypts/decrypts `128` x `1 MiB` frames (`128 MiB` plaintext; `134220288` encoded body bytes) using `64 KiB` streaming slices into reusable buffers, followed by SHA-256 round-trip equality and a 1-frame tamper check.

- **Timing & memory scope note:** `encryptMs` and `decryptMs` exclude SHA-256 verification (decrypted plaintext slices copy into a reusable `decryptedFrame` buffer inside `decryptMs`, and `roundtripHash.update(...)` runs afterward). `totalWallMs` covers the `128 MiB` payload loop plus the single-frame tamper check. `internalMaxRssKiB` and `externalPeakBytes` reflect child-process lifetime peak RSS from startup through measurement/exit.
- **CI gate policy:** `run-all.mjs` checks that this isolated probe stays below the `256 MiB` runaway-memory sanity guard (`streamProbeWithinSanityGuard: true`) and reports the provisional `128 MiB` `vault verify` target (`referenceVaultVerifyCeilingMiB: 128`) for reference only, deferred to V-3/V-5 per `A-24`.

| Metric | Hosted Linux CI (`44638009731`) | Hosted Windows CI (`44638009731`) | Local Windows (16c) |
|---|---|---|---|
| Payload / Frame / Slice | `128 MiB` / `1024 KiB` / `64 KiB` | `128 MiB` / `1024 KiB` / `64 KiB` | `128 MiB` / `1024 KiB` / `64 KiB` |
| Encrypt time / throughput | `73.54 ms` / `1740.64 MiB/s` | `120.56 ms` / `1061.70 MiB/s` | `96.56 ms` / `1325.61 MiB/s` |
| Decrypt time / throughput | `75.90 ms` / `1686.41 MiB/s` | `126.39 ms` / `1012.73 MiB/s` | `95.39 ms` / `1341.88 MiB/s` |
| Loop + tamper wall / child wall | `320.68 ms` / `367.73 ms` | `431.60 ms` / `522.48 ms` | `326.33 ms` / `402.63 ms` |
| Internal `maxRSS` / External OS peak | `124.90 MiB` / `124.90 MiB` | `108.60 MiB` / `108.60 MiB` | `110.13 MiB` / `110.13 MiB` |
| Round-trip + tamper rejected | `true` / `true` | `true` / `true` | `true` / `true` |
| `256 MiB` probe sanity guard | Pass (`streamProbeWithinSanityGuard: true`) | Pass (`streamProbeWithinSanityGuard: true`) | Pass (`streamProbeWithinSanityGuard: true`) |

---

## 4. SQLCipher Native Addon (`benchmarks/v0/measure-sqlcipher.mjs`)

Tests pinned `better-sqlite3-multiple-ciphers` **`13.2.0`** (with transitive `node-addon-api` `8.9.2`; embedding SQLite `3.54.1` and `SQLite3 Multiple Ciphers 2.7.1`). In CI, both `ubuntu-latest` and `windows-latest` force-rebuilt the native addon from source (`node-gyp@13.1.0 rebuild --release --force_build=1`) and loaded it via explicit `{ nativeBinding }` (`FOUNDRY_V0_REQUIRE_BUILT=1`), emitting `addonPackageVersion: "13.2.0"` and `loadedAddonVariant: "built-from-source"`. Local Windows verification loaded the shipped prebuild (`loadedAddonVariant: "default-resolution"`).

- **All 14 pinned SQLCipher compatibility & page-authentication pragmas verified via readback:**
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

| Metric | Hosted Linux CI (`44638009731`) | Hosted Windows CI (`44638009731`) | Local Windows (16c) |
|---|---|---|---|
| Package version reported at runtime | `13.2.0` | `13.2.0` | `13.2.0` |
| Addon variant loaded | `built-from-source` (`explicitNativeBindingUsed: true`) | `built-from-source` (`explicitNativeBindingUsed: true`) | `default-resolution` (prebuild) |
| `FTS5` & `R-tree` available | `true` & `true` | `true` & `true` | `true` & `true` |
| All 14 pinned pragmas match | Pass | Pass | Pass |
| Wrong key rejected | `true` (`SQLITE_NOTADB`) | `true` (`SQLITE_NOTADB`) | `true` (`SQLITE_NOTADB`) |
| Modified page rejected (`hmac_check=1`) | `true` (`SQLITE_CORRUPT`) | `true` (`SQLITE_CORRUPT`) | `true` (`SQLITE_CORRUPT`) |
| Control read (`hmac_check=0`) | `true` (bypassed as control) | `true` (bypassed as control) | `true` (bypassed as control) |
| Marker encodings scanned | `["utf8", "utf16le"]` | `["utf8", "utf16le"]` | `["utf8", "utf16le"]` |
| Live `-wal` scan (`745752 B`) | `markerLeakFound: false` | `markerLeakFound: false` | `markerLeakFound: false` |
| Post-close `.db` scan (`57344 B`) | `markerLeakFound: false` | `markerLeakFound: false` | `markerLeakFound: false` |
| Elapsed / external child wall (ms) | `21.85` / `81.96` | `79.77` / `173.34` | `91.30` / `189.43` |
| Internal `maxRSS` / External OS peak | `58.52 MiB` / `58.89 MiB` | `43.86 MiB` / `44.13 MiB` | `44.33 MiB` / `44.61 MiB` |
| `256 MiB` probe sanity guard | Pass (`sqlcipherProbeWithinSanityGuard: true`) | Pass (`sqlcipherProbeWithinSanityGuard: true`) | Pass (`sqlcipherProbeWithinSanityGuard: true`) |

- **Leak-scan and CI gate scope note:** Both the live `-wal` scan before checkpoint and the post-close `.db` scan check for both UTF-8 and UTF-16LE encodings of the planted marker string. Rollback-journal (`DELETE`/`TRUNCATE`), SQLite temp/spill files under large transactions, and crash recovery with an uncheckpointed `-wal` remain in scope for `V-4`. In `run-all.mjs`, the SQLCipher probe is gated by the `256 MiB` runaway-memory sanity guard while the provisional `192 MiB` `search` ceiling (`referenceSearchCeilingMiB: 192`) is reported for reference only per `A-24`.

---

## 5. Open External Dependency: Windows 11 Smart App Control (`O-2` / `K-4`)

V-0 loads the unsigned native addon binary `better_sqlite3.node` (`better-sqlite3-multiple-ciphers` `13.2.0`). Under Windows 11 Smart App Control (**SAC**), unsigned native addons loaded at runtime may be blocked unless signed or exempted, whereas hosts with SAC off (`VerifiedAndReputablePolicyState = 0`) cannot confirm SAC behavior.

- **Status:** **OPEN (`O-2` / `K-4`)** — Not yet verified on a clean Windows 11 image with Smart App Control enforced (`VerifiedAndReputablePolicyState = 1`) against the unsigned CI-built `13.2.0` binary.
- **Implication:** Per `docs/ROADMAP.md` (V-0 "Done when") and `docs/internal/BUILD_ASSIGNMENTS.md` (`K-4`), `pkg/v-0` remains parked on its branch (`proposed`) and cannot be marked `done` or merged to `main` until `O-2` is executed and recorded here (and in `docs/DECISIONS.md` if signing is required beyond `D-19`).

---

## 6. Architecture Section 9 Ceiling Decision (`A-24`)

Per `docs/DECISIONS.md` entry **`A-24`** (amending `A-17` and the V-0 acceptance timing for Architecture section 9 ceilings per Roadmap rule 4):

1. **Numerical ceilings retained unchanged:** All Architecture section 9 ceilings stay unchanged as target limits: passphrase KDF commands `256 MiB`, `vault verify` `128 MiB`, `import` `256 MiB`, `search` `192 MiB`, first-run `wizard` `192 MiB`, and `Mode A` receiver `96 MiB`.
2. **Amended V-0 acceptance scope & timing:** V-0 confirms only that the isolated `scrypt` KDF primitive (`177.56 MiB` Linux, `165.24 MiB` Windows) fits within the `256 MiB` allowance, and records isolated baseline probes for `FVR1` streaming AES-256-GCM (`124.90 MiB` Linux, `108.60 MiB` Windows for `128 MiB`) and `SQLite3MultipleCiphers` (`58.89 MiB` Linux, `44.13 MiB` Windows).
3. **Full-command confirmation deferred to implementing packages:** Because full commands do not exist yet in V-0, verifying full passphrase KDF commands and aggregate process-tree RSS against Architecture section 9 ceilings moves from V-0 to the packages that implement each command:
   - `V-1` / `V-3` / `V-5`: full passphrase KDF commands (`256 MiB`) and `vault verify` (`128 MiB`)
   - `V-4` / `V-5`: archive `import` (`256 MiB`)
   - `V-4` / `V-7`: full `search` (`192 MiB`)
   - `P-5`: first-run `wizard` (`192 MiB`)
   - `X-6`: `Mode A` receiver (`96 MiB`)

---

## 7. Summary

| Gate | Status | Evidence |
|---|---|---|
| CI `check` (`ubuntu-latest`, `windows-latest`) | Pass | Run `44638009731` |
| CI `v0-measure` (`ubuntu-latest`, `windows-latest`) | Pass | Run `44638009731` (`better-sqlite3-multiple-ciphers` `13.2.0` built from source) |
| Isolated KDF primitive within `256 MiB` (`A-24`) | Pass | `177.56 MiB` Linux / `165.24 MiB` Windows |
| Isolated stream & SQLCipher probes + UTF-8/UTF-16LE leak scans | Pass | `124.90 MiB` / `108.60 MiB`; `58.89 MiB` / `44.13 MiB`; `256 MiB` guard pass |
| Architecture section 9 full-command confirmation (`A-24`) | Amended timing | Deferred to `V-1`/`V-3`/`V-4`/`V-5`/`V-7`/`P-5`/`X-6` |
| Clean Windows 11 with Smart App Control ON (`O-2`) | **Open** | Parked on `pkg/v-0` pending `O-2` / `K-4` VM verification |
