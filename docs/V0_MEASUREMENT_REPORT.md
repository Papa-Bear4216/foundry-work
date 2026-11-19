# V-0 measurement report

Measured 2026-11-19 against pinned Node.js **24.22.3** x64 in GitHub Actions CI
(run `44633733065`, `v0-measure` matrix) and cross-checked locally on Windows x64.

## 1. Test environments (by hardware class)

| Environment | OS / C library | Hardware class | Node.js |
| --- | --- | --- | --- |
| CI Linux (`ubuntu-latest`) | Ubuntu Linux x64, glibc 2.43 (`ldd (Ubuntu GLIBC 2.43-2ubuntu2.7) 2.43`) | 2 vCPUs, 7.7 GiB RAM | `24.22.3` |
| CI Windows (`windows-latest`) | Windows Server x64 | 2 vCPUs, 8.0 GiB RAM | `24.22.3` |
| Local Windows | Windows 11 x64 | 16 logical processors (12 cores), 15.7 GiB RAM | `24.22.3` |

## 2. Passphrase KDF (`scrypt`, `N = 131072`, `r = 8`, `p = 1`, 32-byte key, `maxmem = 256 MiB`)

Measured across 3 iterations in an isolated child process (`benchmarks/v0/measure-kdf.mjs`),
with both internal (`process.resourceUsage().maxRSS`) and external OS peak counters
(`os.wait4` `ru_maxrss` on Linux; Win32 `GetProcessMemoryInfo` `PeakWorkingSetSize` on Windows):

| Environment | Timings (ms) | Median (ms) | Internal peak (MiB) | External peak (MiB) | Ceiling (MiB) |
| --- | --- | ---: | ---: | ---: | ---: |
| CI Linux (`ubuntu-latest`) | 389.52, 372.08, 343.05 | 372.08 | 176.33 | 176.33 | 256 |
| CI Windows (`windows-latest`) | 319.04, 333.21, 337.22 | 333.21 | 165.16 | 165.16 | 256 |
| Local Windows | 213.76, 206.60, 211.35 | 211.35 | 165.66 | 165.66 | 256 |

- All runs stayed well below the **256 MiB** KDF ceiling and completed well under 1 second per unlock.
- `maxmem = 256 MiB` is explicitly required because Node.js defaults `maxmem` to 32 MiB while `128 * N * r * p` for `(2^17, 8, 1)` requires 128 MiB.

## 3. Streaming AES-256-GCM encryption and decryption (1 MiB `FVR1` frames)

Measured in an isolated child process (`benchmarks/v0/measure-encrypt.mjs`) over a
128 MiB synthetic payload (128 x 1 MiB frames) using the Architecture section 4.2 construction:
69-byte `FVR1` header with `total_len = 134,220,288` bytes (`128 * (4 + 1 MiB + 16)` encoded bytes
following offset 69), HKDF-SHA256 per-record key (`foundry/record-key/v1`), 12-byte nonce
(`0x00000000 || u64 frame_idx`), 94-byte AAD binding header, `vault_id`, frame index, and
final-frame flag, serialized and parsed as `u32 BE ciphertext_len || ciphertext || 16-byte tag`
with full SHA-256 round-trip verification and 1-bit frame tamper rejection:

| Environment | Encrypt (MiB/s) | Decrypt (MiB/s) | Internal peak (MiB) | External peak (MiB) | Reference ceiling (MiB) |
| --- | ---: | ---: | ---: | ---: | --- |
| CI Linux (`ubuntu-latest`) | 1,737.36 | 1,986.48 | 127.00 | 127.74 | 128 verify / 256 import |
| CI Windows (`windows-latest`) | 728.31 | 1,148.23 | 111.35 | 111.35 | 128 verify / 256 import |
| Local Windows | 1,568.16 | 1,830.93 | 113.86 | 113.86 | 128 verify / 256 import |

- Encoded length (`134,220,288` bytes), round-trip SHA-256 equality, and 1-bit frame tamper
  rejection passed on all environments.
- Peak memory on Linux CI (`127.74 MiB`) sat just under `128 MiB` because a tight synchronous
  loop allocates intermediate cipher/decipher `Buffer` instances before V8 garbage collection
  runs. Production streaming in V-3 and V-5 should reuse buffers and yield across I/O
  boundaries so multi-gigabyte workloads stay well below the `128 MiB` and `256 MiB` budgets.

## 4. SQLCipher native addon (`better-sqlite3-multiple-ciphers@13.2.0`, MIT)

In CI (`v0-measure`), `better-sqlite3-multiple-ciphers@13.2.0` (sole runtime transitive
dependency: `node-addon-api`, MIT) was compiled **from source** with pinned `node-gyp@13.1.0`
(`node-gyp rebuild --release --force_build=1`) and loaded explicitly via
`{ nativeBinding: ".../build/Release/better_sqlite3.node" }` (`FOUNDRY_V0_REQUIRE_BUILT=1`):

| Check | CI Linux (`ubuntu-latest`) | CI Windows (`windows-latest`) |
| --- | --- | --- |
| Builds from source in CI (`node 24.22.3`) | Pass (`build/Release/better_sqlite3.node`) | Pass (`build/Release/better_sqlite3.node`) |
| Explicit `{ nativeBinding }` source-built load | Pass | Pass |
| SQLite / SQLite3MC versions | `3.54.1` / `SQLite3 Multiple Ciphers 2.7.1` | `3.54.1` / `SQLite3 Multiple Ciphers 2.7.1` |
| Pinned config (`cipher=sqlcipher`, `legacy=4`, `legacy_page_size=4096`, `hmac_check=1`, `temp_store=2`, `secure_delete=1`) | Pass | Pass |
| `FTS5` virtual table (`porter unicode61`) + `MATCH` | Pass | Pass |
| `R-tree` (`rtree_i32`) virtual table + bounding query | Pass | Pass |
| Fail closed on wrong 32-byte key | Pass (`SQLITE_NOTADB`) | Pass (`SQLITE_NOTADB`) |
| Page authentication rejects 1-bit tamper on page 2 | Pass (`SQLITE_CORRUPT`) | Pass (`SQLITE_CORRUPT`) |
| Live `-wal` scan before checkpoint (`745,752` bytes) | Pass (0 leaks) | Pass (0 leaks) |
| Post-close `.db` scan after checkpoint (`57,344` bytes) | Pass (0 leaks) | Pass (0 leaks) |
| Internal / External peak RSS (MiB) | 56.51 / 57.62 | 43.66 / 43.98 |

- Local Windows lacked MSVC Build Tools and exercised the package's bundled prebuild (`44.11 MiB`
  internal / `44.50 MiB` external, all SQLCipher/FTS5/R-tree/WAL/tamper checks passing); CI
  proved full Windows and Linux source compilation and explicit load on `windows-latest` and
  `ubuntu-latest`.

## 5. Windows 11 Smart App Control (**PENDING O-2 / K-4**)

- **Not yet verified.** The local workstation has Smart App Control disabled (`VerifiedAndReputablePolicyState = 0`),
  and GitHub Actions `windows-latest` runners do not enable Smart App Control.
- Per `docs/internal/BUILD_ASSIGNMENTS.md` section 4 (O-2) and section 9 (K-4), testing the unsigned
  native SQLCipher addon on a clean Windows 11 image with Smart App Control switched **on** remains an
  open owner item before V-0 can be declared complete.

## 6. Architecture section 9 ceilings status

Per Architecture section 9 and decision A-17:

- **Passphrase KDF (`256 MiB`):** **Confirmed** by the isolated KDF benchmark (**176.33 MiB** peak on Linux CI, **165.16 MiB** on Windows CI, median unlock under 380 ms on 2-vCPU CI runners).
- **`vault verify` (`128 MiB`), `import` (`256 MiB`), `search` (`192 MiB`):** These isolated V-0 probes establish **feasibility** (`127.74 MiB` Linux / `111.35 MiB` Windows for `FVR1` frame encrypt+decrypt, and `57.62 MiB` Linux / `43.98 MiB` Windows for encrypted SQLite FTS5/R-tree setup), while the full-command ceilings remain **provisional** until representative end-to-end workloads (streaming file hashes without key, full archive imports, and full search paths) are measured in V-3, V-4, V-5, and V-7.

No ceiling change is needed in [DECISIONS.md](DECISIONS.md).

## 7. CI compute observation (K-3)

CI run `44633733065` completed in `16s` (`check` Linux), `35s` (`check` Windows), `93s` (`v0-measure` Linux),
and `215s` (`v0-measure` Windows), drawing roughly 2 Linux runner minutes and 5 Windows runner minutes (~$0.06
equivalent against the $12/month free private-repo compute allowance).
