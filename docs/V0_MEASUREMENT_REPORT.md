# V-0 measurement report

Measured 2026-11-19 against pinned Node.js **24.22.3** x64 in GitHub Actions CI
(run `44635599384`, `v0-measure` matrix) and cross-checked locally on Windows x64.

## 1. Test environments (by hardware class)

| Environment | OS / C library | Hardware class | Node.js |
| --- | --- | --- | --- |
| CI Linux (`ubuntu-latest`) | Ubuntu Linux x64, glibc 2.43 (`ldd (Ubuntu GLIBC 2.43-2ubuntu2.4) 2.43`) | 2 vCPUs, 7.7 GiB RAM | `24.22.3` |
| CI Windows (`windows-latest`) | Windows Server x64 | 2 vCPUs, 8.0 GiB RAM | `24.22.3` |
| Local Windows | Windows 11 x64 | 16 logical processors (12 cores), 15.7 GiB RAM | `24.22.3` |

## 2. Passphrase KDF (`scrypt`, `N = 131072`, `r = 8`, `p = 1`, 32-byte key, `maxmem = 256 MiB`)

Measured across 3 iterations in an isolated child process (`benchmarks/v0/measure-kdf.mjs`),
with both internal (`process.resourceUsage().maxRSS`) and external OS peak counters
(`os.wait4` `ru_maxrss` on Linux; Win32 `GetProcessMemoryInfo` `PeakWorkingSetSize` on Windows):

| Environment | Timings (ms) | Median (ms) | Internal peak (MiB) | External peak (MiB) | Ceiling (MiB) |
| --- | --- | ---: | ---: | ---: | ---: |
| CI Linux (`ubuntu-latest`) | 369.59, 353.75, 391.09 | 369.59 | 177.58 | 177.58 | 256 |
| CI Windows (`windows-latest`) | 262.94, 263.63, 250.04 | 262.94 | 165.31 | 165.31 | 256 |
| Local Windows | 249.44, 227.43, 228.76 | 228.76 | 165.85 | 165.85 | 256 |

- All runs stayed well below the **256 MiB** KDF ceiling and completed well under 1 second per unlock.
- Node.js defaults `scrypt` `maxmem` to 32 MiB, while `128 * N * r` at `(N = 2^17, r = 8)` needs
  128 MiB of working memory (with `p = 1`), so an explicit higher limit is required (`maxmem = 256 MiB`
  is the benchmark's configured cap).

## 3. Streaming AES-256-GCM encryption and decryption (1 MiB `FVR1` frames, 64 KiB slices)

Measured in an isolated child process (`benchmarks/v0/measure-encrypt.mjs`) over a
128 MiB synthetic payload (128 x 1 MiB frames, streamed in 64 KiB cipher/decipher slices)
using the Architecture section 4.2 construction: 69-byte `FVR1` header with
`total_len = 134,220,288` bytes (`128 * (4 + 1 MiB + 16)` encoded bytes following offset 69),
HKDF-SHA256 per-record key (`foundry/record-key/v1`), 12-byte nonce (`0x00000000 || u64 frame_idx`),
94-byte AAD binding header, `vault_id`, frame index, and final-frame flag, serialized and parsed
as `u32 BE ciphertext_len || ciphertext || 16-byte tag` with full SHA-256 round-trip
verification and 1-bit frame tamper rejection:

| Environment | Encrypt (MiB/s) | Decrypt (MiB/s) | Internal peak (MiB) | External peak (MiB) | Reference ceiling (MiB) |
| --- | ---: | ---: | ---: | ---: | --- |
| CI Linux (`ubuntu-latest`) | 1,705.76 | 833.22 | 122.50 | 123.00 | 128 verify / 256 import |
| CI Windows (`windows-latest`) | 1,522.80 | 872.92 | 108.43 | 108.43 | 128 verify / 256 import |
| Local Windows | 1,389.01 | 835.13 | 108.98 | 108.98 | 128 verify / 256 import |

- Encoded length (`134,220,288` bytes), round-trip SHA-256 equality, and 1-bit frame tamper
  rejection passed on all environments.
- Streaming 64 KiB `cipher.update()` / `decipher.update()` slices inside each 1 MiB `FVR1` frame
  keeps peak memory flat at `123.00 MiB` on Linux CI and `108.43 MiB` on Windows CI.

## 4. SQLCipher native addon (`better-sqlite3-multiple-ciphers@13.2.0`, MIT)

In CI (`v0-measure`), `better-sqlite3-multiple-ciphers@13.2.0` (sole runtime transitive
dependency: `node-addon-api`, MIT) was compiled **from source** with pinned `node-gyp@13.1.0`
(`node-gyp rebuild --release --force_build=1`) and loaded explicitly via
`{ nativeBinding: ".../build/Release/better_sqlite3.node" }` (`FOUNDRY_V0_REQUIRE_BUILT=1`):

| Check | CI Linux (`ubuntu-latest`) | CI Windows (`windows-latest`) |
| --- | --- | --- |
| Builds from source in CI (`node 24.22.3`) | Pass (`build/Release/better_sqlite3.node`) | Pass (`build/Release/better_sqlite3.node`) |
| Explicit `{ nativeBinding }` source-built load | Pass (`built-from-source`) | Pass (`built-from-source`) |
| SQLite / SQLite3MC versions | `3.54.1` / `SQLite3 Multiple Ciphers 2.7.1` | `3.54.1` / `SQLite3 Multiple Ciphers 2.7.1` |
| Pinned config (`cipher=sqlcipher`, `legacy=4`, `legacy_page_size=4096`, `hmac_use=1`, `hmac_check=1`, `hmac_pgno=1`, `hmac_salt_mask=58`, `hmac_algorithm=2`, `kdf_algorithm=2`, `plaintext_header_size=0`, `temp_store=2`, `secure_delete=1`) | Pass | Pass |
| `FTS5` virtual table (`porter unicode61`) + `MATCH` | Pass | Pass |
| `R-tree` (`rtree_i32`) virtual table + bounding query | Pass | Pass |
| Fail closed on wrong 32-byte key | Pass (`SQLITE_NOTADB`) | Pass (`SQLITE_NOTADB`) |
| Page-2 HMAC trailer bit-flip with `hmac_check=1` | Pass (`SQLITE_CORRUPT`) | Pass (`SQLITE_CORRUPT`) |
| Same tampered file with `hmac_check=0` control | Pass (intact read) | Pass (intact read) |
| Live `-wal` scan before checkpoint (`745,752` bytes) | Pass (0 leaks) | Pass (0 leaks) |
| Post-close `.db` scan after checkpoint (`57,344` bytes) | Pass (0 leaks) | Pass (0 leaks) |
| Internal / External peak RSS (MiB) | 58.43 / 58.80 | 43.73 / 44.06 |

- Local Windows (`44.32 MiB` internal / `44.61 MiB` external) used default package resolution
  (`loadedAddonVariant: default-resolution`, `explicitNativeBindingUsed: false`) because MSVC Build
  Tools were absent locally; CI proved full Windows and Linux source compilation and explicit
  `{ nativeBinding }` loading on `windows-latest` and `ubuntu-latest`.

## 5. Windows 11 Smart App Control (**PENDING O-2 / K-4**)

- **Not yet verified.** The local workstation has Smart App Control disabled (`VerifiedAndReputablePolicyState = 0`),
  and GitHub Actions `windows-latest` runners do not enable Smart App Control.
- Per `docs/internal/BUILD_ASSIGNMENTS.md` section 4 (O-2) and section 9 (K-4), testing the unsigned
  native SQLCipher addon on a clean Windows 11 image with Smart App Control switched **on** remains an
  open owner item before V-0 can be declared complete.

## 6. Architecture section 9 ceilings status (`A-24`)

Per [DECISIONS.md](DECISIONS.md) entry **A-24** (updating **A-17**):

- **Passphrase KDF (`256 MiB`):** **Confirmed** by the isolated KDF benchmark (**177.58 MiB** peak on Linux CI, **165.31 MiB** on Windows CI, median unlock under 370 ms on 2-vCPU CI runners).
- **Remaining section 9 ceilings (`vault verify` `128 MiB`, `import` `256 MiB`, `search` `192 MiB`, wizard `192 MiB`, Mode A receiver `96 MiB`):** Isolated V-0 probes demonstrate **feasibility** (`123.00 MiB` Linux / `108.43 MiB` Windows for `FVR1` frame encrypt+decrypt, and `58.80 MiB` Linux / `44.06 MiB` Windows for encrypted SQLite FTS5/R-tree setup), and **A-24** retains those command ceilings unchanged while explicitly deferring full-command confirmation to V-3, V-4, V-5, V-7, P-5, and X-6.

## 7. CI compute observation (K-3)

CI run `44635599384` completed in `23s` (`check` Linux), `34s` (`check` Windows), `112s` (`v0-measure` Linux),
and `178s` (`v0-measure` Windows), drawing roughly 3 Linux runner minutes and 4 Windows runner minutes (~$0.06
equivalent against the $12/month free private-repo compute allowance).
