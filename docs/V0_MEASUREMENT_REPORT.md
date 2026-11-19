# V-0 measurement report

Measured 2026-11-19 against pinned Node.js **24.22.3** x64 in GitHub Actions CI
(run `44631889007`, `v0-measure` matrix) and cross-checked locally on Windows x64
and WSL2 Ubuntu x64.

## 1. Test environments (by hardware class)

| Environment | OS / C library | Hardware class | Node.js |
| --- | --- | --- | --- |
| CI Linux (`ubuntu-latest`) | Ubuntu Linux x64, glibc 2.43 (`ldd (Ubuntu GLIBC 2.43-2ubuntu2.4) 2.43`) | 2 vCPUs, 7.7 GiB RAM | `24.22.3` |
| CI Windows (`windows-latest`) | Windows Server x64 | 2 vCPUs, 8.0 GiB RAM | `24.22.3` |
| Local Windows | Windows 11 x64 | 16 logical processors (12 cores), 15.7 GiB RAM | `24.22.3` |
| Local Linux (WSL2) | Ubuntu Linux x64, glibc 2.43 | 8 vCPUs, 3.7 GiB RAM (guest) | `24.21.0` (cross-check) |

## 2. Passphrase KDF (`scrypt`, `N = 131072`, `r = 8`, `p = 1`, 32-byte key, `maxmem = 256 MiB`)

Measured across 3 iterations in an isolated child process (`benchmarks/v0/measure-kdf.mjs`),
with both internal (`process.resourceUsage().maxRSS`) and external OS peak counters
(`os.wait4` `ru_maxrss` on Linux; Win32 `GetProcessMemoryInfo` `PeakWorkingSetSize` on Windows):

| Environment | Timings (ms) | Median (ms) | Internal peak (MiB) | External peak (MiB) | Ceiling (MiB) |
| --- | --- | ---: | ---: | ---: | ---: |
| CI Linux (`ubuntu-latest`) | 323.46, 311.32, 315.46 | 315.46 | 177.50 | 177.50 | 256 |
| CI Windows (`windows-latest`) | 429.02, 339.78, 326.02 | 339.78 | 165.25 | 165.25 | 256 |
| Local Windows | 832.13, 796.12, 881.15 | 832.13 | 171.26 | 171.26 | 256 |
| Local WSL2 Ubuntu (`24.21.0`) | 303.74, 263.08, 290.88 | 290.88 | 174.11 | 174.11 | 256 |

- All runs stayed well below the **256 MiB** KDF ceiling and under 1 second per unlock.
- `maxmem = 256 MiB` is explicitly required because Node.js defaults `maxmem` to 32 MiB while `128 * N * r * p` for `(2^17, 8, 1)` requires 128 MiB.

## 3. Streaming AES-256-GCM encryption and decryption (1 MiB frames)

Measured in an isolated child process (`benchmarks/v0/measure-encrypt.mjs`) over a
128 MiB synthetic payload (128 x 1 MiB frames) using Architecture section 4.2 construction
(HKDF-SHA256 per-record key, 12-byte nonce `0x00000000 || u64 frame_idx`, 94-byte AAD
binding header, `vault_id`, frame index, and final-frame flag), with full SHA-256 round-trip
verification:

| Environment | Encrypt (MiB/s) | Decrypt (MiB/s) | Internal peak (MiB) | External peak (MiB) | Ceilings (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| CI Linux (`ubuntu-latest`) | 3,162.63 | 3,814.48 | 123.17 | 123.17 | 128 verify / 256 import |
| CI Windows (`windows-latest`) | 1,078.60 | 1,205.63 | 110.55 | 110.55 | 128 verify / 256 import |
| Local Windows | 433.93 | 467.02 | 118.36 | 118.36 | 128 verify / 256 import |
| Local WSL2 Ubuntu (`24.21.0`) | 2,237.58 | 2,576.56 | 121.81 | 121.81 | 128 verify / 256 import |

- Round-trip SHA-256 verification passed on all environments (`128 MiB` verified).
- Peak memory stayed under both the **128 MiB** (`vault verify`) and **256 MiB** (`import`) ceilings.
  Note that synchronous tight-loop allocation of 1 MiB frame buffers sits near 123 MiB on Linux;
  production streaming in V-3/V-5 should yield/reuse frame buffers or write sequentially so peak RSS
  remains well below 128 MiB even for multi-gigabyte blobs.

## 4. SQLCipher native addon (`better-sqlite3-multiple-ciphers@13.2.0`, MIT)

In CI (`v0-measure`) and WSL2 Ubuntu, `better-sqlite3-multiple-ciphers@13.2.0` (sole runtime
dependency: `node-addon-api`, MIT) was compiled **from source** via `node-gyp rebuild --release --force_build=1`
with `FOUNDRY_V0_REQUIRE_BUILT=1` asserted in `benchmarks/v0/measure-sqlcipher.mjs`:

| Check | CI Linux (`ubuntu-latest`) | CI Windows (`windows-latest`) |
| --- | --- | --- |
| Builds from source in CI (`node 24.22.3`) | Pass (`build/Release/better_sqlite3.node`) | Pass (`build/Release/better_sqlite3.node`) |
| SQLite / SQLite3MC versions | `3.54.1` / `SQLite3 Multiple Ciphers 2.7.1` | `3.54.1` / `SQLite3 Multiple Ciphers 2.7.1` |
| Pinned config (`cipher=sqlcipher`, `legacy=4`, `legacy_page_size=4096`, `hmac_check=1`, `temp_store=2`, `secure_delete=1`) | Pass | Pass |
| `FTS5` virtual table (`porter unicode61`) + `MATCH` | Pass | Pass |
| `R-tree` (`rtree_i32`) virtual table + bounding query | Pass | Pass |
| Fail closed on wrong 32-byte key | Pass | Pass |
| Page authentication rejects 1-bit tamper on page 2 | Pass | Pass |
| Planted plaintext marker absent from `.db` bytes on disk | Pass (0 leaks in 57,344 bytes) | Pass (0 leaks in 57,344 bytes) |
| Internal / External peak RSS (MiB) | 56.91 / 58.03 | 42.84 / 43.26 |

- Note on local Windows: MSVC Build Tools were absent on the local workstation, so local Windows
  verified loading the package's prebuilt `win32-x64.node` binary (48.07 MiB internal / 48.31 MiB
  external), while CI proved full Windows and Linux source compilation on `windows-latest` and `ubuntu-latest`.

## 5. Windows 11 Smart App Control (**PENDING O-2 / K-4**)

- **Not yet verified.** The local workstation has Smart App Control disabled (`VerifiedAndReputablePolicyState = 0`),
  and GitHub Actions `windows-latest` runners do not enable Smart App Control.
- Per `docs/internal/BUILD_ASSIGNMENTS.md` section 4 (O-2) and section 9 (K-4), testing the unsigned
  native SQLCipher addon on a clean Windows 11 image with Smart App Control switched **on** remains an
  open owner item before V-0 can be declared complete.

## 6. Architecture section 9 ceilings confirmation

All measured operations satisfy the proposed ceilings in [ARCHITECTURE.md](ARCHITECTURE.md) section 9:

- KDF commands: peak **177.50 MiB** (Linux CI) / **165.25 MiB** (Windows CI) <= **256 MiB** ceiling (confirmed).
- Streaming encryption / verify: peak **123.17 MiB** (Linux CI) / **110.55 MiB** (Windows CI) <= **128 MiB** verify / **256 MiB** import ceilings (confirmed, with buffer-reuse discipline recommended in V-3/V-5).
- SQLCipher index open/query probe: peak **58.03 MiB** (Linux CI) / **43.26 MiB** (Windows CI) <= **192 MiB** `search` ceiling (confirmed).

No ceiling change is needed in [DECISIONS.md](DECISIONS.md).

## 7. CI compute observation (K-3)

CI run `44631889007` completed in `13s` (`check` Linux), `40s` (`check` Windows), `87s` (`v0-measure` Linux),
and `194s` (`v0-measure` Windows), using roughly 2 Linux runner minutes and 4 Windows runner minutes (~$0.05
equivalent against the $12/month free private-repo compute allowance).
