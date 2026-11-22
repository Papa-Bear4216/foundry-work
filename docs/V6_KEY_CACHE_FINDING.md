# V-6 Key Cache Spike Finding

Date: 2026-11-21
Branch: `spike/v-6` (based on `main` @ `08baab9`; spike scripts recorded on branch `spike/v-6` at commit `3ba11ce`)
Related specs & decisions: [ARCHITECTURE.md](ARCHITECTURE.md) sections 5.1–5.4, 5.6, 5.7, 9, 10; [ROADMAP.md](ROADMAP.md) row V-6; [DECISIONS.md](DECISIONS.md) A-26, A-31, A-32, A-34; [V0_MEASUREMENT_REPORT.md](V0_MEASUREMENT_REPORT.md).

---

## 1. Executive Summary

Work package V-6 evaluates whether Foundry's two optional `KeyCache` adapters (`os-protected` on Windows, `os-session` on Linux) can be implemented **without a background daemon** and **without adding any runtime npm dependency** (Node built-ins plus OS tools invoked via `child_process` with `shell: false`), while keeping `none` as the always-working default.

| Adapter / Platform | Feasibility (no daemon, no new npm dep) | Verification Status | Recommendation |
|---|---|---|---|
| `none` (all platforms) | **Yes** (pure Node, no OS binary) | Verified in synthetic spike (`key-cache-port.mjs`, spike scripts on branch `spike/v-6` at commit `3ba11ce`) | **Build (permanent default)** — define `KeyCache` port + `none` adapter in `V-7` |
| `os-protected` (Windows DPAPI) | **Spike-demonstrated for synthetic keys**, via inbox Windows PowerShell 5.1 (`shell: false`, stdin/stdout pipe); production adoption requires resolving helper-path trust, binary-pipe memory handling, DPAPI output validation, full-record validation, policy probing, and `A-26` command budgets (Section 8) | **Partially tested empirically on Windows 11 (`win32/x64`)** (synthetic keys only; policy blocks, logout/reboot, password reset, roaming, and full-command ceilings **untested**) | **Build later (opt-in, Phase 2 / `P-5` or follow-up)** — defer until wizard warnings, Section 8 requirements, and pinned Node `24.22.3` CI verification exist |
| `os-session` (Linux kernel keyring) | **Conditionally yes with unresolved feasibility gates**: zero new *npm* dependencies, but requires `keyutils` (`/usr/bin/keyctl`) to be already installed or added as an extra OS package, requires a verified logout-revoked `@s` session ring (distinct from `@us`), and leaves the non-atomic `padd`-before-`timeout` window unresolved (Section 4.2) | **Untested here** (no WSL/Docker/VM started; answered from `keyutils`/`keyrings(7)`/`pam_keyinit(8)` docs; runnable script committed on branch `spike/v-6` at commit `3ba11ce`) | **Build later (opt-in)** — only after real Linux CI and desktop session testing and resolution of Section 8 requirements |
| macOS (Keychain) | **Documented partially feasible, with UX friction** (`/usr/bin/security -i`, persistent like `os-protected`, unsigned-binary ACL prompts) | **Untested** (macOS deferred per `D-5`) | **Do not build in v1** — revisit in Phase 3 (`X-7`) with code signing |

No commitment is made in V-6 to ship either OS adapter. `packages/vault` is untouched; any future implementation would go to Codex under a recorded decision (proposed in [DECISIONS.md](DECISIONS.md) `A-34`) and would have to satisfy every requirement in Section 8.

---

## 2. What Should Be Cached? (`KEK` vs `MK` vs Derived Sub-Key)

Architecture sections 5.1–5.4 define the key hierarchy:

```text
passphrase ──scrypt(N=2^17,r=8,p=1..2,salt)──► KEK (32 B) ─┐
                                                           ├─ unwraps ─► MK (32 B)
recovery key ──HKDF(vault_id)───────────────► RK  (32 B) ──┘               │
                                                                           ├─► PK -> CK -> enc / id keys
                                                                           ├─► index key (per generation)
                                                                           ├─► signing seed (Ed25519)
                                                                           └─► keyring-mac / profile-label / tombstone keys
```

Four candidates were evaluated for the cached value held in `KeyCache`:

| Candidate | Skips `scrypt` (`~128 MiB` algorithmic memory [`documented-by-vendor`], `204.42`–`377.94 ms` median [`measured` in V-0])? | Covers `search`, `import`, `verify --deep`? | Self-invalidates against current keyring on `change-passphrase`? | Self-invalidates against current keyring on `rekey --all`? | Exposes user's raw passphrase? | Verdict |
|---|---|---|---|---|---|---|
| Raw passphrase | No | Yes | Yes | Yes | **Yes** | **Reject** — still pays full KDF cost/memory and exposes reusable user secrets |
| `index` key only | Yes (for `search` only) | **No** (`import`, `verify --deep`, `rebuild`, signing fail) | No | Yes (index key rotated) | No | **Reject** — churns on every erasure/rebuild and still prompts on write/verify |
| Master key (`MK`) | Yes | Yes | **No** (`MK` is unchanged by `changePassphrase`) | Yes (`keyring.mac` fails) | No | **Runner-up** — survives `change-passphrase` against the current keyring if eviction fails or a stale cache blob is restored |
| **Passphrase-derived `KEK` (32 B)** | **Yes** | **Yes** | **Yes** (`kdf.salt` rotates; current `master.by_passphrase` GCM unwrap fails) | **Yes** (`kdf.salt` and `MK` both rotate) | **No** | **Recommended (if an OS adapter is later built)** |

### 2.1 Why `KEK` (bound to `vault_id` and `sha256(kdf.salt)`) wins over `MK`

1. **Same unlock scope as `MK` without skipping keyring authentication:** Caching the 32-byte `scrypt` output avoids running `scrypt` (measured in [V0_MEASUREMENT_REPORT.md](V0_MEASUREMENT_REPORT.md) at `165.84 MiB` local Windows / `165.24 MiB` Windows CI / `177.56 MiB` Linux CI `maxRSS`, and `204.42 ms` local 16-core Windows / `344.86 ms` 2-core Windows CI / `377.94 ms` 2-core Linux CI median wall time), while unlocking the full keyring (`index`, `collection`, `profile`, `signing`) via one AES-256-GCM unwrap of `master.by_passphrase` (unwrap latency **untested** in V-6) plus the standard `keyring.mac` check.
2. **Self-invalidating against the current keyring across passphrase changes:** Per `A-31` and `A-32` (`packages/vault/codec/src/keyring.ts`), `changePassphrase` generates a fresh 32-byte `kdf.salt`, derives a new `KEK`, re-wraps `master.by_passphrase` with the complete `kdf` object in its AAD, and leaves `MK` unchanged. If `MK` were cached and cache eviction failed (crash, permission error, or restored cache file), the stale `MK` would **still unlock the current keyring**. A stale `KEK` fails AES-256-GCM authentication against the **current** keyring's new `kdf` AAD and `master.by_passphrase` ciphertext, forcing cache eviction and a passphrase prompt.
3. **Never caches the recovery key (`RK`):** The recovery-key unlock path (`master.by_recovery`) is an emergency path that **MUST** remain independent of `KeyCache` and **MUST NOT** populate the cache.
4. **No bypass of v1 keyring verification:** Using a cached `KEK` **MUST** still authenticate the current keyring (`format`, `vault_id`, `kdf` bounds, `master.by_passphrase` slot AAD, and constant-time `keyring.mac`) before unwrapping any entry key.

### 2.2 Erasure Interaction and Limits (Architecture §5.7)

Caching `KEK` interacts with erasure in two distinct ways that must be stated explicitly:

1. **Surviving KEK or restorable DPAPI blob + an old keyring copy:** Salt rotation (`change-passphrase` or `rekey --all`) invalidates a cached `KEK` **only against the current keyring's `master.by_passphrase` wrap**. If an old `KEK` survives or a previously backed-up/shadow-copied DPAPI blob is restored alongside a matching **old keyring copy** (carrying the earlier `kdf.salt`), that `KEK` can still unwrap `MK` in the old keyring and recover the collection or index keys that old keyring held before erasure. This matches Architecture §5.3 and §5.7 limit 1: neither passphrase changes nor cache eviction cryptographically revoke historical keyring copies.
2. **Erasure that does not rotate `kdf.salt`:** Ordinary profile, collection, or item erasure (`foundry erase`, Architecture §5.7) destroys the target profile/collection/index keys in the working keyring (`wrapped: null`, `state: "destroyed"`) and appends withdrawal events (`consent.withdrawn`, `redaction.applied`, `key.destroyed`), but does **not** rotate `kdf.salt` or `MK`. Consequently, if cache eviction fails during `erase`, the old cached `KEK` remains cryptographically usable against the **current** keyring.

Accordingly, any future OS adapter and vault unlock path **MUST** enforce:
- Every cache-assisted read **MUST** authenticate the current keyring and honour Architecture §5.7 withdrawal events (`consent.withdrawn`, `redaction.applied`, `key.destroyed`) and destroyed-key states (`wrapped: null`, `state: "destroyed"`).
- High-privilege commands (`change-passphrase`, `rekey --all`, `erase`) **MUST NOT** read from `KeyCache`, **MUST** require fresh interactive authentication (passphrase or recovery key), and **MUST** evict the live cache entry (reporting eviction failure explicitly rather than ignoring it).
- **Explicit limit (live-cache eviction vs old-copy destruction):** Evicting the live cache removes the active cache file or revokes the active kernel key, but a `KeyCache` adapter **cannot guarantee destruction of historical copies** of a Windows DPAPI cache blob retained in OS Volume Shadow Copies, Windows File History, backups, cloud sync, or flash storage blocks (Architecture §5.7 limits 1–2; `R-4`).

---

## 3. Windows: `os-protected` (Per-User DPAPI)

### 3.1 Binary, Spike Invocation Contract, and Production Gaps

- **OS binary (spike):** Windows PowerShell 5.1 (`System32\WindowsPowerShell\v1.0\powershell.exe`), shipped inbox on Windows 10 and Windows 11 (`documented-by-vendor`). PowerShell 7 (`pwsh.exe`) does not ship inbox and is not required.
- **What the spike does (`win-dpapi-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`) — synthetic keys ONLY:**
  1. **Untrusted helper path resolution:** The spike constructs the helper path from the inherited `process.env.SystemRoot` (falling back to `C:\Windows`). An attacker or process able to override `SystemRoot` in the environment could redirect Foundry to a malicious executable that receives the `KEK` on stdin.
  2. **Unvalidated `protect` output:** The spike persists whatever `stdout` a successful `protect` invocation returns without validating that it is a genuine DPAPI ciphertext blob. A substituted or malfunctioning helper that echoes its input would cause plaintext `KEK` material to be written to disk.
  3. **Immutable string copies and incomplete error-path zeroing:** The spike passes `kek.toString('hex')` as a UTF-8 string over stdin/stdout (`encoding: 'utf8'`) and parses `$hex` / `[BitConverter]::ToString` in PowerShell, leaving immutable plaintext `KEK` copies in V8/Node strings and .NET managed strings that survive `Buffer.fill(0)` / `[Array]::Clear`. Additionally, `[Array]::Clear($bytes, ...)` is outside a `try`/`finally` block, so a parse or DPAPI error skips clearing `$bytes`.
  - All three shortcuts above are **acceptable only for the synthetic test keys in the spike**.
- **Production requirements (collected in Section 8):**
  - A production adapter **MUST** resolve the Windows system directory from a source the user environment cannot override — candidate mechanisms (**untested** here) are Win32 `GetSystemDirectoryW` / `GetSystemWindowsDirectoryW` (`kernel32.dll`; not directly exposed by Node.js built-ins, so verifying zero-addon access is an open implementation item) or verifying the canonical resolved path (`fs.realpathSync`, rejecting symlinks/reparse points) against machine-owned registry metadata (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot`, without using untrusted `SystemRoot`/`PATH` to query it), non-user-writable `SYSTEM`/`TrustedInstaller` ownership/ACLs, and Microsoft Authenticode signature verification.
  - A production adapter **MUST** refuse to spawn or send the `KEK` if the helper path does not resolve to that verified trusted path (failing closed to `none`).
  - A production adapter **MUST** validate `protect` stdout before persisting: strict base64/structure and length-bounds verification that the output is a well-formed DPAPI blob, plus an explicit check that neither the encoded output nor its decoded bytes equal or contain the plaintext `KEK` (raw, hex, or base64).
  - A production adapter **MUST** use bounded binary stdin/stdout pipes (`encoding: null` in Node; `[Console]::OpenStandardInput()` / `[Console]::OpenStandardOutput()` in PowerShell) and mutable byte buffers (`Buffer`/`Uint8Array` and `byte[]`) cleared in `finally` blocks on both sides, including every error path.
- **Process invocation arguments (spike):** `['-NoProfile', '-NonInteractive', '-NoLogo', '-OutputFormat', 'Text', '-EncodedCommand', base64Utf16LeScript]` with `shell: false`, `windowsHide: true`, and `timeout: 15_000` (spike configuration parameter).
- **On-disk cache location (if built):** Machine-local `%LOCALAPPDATA%\Foundry\cache\<vault_id>.dpapi.json` — **never** `%APPDATA%` (Roaming), so cached blobs do not roam with Roaming User Profiles.

### 3.2 Mechanisms Evaluated

1. **Mechanism A — `[System.Security.Cryptography.ProtectedData]` (`DataProtectionScope.CurrentUser`):**
   - Loads precompiled GAC assembly via `Add-Type -AssemblyName System.Security` (per vendor documentation, loading an existing GAC assembly does not invoke `csc.exe`; `documented-by-vendor`).
   - Operates on `byte[32]` and passes UTF-8 `optionalEntropy = "foundry/key-cache/v1:<vault_id>:<kdf_salt_sha256>"` so a blob moved to another vault or stale KDF salt fails DPAPI decryption before Node parses it (wrong entropy rejection: `measured`).
   - **Constrained Language Mode (CLM):** In the spike's simulated CLM test (`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'`), **a nonzero exit was observed, but the specific error cause was not isolated by the spike** (only `status !== 0` was checked). Per Microsoft documentation (`documented-by-vendor`, real policy-enforced CLM `untested` here), `Add-Type` and arbitrary .NET type invocation on `[ProtectedData]` are disallowed under CLM.
2. **Mechanism B — `ConvertTo-SecureString` / `ConvertFrom-SecureString` + `PSCredential`:**
   - Uses built-in `Microsoft.PowerShell.Security` cmdlets (`documented-by-vendor` to call `CryptProtectData` with `CurrentUser` scope) and pipeline `$input`.
   - Round-trip succeeded under both `FullLanguage` and simulated `ConstrainedLanguage` mode (`measured`).
   - **Tradeoffs:** Does not support `optionalEntropy` (`documented-by-vendor`), produces a larger hex-encoded DPAPI blob (`716` hex chars `measured`; `358 B` raw `estimated` as `716 / 2`, vs `262 B` raw / `352` base64 chars `measured` for Mechanism A), inherently handles the key as immutable `.NET` strings via `-AsPlainText` and `GetNetworkCredential().Password` (`documented-by-vendor`), and had **no child working-set measurement** in the spike (`untested`).

### 3.3 Empirical Measurements (Windows 11, `win32/x64`) and Budget Interpretation

Measured on one host (`Microsoft Windows 11 10.0.26320`, PowerShell `5.1.26100.9836`, Node `26.13.1` — note workspace CI pins Node `24.22.3`, so any production implementation must be measured on `24.22.3` in CI).

| Metric | Mechanism A (`ProtectedData`) | Mechanism B (`SecureString` / `PSCredential`) | Reference (`scrypt` in [V0_MEASUREMENT_REPORT.md](V0_MEASUREMENT_REPORT.md)) |
|---|---|---|---|
| Cold `protect` wall time | `583.94 ms` (`measured`) | `308.66 ms` single run on warm host (`measured`) | `204.42 ms` median 16c local / `344.86 ms` 2c Win CI (`measured` in V-0) |
| Warm `protect` (5 runs: min / median / max) | `271.36` / `294.65` / `614.90 ms` (`measured`) | `untested` | — |
| Cold `unprotect` wall time | `289.30 ms` (`measured`) | `594.36 ms` Full / `304.79 ms` sim. CLM, single run each (`measured`) | — |
| Warm `unprotect` (5 runs: min / median / max) | `264.84` / `278.92` / `303.96 ms` (`measured`) | `untested` | — |
| Child `powershell.exe` `PeakWorkingSet64` | `75.68 MiB` (`protect`) / `74.61 MiB` (`unprotect`) (`measured`, 1 sample each) | **`untested`** | — |
| Parent Node `maxRSS` | `64.28 MiB` across whole spike process (`measured`) | Not isolated (`untested` in isolation; shared `64.28 MiB` spike process) | `165.84 MiB` local Win / `165.24 MiB` Win CI (`measured` in V-0) |
| Aggregate process-tree peak (Node + child) | `~140 MiB` (`64.28 + 75.68 MiB`, **`estimated`** — sum of independent peaks in an isolated spike) | **`untested`** | `165.84 MiB` single process (`measured` in V-0) |
| Ciphertext size | `262 B` raw / `352` base64 chars (`measured`) | `716` hex chars (`measured`); `358 B` raw (`estimated`, `716 / 2`) | — |
| `master.by_passphrase` AES-256-GCM unwrap latency | **`untested`** | **`untested`** | — |
| `optionalEntropy` domain binding | **Yes** (`measured`: wrong entropy rejected) | **No** (`documented-by-vendor`) | — |
| 1-bit ciphertext tamper rejected | **Yes** (`measured`) | **`untested`** (DPAPI integrity `documented-by-vendor`) | — |
| Simulated `ConstrainedLanguage` mode | Nonzero exit observed; cause not isolated (`measured`) | Round-trip succeeded (`measured`: `308.95 ms` protect / `304.79 ms` unprotect) | — |

**Budget interpretation (Architecture §9 & `A-26`):**
- Spawning `powershell.exe` (`278.92 ms` warm median, `measured`) is *not* faster than local 16-core `scrypt` (`204.42 ms` median, `measured` in V-0), and is roughly comparable to 2-core Windows CI `scrypt` (`344.86 ms` median, `measured` in V-0). Its potential benefit is **UX** (avoiding repeated passphrase prompts) and avoiding the `~128 MiB` algorithmic `scrypt` working set (`documented-by-vendor`; `165.84 MiB` process peak `measured` in V-0) inside the main Node process.
- **No full-command budget proof:** The `~140 MiB` figure is an **`estimated`** sum of independent peaks from an isolated helper spike, NOT a measured command process-tree peak. **This spike does NOT show that `search` (`192 MiB` process / `384 MiB` tree ceiling) or any other Foundry command passes its Architecture §9 ceiling.** Per `A-26`, full-command process and process-tree budget verification belongs to the implementation package's CI gate on pinned Node `24.22.3`.

### 3.4 Secret-Exposure Probes (Windows): Observed vs Untested

The spike (`win-dpapi-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`) ran four narrow probes; **they do not establish zero exposure across all OS mechanisms**:

- **Observed in the spike (`measured`):**
  1. **Static `argv` and `env` check:** The synthetic hex key did not appear in the `args` array or the allowlisted `env` object (`SystemRoot`, `WINDIR`, `SYSTEMDRIVE`, `TEMP`, `TMP`, `PATHEXT`, `COMSPEC`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`) passed to `spawnSync` (`secretInArgvOrEnv: false`).
  2. **Live `Win32_Process.CommandLine` self-probe:** One dedicated probe invocation queried `Win32_Process.CommandLine` for its own `$PID` while receiving the synthetic hex key on stdin and reported `CONTAINS_SECRET=False` (`liveCommandLineLeaksSecret: false`).
  3. **Residual `%TEMP%` entries after the run:** Comparing `readdirSync(tmpdir())` before and after the spike's PowerShell runs showed no unexpected directory entries remaining after the run (excluding the spike's own `foundry-v6-win-*` directory) (`unexpectedTempEntriesCreated: []`).
  4. **`PSReadLine` history metadata:** Checking `ConsoleHost_history.txt` before and after the run showed unchanged existence, byte size, and `mtimeMs` (`psReadLineHistoryUnchanged: true`).
- **Explicitly `untested` in V-6:**
  - **Transient temporary files** created and deleted during execution (a before/after directory listing cannot detect short-lived temp files, nor files outside `%TEMP%`).
  - **Byte-for-byte equality** of `ConsoleHost_history.txt` (only existence, size, and `mtimeMs` were compared).
  - **PowerShell logging and transcription policies:** PowerShell Transcription (GPO `EnableTranscripting`), Module Logging (Event ID 4103), Script Block Logging (Event ID 4104), and AMSI/ETW instrumentation were not enabled or tested. (Vendor documentation states that Event ID 4104 logs script block text rather than stdin bytes — `documented-by-vendor`, `untested` here — while transcription/ETW capture of host I/O or same-user instrumentation falls outside Architecture §10's malware-as-user boundary but must still be understood before shipping.)

### 3.5 Tested Failure Modes vs Vendor-Documented Lifecycle & Policy Expectations

- **Tested in the spike (`measured`, synthetic):**
  - Missing helper path: `existsSync(psExe)` returned `false` (`missingBinaryProbeAvailable: false`, `reason: "powershell-missing"`, `set()` returned `false`).
  - 1-bit ciphertext tamper rejected (`tamperRejected: true`).
  - Wrong `optionalEntropy` rejected (`wrongEntropyRejected: true`).
  - Corrupt cache blob on `get()`: returned `null` and evicted the corrupt file (`corruptBlobReturnedNull: true`, `corruptBlobFileEvicted: true`).
  - Simulated `ConstrainedLanguage` mode: Mechanism A exited non-zero (`blockedInConstrainedLanguageMode: true`; exact cause not isolated by spike); Mechanism B completed round-trip (`constrainedLanguageRoundTripOk: true`).
- **Documented by vendor, `untested` in V-6:**
  - **Policy blocks with `powershell.exe` present (WDAC / AppLocker / Group Policy):** The spike's `probe()` checks only `existsSync(psExe)`, so it would falsely report `{ available: true }` when `powershell.exe` exists on disk but execution is blocked by policy. This is acceptable only for the synthetic spike; a production adapter's `probe()` **MUST** execute a real `protect`/`unprotect` round trip with a synthetic value before declaring the adapter available, and fall back to `none` on any failure.
  - **Real policy-enforced Constrained Language Mode** (as opposed to in-script `$ExecutionContext.SessionState.LanguageMode` assignment).
  - **Logout and reboot persistence:** Per Microsoft DPAPI documentation (`documented-by-vendor`, `untested` here), `DataProtectionScope.CurrentUser` blobs survive logout and reboot and decrypt once the user's Windows login unlocks their DPAPI master key.
  - **Forced administrator password reset:** Per Microsoft DPAPI documentation (`documented-by-vendor`, `untested` here), an out-of-band admin password reset invalidates access to the previous DPAPI master key (`Unprotect` fails with `CryptographicException`), which a production adapter must catch, evict, and degrade to `none`.
  - **Roaming profiles / AD Credential Roaming:** Storing blobs in `%LOCALAPPDATA%` avoids Roaming User Profile sync (`documented-by-vendor`, `untested` here), though Active Directory DPAPI Credential Roaming may still roam the user's DPAPI master key across domain machines (`documented-by-vendor`, `untested` here).

### 3.6 Recorded Output (`win-dpapi-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`)

```json
{
  "platform": "win32",
  "arch": "x64",
  "nodeVersion": "26.13.1",
  "binaryRelativeToSystemRoot": "System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "shellOption": false,
  "mechanismA_protectedData": {
    "roundTripOk": true,
    "blobCharsBase64": 352,
    "blobBytesRaw": 262,
    "coldProtectMs": 583.94,
    "warmProtect": {
      "samplesMs": [
        294.65,
        301.09,
        273.72,
        271.36,
        614.9
      ],
      "minMs": 271.36,
      "medianMs": 294.65,
      "maxMs": 614.9
    },
    "coldUnprotectMs": 289.3,
    "warmUnprotect": {
      "samplesMs": [
        278.92,
        296.59,
        265.93,
        264.84,
        303.96
      ],
      "minMs": 264.84,
      "medianMs": 278.92,
      "maxMs": 303.96
    },
    "childPeakWorkingSetMiB": {
      "protect": 75.68,
      "unprotect": 74.61
    },
    "nodeParentMaxRssMiB": 64.28,
    "stderrCleanOnSecretPath": true,
    "tamperRejected": true,
    "wrongEntropyRejected": true,
    "blockedInConstrainedLanguageMode": true
  },
  "mechanismB_secureString": {
    "fullLanguageRoundTripOk": true,
    "fullLanguageProtectMs": 308.66,
    "fullLanguageUnprotectMs": 594.36,
    "blobCharsHex": 716,
    "constrainedLanguageRoundTripOk": true,
    "constrainedLanguageProtectMs": 308.95,
    "constrainedLanguageUnprotectMs": 304.79,
    "supportsOptionalEntropy": false
  },
  "secretExposureChecks": {
    "secretInArgvOrEnv": false,
    "liveCommandLineLeaksSecret": false,
    "unexpectedTempEntriesCreated": [],
    "psReadLineHistoryUnchanged": true
  },
  "failToNoneChecks": {
    "missingBinaryProbeAvailable": false,
    "missingBinaryProbeReason": "powershell-missing",
    "missingBinarySetReturned": false,
    "corruptBlobReturnedNull": true,
    "corruptBlobFileEvicted": true,
    "fallbackEventsRecorded": 2
  }
}
```

---

## 4. Linux: `os-session` (Kernel Keyring via `keyctl`) — Untested Here

> **Testing status:** **Untested on this host.** Per V-6 host constraints, WSL, Docker, and VMs were not started on this memory-constrained Windows machine. Analysis below is derived from upstream Linux `keyrings(7)`, `session-keyring(7)`, `user-session-keyring(7)`, `pam_keyinit(8)`, `keyctl(1)`, and distribution packaging documentation (`documented-by-vendor`; all Linux runtime behaviour is `untested`). The runnable verification script `linux-keyctl-spike.mjs` is committed in the spike scripts on branch `spike/v-6` at commit `3ba11ce` for the owner or Linux CI (`ubuntu-latest`) to run on real Linux.

### 4.1 Binary Availability and Conditional Dependency Status

Node.js has no built-in wrapper for the `add_key(2)` / `keyctl(2)` Linux syscalls (`documented-by-vendor`). Without a native addon and without a daemon, Node must spawn `/usr/bin/keyctl` (or `/bin/keyctl` on pre-usr-merge systems) from the `keyutils` OS package with `shell: false`.

A packaging distinction exists between the shared library (`libkeyutils1` / `keyutils-libs`) and the CLI package (`keyutils`) (`documented-by-vendor`, `untested` here):

| Distribution | `keyutils` (`/usr/bin/keyctl`) installed by default? (`documented-by-vendor`) | Notes |
|---|---|---|
| Fedora Workstation / Server, RHEL / Rocky / Alma | **Usually yes** | Pulled in by core auth/NFS/security package groups; absent on minimal container images |
| Ubuntu Desktop / Server, Debian | **Not guaranteed** | `libkeyutils1` is usually installed (dependency of `libkrb5-3`/PAM/systemd), but the CLI package `keyutils` is omitted on minimal, netinst, cloud, and container images unless pulled in by desktop/NFS/ecryptfs tasks or `apt install keyutils` |
| Arch Linux | **No** | In `core`, not part of the `base` metapackage (`pacman -S keyutils` required) |

**Dependency consequence:** "No new dependency" is **conditional** for Linux `os-session`. The design adds zero runtime *npm* dependencies, but it requires `keyutils` to be **already installed or installed as an extra OS package**. When `keyctl` is absent, Foundry must degrade cleanly to `none`.

### 4.2 Command Contract, Unresolved Add-Before-Timeout Window, and Spike Gaps

- **NEVER use `keyctl add <type> <desc> <data> <ring>`:** passing `<data>` in `argv` exposes the raw key in `/proc/<pid>/cmdline` and `ps` (`documented-by-vendor`).
- **Stdin-only `keyctl padd` flow (`documented-by-vendor`, `untested` here):**
  1. **Store:** `keyctl padd user foundry:v1:<vault_id>:<salt_hash_16> @s` with raw 32-byte `KEK` written to `stdin` (`shell: false`, minimal `env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }`). Returns numeric `<key_id>` on stdout.
  2. **Set kernel-enforced TTL:** `keyctl timeout <key_id> <ttl_seconds>`. If `timeout` fails, immediately run `keyctl revoke <key_id>` and `keyctl unlink <key_id> @s`.
  3. **Read:** `keyctl search @s user <desc>` -> returns `<key_id>`; then `keyctl pipe <key_id>` -> writes the raw 32 bytes to stdout (never `keyctl print`, which hex-formats binary payloads).
  4. **Explicit clear:** `keyctl revoke <key_id>` followed by `keyctl unlink <key_id> @s`.
- **Unresolved feasibility condition — add-before-timeout window:** `keyctl(1)` has no atomic `padd`-with-TTL subcommand (`documented-by-vendor`). If `keyctl padd` succeeds in the kernel and the child times out or dies before returning `<key_id>` to Node, or if subsequent `revoke` and `unlink` calls fail after `timeout` fails, a key can remain in the keyring **without a kernel TTL**. In a shared or lingering keyring, that key could survive past logout. This race/failure window is an **unresolved feasibility condition** that any future Linux `os-session` implementation must solve (or prove bounded by verified logout-revoked ring teardown plus description-based cleanup) before shipping.
- **Spike script limitations (`linux-keyctl-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`) — synthetic only:**
  - `get()` returns `null` on `keyctl pipe` failure without running the eviction/cleanup contract (`revoke`/`unlink`).
  - `get()` copies `Buffer.from(res.stdout)` without zeroing `res.stdout`, leaving an uncleared copy of the `KEK` in memory.
  - Both gaps are acceptable only for the synthetic spike script; production requirements are listed in Section 8.
- **Latency and memory:** **`untested`** (not measured on this host; any figures must come from running the spike script on real Linux CI and desktop sessions).
- **Secret exposure:** Expected not to appear in `argv`, `/proc/<pid>/cmdline`, `env`, shell history, or temp files (`documented-by-vendor`, **`untested`** here).

### 4.3 Session (`@s`) vs User Session (`@us`) vs User (`@u`) Semantics and Logout Gotchas

Per `keyrings(7)`, `session-keyring(7)`, `user-session-keyring(7)`, and `pam_keyinit(8)` (`documented-by-vendor`, all `untested` here):

1. **Intended target (`@s`, `KEY_SPEC_SESSION_KEYRING`):** Created per login session by `pam_keyinit.so` and inherited across `fork`/`exec`. Destroyed when the last process holding a reference to that session keyring exits or PAM revokes it at session close.
2. **Gotcha A — `@s` fallback to `@us` and spike gap:** If a process has no explicit session keyring, accessing `@s` attaches the per-UID fallback `@us` (`user-session-keyring`), which is shared across all sessions of that UID and survives individual session logouts while any process for that UID remains (including `systemd --user` with `loginctl enable-linger`). The spike script (`linux-keyctl-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`) reports `distinctSessionKeyring` (`@s !== @us`) **but still writes to `@s` even when `@s == @us`** — acceptable only for the synthetic spike.
3. **Gotcha B — Distinct `@s` alone does NOT guarantee logout revocation:** Even when `@s !== @us`, a session keyring stays alive as long as any process or background service (such as `systemd --user` / `user@.service` or a detached daemon) retains a reference to it, or if PAM is not configured to revoke `@s` on session close. A production adapter **MUST** verify a session ring that is actually revoked at logout (distinct from `@us` and `@u`) before storing any `KEK`, and **MUST** refuse ambiguous or unverified setups by falling back to `none`.
4. **Gotcha C — `systemd --user` keyring disconnect:** On modern desktops (GNOME/KDE), terminal servers launched under `systemd --user` can run in a different `@s` than an SSH login or another terminal (`documented-by-vendor`, `untested`).
5. **Gotcha D — Do NOT use `@u` (`user-keyring`) for `os-session`:** `@u` persists across logins while any UID process runs and does not meet Architecture §5.6's "gone at logout" contract (`documented-by-vendor`).
6. **Other failure modes (`documented-by-vendor`, `untested`):**
   - Containers / Flatpak / sandboxes: seccomp profiles commonly block `add_key(2)`/`keyctl(2)` with `EPERM` or `ENOSYS` -> `probe()` fails -> fallback to `none`.
   - Kernel quotas: default per-UID limits are `kernel.keys.maxkeys = 200` and `kernel.keys.maxbytes = 20,000` (`documented-by-vendor`, `untested`) -> `EDQUOT` on `padd` -> fallback to `none`.

### 4.4 Recorded Non-Linux Output (`linux-keyctl-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`)

Syntax checked with `node --check` (exit `0`, `measured`) and executed on Windows to confirm clean non-Linux fail-to-`none` detection (no WSL/Docker/VM invoked):

```json
{
  "platform": "win32",
  "status": "untested-on-this-host",
  "probe": {
    "available": false,
    "reason": "not-linux"
  },
  "note": "Run on a real Linux host or CI runner (e.g. ubuntu-latest with keyutils installed)."
}
```

---

## 5. macOS — Untested and Deferred (`D-5`)

Per `DECISIONS.md` `D-5` and `ROADMAP.md` `X-7`, macOS is deferred until Phase 3. All statements below are `documented-by-vendor` and **`untested`** here:

- **Inbox binary:** `/usr/bin/security` ships with macOS and talks to the OS Keychain service (`securityd` — an OS service, not a Foundry daemon).
- **Secret exposure hazard:** `/usr/bin/security add-generic-password -w <secret>` puts `<secret>` in `argv` (`ps`). Safe use requires interactive stdin mode (`security -i`) or a native Security.framework call.
- **Persistence & UX:** Login Keychain entries persist across logout and reboot (closer to Windows `os-protected` than Linux `os-session`, with no OS-enforced TTL). Unsigned CLI binaries (`D-16`/`D-19`) trigger repeated macOS Keychain ACL confirmation dialogs on every update, making `security`-backed caching poor UX until builds are signed.
- **Verdict:** Mark **untested** and **do not build** in v1.

---

## 6. Threat Statements, Expiry Semantics, and Fail-to-`none` Contract

### 6.1 Exact Threat Statements (Architecture Section 10)

| Adapter | Who can read the cached key while live? | Powered-off device threat | Disk persistence | Cache expiry enforcement |
|---|---|---|---|---|
| `none` (default) | Nobody (key exists only in process RAM during one command, zeroed on exit) | Protected by passphrase `scrypt` (`N=2^17`) + vault/index encryption | None | Immediate (end of process) |
| `os-session` (Linux `keyctl` in `@s`) | **Any process running in the same Linux session keyring (`@s`) under the same UID** (or `root` / `CAP_SYS_PTRACE`) while the key has not expired (`documented-by-vendor`, `untested`) | Protected (kernel RAM only; gone at logout and power-off if `@s` is verified logout-revoked) | None (kernel RAM only, unswappable per `keyrings(7)`) | **Kernel-enforced** via `keyctl timeout <id> <ttl>` (`EKEYEXPIRED` + kernel GC) and session teardown at logout — subject to resolving the `padd`-before-`timeout` window (Section 4.2) |
| `os-protected` (Windows DPAPI `CurrentUser`) | **Any process running as the same Windows user account** (or local `SYSTEM`/Administrator with DPAPI backup key/impersonation) **until the cache file and any OS/backup copies are gone** (`documented-by-vendor`, `untested`) | **Weakened** (Architecture §10): survives reboot; offline security degrades to Windows account password / BitLocker rather than Foundry's passphrase | **Yes** — DPAPI ciphertext blob on disk in `%LOCALAPPDATA%` (and possibly retained in shadow copies/backups/flash outside Foundry's control) | **Advisory only** — Foundry checks `advisory_expires_at_ms` and deletes expired files on read, **but** an attacker running as the user can call `ProtectedData.Unprotect` directly on an expired or restored blob before Foundry cleans it up |

Note: Architecture section 5.6 requires the wizard to state this plainly in one sentence before enabling either cache: *"Caching means anyone who can run code as the user can read the vault while the cache is live."* For Windows `os-protected`, the prompt must additionally disclose that the cached unlock **survives reboot** until explicitly locked/cleared, and that live-cache eviction cannot guarantee destruction of historical OS/backup copies of the cache file.

### 6.2 How `none` Stays Default, Spike Wrapper Gaps, and Fail-to-`none` Contract

1. **Default configuration:** `KeyCache` defaults to `none` on every new vault and on every platform. Neither OS adapter is enabled automatically.
2. **Gaps in the spike scripts (`key-cache-port.mjs`, `win-dpapi-spike.mjs`, `linux-keyctl-spike.mjs` on branch `spike/v-6` at commit `3ba11ce`) — acceptable only for synthetic spike tests:**
   - **Unguarded diagnostics:** `createFailToNoneCache` invokes `onFallback` without `try`/`catch`, so a throwing callback can escape the wrapper and block the passphrase prompt; it also forwards raw `error.message` instead of fixed, non-secret reason codes.
   - **Incomplete Windows record validation:** `win-dpapi-spike.mjs` checks `record.advisory_expires_at_ms !== null && Date.now() > record.advisory_expires_at_ms`. A record with a missing (`undefined`), `NaN`, or non-numeric `advisory_expires_at_ms` (or missing/malformed `format`, `created_at_ms`, or `dpapi_blob_b64`) bypasses the expiry check and is still passed to `Unprotect`.
   - **Silent `clear()` failures:** `createFailToNoneCache.clear()` catches and swallows deletion errors, so an explicit `foundry lock` cannot distinguish an ordinary cache miss from a failed deletion.
   - **Linux read cleanup & stdout buffer:** `linux-keyctl-spike.mjs` returns `null` on `keyctl pipe` failure without running the eviction/cleanup contract and copies `Buffer.from(res.stdout)` without clearing `res.stdout`.
3. **Production fail-to-`none` contract (all collected as `MUST` requirements in Section 8):**
   - `probe()` returning `{ available: false }` disables caching and prompts for the passphrase.
   - Diagnostics callbacks are guarded (`try`/`catch`) and receive only fixed, enumerated, non-secret reason codes; they can never block the passphrase prompt.
   - On Windows `os-protected`, the complete cache record (including expiry presence, type, finiteness, and value, plus format/vault/salt/blob validation) is validated **before** invoking `Unprotect`; any malformed or expired record is evicted without calling `Unprotect`.
   - On both Windows and Linux, `get()` returning anything other than an exact 32-byte `Buffer` (or failing during read/unprotect) zeroes any partial or raw stdout buffer, attempts eviction (`clear`/unlink/revoke), emits a fixed non-secret diagnostic, and returns `null` (cache miss).
   - A cache miss always falls back to interactive passphrase entry (`none`). It **never** opens the vault unencrypted, **never** skips `keyring.mac` / `master.by_passphrase` AAD / §5.7 withdrawal and destroyed-key verification, and **never** blocks passphrase or recovery-key unlock.
   - An explicit `foundry lock` / `clear()` distinguishes an ordinary cache miss (no entry present -> idempotent success) from a deletion/revocation failure (**MUST** report failure explicitly).

---

## 7. Tested vs expected

Every number and substantive claim in this finding is classified below using exactly one status: `measured`, `estimated`, `documented-by-vendor`, or `untested`.

| Claim | Status (measured / estimated / documented-by-vendor / untested) | Evidence |
|---|---|---|
| Isolated `scrypt` (`N=2^17, r=8, p=1`) wall time: `204.42 ms` median (16c local Win), `344.86 ms` median (2c Win CI), `377.94 ms` median (2c Linux CI) | `measured` | [V0_MEASUREMENT_REPORT.md](V0_MEASUREMENT_REPORT.md) |
| Isolated `scrypt` `maxRSS`: `165.84 MiB` (local Win), `165.24 MiB` (Win CI), `177.56 MiB` (Linux CI) | `measured` | [V0_MEASUREMENT_REPORT.md](V0_MEASUREMENT_REPORT.md) |
| `scrypt` (`N=2^17, r=8, p=1`) algorithmic RAM usage `~128 MiB` (`128 * N * r`) | `documented-by-vendor` | RFC 7914 / Architecture §5.2 & §9 |
| `master.by_passphrase` AES-256-GCM unwrap latency | `untested` | No timing recorded in V-6 |
| Windows Mechanism A cold `protect` wall time: `583.94 ms` | `measured` | `win-dpapi-spike.mjs` output (Section 3.6; branch `spike/v-6` @ `3ba11ce`, Win 11, Node `26.13.1`) |
| Windows Mechanism A warm `protect` (5 runs): `271.36` / `294.65` / `614.90 ms` (min / median / max) | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism A cold `unprotect` wall time: `289.30 ms` | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism A warm `unprotect` (5 runs): `264.84` / `278.92` / `303.96 ms` (min / median / max) | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism A child `powershell.exe` `PeakWorkingSet64`: `75.68 MiB` (`protect`), `74.61 MiB` (`unprotect`) | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`, 1 sample each) |
| Windows spike parent Node `maxRSS`: `64.28 MiB` (combined spike process) | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism A aggregate process-tree peak `~140 MiB` (`64.28 + 75.68 MiB`) | `estimated` | Arithmetic sum of independent peaks from isolated spike; not a measured command tree peak |
| Windows Mechanism A ciphertext size: `262 B` raw (`352` base64 chars) | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism A round-trip, 1-bit tamper rejection, wrong `optionalEntropy` rejection, corrupt blob eviction on `get()`, missing-binary probe (`existsSync`), and `2` fallback events recorded | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism A under simulated `ConstrainedLanguage`: nonzero exit observed; specific error cause not isolated | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`; only `status !== 0` checked) |
| Windows Mechanism A specific CLM errors (`CannotDefineNewType` / `TypeNotFound`) and GAC assembly loading without `csc.exe` | `documented-by-vendor` | Microsoft PowerShell / .NET documentation (real policy CLM `untested` in V-6) |
| Windows Mechanism B wall time (single run each): `308.66 ms` Full protect, `594.36 ms` Full unprotect, `308.95 ms` sim. CLM protect, `304.79 ms` sim. CLM unprotect | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism B warm median timings | `untested` | Single run only in spike |
| Windows Mechanism B ciphertext length: `716` hex chars | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows Mechanism B ciphertext raw byte size: `358 B` | `estimated` | Derived as `716 / 2` from measured hex length |
| Windows Mechanism B child `powershell.exe` `PeakWorkingSet64`, isolated parent `maxRSS`, aggregate tree peak, and 1-bit tamper test | `untested` | Not measured in `win-dpapi-spike.mjs` |
| Windows Mechanism B lack of `optionalEntropy` and immutable `.NET` string handling | `documented-by-vendor` | Microsoft PowerShell `ConvertTo-SecureString` / `PSCredential` documentation |
| Full Foundry command ceilings (`search` `192 MiB` process / `384 MiB` tree, `import` `256 MiB`, etc.) with `os-protected` or `os-session` on pinned Node `24.22.3` | `untested` | Isolated spike only; deferred to implementation gate per `A-26` |
| Windows spike child timeout parameter (`15,000 ms`) exercised without timeout | `measured` | Spike configuration in `win-dpapi-spike.mjs` (`3ba11ce`) |
| Windows `argv`/`env` static check (`secretInArgvOrEnv: false`), single live `Win32_Process.CommandLine` self-probe (`liveCommandLineLeaksSecret: false`), residual `%TEMP%` entries after run (`[]`), `PSReadLine` history existence/size/`mtimeMs` unchanged | `measured` | Section 3.6 (`win-dpapi-spike.mjs`, `3ba11ce`) |
| Windows transient temp files created and deleted during run, non-`%TEMP%` writes, byte-for-byte `ConsoleHost_history.txt` equality, PowerShell Transcription, Module Logging (4103), Script Block Logging (4104) under real policy | `untested` | Not probed by `win-dpapi-spike.mjs` |
| PowerShell Event ID 4104 logs script block text rather than stdin bytes | `documented-by-vendor` | Microsoft PowerShell logging documentation (`untested` in V-6) |
| Windows non-env-overridable system directory resolution (`GetSystemDirectoryW` / `GetSystemWindowsDirectoryW` / `HKLM` + ACL + Authenticode) | `untested` | Candidate production mechanisms named in Section 3.1; not implemented in spike |
| Windows policy block (WDAC / AppLocker / GPO) with `powershell.exe` present, real policy-enforced CLM, logout persistence, reboot persistence, forced admin password reset, roaming profiles / AD Credential Roaming (runtime verification) | `untested` | Not executed on this host |
| Windows DPAPI `CurrentUser` survival across logout/reboot, invalidation on forced admin password reset, `%LOCALAPPDATA%` non-roaming, AD Credential Roaming, and PowerShell 5.1 inbox presence on Windows 10/11 | `documented-by-vendor` | Microsoft Windows / DPAPI documentation |
| Linux `linux-keyctl-spike.mjs` syntax check (`node --check` exit `0`) and Windows non-Linux fail-to-`none` probe (`reason: "not-linux"`) | `measured` | Section 4.4 (`linux-keyctl-spike.mjs`, `3ba11ce`) |
| Linux `os-session` runtime round-trip, `keyctl` latency, child/parent RSS, secret-exposure probes, `5,000 ms` child timeout / `2 s` TTL expiry test, `@s` vs `@us` topology, logout revocation, seccomp/quota failure handling | `untested` | No WSL/Docker/VM started per V-6 rule |
| Linux `keyrings(7)` / `session-keyring(7)` / `user-session-keyring(7)` / `pam_keyinit(8)` / `keyctl(1)` semantics, default quotas (`kernel.keys.maxkeys = 200`, `kernel.keys.maxbytes = 20,000`), and distro `keyutils` packaging | `documented-by-vendor` | Upstream Linux man pages and distro packaging rules |
| macOS `/usr/bin/security`, `security -i`, Login Keychain persistence, unsigned binary ACL prompts (runtime verification) | `untested` | Deferred per `D-5` |
| macOS `/usr/bin/security` CLI interface, Keychain persistence, and unsigned-binary ACL behavior | `documented-by-vendor` | Apple Keychain / `security(1)` documentation |

---

## 8. Requirements for Any Future `os-protected` / `os-session` Adapter

Any future Codex package authorized to implement `os-protected` (Windows) or `os-session` (Linux) **MUST** satisfy all of the following requirements (and keep `none` as the permanent default):

1. **Trusted Windows helper resolution (no untrusted `SystemRoot`):** A Windows `os-protected` adapter **MUST** resolve the Windows system directory from a source the user environment cannot override (evaluating untested candidates such as Win32 `GetSystemDirectoryW`/`GetSystemWindowsDirectoryW` or `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot` plus canonical realpath, non-user-writable `SYSTEM`/`TrustedInstaller` ACLs, and Microsoft Authenticode verification) and **MUST** refuse to spawn or send the `KEK` if the helper path does not resolve to that trusted binary.
2. **Validate Windows `protect` output before persisting:** Before writing a cache file, the Windows adapter **MUST** validate that `protect` stdout is a well-formed DPAPI blob (valid base64, DPAPI envelope structure and bounded length) and **MUST** verify that neither the encoded string nor the decoded bytes equal or contain the plaintext `KEK` (raw, hex, or base64).
3. **Binary pipes and `finally`-cleared mutable buffers (no immutable KEK strings):** The production Windows path **MUST** transfer raw `KEK` bytes over bounded binary stdin/stdout streams (`encoding: null` in Node; raw standard streams in PowerShell) using mutable byte buffers (`Buffer`/`Uint8Array` and `byte[]`), and **MUST** clear those buffers in `finally` blocks on both sides, including all parse, length, and DPAPI error paths.
4. **Live capability probe on Windows:** `probe()` **MUST** exercise a real `protect`/`unprotect` round trip with a synthetic dummy value (through the verified helper path and output validation) before declaring `os-protected` available, and **MUST** fall back to `none` on any failure (including WDAC/AppLocker/GPO blocks where `powershell.exe` is present on disk, CLM restrictions, or DPAPI failures).
5. **Full Windows cache-record validation before `Unprotect`:** `get()` **MUST** validate the entire cache record schema — `format`, `vault_id`, `kdf_salt_sha256`, finite `created_at_ms`, strict type/finiteness/bounds on `advisory_expires_at_ms` (rejecting missing, `undefined`, `NaN`, or malformed expiry values and enforcing expiry), and valid blob encoding/length — **before** invoking `Unprotect`, and **MUST** evict malformed or expired records without calling `Unprotect`.
6. **Current-keyring authentication and §5.7 erasure enforcement on every cached read:** Every cache-assisted unlock **MUST** authenticate the current keyring (`format`, `vault_id`, `kdf` bounds, `master.by_passphrase` AAD, constant-time `keyring.mac`) and **MUST** honour Architecture §5.7 withdrawal events (`consent.withdrawn`, `redaction.applied`, `key.destroyed`) and destroyed-key states (`wrapped: null`, `state: "destroyed"`).
7. **High-privilege commands bypass cache and evict live entries:** `change-passphrase`, `rekey --all`, and `erase` **MUST NOT** read from `KeyCache`, **MUST** require fresh interactive authentication, and **MUST** evict the live cache entry (propagating eviction errors clearly). Documentation and wizard prompts **MUST** state as an explicit limit that live-cache eviction cannot guarantee destruction of historical copies of a DPAPI cache blob in OS shadow copies, file history, backups, or flash storage.
8. **Independent recovery unlock:** Recovery-key unlock (`master.by_recovery`) **MUST** remain completely independent of `KeyCache` and **MUST NOT** populate the cache.
9. **Guarded, fixed non-secret diagnostics:** Diagnostic callbacks (`onFallback` / logging) **MUST** be wrapped in `try`/`catch` so they **MUST NOT** throw out of the cache wrapper or block interactive passphrase entry, and **MUST** emit only fixed, enumerated, non-secret reason codes (never raw subprocess output or arbitrary error strings).
10. **Explicit `lock` failure reporting:** An explicit `foundry lock` (or `clear()`) **MUST** distinguish an ordinary cache miss (no cached entry present -> idempotent success) from a failed deletion/revocation (**MUST** report failure explicitly to the caller/user).
11. **Linux verified logout-revoked session keyring:** A Linux `os-session` adapter **MUST** verify that the target session ring is actually revoked at logout and distinct from `@us`/`@u` before storing any `KEK`, and **MUST** refuse ambiguous or unverified keyring setups (degrading to `none`).
12. **Linux add-before-timeout feasibility gate:** A Linux `os-session` adapter **MUST** treat the non-atomic `keyctl padd` -> `keyctl timeout` window (including child timeout before returning `<key_id>` and `revoke`/`unlink` failure paths) as an unresolved feasibility condition and either solve it deterministically or refuse to ship the `keyctl`-CLI adapter.
13. **Linux OS package handling, read-failure cleanup, and stdout buffer zeroing:** A Linux `os-session` adapter **MUST** treat `keyutils` as an optional external OS package (failing to `none` when absent), **MUST** apply the same fail-closed cleanup/eviction contract on read failures as Windows, and **MUST** zero the original `keyctl pipe` stdout buffer (`res.stdout`) in `finally`.
14. **Implementation-package verification gates (`A-26`):** Before shipping either OS adapter, CI and platform verification **MUST** measure full-command process and process-tree peak memory against Architecture §9 ceilings on pinned Node `24.22.3`, test transient temp-file activity and byte-for-byte history equality, verify real Windows policy environments (CLM, WDAC/AppLocker, logging/transcription) and lifecycle cases (logout, reboot, admin password reset, roaming profiles), and execute real Linux CI and desktop session tests.

---

## 9. Recommendations and Conditional Scope for a Future Codex Package

1. **`none` adapter + `KeyCache` port contract — Build in `V-7` (CLI):**
   - Define the minimal `KeyCache` interface (`probe`, `get`, `set`, `clear`) and ship only `none` as the Phase 1 implementation, keeping the thin slice free of platform-specific cache complexity and external OS-binary assumptions.
2. **`os-protected` (Windows DPAPI) — Build later (opt-in, Phase 2 / `P-5` or dedicated follow-up):**
   - **Why later:** The spike demonstrated synthetic DPAPI round-trips without a daemon or new npm dependency, but Phase 1 has no wizard to present the mandatory Architecture §5.6/§10 warnings (including reboot persistence and old-copy limits), production hardening requirements (Section 8 items 1–10, 14) are not yet designed/tested, and full-command ceilings on pinned Node `24.22.3` plus Smart App Control (`D-22` / `P-6`) remain untested.
   - **Conditional design preference if later authorized:** Prefer Mechanism A (`ProtectedData` + `optionalEntropy` over `vault_id` and `sha256(kdf.salt)`) over binary pipes with trusted helper resolution, ciphertext validation, and live capability probing, degrading cleanly to `none` under Constrained Language Mode rather than maintaining a second `ConvertFrom-SecureString` path without `optionalEntropy`.
3. **`os-session` (Linux `keyctl`) — Build later (opt-in, conditional on Linux verification and feasibility gates):**
   - **Why later:** RAM-only kernel-TTL storage is the strongest caching model if it works reliably, **but** it is completely untested here, depends conditionally on the `keyutils` OS package, requires verified logout-revoked `@s` semantics, and has an unresolved `padd`-before-`timeout` window (Section 8 items 11–14).
   - **Prerequisite before any authorization:** Run `linux-keyctl-spike.mjs` (from the spike scripts on branch `spike/v-6` at commit `3ba11ce`) on real Linux CI (`ubuntu-latest` with `keyutils` installed) and on a desktop Linux session with `systemd --user`, and produce a design addressing Section 8 items 11–13.
4. **macOS — Do not build in v1 (`D-5`).** Re-evaluate in `X-7`.

### Conditional Scope for a Future Codex Package (Proposed `A-34`, Not a Commitment)

If the owner later authorizes implementing `os-protected` and/or `os-session`, a future Codex work package would need to:
1. **`packages/vault` (small additive API, if authorized):** Add an internal or exported `{ kek: Buffer }` unlock path (e.g., `unlockByKek`) in `packages/vault/codec/src/keyring.ts` and `keys.ts` that would still enforce `kdf` bounds, `master.by_passphrase` AAD, constant-time `keyring.mac`, and §5.7 destroyed-key/withdrawal rules, plus a helper returning the derived 32-byte `KEK` on passphrase unlock so the CLI could pass it to `KeyCache.set()` and immediately zero its local copy. `changePassphrase`, `rekeyAll`, `erase`, and recovery-key unlock would remain strictly interactive / independent of `KeyCache`.
2. **CLI / Wizard (`V-7` / `P-5`, if authorized):** Provide `foundry lock` (reporting deletion failures distinctly from misses), a `--no-cache` flag, explicit opt-in configuration (default `none`), and the one-sentence warning (plus reboot-persistence and old-copy-limit disclosures on Windows).
3. **CI and verification gates on pinned Node `24.22.3`:** Implement every requirement and gate in Section 8, including full-command `A-26` memory ceilings, real policy/lifecycle checks on Windows, and real Linux CI/desktop tests (with `keyutils` present and absent).
