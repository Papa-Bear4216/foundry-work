# V-6 Key Cache Spike Finding

Date: 2026-11-21
Branch: `spike/v-6` (based on `main` @ `08baab9`)
Related specs & decisions: [ARCHITECTURE.md](ARCHITECTURE.md) sections 5.1–5.4, 5.6, 9, 10; [ROADMAP.md](ROADMAP.md) row V-6; [DECISIONS.md](DECISIONS.md) A-26, A-31, A-32, A-34.

---

## 1. Executive Summary

Work package V-6 answers whether Foundry's two optional `KeyCache` adapters (`os-protected` on Windows, `os-session` on Linux) can be implemented **without a background daemon** and **without adding any runtime npm dependency** (Node built-ins plus OS-shipped tools invoked via `child_process` with `shell: false`), while keeping `none` as the always-working default.

| Adapter / Platform | Feasibility (no daemon, no new npm dep) | Verification Status | Recommendation |
|---|---|---|---|
| `none` (all platforms) | **Yes** (pure Node, no OS binary) | Verified (`spikes/v-6/key-cache-port.mjs`) | **Build (permanent default)** — define `KeyCache` port + `none` adapter in `V-7` |
| `os-protected` (Windows DPAPI) | **Yes**, via inbox `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` (`shell: false`, stdin-only) | **Tested empirically on Windows 11 (`win32/x64`)** | **Build later (opt-in, Phase 2 / P-5)** — defer until wizard security warning & pinned Node 24 CI verification exist |
| `os-session` (Linux kernel keyring) | **Conditionally yes**, via `/usr/bin/keyctl` (`keyutils`) when installed and `@s` is initialized by `pam_keyinit` | **Untested here** (no WSL/Docker/VM started; answered from `keyutils`/`keyrings(7)`/`pam_keyinit(8)` docs + ready-to-run Linux script) | **Build later (opt-in)** — only after `spikes/v-6/linux-keyctl-spike.mjs` is measured on real Linux CI and desktop sessions |
| macOS (Keychain) | **Known partially feasible, with UX friction** (`/usr/bin/security -i`, persistent like `os-protected`, unsigned-binary ACL prompts) | **Untested** (macOS deferred per `D-5`) | **Do not build in v1** — revisit in Phase 3 (`X-7`) with code signing |

No commitment is made in V-6 to ship either OS adapter. `packages/vault` is untouched; any future implementation goes to Codex under a recorded decision (proposed in [DECISIONS.md](DECISIONS.md) `A-34`).

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

Four candidates were evaluated for the 32-byte (or variable) value held in `KeyCache`:

| Candidate | Skips `scrypt` (~128 MiB, 200–380 ms)? | Covers `search`, `import`, `verify --deep`? | Self-invalidates on `change-passphrase`? | Self-invalidates on `rekey --all`? | Exposes user's raw passphrase? | Verdict |
|---|---|---|---|---|---|---|
| Raw passphrase | No | Yes | Yes | Yes | **Yes** | **Reject** — still pays full KDF cost/memory and exposes reusable user secrets |
| `index` key only | Yes (for `search` only) | **No** (`import`, `verify --deep`, `rebuild`, signing fail) | No | Yes (index key rotated) | No | **Reject** — churns on every erasure/rebuild and still prompts on write/verify |
| Master key (`MK`) | Yes | Yes | **No** (MK is unchanged by `changePassphrase`) | Yes (MAC fails) | No | **Runner-up** — survives `change-passphrase` if eviction fails or a stale cache blob is restored |
| **Passphrase-derived `KEK` (32 B)** | **Yes** | **Yes** | **Yes** (`kdf.salt` rotates; `master.by_passphrase` GCM unwrap fails) | **Yes** (`kdf.salt` and `MK` both rotate) | **No** | **Recommended** |

### Why `KEK` (bound to `vault_id` and `sha256(kdf.salt)`) wins over `MK`

1. **Identical performance and scope to `MK`:** Caching the 32-byte `scrypt` output eliminates the `~128 MiB` KDF memory spike and `~200–380 ms` CPU cost on every command, while unlocking the full keyring (`index`, `collection`, `profile`, `signing`) via one AES-256-GCM unwrap of `master.by_passphrase` (`< 0.1 ms`) plus the standard `keyring.mac` check.
2. **Self-invalidating across passphrase changes by cryptographic construction:** Per `A-31` and `A-32` (`packages/vault/codec/src/keyring.ts`), `changePassphrase` generates a fresh 32-byte `kdf.salt`, derives a new `KEK`, re-wraps `master.by_passphrase` with the complete `kdf` object in its AAD, and leaves `MK` unchanged. If `MK` were cached and cache deletion failed (crash, permission error, or restored cache file), the stale `MK` would **still unlock the new keyring**. A stale `KEK` automatically fails AES-256-GCM authentication against the new `kdf` AAD and `master.by_passphrase` ciphertext, forcing a clean cache eviction and passphrase prompt.
3. **Never caches the recovery key (`RK`):** Recovery unlock is an emergency path and must not populate a cache; requiring passphrase-derived `KEK` enforces this naturally.
4. **No bypass of v1 keyring verification:** Using `KEK` still runs `unlockMaster` over `master.by_passphrase` (validating `format`, `vault_id`, `kdf` bounds, slot AAD, and `keyring.mac`) before unwrapping any entry key.
5. **High-privilege commands never read the cache:** `change-passphrase`, `rekey --all`, and `erase` must always require fresh interactive authentication (passphrase or recovery key) and call `cache.clear(desc)` after publishing the updated keyring.

---

## 3. Windows: `os-protected` (Per-User DPAPI)

### 3.1 Binary and Invocation Contract

- **OS binary:** `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` (Windows PowerShell 5.1, shipped inbox on all Windows 10 and Windows 11 installations). PowerShell 7 (`pwsh.exe`) does not ship inbox and is not required.
- **Process invocation:** `child_process.spawnSync(psExe, args, { shell: false, input, encoding: 'utf8', timeout: 15_000, windowsHide: true, env })` using the absolute System32 path (no `PATH` lookup hijacking, no `cmd.exe`).
- **Arguments:** `['-NoProfile', '-NonInteractive', '-NoLogo', '-OutputFormat', 'Text', '-EncodedCommand', base64Utf16LeScript]`.
- **Secret channel:** Strict stdin/stdout pipe only. On `protect`, Node writes 64 lowercase hex chars + `\n` to stdin and reads base64 DPAPI ciphertext from stdout. On `unprotect`, Node writes base64 ciphertext to stdin and reads 64 hex chars from stdout, converts to a 32-byte `Buffer`, and zeroes intermediate buffers.
- **On-disk cache location (if built):** Machine-local `%LOCALAPPDATA%\Foundry\cache\<vault_id>.dpapi.json` — **never** `%APPDATA%` (Roaming), so cached blobs do not roam across domain machines.

### 3.2 Mechanisms Evaluated

1. **Mechanism A — `[System.Security.Cryptography.ProtectedData]` (`DataProtectionScope.CurrentUser`):**
   - Loads precompiled GAC assembly via `Add-Type -AssemblyName System.Security` (does **not** invoke `csc.exe` and creates zero temp files).
   - Operates directly on raw `byte[32]`, zeroes the buffer via `[Array]::Clear($bytes, 0, $bytes.Length)` before exit, and passes UTF-8 `optionalEntropy = "foundry/key-cache/v1:<vault_id>:<kdf_salt_sha256>"` so a blob moved to another vault or stale KDF salt fails DPAPI decryption before Node even parses it.
   - **Limitation:** Blocked under PowerShell **Constrained Language Mode (CLM)** (`Add-Type` fails with `CannotDefineNewType`; `[ProtectedData]` fails with `TypeNotFound`).
2. **Mechanism B — `ConvertTo-SecureString` / `ConvertFrom-SecureString` + `PSCredential`:**
   - Uses built-in `Microsoft.PowerShell.Security` cmdlets (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`, `CurrentUser` scope) and pipeline `$input` instead of `[Console]::In`.
   - **Verified working even under simulated `ConstrainedLanguage` mode** (because `ConvertTo-SecureString`, `ConvertFrom-SecureString`, and `System.Management.Automation.PSCredential` are on the PowerShell CLM core allowlist).
   - **Tradeoffs:** Does not support `optionalEntropy`, produces a larger hex-encoded UTF-16LE DPAPI blob (`716` chars vs `352` base64 chars), and allocates the hex key as a managed `.NET` `String` until the short-lived `powershell.exe` child exits.

### 3.3 Empirical Measurements (Windows 11, `win32/x64`)

Measured on this host (`Microsoft Windows 11 10.0.26320`, PowerShell `5.1.26100.9836`, Node `26.13.1` — note that workspace CI pins Node `24.22.3`, so production numbers must be re-confirmed on `24.22.3` in CI).

| Metric | Mechanism A (`ProtectedData`) | Mechanism B (`SecureString` / `PSCredential`) | Reference (`scrypt` V-0 local Windows) |
|---|---|---|---|
| Cold `protect` wall time | `583.94 ms` | `308.66 ms` (warm host) | `204.42 ms` median (16c) / `344.86 ms` (2c CI) |
| Warm `protect` (5 runs: min / median / max) | `271.36` / `294.65` / `614.90 ms` | — | — |
| Cold `unprotect` wall time | `289.30 ms` | `594.36 ms` (Full) / `304.79 ms` (CLM) | — |
| Warm `unprotect` (5 runs: min / median / max) | `264.84` / `278.92` / `303.96 ms` | — | — |
| Child `powershell.exe` `PeakWorkingSet64` | `75.68 MiB` (`protect`) / `74.61 MiB` (`unprotect`) | Same runtime host (~75 MiB) | — |
| Parent Node `maxRSS` | `64.28 MiB` | `64.28 MiB` | `165.84 MiB` (`scrypt` alone) |
| Aggregate process-tree peak (Node + child) | `~140 MiB` (well below `search` `384 MiB` tree cap) | `~140 MiB` | `165.84 MiB` (single process) |
| Ciphertext size | `262 B` raw (`352` base64 chars) | `358 B` raw (`716` hex chars) | — |
| `optionalEntropy` domain binding | **Yes** (verified: wrong entropy rejected) | **No** | — |
| 1-bit ciphertext tamper rejected | **Yes** (DPAPI HMAC fails closed) | Yes (DPAPI) | — |
| Works in `ConstrainedLanguage` mode | **No** (`CannotDefineNewType` / `TypeNotFound`) | **Yes** (verified round-trip) | — |

**Budget interpretation (Architecture section 9):** Spawning `powershell.exe` (`~279 ms` warm median) is *not* faster than local `scrypt` (`~204 ms`), and is roughly comparable to 2-core CI `scrypt` (`~345 ms`). Its practical benefit is **UX** (skipping interactive passphrase entry across repeated CLI commands) and **lower main-process memory** (`~64 MiB` Node + `~75 MiB` short-lived child, avoiding the `128 MiB` scrypt allocation in `search`, whose ceiling is `192 MiB` process / `384 MiB` tree).

### 3.4 Secret-Exposure Verification (Windows)

All four exposure vectors were checked empirically in `spikes/v-6/win-dpapi-spike.mjs`:

1. **`argv` / live `Win32_Process.CommandLine`:** Confirmed `false` (`secretInArgvOrEnv: false`, `liveCommandLineLeaksSecret: false`). The `-EncodedCommand` script is static code with zero secret material; the key crosses only via the anonymous stdin pipe.
2. **Environment variables:** Minimal allowlisted environment (`SystemRoot`, `WINDIR`, `SYSTEMDRIVE`, `TEMP`, `TMP`, `PATHEXT`, `COMSPEC`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`); no secret ever placed in `env`.
3. **Temporary files:** Snapshot of `%TEMP%` before and after all 12+ `powershell.exe` runs showed `unexpectedTempEntriesCreated: []`. (`Add-Type -AssemblyName System.Security` loads a GAC assembly without compiling or writing temp files.)
4. **Console history & logging:** `PSReadLine` `ConsoleHost_history.txt` was byte-for-byte untouched (`psReadLineHistoryUnchanged: true`), because `-NoProfile -NonInteractive` does not load PSReadLine. If PowerShell Script Block Logging (Event ID 4104) is enabled by policy, it logs only the static wrapper script, never the stdin payload. (Full OS-level PowerShell transcription or ETW pipe capture requires local admin / same-user instrumentation, already outside the threat model in Architecture section 10.)

### 3.5 Behaviour After Logout/Reboot and Failure Modes (Windows)

- **Logout and reboot:** DPAPI `CurrentUser` blobs **survive both logout and reboot**. When the user logs back in (password, Windows Hello PIN, or biometrics), Windows unlocks their DPAPI master key automatically and the cached blob decrypts immediately.
- **Forced admin password reset:** Invalidates access to the old DPAPI master key; `Unprotect` throws `CryptographicException` ("Key not valid for use in specified state"). The adapter catches the error, deletes the unreadable cache file, and falls back to `none`.
- **Roaming profiles / domain Credential Roaming:** Keeping the cache file in `%LOCALAPPDATA%` prevents the blob itself from roaming. On domain-joined machines with Active Directory DPAPI Credential Roaming enabled, the user's DPAPI master key may roam across domain machines, though the cache file stays local.
- **PowerShell missing or blocked (WDAC / AppLocker / Group Policy):** `probe()` detects missing binary or non-zero exit; `set()` returns `false`; `get()` returns `null` -> clean fallback to `none`.
- **Constrained Language Mode (CLM):** Mechanism A (`ProtectedData`) fails with exit code 1 -> caught and degraded to `none` (never fails open).
- **Corrupted/tampered cache file:** `Unprotect` exits non-zero -> fail-to-`none` wrapper deletes the corrupt file (`corruptBlobFileEvicted: true`) and returns `null`, prompting for passphrase.

### 3.6 Recorded Output (`node spikes/v-6/win-dpapi-spike.mjs`)

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

> **Testing status:** **Untested on this host.** Per V-6 host constraints, WSL, Docker, and VMs were not started on this memory-constrained Windows machine. Analysis below is derived from upstream Linux `keyrings(7)`, `session-keyring(7)`, `user-session-keyring(7)`, `pam_keyinit(8)`, `keyctl(1)`, and distribution packaging rules. The runnable verification script [spikes/v-6/linux-keyctl-spike.mjs](../spikes/v-6/linux-keyctl-spike.mjs) is committed on this branch for the owner or Linux CI (`ubuntu-latest`) to execute on real Linux.

### 4.1 Binary Availability Across Major glibc Distributions

Node.js has no built-in wrapper for the `add_key(2)` / `keyctl(2)` Linux syscalls. Without a native addon and without a daemon, Node must spawn `/usr/bin/keyctl` (or `/bin/keyctl` on pre-usr-merge systems) from the `keyutils` package with `shell: false`.

A crucial packaging distinction exists between the shared library (`libkeyutils1` / `keyutils-libs`) and the CLI package (`keyutils`):

| Distribution | `keyutils` (`/usr/bin/keyctl`) installed by default? | Notes |
|---|---|---|
| Fedora Workstation / Server, RHEL / Rocky / Alma | **Usually yes** | Pulled in by core auth/NFS/security package groups; absent on minimal container images |
| Ubuntu Desktop / Server, Debian | **Not guaranteed** | `libkeyutils1` is usually installed (dependency of `libkrb5-3`/PAM/systemd), but the CLI package `keyutils` is omitted on minimal, netinst, cloud, and container images (and only present when pulled in by desktop/NFS/ecryptfs tasks or `apt install keyutils`) |
| Arch Linux | **No** | In `core`, but not part of the `base` metapackage (`pacman -S keyutils` required) |

**Consequence:** `os-session` cannot be assumed available out of the box on every v1 glibc Linux machine; it is an optional capability that probes `/usr/bin/keyctl` (and `/bin/keyctl`) and degrades cleanly to `none` when absent.

### 4.2 Exact Command Contract and Secret-Exposure Rules

- **NEVER use `keyctl add <type> <desc> <data> <ring>`:** passing `<data>` on the command line exposes the raw key in `/proc/<pid>/cmdline` and `ps`.
- **Use stdin-only `keyctl padd`:**
  1. **Store:** `keyctl padd user foundry:v1:<vault_id>:<salt_hash_16> @s` with the raw 32-byte `KEK` written to `stdin` (`shell: false`, minimal `env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }`). Returns numeric `<key_id>` on stdout.
  2. **Set kernel-enforced TTL immediately:** `keyctl timeout <key_id> <ttl_seconds>`. If `timeout` fails, immediately run `keyctl revoke <key_id>` and `keyctl unlink <key_id> @s` (fail closed — never leave an immortal key). Note there is a brief (millisecond) window between `padd` and `timeout`; a crash inside that window could leave a key without a TTL until logout, which is acceptable only inside a true `@s` session keyring that is destroyed at logout.
  3. **Read:** `keyctl search @s user <desc>` -> returns `<key_id>`; then `keyctl pipe <key_id>` -> writes the exact 32 raw bytes to stdout (never `keyctl print`, which hex-formats binary payloads).
  4. **Explicit clear:** `keyctl revoke <key_id>` followed by `keyctl unlink <key_id> @s`.
- **Secret exposure:** Payload never appears in `argv`, `/proc/<pid>/cmdline`, `env`, shell history, or temp files (stored solely in unswappable kernel memory).
- **Expected latency & memory (untested; to be measured by `linux-keyctl-spike.mjs`):** `keyctl` is a tiny C binary (~50 KiB), so each call is expected to be single-digit milliseconds and `< 5 MiB` RSS — negligible relative to Architecture section 9 ceilings.

### 4.3 Session (`@s`) vs User Session (`@us`) vs User (`@u`) Semantics and Logout Gotchas

Per `keyrings(7)`, `session-keyring(7)`, `user-session-keyring(7)`, and `pam_keyinit(8)`:

1. **Intended target (`@s`, `KEY_SPEC_SESSION_KEYRING`):**
   - Created per login session by `pam_keyinit.so` (TTY login, SSH, display manager) and inherited across `fork`/`exec`.
   - **Gone at logout:** When the last process referencing that session keyring exits (or PAM revokes it at session close), the kernel destroys `@s` and zeroes its keys in RAM.
2. **Gotcha A — Missing `pam_keyinit` / `@s` fallback to `@us`:**
   - If a process has no explicit session keyring, kernel access to `@s` attaches the per-UID fallback `@us` (`user-session-keyring`), which is shared across *all* sessions of that UID and survives individual session logouts while any process for that UID remains (including `systemd --user` with `loginctl enable-linger`).
   - Worse, if a child process creates a brand-new anonymous session keyring for itself, keys stored in it disappear the instant `keyctl` exits!
   - **Mitigation:** Compare `keyctl id @s` and `keyctl id @us` during `probe()`. If `@s` is unavailable, or if strict "gone at logout" is required and `@s == @us`, report the distinction clearly (or refuse and fall back to `none`).
3. **Gotcha B — `systemd --user` keyring disconnect:**
   - On modern Linux desktops (GNOME/KDE), terminal servers (e.g., `gnome-terminal-server`) and user services launched under `systemd --user` run in `user@.service`'s PAM context, which can have a **different** `@s` than an SSH login or another terminal. Keys cached in one session are not visible across separate `@s` sessions (strictly safer, though sometimes surprising to users).
4. **Gotcha C — Do NOT use `@u` (`user-keyring`) for `os-session`:**
   - `@u` persists across logins as long as any UID process runs and does not guarantee "gone at logout" when lingering user services exist; it also requires possessor linkage (`@s` linking `@u`, which `pam_keyinit` normally sets up) or explicit `keyctl setperm` for read access.
5. **Other failure modes:**
   - **Containers / Flatpak / sandboxes:** Seccomp profiles commonly block `add_key(2)`/`keyctl(2)` with `EPERM` or `ENOSYS` -> `probe()` fails cleanly -> fallback to `none`.
   - **Kernel quotas:** Per-UID `kernel.keys.maxkeys` (default 200) and `kernel.keys.maxbytes` (default 20,000) can return `EDQUOT` on `padd` -> caught -> fallback to `none`.

### 4.4 Recorded Output on Windows Host (`node spikes/v-6/linux-keyctl-spike.mjs`)

Syntax checked with `node --check spikes/v-6/linux-keyctl-spike.mjs` (exit 0) and executed on Windows to confirm clean non-Linux fail-to-`none` detection (no WSL/Docker/VM invoked):

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

Per `DECISIONS.md` `D-5` and `ROADMAP.md` `X-7`, macOS is deferred until Phase 3. What is known from platform documentation (untested here):

- **Inbox binary:** `/usr/bin/security` ships with macOS and talks to the OS Keychain service (`securityd` — an OS service, not a Foundry daemon).
- **Secret exposure hazard:** `/usr/bin/security add-generic-password -w <secret>` puts `<secret>` in `argv` (`ps`). Safe use requires interactive stdin mode (`security -i`) or a native Security.framework call.
- **Persistence & UX:** Login Keychain entries persist across logout and reboot (closer to Windows `os-protected` than Linux `os-session`, with no OS-enforced TTL). Crucially, unsigned CLI binaries (see `D-16`/`D-19`) trigger repeated macOS Keychain ACL confirmation dialogs on every update, making `security`-backed caching poor UX until builds are signed.
- **Verdict:** Mark **untested** and **do not build** in v1.

---

## 6. Threat Statements, Expiry Semantics, and Fail-to-`none` Contract

### 6.1 Exact Threat Statements (Architecture Section 10)

| Adapter | Who can read the cached key while live? | Powered-off device threat | Disk persistence | Cache expiry enforcement |
|---|---|---|---|---|
| `none` (default) | Nobody (key exists only in process RAM during one command, zeroed on exit) | Protected by passphrase `scrypt` (`N=2^17`) + vault/index encryption | None | Immediate (end of process) |
| `os-session` (Linux `keyctl` in `@s`) | **Any process running in the same Linux session keyring (`@s`) under the same UID** (or `root` / `CAP_SYS_PTRACE`) while the key has not expired | Protected (kernel RAM only; gone at logout and power-off) | None (kernel RAM only, not swapped) | **Kernel-enforced** via `keyctl timeout <id> <ttl>` (`EKEYEXPIRED` + kernel GC) and session teardown at logout |
| `os-protected` (Windows DPAPI `CurrentUser`) | **Any process running as the same Windows user account** (or local `SYSTEM`/Administrator with DPAPI backup key/impersonation) **until the cache file is deleted** | **Weakened** (Architecture 10): survives reboot; offline security degrades to Windows account password / BitLocker rather than Foundry's passphrase | **Yes** — DPAPI ciphertext blob on disk in `%LOCALAPPDATA%` | **Advisory only** — Foundry checks `advisory_expires_at_ms` and deletes expired files on read, **but** an attacker running as the user can call `ProtectedData.Unprotect` directly on an expired blob before Foundry cleans it up |

Note: Architecture section 5.6 requires the wizard to state this plainly in one sentence before enabling either cache: *"Caching means anyone who can run code as the user can read the vault while the cache is live."* For Windows `os-protected`, the prompt should additionally note that the cached unlock **survives reboot** until explicitly locked/cleared.

### 6.2 How `none` Stays Default and Never Fails Open

1. **Default configuration:** `KeyCache` defaults to `none` on every new vault and on every platform. Neither OS adapter is enabled automatically.
2. **Fail-to-`none` invariant (`spikes/v-6/key-cache-port.mjs`):**
   - `probe()` returning `{ available: false }` disables caching and prompts for the passphrase.
   - `get()` returning anything other than an exact 32-byte `Buffer` (null, binary missing, non-zero exit, timeout, CLM block, tampered blob, wrong entropy, `EKEYEXPIRED`, `EPERM`) **zeroes any partial buffer, attempts `clear(desc)`, logs a non-secret diagnostic, and returns `null`** (cache miss).
   - A cache miss always falls back to interactive passphrase entry (`none`). It **never** opens the vault unencrypted, **never** skips `keyring.mac` / `master.by_passphrase` AAD verification, and **never** blocks a user from unlocking their vault with their passphrase or recovery key.
   - If the cached 32-byte `KEK` fails to unwrap `master.by_passphrase` (e.g., after an out-of-band passphrase change or `rekey --all`), the unlock path calls `cache.clear(desc)`, zeroes the buffer, and falls back cleanly to the passphrase prompt.
   - `foundry lock` (explicit cache clear) always runs `cache.clear(desc)` and succeeds idempotently even if no key was cached.

---

## 7. Recommendations and Scope for a Future Codex Package

1. **`none` adapter + `KeyCache` port contract — Build in `V-7` (CLI):**
   - Define the minimal `KeyCache` interface (`probe`, `get`, `set`, `clear`) and ship only `none` as the Phase 1 implementation, so the CLI unlock path is port-clean with zero platform-specific risk in the thin slice.
2. **`os-protected` (Windows DPAPI) — Build later (opt-in, Phase 2 / `P-5` wizard or dedicated follow-up):**
   - **Why later:** Proven feasible without a daemon or dependency, but Phase 1 has no wizard to display the mandatory Architecture 5.6/10 warning (especially reboot persistence), and Windows CI must still verify `powershell.exe` peak working set and latency on pinned Node `24.22.3` plus Smart App Control behavior (`D-22` / `P-6`).
   - **Design recommendation if built:** Use Mechanism A (`ProtectedData` + `optionalEntropy` over `vault_id` and `sha256(kdf.salt)`) via absolute `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` (`shell: false`, stdin-only), store ciphertext in `%LOCALAPPDATA%`, and degrade cleanly to `none` under Constrained Language Mode (avoid maintaining a second `ConvertFrom-SecureString` path without `optionalEntropy` unless enterprise CLM support is explicitly requested).
3. **`os-session` (Linux `keyctl`) — Build later (opt-in, after real Linux verification):**
   - **Why later:** Best security semantics (RAM-only, kernel TTL, wiped at logout), **but** untested on real Linux here and dependent on optional `keyutils` installation plus `pam_keyinit` session-keyring setup.
   - **Prerequisite before implementation:** Run `node spikes/v-6/linux-keyctl-spike.mjs` on real Linux CI (`ubuntu-latest` with `keyutils` installed) and on a desktop Linux session with `systemd --user`, recording empirical latency, RSS, and `@s` vs `@us` topology. Refuse silent `@u` fallback; fail cleanly to `none` when `keyctl` is absent or `@s` is not an isolated session keyring.
4. **macOS — Do not build in v1 (`D-5`).** Re-evaluate in `X-7`.

### What a Future Codex Package Needs (Proposed `A-34`, Not a Commitment)

If the owner later authorizes implementing `os-protected` and/or `os-session`, the Codex work package needs:
1. **`packages/vault` (small additive API):** Add an internal/exported `unlockByKek` (or `Unlock = ... | { kek: Buffer }`) in `packages/vault/codec/src/keyring.ts` and `keys.ts` that still enforces `kdf` bounds, `master.by_passphrase` AAD, and `keyring.mac`, plus a helper returning the derived 32-byte `KEK` on passphrase unlock so the CLI can hand it to `KeyCache.set()` and immediately zero its local copy. Keep `changePassphrase`, `rekeyAll`, and `erase` strictly interactive (never accepting cached `KEK`) and calling `cache.clear()`.
2. **CLI / Wizard (`V-7` / `P-5`):** Add `foundry lock` (explicit cache eviction), a `--no-cache` flag, explicit opt-in configuration (default `none`), and the one-sentence warning (plus reboot-persistence disclosure on Windows).
3. **CI gates on pinned Node `24.22.3`:** Round-trip, tamper/wrong-entropy rejection, argv/env/temp/history leak tests, fail-to-`none` tests, and process-tree peak RSS assertions on both `windows-latest` and `ubuntu-latest` (with `keyutils` installed for the Linux adapter test and a second check with `keyctl` absent).
