/**
 * V-6 spike: Windows `os-protected` (per-user DPAPI) evaluation.
 *
 * Tests whether a Node.js process can protect/unprotect a synthetic 32-byte key
 * using Windows per-user DPAPI without a native addon and without a daemon,
 * invoking inbox Windows PowerShell (`powershell.exe`) via `child_process.spawnSync`
 * with `shell: false` and stdin-only secret transfer.
 *
 * Synthetic TEST-ONLY secrets only. Cleans up all created temporary files on exit.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createFailToNoneCache, createNoneAdapter } from './key-cache-port.mjs';

const POWERSHELL_REL = join('System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const POWERSHELL_EXE = join(process.env.SystemRoot || 'C:\\Windows', POWERSHELL_REL);
const CHILD_TIMEOUT_MS = 15_000;
const ENTROPY_PREFIX = 'foundry/key-cache/v1:';

function encodePsCommand(script) {
  return Buffer.from(script, 'utf16le').toString('base64');
}

function minimalEnv() {
  const allow = [
    'SystemRoot',
    'WINDIR',
    'SYSTEMDRIVE',
    'TEMP',
    'TMP',
    'PATHEXT',
    'COMSPEC',
    'USERPROFILE',
    'APPDATA',
    'LOCALAPPDATA',
  ];
  /** @type {Record<string, string>} */
  const env = {};
  for (const key of allow) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return env;
}

function stats(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  return {
    samplesMs: samples.map(v => Number(v.toFixed(2))),
    minMs: Number(sorted[0].toFixed(2)),
    medianMs: Number(median.toFixed(2)),
    maxMs: Number(sorted[sorted.length - 1].toFixed(2)),
  };
}

function runPowerShell(psExe, script, stdinText) {
  const encoded = encodePsCommand(script);
  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-NoLogo',
    '-OutputFormat',
    'Text',
    '-EncodedCommand',
    encoded,
  ];
  const env = minimalEnv();
  const t0 = performance.now();
  const res = spawnSync(psExe, args, {
    shell: false,
    input: stdinText,
    encoding: 'utf8',
    timeout: CHILD_TIMEOUT_MS,
    windowsHide: true,
    env,
  });
  const elapsedMs = performance.now() - t0;
  return { res, args, env, encoded, elapsedMs };
}

// --- Mechanism A: [System.Security.Cryptography.ProtectedData] ---

function buildProtectedDataProtectScript(entropyTag, emitPeakRss = false) {
  const rssLine = emitPeakRss
    ? '[Console]::Error.WriteLine("PEAK_WS_BYTES=" + [System.Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64)'
    : '';
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    'Add-Type -AssemblyName System.Security',
    '$hex = [Console]::In.ReadToEnd().Trim()',
    'if ($hex.Length -ne 64) { throw "invalid-key-length" }',
    '$bytes = New-Object byte[] 32',
    'for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }',
    `$entropy = [Text.Encoding]::UTF8.GetBytes('${entropyTag}')`,
    '$blob = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Array]::Clear($bytes, 0, $bytes.Length)',
    '[Console]::Out.Write([Convert]::ToBase64String($blob))',
    rssLine,
  ].filter(Boolean).join('\n');
}

function buildProtectedDataUnprotectScript(entropyTag, emitPeakRss = false) {
  const rssLine = emitPeakRss
    ? '[Console]::Error.WriteLine("PEAK_WS_BYTES=" + [System.Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64)'
    : '';
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    'Add-Type -AssemblyName System.Security',
    '$blob = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())',
    `$entropy = [Text.Encoding]::UTF8.GetBytes('${entropyTag}')`,
    '$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    'if ($bytes.Length -ne 32) { [Array]::Clear($bytes, 0, $bytes.Length); throw "invalid-unprotected-length" }',
    '$hex = ([BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()',
    '[Array]::Clear($bytes, 0, $bytes.Length)',
    '[Console]::Out.Write($hex)',
    rssLine,
  ].filter(Boolean).join('\n');
}

// --- Mechanism B: ConvertTo-SecureString / ConvertFrom-SecureString (CLM-compatible) ---

function buildSecureStringProtectScript(forceClm = false) {
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    forceClm ? "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'" : '',
    '$hex = ($input | Out-String).Trim()',
    'if ($hex.Length -ne 64) { throw "invalid-key-length" }',
    '$ss = ConvertTo-SecureString -String $hex -AsPlainText -Force',
    'ConvertFrom-SecureString -SecureString $ss',
  ].filter(Boolean).join('\n');
}

function buildSecureStringUnprotectScript(forceClm = false) {
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    forceClm ? "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'" : '',
    '$enc = ($input | Out-String).Trim()',
    '$ss = ConvertTo-SecureString -String $enc',
    "$cred = New-Object System.Management.Automation.PSCredential('foundry', $ss)",
    '$plain = $cred.GetNetworkCredential().Password',
    'if ($plain.Length -ne 64) { throw "invalid-unprotected-length" }',
    'Write-Output $plain',
  ].filter(Boolean).join('\n');
}

function entropyTagFor(desc) {
  // Strictly hex inputs only -> safe literal inside single-quoted PowerShell string.
  assert.match(desc.vaultId, /^[0-9a-f]{32}$/u);
  assert.match(desc.kdfSaltHash, /^[0-9a-f]{64}$/u);
  return `${ENTROPY_PREFIX}${desc.vaultId}:${desc.kdfSaltHash}`;
}

function createWinDpapiSpikeAdapter(cacheDir, psExe = POWERSHELL_EXE) {
  const filePathFor = (desc) => join(cacheDir, `${desc.vaultId}.dpapi.json`);
  return {
    name: /** @type {const} */ ('os-protected'),
    probe() {
      if (process.platform !== 'win32') return { available: false, reason: 'not-windows' };
      if (!existsSync(psExe)) return { available: false, reason: 'powershell-missing' };
      return { available: true };
    },
    set(desc, kek, ttlSeconds = 0) {
      const tag = entropyTagFor(desc);
      const hex = kek.toString('hex');
      const { res } = runPowerShell(psExe, buildProtectedDataProtectScript(tag), `${hex}\n`);
      if (res.error || res.status !== 0) {
        throw new Error(res.error?.message || res.stderr.trim() || `powershell-exit-${res.status}`);
      }
      const blob = res.stdout.trim();
      const record = {
        format: 'foundry-keycache-win-dpapi/spike',
        vault_id: desc.vaultId,
        kdf_salt_sha256: desc.kdfSaltHash,
        created_at_ms: Date.now(),
        advisory_expires_at_ms: ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null,
        dpapi_blob_b64: blob,
      };
      writeFileSync(filePathFor(desc), JSON.stringify(record), 'utf8');
      return true;
    },
    get(desc) {
      const fp = filePathFor(desc);
      if (!existsSync(fp)) return null;
      const record = JSON.parse(readFileSync(fp, 'utf8'));
      if (record.vault_id !== desc.vaultId || record.kdf_salt_sha256 !== desc.kdfSaltHash) {
        this.clear(desc);
        return null;
      }
      if (record.advisory_expires_at_ms !== null && Date.now() > record.advisory_expires_at_ms) {
        this.clear(desc);
        return null;
      }
      const tag = entropyTagFor(desc);
      const { res } = runPowerShell(psExe, buildProtectedDataUnprotectScript(tag), `${record.dpapi_blob_b64}\n`);
      if (res.error || res.status !== 0) {
        throw new Error(res.error?.message || res.stderr.trim() || `powershell-exit-${res.status}`);
      }
      const hex = res.stdout.trim();
      if (!/^[0-9a-f]{64}$/u.test(hex)) throw new Error('non-hex-unprotect-output');
      return Buffer.from(hex, 'hex');
    },
    clear(desc) {
      const fp = filePathFor(desc);
      if (existsSync(fp)) unlinkSync(fp);
    },
  };
}

function readHistoryState() {
  const appData = process.env.APPDATA;
  if (!appData) return { exists: false, size: 0, mtimeMs: 0 };
  const p = join(appData, 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt');
  if (!existsSync(p)) return { exists: false, size: 0, mtimeMs: 0 };
  const s = statSync(p);
  return { exists: true, size: s.size, mtimeMs: s.mtimeMs };
}

function parsePeakWsMiB(stderr) {
  const m = /PEAK_WS_BYTES=(\d+)/u.exec(stderr);
  return m ? Number((Number(m[1]) / (1024 * 1024)).toFixed(2)) : null;
}

function main() {
  if (process.platform !== 'win32') {
    console.log(JSON.stringify({ platform: process.platform, skipped: true, reason: 'Windows-only spike' }, null, 2));
    return;
  }

  const workDir = mkdtempSync(join(tmpdir(), 'foundry-v6-win-'));
  const syntheticKey = randomBytes(32);
  const syntheticKeyHex = syntheticKey.toString('hex');
  const desc = {
    vaultId: randomBytes(16).toString('hex'),
    kdfSaltHash: createHash('sha256').update(randomBytes(32)).digest('hex'),
  };

  try {
    const tempBefore = new Set(readdirSync(tmpdir()));
    const historyBefore = readHistoryState();

    // 1. Mechanism A: ProtectedData cold + 5 warm runs + secret-exposure checks
    const tag = entropyTagFor(desc);
    const protectTimes = [];
    const unprotectTimes = [];
    let lastBlob = '';
    let protectPeakMiB = null;
    let unprotectPeakMiB = null;
    let stderrCleanOnSecretPath = true;
    let secretInArgvOrEnv = false;

    for (let i = 0; i < 6; i++) {
      const emitRss = i === 5;
      const pRun = runPowerShell(POWERSHELL_EXE, buildProtectedDataProtectScript(tag, emitRss), `${syntheticKeyHex}\n`);
      assert.ifError(pRun.res.error);
      assert.equal(pRun.res.status, 0, pRun.res.stderr);
      if (!emitRss && pRun.res.stderr.trim() !== '') stderrCleanOnSecretPath = false;
      if (emitRss) protectPeakMiB = parsePeakWsMiB(pRun.res.stderr);
      if (pRun.args.join(' ').includes(syntheticKeyHex) || JSON.stringify(pRun.env).includes(syntheticKeyHex)) {
        secretInArgvOrEnv = true;
      }
      lastBlob = pRun.res.stdout.trim();
      protectTimes.push(pRun.elapsedMs);

      const uRun = runPowerShell(POWERSHELL_EXE, buildProtectedDataUnprotectScript(tag, emitRss), `${lastBlob}\n`);
      assert.ifError(uRun.res.error);
      assert.equal(uRun.res.status, 0, uRun.res.stderr);
      if (!emitRss && uRun.res.stderr.trim() !== '') stderrCleanOnSecretPath = false;
      if (emitRss) unprotectPeakMiB = parsePeakWsMiB(uRun.res.stderr);
      const recovered = Buffer.from(uRun.res.stdout.trim(), 'hex');
      assert.equal(Buffer.compare(recovered, syntheticKey), 0);
      recovered.fill(0);
      unprotectTimes.push(uRun.elapsedMs);
    }

    // 2. Live process command-line probe (confirming Win32_Process.CommandLine contains no secret)
    const liveCmdProbe = runPowerShell(
      POWERSHELL_EXE,
      [
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        '$x = [Console]::In.ReadToEnd().Trim()',
        '$cl = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $PID)).CommandLine',
        'Write-Output ("CONTAINS_SECRET=" + $cl.Contains($x))',
      ].join('\n'),
      `${syntheticKeyHex}\n`,
    );
    assert.equal(liveCmdProbe.res.status, 0, liveCmdProbe.res.stderr);
    const liveCommandLineLeaksSecret = !liveCmdProbe.res.stdout.includes('CONTAINS_SECRET=False');

    // 3. Tamper & wrong-entropy checks
    const blobBytes = Buffer.from(lastBlob, 'base64');
    blobBytes[blobBytes.length - 1] ^= 0x01;
    const tamperedRun = runPowerShell(
      POWERSHELL_EXE,
      buildProtectedDataUnprotectScript(tag),
      `${blobBytes.toString('base64')}\n`,
    );
    const tamperRejected = tamperedRun.res.status !== 0 && !tamperedRun.res.stdout.includes(syntheticKeyHex);

    const wrongTag = `${ENTROPY_PREFIX}${desc.vaultId}:${'0'.repeat(64)}`;
    const wrongEntropyRun = runPowerShell(
      POWERSHELL_EXE,
      buildProtectedDataUnprotectScript(wrongTag),
      `${lastBlob}\n`,
    );
    const wrongEntropyRejected = wrongEntropyRun.res.status !== 0 && !wrongEntropyRun.res.stdout.includes(syntheticKeyHex);

    // 4. ConstrainedLanguage mode tests (ProtectedData vs ConvertFrom-SecureString)
    const clmPdRun = runPowerShell(
      POWERSHELL_EXE,
      [
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'",
        'Add-Type -AssemblyName System.Security',
        '[System.Security.Cryptography.ProtectedData]::Protect([byte[]]@(1,2,3,4), $null, "CurrentUser")',
      ].join('\n'),
      '',
    );
    const clmProtectedDataBlocked = clmPdRun.res.status !== 0;

    // 5. Mechanism B: ConvertFrom-SecureString (FullLanguage + ConstrainedLanguage)
    const ssProtectFull = runPowerShell(POWERSHELL_EXE, buildSecureStringProtectScript(false), `${syntheticKeyHex}\n`);
    assert.equal(ssProtectFull.res.status, 0, ssProtectFull.res.stderr);
    const ssBlobFull = ssProtectFull.res.stdout.trim();
    const ssUnprotectFull = runPowerShell(POWERSHELL_EXE, buildSecureStringUnprotectScript(false), `${ssBlobFull}\n`);
    assert.equal(ssUnprotectFull.res.status, 0, ssUnprotectFull.res.stderr);
    const ssFullRoundTrip = ssUnprotectFull.res.stdout.trim() === syntheticKeyHex;

    const ssProtectClm = runPowerShell(POWERSHELL_EXE, buildSecureStringProtectScript(true), `${syntheticKeyHex}\n`);
    assert.equal(ssProtectClm.res.status, 0, ssProtectClm.res.stderr);
    const ssBlobClm = ssProtectClm.res.stdout.trim();
    const ssUnprotectClm = runPowerShell(POWERSHELL_EXE, buildSecureStringUnprotectScript(true), `${ssBlobClm}\n`);
    assert.equal(ssUnprotectClm.res.status, 0, ssUnprotectClm.res.stderr);
    const ssClmRoundTrip = ssUnprotectClm.res.stdout.trim() === syntheticKeyHex;

    // 6. Fail-to-`none` behavior tests
    const fallbacks = [];
    const missingBinCache = createFailToNoneCache(
      createWinDpapiSpikeAdapter(workDir, join(workDir, 'nonexistent-powershell.exe')),
      e => fallbacks.push(e),
    );
    const missingProbe = missingBinCache.probe();
    const missingSetOk = missingBinCache.set(desc, syntheticKey);

    const liveCache = createFailToNoneCache(createWinDpapiSpikeAdapter(workDir), e => fallbacks.push(e));
    assert.equal(liveCache.set(desc, syntheticKey, 60), true);
    const cached = liveCache.get(desc);
    assert.ok(cached && Buffer.compare(cached, syntheticKey) === 0);
    cached.fill(0);

    // Corrupt stored blob -> must return null (miss), delete corrupt file, never throw
    const cacheFile = join(workDir, `${desc.vaultId}.dpapi.json`);
    writeFileSync(cacheFile, JSON.stringify({
      format: 'foundry-keycache-win-dpapi/spike',
      vault_id: desc.vaultId,
      kdf_salt_sha256: desc.kdfSaltHash,
      created_at_ms: Date.now(),
      advisory_expires_at_ms: null,
      dpapi_blob_b64: 'AAAA',
    }), 'utf8');
    const corruptGetResult = liveCache.get(desc);
    const corruptFileEvicted = !existsSync(cacheFile);

    // None adapter sanity check
    const noneCache = createNoneAdapter();
    assert.equal(noneCache.probe().available, true);
    assert.equal(noneCache.set(desc, syntheticKey), false);
    assert.equal(noneCache.get(desc), null);

    // 7. Residual temp file & PSReadLine history checks
    const tempAfter = new Set(readdirSync(tmpdir()));
    const newTempEntries = [...tempAfter].filter(name => !tempBefore.has(name) && !name.startsWith('foundry-v6-win-'));
    const historyAfter = readHistoryState();
    const psReadLineUnchanged = historyBefore.exists === historyAfter.exists
      && historyBefore.size === historyAfter.size
      && historyBefore.mtimeMs === historyAfter.mtimeMs;

    const report = {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.versions.node,
      binaryRelativeToSystemRoot: POWERSHELL_REL,
      shellOption: false,
      mechanismA_protectedData: {
        roundTripOk: true,
        blobCharsBase64: lastBlob.length,
        blobBytesRaw: Buffer.from(lastBlob, 'base64').length,
        coldProtectMs: Number(protectTimes[0].toFixed(2)),
        warmProtect: stats(protectTimes.slice(1)),
        coldUnprotectMs: Number(unprotectTimes[0].toFixed(2)),
        warmUnprotect: stats(unprotectTimes.slice(1)),
        childPeakWorkingSetMiB: { protect: protectPeakMiB, unprotect: unprotectPeakMiB },
        nodeParentMaxRssMiB: Number((process.resourceUsage().maxRSS / 1024).toFixed(2)),
        stderrCleanOnSecretPath,
        tamperRejected,
        wrongEntropyRejected,
        blockedInConstrainedLanguageMode: clmProtectedDataBlocked,
      },
      mechanismB_secureString: {
        fullLanguageRoundTripOk: ssFullRoundTrip,
        fullLanguageProtectMs: Number(ssProtectFull.elapsedMs.toFixed(2)),
        fullLanguageUnprotectMs: Number(ssUnprotectFull.elapsedMs.toFixed(2)),
        blobCharsHex: ssBlobFull.length,
        constrainedLanguageRoundTripOk: ssClmRoundTrip,
        constrainedLanguageProtectMs: Number(ssProtectClm.elapsedMs.toFixed(2)),
        constrainedLanguageUnprotectMs: Number(ssUnprotectClm.elapsedMs.toFixed(2)),
        supportsOptionalEntropy: false,
      },
      secretExposureChecks: {
        secretInArgvOrEnv,
        liveCommandLineLeaksSecret,
        unexpectedTempEntriesCreated: newTempEntries,
        psReadLineHistoryUnchanged: psReadLineUnchanged,
      },
      failToNoneChecks: {
        missingBinaryProbeAvailable: missingProbe.available,
        missingBinaryProbeReason: missingProbe.reason,
        missingBinarySetReturned: missingSetOk,
        corruptBlobReturnedNull: corruptGetResult === null,
        corruptBlobFileEvicted: corruptFileEvicted,
        fallbackEventsRecorded: fallbacks.length,
      },
    };

    console.log(JSON.stringify(report, null, 2));
  } finally {
    syntheticKey.fill(0);
    rmSync(workDir, { recursive: true, force: true });
    assert.equal(existsSync(workDir), false, 'spike temp directory must be removed');
  }
}

main();
