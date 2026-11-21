import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { cpus, tmpdir, totalmem } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PINNED_NODE_VERSION = '24.22.3';
if (process.versions.node !== PINNED_NODE_VERSION) {
  throw new Error(`Expected pinned Node.js ${PINNED_NODE_VERSION}, got ${process.versions.node}`);
}

const dir = dirname(fileURLToPath(import.meta.url));
const nodeBin = process.execPath;
const MIB = 1024 * 1024;
const CHILD_TIMEOUT_MS = 120_000;

function getGlibcVersion() {
  if (process.platform !== 'linux') return null;
  try {
    const out = spawnSync('ldd', ['--version'], { encoding: 'utf8' });
    const first = (out.stdout || out.stderr || '').split(/\r?\n/)[0]?.trim();
    return first || null;
  } catch {
    return null;
  }
}

function measureChildWindows(scriptPath, childIoDir) {
  const stdoutPath = join(childIoDir, 'stdout.txt');
  const stderrPath = join(childIoDir, 'stderr.txt');
  const psScript = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class WinMem {
  [StructLayout(LayoutKind.Sequential, Size = 72)]
  public struct PROCESS_MEMORY_COUNTERS {
    public uint cb;
    public uint PageFaultCount;
    public ulong PeakWorkingSetSize;
    public ulong WorkingSetSize;
    public ulong QuotaPeakPagedPoolUsage;
    public ulong QuotaPagedPoolUsage;
    public ulong QuotaPeakNonPagedPoolUsage;
    public ulong QuotaNonPagedPoolUsage;
    public ulong PagefileUsage;
    public ulong PeakPagefileUsage;
  }

  [DllImport("psapi.dll", SetLastError = true)]
  public static extern bool GetProcessMemoryInfo(IntPtr hProcess, out PROCESS_MEMORY_COUNTERS counters, uint cb);
}
"@
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $env:FOUNDRY_NODE_BIN
$psi.Arguments = '"' + $env:FOUNDRY_SCRIPT + '"'
$psi.WorkingDirectory = $env:FOUNDRY_WORKDIR
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$proc = [System.Diagnostics.Process]::Start($psi)
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()
$exited = $proc.WaitForExit($env:FOUNDRY_TIMEOUT_MS)
if (-not $exited) {
  try { $proc.Kill($true) } catch { try { $proc.Kill() } catch {} }
  $proc.WaitForExit()
  $proc.Dispose()
  throw "Child process timed out after $env:FOUNDRY_TIMEOUT_MS ms."
}
$proc.WaitForExit()
$sw.Stop()
[System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask))

$pmc = New-Object WinMem+PROCESS_MEMORY_COUNTERS
$pmc.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($pmc)
$ok = [WinMem]::GetProcessMemoryInfo($proc.Handle, [ref]$pmc, $pmc.cb)
$peakBytes = [uint64]$pmc.PeakWorkingSetSize
$exitCode = $proc.ExitCode
$proc.Dispose()
if (-not $ok -or $peakBytes -eq 0) {
  throw "GetProcessMemoryInfo failed or returned zero PeakWorkingSetSize."
}

[System.IO.File]::WriteAllText($env:FOUNDRY_STDOUT_FILE, $stdoutTask.Result, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($env:FOUNDRY_STDERR_FILE, $stderrTask.Result, [System.Text.UTF8Encoding]::new($false))

[PSCustomObject]@{
  exitCode = $exitCode
  wallMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
  externalPeakBytes = $peakBytes
} | ConvertTo-Json -Compress
`;
  const res = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psScript], {
    encoding: 'utf8',
    timeout: CHILD_TIMEOUT_MS + 15_000,
    env: {
      ...process.env,
      FOUNDRY_NODE_BIN: nodeBin,
      FOUNDRY_SCRIPT: scriptPath,
      FOUNDRY_WORKDIR: dir,
      FOUNDRY_TIMEOUT_MS: String(CHILD_TIMEOUT_MS),
      FOUNDRY_STDOUT_FILE: stdoutPath,
      FOUNDRY_STDERR_FILE: stderrPath,
    },
  });
  if (res.status !== 0) {
    throw new Error(`Windows child wrapper failed (${res.status}): ${res.stderr}`);
  }
  const meta = JSON.parse(res.stdout.trim());
  return {
    ...meta,
    stdout: readFileSync(stdoutPath, 'utf8'),
    stderr: readFileSync(stderrPath, 'utf8'),
  };
}

function measureChildPosix(scriptPath, childIoDir) {
  const stdoutPath = join(childIoDir, 'stdout.txt');
  const stderrPath = join(childIoDir, 'stderr.txt');
  const pyCode = `
import json, os, signal, subprocess, sys, time
timeout_s = float(sys.argv[4]) / 1000.0
t0 = time.monotonic()
with open(sys.argv[5], "w", encoding="utf-8") as fout, open(sys.argv[6], "w", encoding="utf-8") as ferr:
    proc = subprocess.Popen(
        [sys.argv[1], sys.argv[2]],
        cwd=sys.argv[3],
        stdout=fout,
        stderr=ferr,
    )
    pid = proc.pid
    rusage = None
    status = 0
    while True:
        wpid, st, ru = os.wait4(pid, os.WNOHANG)
        if wpid == pid:
            status = st
            rusage = ru
            break
        if time.monotonic() - t0 > timeout_s:
            os.kill(pid, signal.SIGKILL)
            _, status, rusage = os.wait4(pid, 0)
            raise RuntimeError(f"Child process timed out after {sys.argv[4]} ms")
        time.sleep(0.01)
wall_ms = round((time.monotonic() - t0) * 1000.0, 2)
code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
if rusage.ru_maxrss <= 0:
    raise RuntimeError(f"os.wait4 returned non-positive ru_maxrss: {rusage.ru_maxrss}")
print(json.dumps({
    "exitCode": code,
    "wallMs": wall_ms,
    "externalPeakKiB": int(rusage.ru_maxrss),
}))
`;
  const res = spawnSync(
    'python3',
    ['-c', pyCode, nodeBin, scriptPath, dir, String(CHILD_TIMEOUT_MS), stdoutPath, stderrPath],
    { encoding: 'utf8', timeout: CHILD_TIMEOUT_MS + 15_000 },
  );
  if (res.status !== 0) {
    throw new Error(`POSIX child wrapper failed (${res.status}): ${res.stderr}`);
  }
  const parsed = JSON.parse(res.stdout.trim());
  return {
    ...parsed,
    externalPeakBytes: parsed.externalPeakKiB * 1024,
    stdout: readFileSync(stdoutPath, 'utf8'),
    stderr: readFileSync(stderrPath, 'utf8'),
  };
}

function runMeasured(scriptName) {
  const scriptPath = join(dir, scriptName);
  const childIoDir = mkdtempSync(join(tmpdir(), 'foundry-v0-io-'));
  try {
    const raw = process.platform === 'win32'
      ? measureChildWindows(scriptPath, childIoDir)
      : measureChildPosix(scriptPath, childIoDir);
    if (raw.exitCode !== 0) {
      throw new Error(`${scriptName} failed (exit ${raw.exitCode}): ${raw.stderr || raw.stdout}`);
    }
    if (typeof raw.externalPeakBytes !== 'number' || !Number.isFinite(raw.externalPeakBytes) || raw.externalPeakBytes <= 0) {
      throw new Error(`${scriptName} produced invalid externalPeakBytes: ${raw.externalPeakBytes}`);
    }
    const payload = JSON.parse(raw.stdout.trim());
    if (typeof payload.internalMaxRssKiB !== 'number' || !Number.isFinite(payload.internalMaxRssKiB) || payload.internalMaxRssKiB <= 0) {
      throw new Error(`${scriptName} produced invalid internalMaxRssKiB: ${payload.internalMaxRssKiB}`);
    }
    const externalPeakMiB = Number((raw.externalPeakBytes / MIB).toFixed(2));
    return {
      ...payload,
      externalWallMs: raw.wallMs,
      externalPeakBytes: raw.externalPeakBytes,
      externalPeakMiB,
    };
  } finally {
    rmSync(childIoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

const kdf = runMeasured('measure-kdf.mjs');
const encrypt = runMeasured('measure-encrypt.mjs');
const sqlcipher = runMeasured('measure-sqlcipher.mjs');

const kdfMaxBytes = Math.max(kdf.internalMaxRssKiB * 1024, kdf.externalPeakBytes);
const encryptMaxBytes = Math.max(encrypt.internalMaxRssKiB * 1024, encrypt.externalPeakBytes);
const sqlcipherMaxBytes = Math.max(sqlcipher.internalMaxRssKiB * 1024, sqlcipher.externalPeakBytes);
const PROBE_SANITY_GUARD_MIB = 256;

const report = {
  environment: {
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
    cpuCores: cpus().length,
    totalRamGiB: Number((totalmem() / (1024 ** 3)).toFixed(1)),
    glibc: getGlibcVersion(),
  },
  benchmarks: {
    kdf,
    encrypt,
    sqlcipher,
  },
  budgets: {
    scopeNote:
      'V-0 measures isolated primitives in individual benchmark child processes (startup through measurement/exit), not full end-to-end commands or launcher+helper trees.',
    policyNote:
      'CI fails if KDF exceeds its 256 MiB allowance, if any isolated probe exceeds the 256 MiB runaway-memory sanity guard, or if any functional/security check fails. Provisional Architecture section 9 full-command ceilings (vault verify 128 MiB, search 192 MiB) are reported for reference only and deferred to implementing packages per A-26.',
    kdfBudgetMiB: 256,
    kdfMaxMiB: Number((kdfMaxBytes / MIB).toFixed(2)),
    kdfWithinBudget: kdfMaxBytes <= 256 * MIB,
    probeSanityGuardMiB: PROBE_SANITY_GUARD_MIB,
    streamProbeMaxMiB: Number((encryptMaxBytes / MIB).toFixed(2)),
    streamProbeWithinSanityGuard: encryptMaxBytes <= PROBE_SANITY_GUARD_MIB * MIB,
    referenceVaultVerifyCeilingMiB: 128,
    sqlcipherProbeMaxMiB: Number((sqlcipherMaxBytes / MIB).toFixed(2)),
    sqlcipherProbeWithinSanityGuard: sqlcipherMaxBytes <= PROBE_SANITY_GUARD_MIB * MIB,
    referenceSearchCeilingMiB: 192,
  },
  checks: {
    sqlcipherChecksPassed:
      sqlcipher.addonLoaded &&
      sqlcipher.fts5Available &&
      sqlcipher.rtreeAvailable &&
      sqlcipher.wrongKeyRejected &&
      sqlcipher.modifiedPageRejected &&
      sqlcipher.hmacControlBypassSucceeded &&
      !sqlcipher.liveWalScan?.markerLeakFound &&
      !sqlcipher.markerLeakFound,
    encryptChecksPassed:
      encrypt.roundtripVerified && encrypt.tamperRejected,
  },
};

console.log(JSON.stringify(report, null, 2));

if (
  !report.budgets.kdfWithinBudget ||
  !report.budgets.streamProbeWithinSanityGuard ||
  !report.budgets.sqlcipherProbeWithinSanityGuard ||
  !report.checks.sqlcipherChecksPassed ||
  !report.checks.encryptChecksPassed
) {
  process.exitCode = 1;
}
