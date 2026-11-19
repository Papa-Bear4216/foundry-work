import { spawnSync } from 'node:child_process';
import { cpus, totalmem } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const nodeBin = process.execPath;
const MIB = 1024 * 1024;

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

function measureChildWindows(scriptPath) {
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
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
$sw.Stop()

$pmc = New-Object WinMem+PROCESS_MEMORY_COUNTERS
$pmc.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($pmc)
$ok = [WinMem]::GetProcessMemoryInfo($proc.Handle, [ref]$pmc, $pmc.cb)
$peakBytes = [uint64]$pmc.PeakWorkingSetSize
$exitCode = $proc.ExitCode
$proc.Dispose()
if (-not $ok -or $peakBytes -eq 0) {
  throw "GetProcessMemoryInfo failed or returned zero PeakWorkingSetSize."
}

[PSCustomObject]@{
  exitCode = $exitCode
  wallMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
  externalPeakBytes = $peakBytes
  stdout = $stdout
  stderr = $stderr
} | ConvertTo-Json -Compress
`;
  const res = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psScript], {
    encoding: 'utf8',
    env: {
      ...process.env,
      FOUNDRY_NODE_BIN: nodeBin,
      FOUNDRY_SCRIPT: scriptPath,
      FOUNDRY_WORKDIR: dir,
    },
  });
  if (res.status !== 0) {
    throw new Error(`Windows child wrapper failed (${res.status}): ${res.stderr}`);
  }
  return JSON.parse(res.stdout.trim());
}

function measureChildPosix(scriptPath) {
  const pyCode = `
import json, os, subprocess, sys, time
t0 = time.monotonic()
proc = subprocess.Popen(
    [sys.argv[1], sys.argv[2]],
    cwd=sys.argv[3],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
pid = proc.pid
_, status, rusage = os.wait4(pid, 0)
wall_ms = round((time.monotonic() - t0) * 1000.0, 2)
stdout = proc.stdout.read()
stderr = proc.stderr.read()
proc.stdout.close()
proc.stderr.close()
if os.WIFEXITED(status):
    code = os.WEXITSTATUS(status)
else:
    code = -os.WTERMSIG(status)
if rusage.ru_maxrss <= 0:
    raise RuntimeError(f"os.wait4 returned non-positive ru_maxrss: {rusage.ru_maxrss}")
print(json.dumps({
    "exitCode": code,
    "wallMs": wall_ms,
    "externalPeakKiB": int(rusage.ru_maxrss),
    "stdout": stdout,
    "stderr": stderr,
}))
`;
  const res = spawnSync('python3', ['-c', pyCode, nodeBin, scriptPath, dir], { encoding: 'utf8' });
  if (res.status !== 0) {
    throw new Error(`POSIX child wrapper failed (${res.status}): ${res.stderr}`);
  }
  const parsed = JSON.parse(res.stdout.trim());
  return {
    ...parsed,
    externalPeakBytes: parsed.externalPeakKiB * 1024,
  };
}

function runMeasured(scriptName) {
  const scriptPath = join(dir, scriptName);
  const raw = process.platform === 'win32'
    ? measureChildWindows(scriptPath)
    : measureChildPosix(scriptPath);
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
}

const kdf = runMeasured('measure-kdf.mjs');
const encrypt = runMeasured('measure-encrypt.mjs');
const sqlcipher = runMeasured('measure-sqlcipher.mjs');

const kdfMaxBytes = Math.max(kdf.internalMaxRssKiB * 1024, kdf.externalPeakBytes);
const encryptMaxBytes = Math.max(encrypt.internalMaxRssKiB * 1024, encrypt.externalPeakBytes);

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
  ceilings: {
    kdfCeilingMiB: 256,
    kdfWithinCeiling: kdfMaxBytes <= 256 * MIB,
    streamEncryptVerifyCeilingMiB: 128,
    streamEncryptImportCeilingMiB: 256,
    streamWithinVerifyCeiling: encryptMaxBytes <= 128 * MIB,
    streamWithinImportCeiling: encryptMaxBytes <= 256 * MIB,
    sqlcipherLoadedWithFts5AndRtree:
      sqlcipher.addonLoaded &&
      sqlcipher.fts5Available &&
      sqlcipher.rtreeAvailable &&
      sqlcipher.wrongKeyRejected &&
      sqlcipher.modifiedPageRejected &&
      !sqlcipher.liveWalScan?.markerLeakFound &&
      !sqlcipher.markerLeakFound,
    encryptRoundtripAndTamperVerified:
      encrypt.roundtripVerified && encrypt.tamperRejected,
  },
};

console.log(JSON.stringify(report, null, 2));

if (
  !report.ceilings.kdfWithinCeiling ||
  !report.ceilings.streamWithinImportCeiling ||
  !report.ceilings.sqlcipherLoadedWithFts5AndRtree ||
  !report.ceilings.encryptRoundtripAndTamperVerified
) {
  process.exitCode = 1;
}
