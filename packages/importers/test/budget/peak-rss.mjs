import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const DEFAULT_TIMEOUT_MS = 300_000;

const windows = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ImporterProbeMemory {
  [StructLayout(LayoutKind.Sequential, Size = 72)]
  public struct Counters {
    public uint Length;
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
  public static extern bool GetProcessMemoryInfo(IntPtr process, out Counters counters, uint size);
}
"@
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $env:FOUNDRY_RSS_NODE
$psi.Arguments = $env:FOUNDRY_RSS_ARGS
$psi.WorkingDirectory = $env:FOUNDRY_RSS_CWD
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$child = [System.Diagnostics.Process]::Start($psi)
try {
  $handle = $child.Handle
  $stdout = $child.StandardOutput.ReadToEndAsync()
  $stderr = $child.StandardError.ReadToEndAsync()
  [Console]::OpenStandardInput().CopyTo($child.StandardInput.BaseStream)
  $child.StandardInput.Close()
  if (-not $child.WaitForExit([int]$env:FOUNDRY_RSS_TIMEOUT)) {
    $child.Kill()
    $child.WaitForExit()
    throw 'Importer budget probe timed out.'
  }
  $counters = New-Object ImporterProbeMemory+Counters
  $counters.Length = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($counters)
  if (-not [ImporterProbeMemory]::GetProcessMemoryInfo($handle, [ref]$counters, $counters.Length)) {
    throw 'GetProcessMemoryInfo failed.'
  }
  @{
    status = $child.ExitCode
    externalPeakKiB = $counters.PeakWorkingSetSize / 1024
    stdout = $stdout.Result
    stderr = $stderr.Result
  } | ConvertTo-Json -Compress
} finally {
  if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
  $child.Dispose()
}
`;

const posix = String.raw`
import json, os, signal, subprocess, sys, tempfile, time

node, script, cwd, timeout_ms = sys.argv[1:5]
extra_args = sys.argv[5:]
with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
    child = subprocess.Popen([node, script, *extra_args], cwd=cwd, stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + int(timeout_ms) / 1000
    while True:
        pid, status, usage = os.wait4(child.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() >= deadline:
            os.kill(child.pid, signal.SIGKILL)
            os.wait4(child.pid, 0)
            raise RuntimeError("Importer budget probe timed out.")
        time.sleep(0.01)
    stdout.seek(0)
    stderr.seek(0)
    print(json.dumps({
        "status": os.waitstatus_to_exitcode(status),
        "externalPeakKiB": usage.ru_maxrss / 1024 if sys.platform == "darwin" else usage.ru_maxrss,
        "stdout": stdout.read().decode("utf-8"),
        "stderr": stderr.read().decode("utf-8"),
    }))
`;

export function measurePeakRss(script, args, cwd, input, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const options = { encoding: 'utf8', input, timeout: timeoutMs + 15_000, windowsHide: true };
  const quotedArgs = [script, ...args].map(a => `"${a}"`).join(' ');
  const measured =
    process.platform === 'win32'
      ? spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', windows], {
          ...options,
          env: {
            ...process.env,
            FOUNDRY_RSS_NODE: process.execPath,
            FOUNDRY_RSS_ARGS: quotedArgs,
            FOUNDRY_RSS_CWD: cwd,
            FOUNDRY_RSS_TIMEOUT: String(timeoutMs),
          },
        })
      : spawnSync('python3', ['-c', posix, process.execPath, script, cwd, String(timeoutMs), ...args], options);

  assert.ifError(measured.error);
  assert.equal(measured.status, 0, measured.stderr);
  const result = JSON.parse(measured.stdout);
  assert.ok(Number.isFinite(result.externalPeakKiB) && result.externalPeakKiB > 0);
  return result;
}
