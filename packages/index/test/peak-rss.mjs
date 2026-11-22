import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const timeout = 240_000;
// Keep the Windows process handle open until the exit-time counter is read.
const windows = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class IndexProbeMemory {
  [StructLayout(LayoutKind.Sequential)]
  public struct Counters {
    public uint Length, PageFaultCount;
    public UIntPtr PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage,
      QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage;
  }
  [DllImport("psapi.dll", SetLastError = true)]
  public static extern bool GetProcessMemoryInfo(IntPtr process, out Counters counters, uint size);
}
"@
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $env:FOUNDRY_INDEX_RSS_NODE
$psi.Arguments = '"' + $env:FOUNDRY_INDEX_RSS_SCRIPT + '" ' + $env:FOUNDRY_INDEX_RSS_PHASE + ' "' +
  $env:FOUNDRY_INDEX_RSS_ROOT + '" ' + $env:FOUNDRY_INDEX_RSS_CREDENTIAL
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$child = [System.Diagnostics.Process]::Start($psi)
try {
  $handle = $child.Handle
  $stdout = $child.StandardOutput.ReadToEndAsync()
  $stderr = $child.StandardError.ReadToEndAsync()
  if (-not $child.WaitForExit([int]$env:FOUNDRY_INDEX_RSS_TIMEOUT)) { throw 'Index probe timed out.' }
  $counters = New-Object IndexProbeMemory+Counters
  $counters.Length = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($counters)
  if (-not [IndexProbeMemory]::GetProcessMemoryInfo($handle, [ref]$counters, $counters.Length)) {
    throw 'GetProcessMemoryInfo failed.'
  }
  @{
    status = $child.ExitCode
    externalPeakKiB = $counters.PeakWorkingSetSize.ToUInt64() / 1024
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

timeout, *command = sys.argv[1:]
with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
    child = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + int(timeout) / 1000
    while True:
        pid, status, usage = os.wait4(child.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() >= deadline:
            os.kill(child.pid, signal.SIGKILL)
            os.wait4(child.pid, 0)
            raise RuntimeError("Index probe timed out.")
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

export function measurePeakRss(script, phase, root, credential) {
  const options = { encoding: 'utf8', windowsHide: true, timeout: timeout + 15_000 };
  const child = process.platform === 'win32'
    ? spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', windows], {
      ...options, env: {
        ...process.env,
        FOUNDRY_INDEX_RSS_NODE: process.execPath,
        FOUNDRY_INDEX_RSS_SCRIPT: script,
        FOUNDRY_INDEX_RSS_PHASE: phase,
        FOUNDRY_INDEX_RSS_ROOT: root,
        FOUNDRY_INDEX_RSS_CREDENTIAL: credential,
        FOUNDRY_INDEX_RSS_TIMEOUT: String(timeout),
      },
    })
    : spawnSync('python3', ['-c', posix, String(timeout), process.execPath, script, phase, root, credential], options);
  assert.ifError(child.error);
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(Number.isFinite(result.externalPeakKiB) && result.externalPeakKiB > 0);
  return result;
}
