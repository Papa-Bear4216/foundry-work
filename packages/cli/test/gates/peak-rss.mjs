// TEST ONLY: OS exit-time peak RSS measurement for `foundry` CLI commands (Windows GetProcessMemoryInfo, Linux wait4).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const BIN = fileURLToPath(new URL('../../bin/foundry.mjs', import.meta.url));
const DEFAULT_TIMEOUT_MS = 600_000;

/** Clean environment without FOUNDRY_*, VAULT_*, or NODE_OPTIONS variables. */
export function cleanChildEnv(extra = {}) {
  const env = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (!/^(FOUNDRY_|VAULT_|NODE_OPTIONS$)/iu.test(name)) env[name] = value;
  }
  return { ...env, ...extra };
}

/** Recursively make read-only sealed vault files writable before deleting a temporary directory. */
export function cleanupDir(dir) {
  if (!existsSync(dir)) return;
  const makeWritable = target => {
    try { chmodSync(target, 0o700); } catch { /* ignore */ }
    for (const entry of readdirSync(target, { withFileTypes: true })) {
      const full = join(target, entry.name);
      if (entry.isDirectory()) makeWritable(full);
      else if (entry.isFile()) {
        try { chmodSync(full, 0o600); } catch { /* ignore */ }
      }
    }
  };
  makeWritable(dir);
  rmSync(dir, { recursive: true, force: true });
}

const windowsScript = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CliProbeMemory {
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
$spec = $env:CLI_RSS_SPEC | ConvertFrom-Json
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $spec.node
$psi.Arguments = $spec.arguments
$psi.WorkingDirectory = $spec.cwd
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.EnvironmentVariables.Clear()
foreach ($prop in $spec.env.PSObject.Properties) {
  $psi.EnvironmentVariables[$prop.Name] = [string]$prop.Value
}
$child = [System.Diagnostics.Process]::Start($psi)
try {
  $handle = $child.Handle
  $stdout = $child.StandardOutput.ReadToEndAsync()
  $stderr = $child.StandardError.ReadToEndAsync()
  [Console]::OpenStandardInput().CopyTo($child.StandardInput.BaseStream)
  $child.StandardInput.Close()
  if (-not $child.WaitForExit([int]$spec.timeoutMs)) {
    $child.Kill()
    $child.WaitForExit()
    throw 'CLI peak-RSS probe timed out.'
  }
  $counters = New-Object CliProbeMemory+Counters
  $counters.Length = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($counters)
  if (-not [CliProbeMemory]::GetProcessMemoryInfo($handle, [ref]$counters, $counters.Length)) {
    throw 'GetProcessMemoryInfo failed.'
  }
  @{
    status = $child.ExitCode
    externalPeakKiB = [math]::Round($counters.PeakWorkingSetSize / 1024)
    stdout = $stdout.Result
    stderr = $stderr.Result
  } | ConvertTo-Json -Compress
} finally {
  if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
  $child.Dispose()
}
`;

const posixScript = String.raw`
import json, os, signal, subprocess, sys, tempfile, time

spec = json.loads(os.environ["CLI_RSS_SPEC"])
with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
    child = subprocess.Popen(
        [spec["node"], *spec["args"]],
        cwd=spec["cwd"],
        env=spec["env"],
        stdin=sys.stdin.buffer,
        stdout=stdout,
        stderr=stderr,
    )
    deadline = time.monotonic() + int(spec["timeoutMs"]) / 1000.0
    while True:
        pid, status, usage = os.wait4(child.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() >= deadline:
            os.kill(child.pid, signal.SIGKILL)
            os.wait4(child.pid, 0)
            raise RuntimeError("CLI peak-RSS probe timed out.")
        time.sleep(0.01)
    stdout.seek(0)
    stderr.seek(0)
    peak_kib = round(usage.ru_maxrss / 1024) if sys.platform == "darwin" else round(usage.ru_maxrss)
    print(json.dumps({
        "status": os.waitstatus_to_exitcode(status),
        "externalPeakKiB": peak_kib,
        "stdout": stdout.read().decode("utf-8"),
        "stderr": stderr.read().decode("utf-8"),
    }))
`;

function quoteWinArg(arg) {
  const s = String(arg);
  if (s.length > 0 && !/[\s"]/u.test(s)) return s;
  return `"${s.replace(/(\\*)"/gu, '$1$1\\"').replace(/(\\+)$/gu, '$1$1')}"`;
}

/**
 * Run `foundry` (via `bin/foundry.mjs`) and measure the entire process's OS peak RSS at exit.
 */
export function measureCliPeakRss(argv, { cwd = process.cwd(), stdin = '', env = {}, extraNodeArgs = [], timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const childEnv = cleanChildEnv(env);
  const allArgs = [...extraNodeArgs, BIN, ...argv];
  const spec = JSON.stringify({
    node: process.execPath,
    args: allArgs,
    arguments: allArgs.map(quoteWinArg).join(' '),
    cwd,
    env: childEnv,
    timeoutMs,
  });
  const wrapperEnv = { ...process.env, CLI_RSS_SPEC: spec };
  const options = { encoding: 'utf8', input: stdin, timeout: timeoutMs + 30_000, windowsHide: true, env: wrapperEnv };
  const started = Date.now();
  const measured = process.platform === 'win32'
    ? spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', windowsScript], options)
    : spawnSync('python3', ['-c', posixScript], options);
  const wallMs = Date.now() - started;
  assert.ifError(measured.error);
  assert.equal(measured.status, 0, `peak-RSS wrapper failed: ${measured.stderr}`);
  const result = JSON.parse(measured.stdout);
  assert.ok(Number.isFinite(result.externalPeakKiB) && result.externalPeakKiB > 0, 'invalid externalPeakKiB');
  return { ...result, wallMs };
}
