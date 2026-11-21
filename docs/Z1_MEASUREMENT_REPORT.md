# Z-1 measurement report

Measured 2026-11-19 with stock Node **24.22.3** x64. Both platforms fit the
**96 MiB (98,304 KiB)** per-process budget in this prototype. The largest
outside peak was **53.95 MiB** on Windows and **68.01 MiB** on Linux, leaving
42.05 MiB and 27.99 MiB of headroom, respectively.

| Platform | Hardware class |
| --- | --- |
| Windows | Windows 11 Home Insider Preview build 26320, x64, 12 physical cores and 16 logical processors, 15.70 GiB RAM |
| Linux | Ubuntu 26.04.1 LTS under WSL 2, x86_64, glibc 2.43, 8 visible vCPUs, 3.73 GiB visible RAM |

Both Node archives matched the release SHA-256 manifest. Benchmark files used
NTFS on Windows and native ext4 on Linux. The Linux results describe the WSL
guest.

## Results

Each row uses five fresh child processes. The peak and elapsed columns are
independent maxima across those five trials. The median shows the middle
outside elapsed time. Peak memory is in KiB and elapsed time is in ms.

| Platform | Operation | Inside peak | Outside peak | Inside max ms | Outside max ms | Outside median ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Windows | Cold start | 45,240 | 45,240 | 131.0 | 390.6 | 209.8 |
| Windows | Append | 48,744 | 48,744 | 408.7 | 615.2 | 375.9 |
| Windows | Worst-case rebuild | 55,244 | 55,244 | 913.4 | 1,104.8 | 1,069.4 |
| Windows | Warm query | 47,016 | 47,016 | 216.6 | 417.8 | 361.9 |
| Windows | Cold query | 54,468 | 54,468 | 964.3 | 1,138.6 | 960.2 |
| Windows | Digest | 48,164 | 48,164 | 139.2 | 392.6 | 221.0 |
| Linux | Cold start | 53,480 | 53,972 | 7.5 | 156.1 | 117.2 |
| Linux | Append | 58,560 | 59,084 | 58.3 | 207.5 | 165.5 |
| Linux | Worst-case rebuild | 69,084 | 69,616 | 1,044.1 | 1,158.2 | 1,029.2 |
| Linux | Warm query | 55,932 | 55,932 | 82.2 | 268.4 | 155.5 |
| Linux | Cold query | 69,072 | 69,640 | 942.4 | 1,051.3 | 994.0 |
| Linux | Digest | 56,676 | 57,176 | 21.0 | 180.0 | 115.8 |

The Windows peak counters agreed in all 30 workload trials. The Linux
outside counter was up to 720 KiB higher on the same trial. The two
measurements use separate OS interfaces and bracket the result write. The
budget comparison uses the larger observation.

The stock `node:sqlite` module reported SQLite **3.54.1** on both platforms.
Each FTS5 probe created a virtual table, inserted a row and returned one
`MATCH` result. Windows reported 44,348 KiB inside and 44,368 KiB outside.
Linux reported 53,196 KiB inside and 53,852 KiB outside.

Every rebuild indexed 10,000 blocks. Every append reached 10,001 blocks.
Each query returned 20 rows. The standalone and post-append digest files
were 5,977 UTF-8 bytes. The maximum outside query times were under the
2 s warm and 15 s cold limits on both platforms.

## Reproduction and scope

With the pinned Node binary first on PATH, run from the repository root.
On Linux, use a native filesystem for the checkout or copy the three
benchmark scripts together onto native storage, and set `TMPDIR` to an
absolute writable directory there.

```sh
node --version
node packages/facts-ledger/bench/measure.mjs
```

The benchmark prints one JSON line with the fixture identity, one with the
FTS5 probe, and 30 with paired observations. The generator produced the
same 11,042,589-byte JSONL file on both platforms, with SHA-256
`bc27ec18612eacc5aed4be1e2f70889d4718b711ab36502c93ba26156331d26a`.
It has 10,000 chained schema-2 blocks, each with one synthetic asserted
fact, two tags and one synthetic evidence reference. Inputs and setup
indexes are generated in temporary storage and removed by the runner.

- Cold start launches a new Node process, loads SQLite, opens the existing
  index and checks the log length and SHA-256 of its first 4 KiB.
- Append starts with 10,000 blocks and a current index. It acquires the
  SQLite writer lock without contention, reads the parent and last byte,
  appends and flushes one block, ingests the tail and regenerates the digest.
- Worst-case rebuild forces the full-index path for this fixture by
  starting with an absent index. It streams all blocks in 64 KiB chunks
  into the relational tables and FTS5 in one transaction.
- Warm query uses a prebuilt index. Cold query builds the complete index
  before running the same two-term FTS5 search. Both rank the matching set,
  select 20 rows with an explicit tie-breaker and serialize the result.
- Digest reads the seeded index and writes a byte-capped Markdown file
  through a temporary file and rename.

The inside clock starts after static module loading and ends after the
operation closes SQLite. The child then records `process.resourceUsage().maxRSS`.
The outside clock runs from immediately before spawn to receipt of the
child's result, including runtime startup and module loading. With the
child still alive, the parent reads Windows `PeakWorkingSet64` via
`Get-Process` or Linux `VmHWM` via `/proc/<pid>/status`. Counter collection
and the exit handshake are outside the timed interval. Fixture generation,
seeding and copying are also outside it. OS file caches were left in their
normal state throughout.

This is a measure-first prototype. Later packages still need to measure
the production commands, including evidence verification and any Git
children, and run the Python/Windows append interop test from section 9.
The measurements support retaining the 96 MiB ceiling. The condition for
a dated decision entry did not occur.
