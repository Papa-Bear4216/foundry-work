import { lstat, readdir } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { Archive, ArchiveEntry } from '../types.js';
import { ArchiveError } from './errors.js';
import { getEntryDedupKey, openZipFile } from './zip-reader.js';
import type { ZipOpenOptions } from './zip-reader.js';

const PART_PATTERN = /^(.+)-(\d+)\.zip$/i;

/**
 * Deterministic comparator for multi-part Takeout zip filenames (e.g. takeout-...-001.zip, -002.zip).
 * Sorts matching prefix+part-number numerically and falls back to raw bytewise code-unit order.
 */
export function comparePartNames(a: string, b: string): number {
  const ma = PART_PATTERN.exec(a);
  const mb = PART_PATTERN.exec(b);
  if (ma && mb && ma[1] === mb[1]) {
    const na = Number.parseInt(ma[2]!, 10);
    const nb = Number.parseInt(mb[2]!, 10);
    if (na !== nb) return na - nb;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Validates that a directory of Takeout zip files represents one consistent export set:
 * identical export prefix, positive integer ordinals, no duplicate ordinals, and no missing
 * leading or middle ordinals (contiguous 1..N).
 */
function validateAndOrderPartNames(zipNames: readonly string[]): string[] {
  if (zipNames.length === 1) {
    const only = zipNames[0]!;
    const match = PART_PATTERN.exec(only);
    if (match) {
      const ordinal = Number.parseInt(match[2]!, 10);
      if (!Number.isSafeInteger(ordinal) || ordinal < 1) {
        throw new ArchiveError('INVALID_MULTIPART', `Invalid archive part ordinal in ${only}.`);
      }
      if (ordinal !== 1) {
        throw new ArchiveError(
          'INVALID_MULTIPART',
          `Missing archive part 1 for export prefix "${match[1]}": found starting part ${ordinal} (${only}).`,
        );
      }
    }
    return [only];
  }

  const parsed: Array<{ name: string; prefix: string; ordinal: number }> = [];
  let expectedPrefix: string | undefined;
  const seenOrdinals = new Map<number, string>();

  for (const name of zipNames) {
    const match = PART_PATTERN.exec(name);
    if (!match) {
      throw new ArchiveError(
        'INVALID_MULTIPART',
        `Archive directory contains multiple .zip files without consistent "<prefix>-<ordinal>.zip" naming: ${name}`,
      );
    }
    const prefix = match[1]!;
    const ordinal = Number.parseInt(match[2]!, 10);
    if (!Number.isSafeInteger(ordinal) || ordinal < 1) {
      throw new ArchiveError('INVALID_MULTIPART', `Invalid archive part ordinal in ${name}.`);
    }
    if (expectedPrefix === undefined) {
      expectedPrefix = prefix;
    } else if (prefix !== expectedPrefix) {
      throw new ArchiveError(
        'INVALID_MULTIPART',
        `Mixed export prefixes in archive directory: "${expectedPrefix}" and "${prefix}" (${name}).`,
      );
    }
    const duplicateOf = seenOrdinals.get(ordinal);
    if (duplicateOf !== undefined) {
      throw new ArchiveError(
        'INVALID_MULTIPART',
        `Duplicate archive part ordinal ${ordinal} for export prefix "${prefix}": ${duplicateOf} and ${name}.`,
      );
    }
    seenOrdinals.set(ordinal, name);
    parsed.push({ name, prefix, ordinal });
  }

  parsed.sort((a, b) => a.ordinal - b.ordinal);
  for (let i = 0; i < parsed.length; i++) {
    const expectedOrdinal = i + 1;
    if (parsed[i]!.ordinal !== expectedOrdinal) {
      throw new ArchiveError(
        'INVALID_MULTIPART',
        `Missing archive part ordinal ${expectedOrdinal} for export prefix "${expectedPrefix}" (found ${parsed[i]!.name}).`,
      );
    }
  }

  return parsed.map(p => p.name);
}

/**
 * Opens either a single .zip file or a folder of multi-part Takeout .zip files
 * (`takeout-...-001.zip`, `-002.zip`, ...) and presents them as ONE unified Archive tree.
 */
export async function openArchive(pathOrDir: string, options: ZipOpenOptions = {}): Promise<Archive> {
  const info = await lstat(pathOrDir, { bigint: true });
  if (info.isFile()) {
    const fileName = basename(pathOrDir);
    validateAndOrderPartNames([fileName]);
    return openZipFile(pathOrDir, { ...options, partName: fileName });
  }
  if (!info.isDirectory()) {
    throw new ArchiveError('INVALID_FORMAT', `Archive path is neither a regular file nor a directory: ${pathOrDir}`);
  }

  const dirents = await readdir(pathOrDir, { withFileTypes: true });
  const rawZipNames = dirents
    .filter(d => d.isFile() && d.name.toLowerCase().endsWith('.zip'))
    .map(d => d.name)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  if (rawZipNames.length === 0) {
    throw new ArchiveError('EMPTY_ARCHIVE_DIR', `No .zip files found in archive directory: ${pathOrDir}`);
  }

  const zipNames = validateAndOrderPartNames(rawZipNames);

  const opened: Archive[] = [];
  const entries: ArchiveEntry[] = [];
  const seenKeys = new Set<string>();

  try {
    for (const name of zipNames) {
      const partArchive = await openZipFile(join(pathOrDir, name), { ...options, partName: name });
      opened.push(partArchive);
      for (const entry of partArchive.entries) {
        const dedupKey = getEntryDedupKey(entry);
        if (seenKeys.has(dedupKey)) {
          throw new ArchiveError(
            'DUPLICATE_ENTRY',
            `Duplicate entry path across multi-part archive: ${entry.path} (in ${name}).`,
          );
        }
        seenKeys.add(dedupKey);
        entries.push(entry);
      }
    }
  } catch (error) {
    await Promise.allSettled(opened.map(a => a.close()));
    throw error;
  }

  // Deterministic bytewise ordering across the unified tree.
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return {
    entries,
    parts: zipNames,
    async close() {
      const results = await Promise.allSettled(opened.map(a => a.close()));
      const rejected = results.find((r): r is PromiseRejectedResult => r.status === 'rejected');
      if (rejected) throw rejected.reason;
    },
  };
}
