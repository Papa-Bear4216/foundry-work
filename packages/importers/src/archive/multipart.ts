import { lstat, readdir } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { Archive, ArchiveEntry } from '../types.js';
import { ArchiveError } from './errors.js';
import { openZipFile } from './zip-reader.js';
import type { ZipOpenOptions } from './zip-reader.js';

/**
 * Deterministic comparator for multi-part Takeout zip filenames (e.g. takeout-...-001.zip, -002.zip).
 * Sorts matching prefix+part-number numerically and falls back to raw bytewise code-unit order.
 */
export function comparePartNames(a: string, b: string): number {
  const partPattern = /^(.*)-(\d+)\.zip$/i;
  const ma = partPattern.exec(a);
  const mb = partPattern.exec(b);
  if (ma && mb && ma[1] === mb[1]) {
    const na = Number.parseInt(ma[2]!, 10);
    const nb = Number.parseInt(mb[2]!, 10);
    if (na !== nb) return na - nb;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Opens either a single .zip file or a folder of multi-part Takeout .zip files
 * (`takeout-...-001.zip`, `-002.zip`, ...) and presents them as ONE unified Archive tree.
 */
export async function openArchive(pathOrDir: string, options: ZipOpenOptions = {}): Promise<Archive> {
  const info = await lstat(pathOrDir, { bigint: true });
  if (info.isFile()) {
    return openZipFile(pathOrDir, { ...options, partName: basename(pathOrDir) });
  }
  if (!info.isDirectory()) {
    throw new ArchiveError('INVALID_FORMAT', `Archive path is neither a regular file nor a directory: ${pathOrDir}`);
  }

  const dirents = await readdir(pathOrDir, { withFileTypes: true });
  const zipNames = dirents
    .filter(d => d.isFile() && d.name.toLowerCase().endsWith('.zip'))
    .map(d => d.name)
    .sort(comparePartNames);

  if (zipNames.length === 0) {
    throw new ArchiveError('EMPTY_ARCHIVE_DIR', `No .zip files found in archive directory: ${pathOrDir}`);
  }

  const opened: Archive[] = [];
  const entries: ArchiveEntry[] = [];
  const seenPaths = new Set<string>();

  try {
    for (const name of zipNames) {
      const partArchive = await openZipFile(join(pathOrDir, name), { ...options, partName: name });
      opened.push(partArchive);
      for (const entry of partArchive.entries) {
        if (seenPaths.has(entry.path)) {
          throw new ArchiveError(
            'DUPLICATE_ENTRY',
            `Duplicate entry path across multi-part archive: ${entry.path} (in ${name}).`,
          );
        }
        seenPaths.add(entry.path);
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
