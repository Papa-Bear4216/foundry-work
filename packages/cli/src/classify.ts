/**
 * Write-time sensitivity of one imported item (P-1 fix round 1, item 6).
 *
 * The classifier sees the raw item bytes AND the text the source's deriver produces from them (for
 * example a base64 or quoted-printable mail body, decoded). Both go through the windowed scan of
 * `classifySensitivity`. When the deriver throws, the raw bytes alone decide the tier and the result
 * carries the rule id `derive-failed`; the failure itself never raises the tier and never fails the import.
 *
 * Memory: while this runs, the pipeline's plaintext buffer, the deriver's own copy of it (its
 * `Buffer.concat`), the deriver's decoded strings, and the collected derived texts are alive. All of them
 * are released when this function returns, before the item is written.
 */
import { Readable } from 'node:stream';
import type { ClassificationInput, ClassificationResult } from 'foundry-profiles';
import type { Deriver, ImportArchiveOptions, StoredItem } from 'importers';

/** The pipeline's item payload (the third argument of `resolveSensitivity`). */
export type ResolveSensitivityItem = NonNullable<
  Parameters<NonNullable<ImportArchiveOptions['resolveSensitivity']>>[2]
>;

export type Classify = (input: ClassificationInput) => ClassificationResult;

/** Rule id of a result whose derived text could not be produced. */
export const DERIVE_FAILED_RULE = 'derive-failed';

/** Every derived `title` and `text` of the item, or undefined when the source has no deriver. Throws when the deriver throws. */
async function derivedTexts(
  derivers: readonly Deriver[],
  input: ClassificationInput,
  item: ResolveSensitivityItem,
): Promise<string[] | undefined> {
  const deriver = derivers.find(candidate => candidate.id === input.source);
  if (deriver === undefined) return undefined;
  const stored: StoredItem = {
    source: input.source,
    path: input.path ?? '',
    mime: item.mime,
    size: item.plaintext.byteLength,
    blobId: '', // not known before the write; no deriver reads it
    profile: item.profile,
    collection: item.collection,
    sensitivity: 'personal', // placeholder; no deriver reads it
    ...(item.sourceTs !== undefined ? { sourceTs: item.sourceTs } : {}),
    tags: [...item.tags],
  };
  const texts: string[] = [];
  // One chunk: the pipeline's own buffer (a Buffer, so the deriver does not wrap it again). Not modified.
  for await (const derived of deriver.derive(stored, Readable.from([item.plaintext]))) {
    if (derived.kind !== 'text') continue;
    if (derived.title) texts.push(derived.title);
    if (derived.text) texts.push(derived.text);
  }
  return texts;
}

/**
 * Classify one item from its raw bytes plus its derived text. `input` carries the item metadata (profile,
 * collection, source, path, user rules); `item` is the pipeline's item payload.
 */
export async function classifyImportItem(
  classify: Classify,
  derivers: readonly Deriver[],
  input: Omit<ClassificationInput, 'plaintext' | 'derivedTexts'>,
  item: ResolveSensitivityItem,
): Promise<ClassificationResult> {
  const base: ClassificationInput = {
    ...input,
    plaintext: item.plaintext,
    mime: item.mime,
    tags: item.tags,
  };
  let texts: string[] | undefined;
  try {
    texts = await derivedTexts(derivers, input, item);
  } catch {
    return { sensitivity: classify(base).sensitivity, rule: DERIVE_FAILED_RULE };
  }
  return classify(texts === undefined ? base : { ...base, derivedTexts: texts });
}
