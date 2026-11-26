/**
 * Write-time sensitivity of one imported item (P-1 fix round 1, items 6 and B0).
 *
 * The classifier sees the raw item bytes AND the search text the index stores for the item. That text
 * comes from `derive.ts` `itemTextOfPlaintext`, which applies the projection's own limits: the first
 * `MAX_DERIVE_BYTES` (8 MiB) of the item are parsed, with the same `truncated` flag, and the text is at
 * most `MAX_TEXT_BYTES` (1 MiB). For mail this is the decoded body (base64 and quoted-printable parts).
 * The raw bytes of the WHOLE item go through the windowed scan of `classifySensitivity` as well, and so
 * does the derived text. When deriving the text throws, the raw bytes alone decide the tier and the
 * result carries the rule id `derive-failed`; the failure itself never raises the tier and never fails
 * the import.
 *
 * Memory: the item's plaintext is the pipeline's own buffer (at most the 64 MiB item cap); the parser
 * reads at most its first 8 MiB through a view (no copy). While this runs, the parser's decoded strings
 * (bounded by the 8 MiB input) and the rendered text (at most 1 MiB) are alive. All of them are released
 * when this function returns, before the item is written.
 */
import type { ClassificationInput, ClassificationResult } from 'foundry-profiles';
import type { ImportArchiveOptions } from 'importers';

/** The pipeline's item payload (the third argument of `resolveSensitivity`). */
export type ResolveSensitivityItem = NonNullable<
  Parameters<NonNullable<ImportArchiveOptions['resolveSensitivity']>>[2]
>;

export type Classify = (input: ClassificationInput) => ClassificationResult;

/** The item's search text (as the index stores it), or undefined when its type has none. */
export type DeriveText = (mime: string | null, plaintext: Uint8Array) => string | undefined;

/** Rule id of a result whose derived text could not be produced. */
export const DERIVE_FAILED_RULE = 'derive-failed';

/**
 * Classify one item from its raw bytes plus its derived search text. `input` carries the item metadata
 * (profile, collection, source, path, user rules); `item` is the pipeline's item payload.
 */
export function classifyImportItem(
  classify: Classify,
  deriveText: DeriveText,
  input: Omit<ClassificationInput, 'plaintext' | 'derivedTexts'>,
  item: ResolveSensitivityItem,
): ClassificationResult {
  const base: ClassificationInput = {
    ...input,
    plaintext: item.plaintext,
    mime: item.mime,
    tags: item.tags,
  };
  let text: string | undefined;
  try {
    text = deriveText(item.mime, item.plaintext);
  } catch {
    return { sensitivity: classify(base).sensitivity, rule: DERIVE_FAILED_RULE };
  }
  return classify(text ? { ...base, derivedTexts: [text] } : base);
}
