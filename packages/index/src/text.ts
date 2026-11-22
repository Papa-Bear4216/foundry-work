export const MAX_CHUNKS = 1024;
const target = 800;
const overlap = 100;

/** Decode UTF-8 frames incrementally, preserving context across chunk boundaries. */
export function* chunkText(frames: Iterable<Uint8Array>): Generator<string> {
  const decoder = new TextDecoder();
  let pending = '';
  let emitted = 0;

  function* flush(final: boolean): Generator<string> {
    while (pending.length > target && emitted < MAX_CHUNKS) {
      const window = pending.slice(0, target);
      const paragraphs = window.lastIndexOf('\n\n');
      const sentence = [...window.matchAll(/[.!?]\s/g)].at(-1)?.index;
      let cut = paragraphs >= target / 2 ? paragraphs : (sentence ?? 0) + 1;
      if (cut < target / 2) cut = target;
      // Keep a UTF-16 surrogate pair within one chunk.
      if (/[\uD800-\uDBFF]/u.test(pending[cut - 1])) cut--;
      const chunk = pending.slice(0, cut).trim();
      let next = cut - overlap;
      if (/[\uDC00-\uDFFF]/u.test(pending[next])) next--;
      pending = pending.slice(next);
      if (chunk) {
        emitted++;
        yield chunk;
      }
    }
    if (final && emitted < MAX_CHUNKS && pending.trim()) yield pending.trim();
  }

  for (const frame of frames) {
    // Small slices also bound the temporary decoded string for a large frame.
    for (let offset = 0; offset < frame.length && emitted < MAX_CHUNKS; offset += 8192) {
      pending += decoder.decode(frame.subarray(offset, offset + 8192), { stream: true });
      yield* flush(false);
    }
    if (emitted === MAX_CHUNKS) return;
  }
  pending += decoder.decode();
  yield* flush(true);
}
