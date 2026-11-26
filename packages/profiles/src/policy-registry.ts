/**
 * P-1 fix round 1 (B2): the private copy of the replayed child model-prompt policy.
 *
 * `loadVaultProfileState` records, for each state object it returns, a COPY of the replayed
 * `allowChildModelPrompts` table taken at replay time. The prompt gate reads only that copy. A state
 * object this module did not record (a hand-built object, a plain `Map`, `undefined`) has no policy, so
 * every child item is ineligible. Changing the state's own `collections` map after replay changes
 * nothing here. This module is internal: `index.ts` does not export it.
 */
import type { VaultProfileState } from './types.ts';

const replayedPolicies = new WeakMap<VaultProfileState, ReadonlyMap<string, boolean>>();

/** Record the replayed policy table of `state` (a copy is taken here). Called only by `loadVaultProfileState`. */
export function recordReplayedPolicy(state: VaultProfileState, table: Iterable<readonly [string, boolean]>): void {
  const copy = new Map<string, boolean>();
  for (const [collection, allow] of table) copy.set(collection, allow === true);
  replayedPolicies.set(state, copy);
}

/** True only when `state` came from `loadVaultProfileState` and its replayed copy switches `collection` on. */
export function replayedChildPromptsAllowed(state: unknown, collection: string): boolean {
  if (state === null || typeof state !== 'object') return false;
  const table = replayedPolicies.get(state as VaultProfileState);
  return table?.get(collection) === true;
}
