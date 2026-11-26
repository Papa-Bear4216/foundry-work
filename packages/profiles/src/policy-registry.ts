/**
 * P-1 fix round 1 (B2): the private copy of the replayed child model-prompt policy.
 *
 * `loadVaultProfileState` records, for each state object it returns, a COPY of the replayed
 * `allowChildModelPrompts` table taken at replay time. The prompt gate reads only that copy. A state
 * object this module did not record (a hand-built object, a plain `Map`, `undefined`) has no policy, so
 * every child item is ineligible. Changing the state's own `collections` map after replay changes
 * nothing here. This module is internal: `index.ts` does not export it.
 *
 * P-1 fix round 2 (G1): the copy also holds the vault ID read from `VAULT.json` at replay time. The gate
 * accepts an item only when its `vaultId` equals that ID, so the policy of vault A never approves an
 * item of vault B, even when their collection names match.
 */
import type { VaultProfileState } from './types.ts';

interface ReplayedPolicy {
  readonly vaultId: string;
  readonly table: ReadonlyMap<string, boolean>;
}

const replayedPolicies = new WeakMap<VaultProfileState, ReplayedPolicy>();

/**
 * Record the vault ID and replayed policy table of `state` (a copy is taken here). Called only by
 * `loadVaultProfileState`.
 */
export function recordReplayedPolicy(
  state: VaultProfileState,
  vaultId: string,
  table: Iterable<readonly [string, boolean]>,
): void {
  const copy = new Map<string, boolean>();
  for (const [collection, allow] of table) copy.set(collection, allow === true);
  replayedPolicies.set(state, Object.freeze({ vaultId, table: copy }));
}

/** The vault ID recorded for `state` at replay time, or undefined when `state` was not recorded. */
export function replayedVaultId(state: unknown): string | undefined {
  if (state === null || typeof state !== 'object') return undefined;
  return replayedPolicies.get(state as VaultProfileState)?.vaultId;
}

/** True only when `state` came from `loadVaultProfileState` and its replayed copy switches `collection` on. */
export function replayedChildPromptsAllowed(state: unknown, collection: string): boolean {
  if (state === null || typeof state !== 'object') return false;
  const policy = replayedPolicies.get(state as VaultProfileState);
  return policy?.table.get(collection) === true;
}
