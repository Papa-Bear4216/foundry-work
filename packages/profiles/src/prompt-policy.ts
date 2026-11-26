import { replayedChildPromptsAllowed, replayedVaultId } from './policy-registry.ts';
import type { PromptCandidateItem, PromptEligibility, VaultProfileState } from './types.ts';
import {
  assertProfileId,
  assertSensitivityTier,
  assertUserCollectionName,
} from './validation.ts';

/**
 * Deterministic model-prompt gating check (Product Spec section 9, Roadmap P-1). Checks, in this order:
 * 0. `item.vaultId` must equal the vault ID that `loadVaultProfileState` recorded for this `state` object
 *    (read from `VAULT.json` at replay time). A missing or different vault ID, or a state with no recorded
 *    snapshot, gives `VAULT_MISMATCH` for EVERY item, also non-child and `me` items (P-1 fix round 2, G1).
 *    The public `state.vaultId` field is never read here.
 * 1. `sensitivity === 'secret'` is NEVER eligible (`SECRET_TIER_EXCLUDED`, cannot be overridden).
 * 2. `item.collection` must start with `item.profile + '/'`, otherwise `COLLECTION_PROFILE_MISMATCH`
 *    (fail closed; this also shuts out records written before P-1, whose names are `<source>/<year>`).
 * 3. `sensitivity === 'child'`, `profile === 'child'`, or a `child/...` collection is excluded
 *    (`CHILD_TIER_EXCLUDED`) unless the item's exact `collection` is switched on in the PRIVATE copy of
 *    the policy that `loadVaultProfileState` took at replay time for this `state` object. Any other
 *    value (a hand-built object, a `Map`, `undefined`, or a state changed after replay) cannot switch
 *    child data on.
 *
 * Caller duty (A-43, ruling R14): the gate trusts the candidate's `profile`, `collection` and
 * `sensitivity`. Pass items read from authenticated vault or index records, never caller-supplied metadata.
 */
export function isPromptEligible(
  item: PromptCandidateItem,
  state?: VaultProfileState,
): PromptEligibility {
  const profile = assertProfileId(item.profile);
  const collection = assertUserCollectionName(item.collection);
  const sensitivity = assertSensitivityTier(item.sensitivity);

  const recordedVaultId = replayedVaultId(state);
  const itemVaultId: unknown = (item as { vaultId?: unknown }).vaultId;
  if (
    recordedVaultId === undefined ||
    typeof itemVaultId !== 'string' ||
    itemVaultId.length === 0 ||
    itemVaultId !== recordedVaultId
  ) {
    return { eligible: false, reason: 'VAULT_MISMATCH' };
  }

  if (sensitivity === 'secret') {
    return { eligible: false, reason: 'SECRET_TIER_EXCLUDED' };
  }

  if (!collection.startsWith(`${profile}/`)) {
    return { eligible: false, reason: 'COLLECTION_PROFILE_MISMATCH' };
  }

  const isChildData =
    sensitivity === 'child' ||
    profile === 'child' ||
    collection === 'child' ||
    collection.startsWith('child/');

  if (isChildData) {
    if (replayedChildPromptsAllowed(state, collection)) {
      return { eligible: true };
    }
    return { eligible: false, reason: 'CHILD_TIER_EXCLUDED' };
  }

  return { eligible: true };
}

/**
 * Filters candidate items down to those eligible for inclusion in a model prompt.
 */
export function filterItemsForModelPrompt<T extends PromptCandidateItem>(
  items: readonly T[],
  state?: VaultProfileState,
): T[] {
  return items.filter(item => isPromptEligible(item, state).eligible);
}
