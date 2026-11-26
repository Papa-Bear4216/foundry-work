import type {
  CollectionPolicyEntry,
  CollectionPolicyLookup,
  PromptCandidateItem,
  PromptEligibility,
} from './types.ts';
import {
  assertProfileId,
  assertSensitivityTier,
  assertUserCollectionName,
} from './validation.ts';

function readAllowChildModelPrompts(
  collection: string,
  policySource?: CollectionPolicyLookup,
): boolean {
  if (!policySource) return false;

  if ('collections' in policySource && policySource.collections instanceof Map) {
    const state = policySource.collections.get(collection);
    return state?.allowChildModelPrompts === true;
  }

  if (policySource instanceof Map) {
    const entry = policySource.get(collection) as CollectionPolicyEntry | undefined;
    if (typeof entry === 'boolean') return entry;
    return entry?.allowChildModelPrompts === true;
  }

  const record = policySource as Readonly<Record<string, CollectionPolicyEntry>>;
  if (!Object.hasOwn(record, collection)) return false;
  const entry = record[collection];
  if (typeof entry === 'boolean') return entry;
  return entry?.allowChildModelPrompts === true;
}

/**
 * Deterministic model-prompt gating check (Product Spec section 9, Roadmap P-1):
 * - `sensitivity === 'secret'` is NEVER eligible (cannot be overridden).
 * - `sensitivity === 'child'`, `profile === 'child'`, or a `child/...` collection is excluded
 *   by default (`reason: 'CHILD_TIER_EXCLUDED'`) and becomes eligible ONLY when the item's
 *   exact `collection` has `allowChildModelPrompts === true` in the replayed vault policy state.
 */
export function isPromptEligible(
  item: PromptCandidateItem,
  policySource?: CollectionPolicyLookup,
): PromptEligibility {
  const profile = assertProfileId(item.profile);
  const collection = assertUserCollectionName(item.collection);
  const sensitivity = assertSensitivityTier(item.sensitivity);

  if (sensitivity === 'secret') {
    return { eligible: false, reason: 'SECRET_TIER_EXCLUDED' };
  }

  const isChildData =
    sensitivity === 'child' ||
    profile === 'child' ||
    collection === 'child' ||
    collection.startsWith('child/');

  if (isChildData) {
    if (readAllowChildModelPrompts(collection, policySource)) {
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
  policySource?: CollectionPolicyLookup,
): T[] {
  return items.filter(item => isPromptEligible(item, policySource).eligible);
}
