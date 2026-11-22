import { IndexError } from './driver.ts';

export function object(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new IndexError('PROJECTION', `Expected an object for ${field}.`);
  }
  return value as Record<string, unknown>;
}

export function string(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new IndexError('PROJECTION', `Expected a nonempty string for ${field}.`);
  }
  return value;
}

export function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new IndexError('PROJECTION', `Expected an integer for ${field}.`);
  }
  return value;
}

export function optionalString(value: unknown, field: string): string | null {
  return value == null ? null : string(value, field);
}
