/**
 * V-6 spike: KeyCache port contract, always-available `none` adapter,
 * and fail-to-`none` wrapper. Zero runtime dependencies (Node built-ins only).
 *
 * Synthetic TEST-ONLY spike code on branch `spike/v-6` (not merged).
 */

/**
 * @typedef {Object} CacheDescriptor
 * @property {string} vaultId 32 lowercase hex chars (16 raw bytes)
 * @property {string} kdfSaltHash 64 lowercase hex chars (SHA-256 of keyring kdf.salt)
 */

/**
 * @typedef {Object} KeyCacheAdapter
 * @property {'none' | 'os-session' | 'os-protected'} name
 * @property {() => { available: boolean; reason?: string }} probe
 * @property {(desc: CacheDescriptor) => Buffer | null} get
 * @property {(desc: CacheDescriptor, kek: Buffer, ttlSeconds?: number) => boolean} set
 * @property {(desc: CacheDescriptor) => void} clear
 */

/** Always-available default adapter: never stores or returns key material. */
export function createNoneAdapter() {
  return {
    name: /** @type {const} */ ('none'),
    probe() {
      return { available: true };
    },
    get(_desc) {
      return null;
    },
    set(_desc, _kek, _ttlSeconds) {
      return false;
    },
    clear(_desc) {},
  };
}

/**
 * Wraps any OS adapter so every failure degrades safely to `none` (cache miss),
 * never fails open, and never blocks passphrase-based vault unlock.
 *
 * @param {KeyCacheAdapter} adapter
 * @param {(event: { op: string; adapter: string; reason: string }) => void} [onFallback]
 */
export function createFailToNoneCache(adapter, onFallback) {
  const report = (op, error) => {
    const reason = error instanceof Error ? error.message : String(error);
    if (onFallback) onFallback({ op, adapter: adapter.name, reason });
  };

  return {
    name: adapter.name,
    probe() {
      try {
        return adapter.probe();
      } catch (error) {
        report('probe', error);
        return { available: false, reason: 'probe-threw' };
      }
    },
    get(desc) {
      try {
        const key = adapter.get(desc);
        if (key === null) return null;
        if (!Buffer.isBuffer(key) || key.length !== 32) {
          if (Buffer.isBuffer(key)) key.fill(0);
          try { adapter.clear(desc); } catch { /* ignore cleanup failure */ }
          report('get', new Error('invalid cached key length; evicted'));
          return null;
        }
        return key;
      } catch (error) {
        try { adapter.clear(desc); } catch { /* ignore cleanup failure */ }
        report('get', error);
        return null;
      }
    },
    set(desc, kek, ttlSeconds) {
      if (!Buffer.isBuffer(kek) || kek.length !== 32) return false;
      try {
        return Boolean(adapter.set(desc, kek, ttlSeconds));
      } catch (error) {
        report('set', error);
        return false;
      }
    },
    clear(desc) {
      try {
        adapter.clear(desc);
      } catch (error) {
        report('clear', error);
      }
    },
  };
}
