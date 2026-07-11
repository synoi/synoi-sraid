/**
 * @synoi/sraid — internal/key-cache.ts
 *
 * Bounded, insertion-order LRU for cached KeyObjects, plus a registry so a
 * single revocation call can fan out across every live cache.
 *
 * INTERNAL: not exported from index.ts. Only `evictKeyFromCaches` is public.
 *
 * Why a hand-rolled LRU and not `lru-cache`: this package is deliberately
 * zero-runtime-dependency (only @noble/* dev/peer surface). Pulling an npm LRU
 * to bound a key cache would widen the supply-chain attack surface of the exact
 * L0 library whose value is a minimal, auditable core. A ~40-line insertion-
 * order LRU costs nothing and keeps that posture.
 *
 * The cache key is the lowercase hex of the RAW public-key bytes — the same
 * string mldsa.ts and ed25519.ts already use as their Map key. It is NOT an
 * OID, DID, or kid. ed25519 keys (32B hex) and ml-dsa-65 keys (1952B hex)
 * never collide, so the two caches share one key namespace safely and a
 * cross-cache evict is a harmless no-op when the key is absent.
 */

/** Per-cache capacity. At 1952 bytes/ml-dsa-key this bounds raw-key-equivalent
 * residency near ~2MB plus KeyObject overhead — bounded and safe. */
export const KEY_CACHE_MAX = 1000

/** Registry of every live cache, for coordinated eviction. */
const registry: BoundedKeyCache<unknown>[] = []

/**
 * Insertion-order LRU. Map preserves insertion order, so the oldest live entry
 * is always `keys().next()`. A `get` hit re-inserts (delete + set) to promote
 * the entry to most-recently-used. `set` evicts the oldest when at capacity.
 */
export class BoundedKeyCache<V> {
  private readonly map = new Map<string, V>()

  constructor(readonly max: number = KEY_CACHE_MAX) {
    registry.push(this as BoundedKeyCache<unknown>)
  }

  get size(): number {
    return this.map.size
  }

  get(key: string): V | undefined {
    const v = this.map.get(key)
    if (v === undefined) return undefined
    // Promote to most-recently-used.
    this.map.delete(key)
    this.map.set(key, v)
    return v
  }

  set(key: string, value: V): void {
    // If present, drop first so re-insert lands at the MRU end.
    if (this.map.has(key)) this.map.delete(key)
    else if (this.map.size >= this.max) {
      const oldest = this.map.keys().next().value
      if (oldest !== undefined) this.map.delete(oldest)
    }
    this.map.set(key, value)
  }

  delete(key: string): boolean {
    return this.map.delete(key)
  }
}

/**
 * Evict a key from every live cache. Use for coordinated key revocation: when a
 * signing key is rotated or compromised, drop any cached KeyObject for it so a
 * later verify cannot be served a stale entry.
 *
 * @param keyId lowercase hex of the RAW public-key bytes (the cache key). Not
 *              an OID/DID/kid. Deleting an absent key is a harmless no-op.
 */
export function evictKeyFromCaches(keyId: string): void {
  for (const cache of registry) cache.delete(keyId)
}
