/**
 * @synoi/sraid — capability.ts
 *
 * Capability-pattern matching and the live-status contract.
 *
 * These stay in the core entry, while the grant/delegation VERIFIERS moved to
 * `@synoi/sraid/authority` in 0.4.0, because they are different things:
 *
 *   - `capabilityCovers` is a pure, total string predicate with no crypto, no
 *     I/O and no policy. It decides whether one dotted-taxonomy pattern covers
 *     another, and it is the leaf primitive that grant stores build on
 *     (synoi-app's `in-memory-engine.ts` and `app-store/store.ts` both call it
 *     directly rather than going through a verifier).
 *   - `GrantStatus` / `AuthorityResolver` are the CONTRACT for live grant
 *     state. The contract is a type; satisfying it is somebody else's job.
 *     Keeping it here lets a store, a resolver and a verifier agree on shape
 *     without any of them depending on the verifier.
 *
 * Nothing in this module makes, or can make, a live claim.
 */

/**
 * Match a capability `target` against a grant `pattern`. Pure string logic,
 * re-stated here so the core stays dependency-free (the same rule lives in
 * `@synoi/gap-types` `capabilityMatches`; the object layer must not depend on
 * the protocol layer).
 *
 *   - exact match → true
 *   - '*' → match-all
 *   - 'skill.*' matches 'skill.create' and deeper (segment-boundary only).
 *     A non-boundary 'admin.us*' must NOT match 'admin.users.delete'
 *     (privilege-escalation footgun) — only a '.'-anchored '*' is a wildcard.
 */
export function capabilityCovers(pattern: string, target: string): boolean {
  if (pattern === target) return true
  if (pattern === '*') return true
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -1) // keep trailing '.', e.g. 'skill.'
    return target.startsWith(prefix)
  }
  return false
}

/**
 * The live-state interface that the OID Resolver implements. It is the ONLY
 * source of truth for the two properties that cannot be checked offline:
 * whether a grant currently exists (resolves) and whether it has been revoked.
 *
 * RESOLVER-DEPENDENT: undeployed today (SRAID_FOUNDATION_PUNCHLIST C). Defined
 * here so callers, a future resolver, and the out-of-core verifier all agree
 * on one contract.
 */
export interface AuthorityResolver {
  /**
   * Resolve a grant OID to its current status. Implementations should return
   * `{ exists: false }` for an unknown OID and `{ exists: true, revoked: true,
   * revoked_at_ms }` for a revoked one.
   */
  resolveGrantStatus(grantOid: string): Promise<GrantStatus> | GrantStatus
}

export interface GrantStatus {
  /** Whether the grant OID resolves to a known, published grant. */
  exists: boolean
  /** Whether the grant has been revoked. Only meaningful when `exists`. */
  revoked?: boolean
  /** When the revocation took effect, if revoked. */
  revoked_at_ms?: number
}
