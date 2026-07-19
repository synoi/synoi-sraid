/**
 * @synoi/sraid — oid.ts
 *
 * OID (Object IDentifier) computation. An OID is a content-addressed
 * identifier for a CDRO object:
 *
 *     OID = "sha256:" + hex(sha256(canonicalize(content)))
 *
 * The hash input is the canonical form of the OBJECT MINUS the six detached
 * signature / envelope fields (see `CDRO_ENVELOPE_FIELDS`). Higher-layer code
 * (e.g. GAP) typically passes the object's `body` directly; this function
 * accepts any value and canonicalizes it without further interpretation, so
 * callers stay in control of what enters the hash.
 *
 * This module is the SINGLE NORMATIVE SOURCE of the CDRO OID projection
 * (ADR_019). The strip-set and number rule are specified in prose in
 * PROJECTION_SPEC.md; all other surfaces derive from here.
 *
 * This matches the gateway's `computeGapOid` (src/gap/oid.ts) and
 * `payloadOid` (src/inference/receipts.ts) byte-for-byte.
 */

import { createHash } from 'node:crypto'
import { canonicalize } from './canonicalize.js'
import { CDRO_ENVELOPE_FIELDS, cdroContentCore } from './internal/content-core.js'

// The CDRO strip-set and its content-core projection are the SINGLE NORMATIVE
// SOURCE (ADR_019) and live in the PURE ./internal/content-core module (no
// node:crypto), so the browser verify surface can share them byte-for-byte.
// oid.ts re-exports them and layers the SHA-256 hashing (below) on top; this
// keeps the public surface (`import { cdroContentCore, CDRO_ENVELOPE_FIELDS }
// from '@synoi/sraid'`) unchanged. See ./internal/content-core.ts for the
// normative strip-set documentation; do not re-list it here.
export { CDRO_ENVELOPE_FIELDS, cdroContentCore }

/**
 * Compute an OID over an arbitrary canonical-compatible value.
 *
 *   oidOf({ a: 1, b: 2 }) === oidOf({ b: 2, a: 1 })
 *
 * Returns `sha256:` followed by 64 lowercase hex characters.
 *
 * Uses the platform SHA-256 (node:crypto / OpenSSL), which is byte-identical
 * to any conformant SHA-256 and materially faster than a pure-JS hash. The
 * output contract is unchanged.
 */
export function oidOf(canonical: unknown): string {
  const bytes = new TextEncoder().encode(canonicalize(canonical))
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

/**
 * Compute an OID directly from already-canonicalized bytes. Useful when
 * the caller has produced the canonical string itself (for example, when
 * the same bytes will also feed into a signature) and wants to avoid
 * canonicalizing twice.
 */
export function oidOfCanonical(canonical: string | Uint8Array): string {
  const bytes =
    typeof canonical === 'string'
      ? new TextEncoder().encode(canonical)
      : canonical
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

/**
 * Compute the OID of a full CDRO over its content core (see
 * `cdroContentCore`). This is the correct way to derive identity for a
 * complete CDRO: it hashes `authority`, `supersedes`, `gap_version`, `body`,
 * and every other content field, so the L4 authority block is identity-bound
 * and cannot be silently dropped.
 *
 * INVARIANT (ADR_019): `cdroOid(obj)` yields the SAME OID whether `obj` is
 * pre- or post-attestation, because the detached envelope fields are stripped
 * (see `CDRO_ENVELOPE_FIELDS`). This is what lets a third party recompute the
 * OID of a signed receipt and match the value the signer stamped.
 *
 * Note this differs from `oidOf(cdro.body)`: a CDRO's identity is over the
 * whole content core, not just its body.
 */
export function cdroOid(cdro: unknown): string {
  return oidOf(cdroContentCore(cdro))
}
