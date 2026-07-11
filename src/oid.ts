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
 * The detached-signature / envelope fields removed by `cdroContentCore`
 * before hashing. This is the SINGLE NORMATIVE strip-set for the CDRO OID
 * projection (ADR_019 decision 1); every other surface (GAP SDKs, the
 * gateway signer, IMPLEMENTING.md) derives from THIS set, never re-lists it.
 *
 * The set is defined SEMANTICALLY: it is "every field produced BY the signer
 * after canonicalization, plus the OID output itself." Concretely:
 *
 *   oid                  — the projection OUTPUT (cannot be an input to itself).
 *   signature            — legacy hybrid SignatureEnvelope (attaches after hash).
 *   ml_dsa_signature     — detached PQ signature (attaches after hash).
 *   signature_key_id     — signer-stamped key id (produced by the signer).
 *   signature_algorithm  — signer-stamped alg id (produced by the signer).
 *   attestation          — DSSE AttestationEnvelope (attaches after hash).
 *
 * EVERYTHING ELSE IS KEPT and hashed into the OID, including in particular:
 *   - `gap_version` — IN identity so a protocol downgrade is OID-detectable.
 *   - `supersedes`  — IN identity because the SRAID Merkle-DAG head-proves-
 *                     history property requires every lineage edge inside the
 *                     hash. Superseding mints a NEW object; it never mutates
 *                     the old one's bytes, so keeping it here is safe and
 *                     makes the lineage edge tamper-evident.
 *   - `type`, `sraid_version`, `tenant_id`, `created_at_ms`, `created_by`,
 *     `body`, `authority`, `sensitivity`, `prev`, `links`, and any other
 *     content field.
 *
 * This is the ONE projection that yields the SAME OID whether the object is
 * pre- or post-attestation: attaching an `attestation` (or `signature`,
 * `ml_dsa_signature`, `signature_key_id`, `signature_algorithm`) after hashing
 * is stripped back out here, so `cdroOid(obj)` is invariant across signing.
 *
 * It is FROZEN so no caller can mutate the normative set at runtime.
 */
export const CDRO_ENVELOPE_FIELDS: readonly string[] = Object.freeze([
  'oid',
  'signature',
  'ml_dsa_signature',
  'signature_key_id',
  'signature_algorithm',
  'attestation',
])

const CDRO_ENVELOPE_FIELD_SET: ReadonlySet<string> = new Set(CDRO_ENVELOPE_FIELDS)

/**
 * Build the OID content core of a full CDRO: the object with EXACTLY the six
 * detached-signature / envelope fields in `CDRO_ENVELOPE_FIELDS` removed at
 * the top level, and everything else kept.
 *
 * This is the mechanism that makes the L4 `authority` block, the L3 lineage
 * edges (`prev`, `links`, `supersedes`), the propagating `sensitivity` tier,
 * and `gap_version` tamper-evident: they are hashed into identity by
 * construction, so a field cannot be added, stripped, re-pointed, or
 * downgraded without producing a different OID (and invalidating the
 * signature, which is computed over these same bytes). Because `prev`/`links`/
 * `supersedes` OIDs are inside the hash, a node's OID transitively commits its
 * whole reachable history (the Merkle-DAG "head proves history" property).
 *
 * Returns a plain object suitable for `canonicalize` / `oidOf`.
 */
export function cdroContentCore(cdro: unknown): Record<string, unknown> {
  if (cdro === null || typeof cdro !== 'object' || Array.isArray(cdro)) {
    throw new TypeError('cdroContentCore: argument must be a CDRO object')
  }
  const core: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(cdro as Record<string, unknown>)) {
    if (CDRO_ENVELOPE_FIELD_SET.has(k)) continue
    core[k] = v
  }
  return core
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
