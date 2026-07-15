/**
 * @synoi/sraid — internal/content-core.ts
 *
 * The CDRO OID content-core projection: the normative strip-set and the
 * field-removal function that together define WHAT bytes an OID is computed
 * over. This is a PURE module — no hashing, no node:crypto, no Buffer — so it
 * is safe to import from both the node default entry (via oid.ts) and the
 * browser verify surface (via verify-browser.ts) without dragging node
 * builtins into a browser bundle.
 *
 * This is the SINGLE NORMATIVE SOURCE of the CDRO OID projection (ADR_019).
 * oid.ts re-exports these symbols and layers the SHA-256 hashing on top; every
 * other surface (GAP SDKs, the gateway signer, IMPLEMENTING.md) derives from
 * THIS set, never re-lists it.
 */

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
