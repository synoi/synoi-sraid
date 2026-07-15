/**
 * @synoi/sraid/verify-browser — browser / Chrome-extension / service-worker
 * verify surface.
 *
 * The default (`.`) entry statically imports `node:crypto` in three places:
 * ed25519.ts (node-only Ed25519 verify), mldsa.ts (native ML-DSA + polyfill),
 * and oid.ts (createHash). `node:crypto` does not exist in a browser or
 * service-worker context, so `import '@synoi/sraid'` breaks any browser bundle.
 * This entry is the browser-safe alternative: it carries exactly what a v2
 * hybrid DSSE receipt verifier needs, implemented WITHOUT any static
 * node:crypto import.
 *
 * WHAT THIS EXPOSES (all browser-safe):
 *   - canonicalize            — pure RFC 8785 JCS serializer (shared, unchanged).
 *   - cdroContentCore,        — the CDRO OID content-core projection and its
 *     CDRO_ENVELOPE_FIELDS       normative strip-set (pure; shared byte-for-byte
 *                                with the node entry via internal/content-core).
 *   - verifyAttestation       — hybrid DSSE verify (Ed25519 AND ML-DSA-65, both
 *                                required over the PAE). ASYNC here: WebCrypto
 *                                Ed25519 verify is Promise-based.
 *   - pae, ALG_ED25519,       — the DSSE PAE encoder and algorithm ids (pure,
 *     ALG_ML_DSA_65              shared with the node entry).
 *   - cdroOid, oidOf,         — OID helpers over WebCrypto SHA-256. ASYNC here
 *     oidOfCanonical             (subtle.digest is Promise-based).
 *
 * CRYPTO BACKENDS (browsers have no native ML-DSA and no node:crypto):
 *   - Ed25519 verify  → WebCrypto (RFC 8032 cofactored, matching the node path),
 *                       with a @noble/curves fallback below the WebCrypto-Ed25519
 *                       support floor. See internal/ed25519-browser.ts.
 *   - ML-DSA-65 verify → @noble/post-quantum (pure JS). See internal/mldsa-browser.ts.
 *   - SHA-256          → WebCrypto subtle.digest. See internal/sha256-browser.ts.
 *
 * NODE PARITY: the node default entry (`@synoi/sraid`) is unchanged and stays
 * synchronous with its node:crypto fast paths. This entry is purely additive.
 * The only surface difference is async: verifyAttestation, cdroOid, oidOf, and
 * oidOfCanonical return Promises here because WebCrypto is Promise-based.
 *
 * Downstream: @synoi/verify's browser build imports this subpath to bring v2
 * hybrid DSSE verification (verifyReceiptV2) to the browser, replacing the
 * fail-closed `v2-not-supported-in-browser-build` stub.
 */

import { canonicalize } from './canonicalize.js'
import { CDRO_ENVELOPE_FIELDS, cdroContentCore } from './internal/content-core.js'
import { decodeBase64StrictBrowser } from './internal/base64-browser.js'
import { verifyEd25519Browser } from './internal/ed25519-browser.js'
import { verifyMlDsa65Browser } from './internal/mldsa-browser.js'
import { sha256HexPrefixed } from './internal/sha256-browser.js'
import {
  ALG_ED25519,
  ALG_ML_DSA_65,
  findSig,
  isWellFormedEnvelope,
  pae,
  type VerifyAttestationInput,
  type VerifyAttestationResult,
} from './internal/attestation-core.js'

// ── Pure / shared re-exports (byte-for-byte identical to the node entry) ──────

export { canonicalize } from './canonicalize.js'
export { CDRO_ENVELOPE_FIELDS, cdroContentCore } from './internal/content-core.js'
export {
  pae,
  ALG_ED25519,
  ALG_ML_DSA_65,
  type VerifyAttestationInput,
  type VerifyAttestationResult,
}

// ── Hybrid DSSE attestation verify (browser, ASYNC) ───────────────────────────

/**
 * Verify a hybrid DSSE attestation envelope in a browser context. Returns
 * `valid: true` only when the envelope carries BOTH an `ed25519` and an
 * `ml-dsa-65` signature and BOTH verify against the supplied public keys over
 * `PAE(payloadType, payload)`. The payloadType is bound into the signed bytes,
 * so a signature minted for a different payloadType will not verify.
 *
 * ASYNC counterpart of the node `verifyAttestation`: identical envelope shape,
 * AND policy, PAE bytes, and reason strings — only the return is a Promise,
 * because Ed25519 verify runs on WebCrypto. Never rejects: any malformed input
 * or verification failure resolves to `{ valid: false, reasons: [...] }`.
 */
export async function verifyAttestation(
  input: VerifyAttestationInput,
): Promise<VerifyAttestationResult> {
  const reasons: string[] = []

  const env = input.envelope
  if (!isWellFormedEnvelope(env)) {
    return { valid: false, reasons: ['envelope-malformed'] }
  }

  if (
    input.expectedPayloadType !== undefined &&
    env.payloadType !== input.expectedPayloadType
  ) {
    return { valid: false, reasons: ['payload-type-mismatch'] }
  }

  // The signed bytes: PAE binds payloadType + payload together.
  const message = pae(env.payloadType, env.payload)

  // Find the required hybrid pair. The AND policy: both must be present.
  const edEntry = findSig(env.signatures, ALG_ED25519)
  const mlEntry = findSig(env.signatures, ALG_ML_DSA_65)

  if (!edEntry) reasons.push('missing-ed25519')
  if (!mlEntry) reasons.push('missing-ml-dsa-65')

  let edOk = false
  let mlOk = false

  if (edEntry) {
    let edSig: Uint8Array | null = null
    try {
      edSig = decodeBase64StrictBrowser(edEntry.sig)
    } catch {
      reasons.push('ed25519-malformed')
    }
    if (edSig) {
      try {
        edOk = await verifyEd25519Browser(edSig, message, input.ed25519_pub)
      } catch {
        edOk = false
      }
      if (!edOk) reasons.push('ed25519-invalid')
    }
  }

  if (mlEntry) {
    let mlSig: Uint8Array | null = null
    try {
      mlSig = decodeBase64StrictBrowser(mlEntry.sig)
    } catch {
      reasons.push('ml-dsa-malformed')
    }
    if (mlSig) {
      try {
        mlOk = verifyMlDsa65Browser(mlSig, message, input.ml_dsa_pub)
      } catch {
        mlOk = false
      }
      if (!mlOk) reasons.push('ml-dsa-invalid')
    }
  }

  return { valid: edOk && mlOk && !!edEntry && !!mlEntry, reasons }
}

// ── OID helpers (browser, ASYNC via WebCrypto SHA-256) ────────────────────────

/**
 * Compute an OID over an arbitrary canonical-compatible value using WebCrypto
 * SHA-256. Returns `sha256:` followed by 64 lowercase hex characters.
 *
 * ASYNC counterpart of the node `oidOf`: same canonical bytes and same
 * `sha256:`-prefixed output, but returns a Promise because subtle.digest is
 * Promise-based. Byte-identical result to the node entry for the same input.
 */
export async function oidOf(canonical: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(canonical))
  return sha256HexPrefixed(bytes)
}

/**
 * Compute an OID directly from already-canonicalized bytes using WebCrypto
 * SHA-256. ASYNC counterpart of the node `oidOfCanonical`.
 */
export async function oidOfCanonical(canonical: string | Uint8Array): Promise<string> {
  const bytes =
    typeof canonical === 'string' ? new TextEncoder().encode(canonical) : canonical
  return sha256HexPrefixed(bytes)
}

/**
 * Compute the OID of a full CDRO over its content core (see `cdroContentCore`),
 * using WebCrypto SHA-256. ASYNC counterpart of the node `cdroOid`; yields the
 * SAME OID whether the object is pre- or post-attestation, and the SAME value
 * the node entry produces for the same object.
 */
export async function cdroOid(cdro: unknown): Promise<string> {
  return oidOf(cdroContentCore(cdro))
}
