/**
 * @synoi/sraid — internal/attestation-core.ts
 *
 * The crypto-agnostic core of the L2 DSSE attestation profile: the PAE
 * encoding, the algorithm identifiers, the public verify input/result types,
 * the both-required signature lookup, and the envelope-shape predicate.
 *
 * This is a PURE module — no crypto, no node:crypto, no Buffer — so the same
 * PAE bytes, AND-policy shape, and type contract are shared byte-for-byte by
 * BOTH the node default entry (attestation.ts, node:crypto verifiers) and the
 * browser verify surface (verify-browser.ts, WebCrypto + @noble verifiers).
 * Divergent PAE or shape logic between the two would be a signature-validity
 * hazard; keeping it in one place removes that risk.
 *
 * The verify ORCHESTRATION (decode each sig, run both verifiers, gate on the
 * AND policy) is intentionally NOT here: the node path is synchronous
 * (node:crypto verify) and the browser path is asynchronous (WebCrypto verify),
 * so a single shared body cannot serve both. Each entry keeps its own thin
 * orchestration and reuses these leaf helpers.
 */

import type { AttestationEnvelope, AttestationSignature } from '../types.js'

/** The single supported algorithm identifiers for the JSON profile. */
export const ALG_ED25519 = 'ed25519'
export const ALG_ML_DSA_65 = 'ml-dsa-65'

/**
 * The DSSE Pre-Authentication Encoding (PAE).
 *
 * Per the DSSE spec:
 *
 *   PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
 *
 * where:
 *   - SP is a single ASCII space (0x20),
 *   - LEN(x) is the ASCII-decimal byte length of x's UTF-8 encoding,
 *   - type and body are the raw UTF-8 bytes (NOT base64).
 *
 * Binding the payloadType (and both lengths) into the signed bytes is what
 * makes a signature non-transferable across object types. Returns the raw
 * bytes to be signed/verified.
 */
export function pae(payloadType: string, payload: string | Uint8Array): Uint8Array {
  const enc = new TextEncoder()
  const typeBytes = enc.encode(payloadType)
  const bodyBytes = typeof payload === 'string' ? enc.encode(payload) : payload

  const prefix = enc.encode(
    `DSSEv1 ${typeBytes.length} ${payloadType} ${bodyBytes.length} `,
  )
  const out = new Uint8Array(prefix.length + bodyBytes.length)
  out.set(prefix, 0)
  out.set(bodyBytes, prefix.length)
  return out
}

export interface VerifyAttestationInput {
  /**
   * The DSSE attestation envelope to verify. Its `payloadType` is bound into
   * the PAE; its `payload` is the canonical UTF-8 string that was signed.
   */
  envelope: AttestationEnvelope
  /** Raw 32-byte Ed25519 public key. */
  ed25519_pub: Uint8Array
  /** Raw ML-DSA-65 public key bytes. */
  ml_dsa_pub: Uint8Array
  /**
   * Optional. If supplied, the verifier asserts the envelope's `payloadType`
   * equals this value before verifying signatures — an explicit type-pinning
   * check on top of the structural PAE binding. A mismatch fails with
   * `payload-type-mismatch`.
   */
  expectedPayloadType?: string
}

export interface VerifyAttestationResult {
  /** True only when BOTH required signatures verified over the same PAE. */
  valid: boolean
  /**
   * Human-readable failure reasons. Empty when valid. Possible values:
   * 'envelope-malformed', 'payload-type-mismatch', 'missing-ed25519',
   * 'missing-ml-dsa-65', 'ed25519-malformed', 'ml-dsa-malformed',
   * 'ed25519-invalid', 'ml-dsa-invalid'.
   */
  reasons: string[]
}

/**
 * Structural well-formedness of an attestation envelope: a non-null object with
 * a non-empty string `payloadType`, a string `payload`, and an array
 * `signatures`. A false result maps to the `envelope-malformed` reason. This is
 * the SINGLE definition of envelope shape, shared by the node and browser
 * verifiers so they reject the same inputs.
 */
export function isWellFormedEnvelope(env: unknown): env is AttestationEnvelope {
  return (
    env !== null &&
    typeof env === 'object' &&
    typeof (env as AttestationEnvelope).payloadType === 'string' &&
    (env as AttestationEnvelope).payloadType.length > 0 &&
    typeof (env as AttestationEnvelope).payload === 'string' &&
    Array.isArray((env as AttestationEnvelope).signatures)
  )
}

/**
 * Find the first well-formed signature entry for `alg` (a `{ alg, sig }` object
 * whose `sig` is a string). Returns undefined when absent; the AND policy in
 * each verifier turns a missing pair member into a `missing-*` reason.
 */
export function findSig(
  sigs: readonly AttestationSignature[],
  alg: string,
): AttestationSignature | undefined {
  for (const s of sigs) {
    if (s && typeof s === 'object' && s.alg === alg && typeof s.sig === 'string') {
      return s
    }
  }
  return undefined
}
