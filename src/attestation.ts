/**
 * @synoi/sraid — attestation.ts
 *
 * L2 attestation layer: a DSSE (Dead Simple Signing Envelope) profile that
 * carries one or more detached signatures over a SRAID object's canonical
 * payload, with the payload TYPE structurally bound into the signed bytes.
 *
 * Why this exists (SRAID F7 / Adversary A4, SRAID_FOUNDATION_PUNCHLIST A3,
 * OBJECT_MODEL_CLEANSHEET §3.2): the legacy `SignatureEnvelope` signs the
 * bare canonical bytes with NO payload-type binding. Because every SRAID
 * object shape (decision receipt, capability grant, memory record, identity
 * disclosure, supply-chain attestation, …) is signed identically over its
 * canonical bytes, a signature minted for one type could be replayed as a
 * valid signature for a different type whose canonical bytes happen to match
 * — a cross-type / confused-deputy hazard. DSSE closes this by signing the
 * Pre-Authentication Encoding (PAE), which prepends the payloadType and the
 * lengths of both fields, so the type is part of what is signed.
 *
 * SynOI policy (the AND rule): a SRAID attestation MUST carry BOTH an
 * `ed25519` and an `ml-dsa-65` signature over the SAME PAE, and the verifier
 * here requires BOTH to verify before returning `valid: true`. DSSE itself
 * is an OR-of-signatures envelope; the both-required rule lives in this
 * verifier and in the SRAID spec, not in DSSE. This preserves the hybrid
 * classical + post-quantum property of the legacy scheme.
 *
 * Profile: JSON (`payloadType` is a media type string; `payload` is the
 * canonical UTF-8 string). A future CBOR profile would use COSE (RFC 9052);
 * it is reserved, not implemented here.
 *
 * Identity stability: signatures live in a detached `signatures[]` array and
 * are NEVER part of the OID hash input (see `cdroContentCore` in oid.ts), so
 * adding, rotating, or replacing a signature never changes the object's OID.
 */

import { verifyEd25519 } from './ed25519.js'
import { decodeBase64Strict } from './internal/base64.js'
import { verifyMlDsa65 } from './mldsa.js'
import type { AttestationEnvelope, AttestationSignature } from './types.js'

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
 * Verify a hybrid DSSE attestation envelope. Returns `valid: true` only when
 * the envelope carries BOTH an `ed25519` and an `ml-dsa-65` signature and
 * BOTH verify against the supplied public keys over `PAE(payloadType,
 * payload)`. The payloadType is bound into the signed bytes, so a signature
 * minted for a different payloadType will not verify.
 */
export function verifyAttestation(input: VerifyAttestationInput): VerifyAttestationResult {
  const reasons: string[] = []

  const env = input.envelope
  if (
    env === null ||
    typeof env !== 'object' ||
    typeof env.payloadType !== 'string' ||
    env.payloadType.length === 0 ||
    typeof env.payload !== 'string' ||
    !Array.isArray(env.signatures)
  ) {
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
      edSig = fromBase64(edEntry.sig)
    } catch {
      reasons.push('ed25519-malformed')
    }
    if (edSig) {
      try {
        edOk = verifyEd25519(edSig, message, input.ed25519_pub)
      } catch {
        edOk = false
      }
      if (!edOk) reasons.push('ed25519-invalid')
    }
  }

  if (mlEntry) {
    let mlSig: Uint8Array | null = null
    try {
      mlSig = fromBase64(mlEntry.sig)
    } catch {
      reasons.push('ml-dsa-malformed')
    }
    if (mlSig) {
      try {
        mlOk = verifyMlDsa65(mlSig, message, input.ml_dsa_pub)
      } catch {
        mlOk = false
      }
      if (!mlOk) reasons.push('ml-dsa-invalid')
    }
  }

  return { valid: edOk && mlOk && !!edEntry && !!mlEntry, reasons }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function findSig(
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

// Strict standard base64. Throws Error('base64-malformed') on any deviation
// (illegal char, bad length, bad padding) rather than silently truncating.
// Both call sites wrap this in try/catch and map the throw to a *-malformed
// reason, so verifyAttestation never throws.
function fromBase64(s: string): Uint8Array {
  return decodeBase64Strict(s)
}
