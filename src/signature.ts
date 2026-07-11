/**
 * @synoi/sraid — signature.ts
 *
 * Hybrid ed25519 + ml-dsa-65 signature verification for CDRO envelopes.
 *
 * SynOI signs every Decision Receipt and every governance object with
 * BOTH a classical Ed25519 signature and a post-quantum ML-DSA-65
 * signature. The verifier in this package requires BOTH to be valid
 * before returning `valid: true` — even though either alone is
 * cryptographically meaningful, signed objects exit the system only when
 * both check out.
 *
 * The signature bytes are computed over the canonical form of the object
 * minus the `signature` field itself. Callers are expected to produce
 * that canonical form (typically via `canonicalize()` in this package)
 * and pass it as `canonical` here — verifiers MUST use the same exact
 * bytes that the signer used, so callers control that contract.
 */

import { verifyEd25519 } from './ed25519.js'
import { decodeBase64Strict } from './internal/base64.js'
import { verifyMlDsa65 } from './mldsa.js'
import type { SignatureEnvelope } from './types.js'

export interface VerifySignatureInput {
  /** The canonical bytes that were signed (string is utf-8 encoded). */
  canonical: string | Uint8Array
  /** Signature envelope to verify. */
  envelope: SignatureEnvelope
  /** Raw 32-byte Ed25519 public key. */
  ed25519_pub: Uint8Array
  /** Raw ML-DSA-65 public key bytes. */
  ml_dsa_pub: Uint8Array
}

export interface VerifySignatureResult {
  /** True only when BOTH signatures verified successfully. */
  valid: boolean
  /**
   * Human-readable reasons for failure. Empty when valid. Possible
   * values: 'ed25519-invalid', 'ml-dsa-invalid', 'ed25519-malformed',
   * 'ml-dsa-malformed', 'envelope-malformed'.
   */
  reasons: string[]
}

/**
 * Verify a hybrid CDRO signature envelope. Returns `valid: true` only
 * when both the Ed25519 and the ML-DSA-65 signatures verify against the
 * supplied public keys and canonical bytes.
 */
export function verifySignature(input: VerifySignatureInput): VerifySignatureResult {
  const reasons: string[] = []

  if (
    !input.envelope ||
    typeof input.envelope.ed25519 !== 'string' ||
    typeof input.envelope.ml_dsa_65 !== 'string' ||
    typeof input.envelope.signer_kid !== 'string'
  ) {
    return { valid: false, reasons: ['envelope-malformed'] }
  }

  const message =
    typeof input.canonical === 'string'
      ? new TextEncoder().encode(input.canonical)
      : input.canonical

  // Decode the two signatures from base64. If either fails to decode,
  // the envelope is malformed — but we still want to verify the OTHER
  // signature so we can report both reasons in one pass.
  let edSig: Uint8Array | null = null
  let mlSig: Uint8Array | null = null
  try {
    edSig = fromBase64(input.envelope.ed25519)
  } catch {
    reasons.push('ed25519-malformed')
  }
  try {
    mlSig = fromBase64(input.envelope.ml_dsa_65)
  } catch {
    reasons.push('ml-dsa-malformed')
  }

  let edOk = false
  let mlOk = false

  if (edSig) {
    try {
      edOk = verifyEd25519(edSig, message, input.ed25519_pub)
    } catch {
      // Treat invalid signature shape as a verification failure rather
      // than a thrown exception, so callers can rely on a clean result.
      edOk = false
    }
    if (!edOk) reasons.push('ed25519-invalid')
  }

  if (mlSig) {
    try {
      mlOk = verifyMlDsa65(mlSig, message, input.ml_dsa_pub)
    } catch {
      mlOk = false
    }
    if (!mlOk) reasons.push('ml-dsa-invalid')
  }

  return { valid: edOk && mlOk, reasons }
}

// ── Base64 helpers (standard, with `=` padding) ──────────────────────────────

// Strict standard base64. Throws Error('base64-malformed') on any deviation
// rather than silently truncating at the first illegal byte. Both call sites
// wrap this in try/catch and map the throw to a *-malformed reason, so
// verifySignature never throws.
function fromBase64(s: string): Uint8Array {
  return decodeBase64Strict(s)
}
