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
 *
 * NODE ENTRY: this module verifies via node:crypto (Ed25519 native, ML-DSA-65
 * native-with-@noble-fallback) and is SYNCHRONOUS. The PAE, algorithm ids,
 * types, AND-policy lookup, and envelope-shape predicate are shared with the
 * browser verify surface via ./internal/attestation-core.ts (pure, no
 * node:crypto); only the verify orchestration below is node-specific. The
 * browser-safe async equivalent lives in ./verify-browser.ts.
 */

import { verifyEd25519 } from './ed25519.js'
import { decodeBase64Strict } from './internal/base64.js'
import { verifyMlDsa65 } from './mldsa.js'
import {
  ALG_ED25519,
  ALG_ML_DSA_65,
  findSig,
  isWellFormedEnvelope,
  pae,
  type VerifyAttestationInput,
  type VerifyAttestationResult,
} from './internal/attestation-core.js'

// Re-export the crypto-agnostic core so the public surface is unchanged:
// `import { pae, ALG_ED25519, ALG_ML_DSA_65 } from '@synoi/sraid'` still works.
export {
  ALG_ED25519,
  ALG_ML_DSA_65,
  pae,
  type VerifyAttestationInput,
  type VerifyAttestationResult,
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

// Strict standard base64. Throws Error('base64-malformed') on any deviation
// (illegal char, bad length, bad padding) rather than silently truncating. The
// call sites wrap this in try/catch and map the throw to a *-malformed reason,
// so verifyAttestation never throws.
function fromBase64(s: string): Uint8Array {
  return decodeBase64Strict(s)
}
