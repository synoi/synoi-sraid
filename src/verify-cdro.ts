/**
 * @synoi/sraid — verify-cdro.ts
 *
 * THE consumer entry point. One call that does the three things a caller must
 * do together, in the order that makes them safe:
 *
 *   1. VALIDATE   the envelope shape (rejects the __proto__ collision shape).
 *   2. BIND       the attestation's payload to THIS object's content core.
 *   3. RECOMPUTE  the OID and compare it to the stamped `oid`.
 *   4. VERIFY     both signatures over the PAE (Ed25519 AND ML-DSA-65).
 *
 * Why this exists (panel finding 4.9). `verifyAttestation` verifies an
 * ENVELOPE, not an OBJECT. An envelope stapled to an unrelated CDRO returns
 * `valid: true`, and `validateCdro` on that object returns `ok: true`, because
 * neither function is told they are supposed to be about the same thing. Every
 * traced production consumer does bind first — nine to eleven call sites,
 * several cross-referencing each other in comments, so it is disciplined
 * rather than accidental — but the safety rested entirely on convention, with
 * nothing at the type or lint level enforcing it.
 *
 * The __proto__ OID collision showed that convention is bypassable: both sides
 * of the hand-written `att.payload === canonicalize(cdroContentCore(x))` check
 * dropped the same member, so a polluted object passed a correctly-written
 * binding check. A caller doing everything right still got the wrong answer.
 * The response is to stop asking callers to assemble the check themselves.
 *
 * ORDER MATTERS and is not caller-configurable. Shape before bind, bind before
 * OID, OID before crypto: the cheap structural gates run first, so a malformed
 * or unbound object never reaches ML-DSA verification. This mirrors the
 * hard-coded cheapest-first gate order in the delegation-chain verifier, which
 * the adversary seat attempted to reorder and could not.
 *
 * WHAT THIS DOES NOT DO, stated rather than implied:
 *   - It does not resolve `signer_kid`. The caller supplies the keys, so this
 *     verifies SIGNATURES, not IDENTITIES. There is no key directory.
 *   - It does not check revocation. Nothing here is a live claim.
 *   - It does not check authorization. That is `@synoi/authority-verify`.
 */

import { canonicalize } from './canonicalize.js'
import { cdroOid, cdroContentCore } from './oid.js'
import { validateCdro } from './validate.js'
import { verifyAttestation } from './attestation.js'
import type { AttestationEnvelope } from './types.js'

export interface VerifyCdroInput {
  /** The full CDRO, including its `oid` and `attestation`. */
  cdro: unknown
  /** Raw 32-byte Ed25519 public key. */
  ed25519_pub: Uint8Array
  /** Raw ML-DSA-65 public key bytes. */
  ml_dsa_pub: Uint8Array
  /**
   * Optional payloadType pinning, passed through to `verifyAttestation`. Supply
   * it whenever the caller knows which type it expects: it turns the structural
   * PAE binding into an explicit assertion and fails a cross-type replay early.
   */
  expectedPayloadType?: string
}

export interface VerifyCdroResult {
  /**
   * True only when EVERY check below passed. A false here never means "the
   * object is forged" on its own — read the per-check fields and `reasons`.
   */
  valid: boolean
  /** Envelope shape check (`validateCdro`). */
  shape_ok: boolean
  /** The attestation's `payload` equals this object's canonical content core. */
  binding_ok: boolean
  /** The recomputed OID equals the stamped `oid`. */
  oid_ok: boolean
  /** Both signatures verified over the PAE. */
  signature_ok: boolean
  /** The OID this object's content actually hashes to. */
  computed_oid: string | null
  /**
   * Machine-readable failure reasons, in check order. Includes the reason
   * strings from `verifyAttestation` unchanged.
   */
  reasons: string[]
}

function fail(
  partial: Partial<VerifyCdroResult>,
  reasons: string[],
): VerifyCdroResult {
  return {
    valid: false,
    shape_ok: false,
    binding_ok: false,
    oid_ok: false,
    signature_ok: false,
    computed_oid: null,
    ...partial,
    reasons,
  }
}

/**
 * Verify a complete signed CDRO: shape, binding, OID, and both signatures.
 *
 * This is the function consumers should call. Prefer it over assembling
 * `validateCdro` + a hand-written binding comparison + `verifyAttestation`,
 * which is the pattern that let the __proto__ collision through.
 *
 * Never throws. Any malformed input, including one that makes `canonicalize`
 * reject, resolves to `{ valid: false, reasons: [...] }`.
 */
export function verifyCdro(input: VerifyCdroInput): VerifyCdroResult {
  const reasons: string[] = []

  // ── 1. Shape. Rejects the __proto__ collision shape via [E17] before any
  //       byte of this object is hashed or compared.
  const shape = validateCdro(input.cdro)
  if (!shape.ok) {
    return fail({}, shape.errors)
  }
  const cdro = input.cdro as Record<string, unknown>

  const att = cdro['attestation']
  if (att === undefined || att === null) {
    return fail({ shape_ok: true }, ['missing-attestation'])
  }

  // ── 2. Bind. The attestation must be about THIS object: its signed payload
  //       must equal this object's canonical content core. Without this, a
  //       valid envelope stapled to an unrelated object verifies.
  let corePayload: string
  try {
    corePayload = canonicalize(cdroContentCore(cdro))
  } catch (e) {
    return fail({ shape_ok: true }, [
      'not-canonicalizable',
      e instanceof Error ? e.message : String(e),
    ])
  }

  const envelope = att as AttestationEnvelope
  const binding_ok = envelope.payload === corePayload
  if (!binding_ok) reasons.push('binding-mismatch')

  // ── 3. OID. The stamped identity must be the identity of the content.
  let computed_oid: string | null = null
  try {
    computed_oid = cdroOid(cdro)
  } catch (e) {
    return fail({ shape_ok: true, binding_ok }, [
      ...reasons,
      'oid-not-computable',
      e instanceof Error ? e.message : String(e),
    ])
  }
  const oid_ok = computed_oid === cdro['oid']
  if (!oid_ok) reasons.push('oid-mismatch')

  // Structural gates first: do not spend an ML-DSA verification on an object
  // that is already known to be unbound or misidentified.
  if (!binding_ok || !oid_ok) {
    return {
      valid: false,
      shape_ok: true,
      binding_ok,
      oid_ok,
      signature_ok: false,
      computed_oid,
      reasons,
    }
  }

  // ── 4. Signatures. Both required, over the PAE.
  const sig = verifyAttestation({
    envelope,
    ed25519_pub: input.ed25519_pub,
    ml_dsa_pub: input.ml_dsa_pub,
    ...(input.expectedPayloadType !== undefined
      ? { expectedPayloadType: input.expectedPayloadType }
      : {}),
  })
  if (!sig.valid) reasons.push(...sig.reasons)

  return {
    valid: sig.valid,
    shape_ok: true,
    binding_ok: true,
    oid_ok: true,
    signature_ok: sig.valid,
    computed_oid,
    reasons,
  }
}
