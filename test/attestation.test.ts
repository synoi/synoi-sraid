/**
 * test/attestation.test.ts — DSSE attestation envelope (PAE type-binding,
 * hybrid Ed25519 + ML-DSA-65 both-required).
 *
 * Covers:
 *   - PAE produces the exact DSSE wire bytes (spec test vector).
 *   - sign-over-PAE + verify round trip (both algs present).
 *   - the cross-type confusion fix: a signature minted for payloadType A
 *     does NOT verify when the envelope claims payloadType B (this is the
 *     whole point of T11 — SRAID F7 / Adversary A4).
 *   - the hybrid AND policy: missing either alg → invalid.
 *   - tampered payload / tampered sig / wrong key → invalid.
 *   - malformed envelope and expectedPayloadType pinning.
 */

import { webcrypto, randomBytes } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { pae, verifyAttestation, ALG_ED25519, ALG_ML_DSA_65 } from '../src/attestation.js'
import type { AttestationEnvelope } from '../src/types.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64')
}

// ── PAE wire-format vector ─────────────────────────────────────────────────
//
// DSSE: PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
// For type="http://example.com/HelloWorld", body="hello world" this is a
// known shape; assert byte-exactness for a small case here.
{
  const type = 'application/vnd.synoi.sraid+json'
  const body = 'hi'
  const expected =
    `DSSEv1 ${type.length} ${type} ${body.length} ${body}`
  const actual = Buffer.from(pae(type, body)).toString('utf8')
  ok('PAE matches DSSEv1 LEN-prefixed encoding', actual === expected, JSON.stringify({ expected, actual }))
}

// ── Key generation ─────────────────────────────────────────────────────────

const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)
const mlKeys = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
const mlPriv = mlKeys.secretKey
const mlPub = mlKeys.publicKey

const payloadType = 'application/vnd.synoi.sraid+json'
const payload = canonicalize({ tenant_id: 't-home', action: 'open_door', risk: 'B' })

function signEnvelope(pt: string, pl: string): AttestationEnvelope {
  const msg = pae(pt, pl)
  return {
    payloadType: pt,
    payload: pl,
    signatures: [
      { alg: ALG_ED25519, keyid: 'k1', sig: toB64(ed25519.sign(msg, edPriv)) },
      { alg: ALG_ML_DSA_65, keyid: 'k1', sig: toB64(ml_dsa65.sign(msg, mlPriv)) },
    ],
  }
}

// ── Round trip ───────────────────────────────────────────────────────────────

const env = signEnvelope(payloadType, payload)
const r = verifyAttestation({ envelope: env, ed25519_pub: edPub, ml_dsa_pub: mlPub })
ok('round trip: valid=true', r.valid === true, JSON.stringify(r))
ok('round trip: no reasons', r.reasons.length === 0, JSON.stringify(r.reasons))

// ── expectedPayloadType pin matches ───────────────────────────────────────────

const rPin = verifyAttestation({
  envelope: env, ed25519_pub: edPub, ml_dsa_pub: mlPub, expectedPayloadType: payloadType,
})
ok('expectedPayloadType match: valid=true', rPin.valid === true, JSON.stringify(rPin))

// ── Cross-type confusion fix (the T11 point) ──────────────────────────────────
//
// Take signatures legitimately minted for payloadType A, and present them in
// an envelope that claims payloadType B with the SAME payload bytes. Because
// the PAE binds the type, the signatures no longer verify. The legacy
// bare-bytes scheme would have accepted this.

const envTypeA = signEnvelope('application/vnd.synoi.sraid+json', payload)
const confusedEnvelope: AttestationEnvelope = {
  payloadType: 'application/vnd.in-toto+json',   // different type, same payload + sigs
  payload,
  signatures: envTypeA.signatures,
}
const rConfuse = verifyAttestation({ envelope: confusedEnvelope, ed25519_pub: edPub, ml_dsa_pub: mlPub })
ok('cross-type confusion: valid=false (PAE binds type)', rConfuse.valid === false, JSON.stringify(rConfuse))
ok('cross-type confusion: both sigs report invalid',
   rConfuse.reasons.includes('ed25519-invalid') && rConfuse.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(rConfuse.reasons))

// expectedPayloadType pin also catches the swap up front.
const rPinMismatch = verifyAttestation({
  envelope: confusedEnvelope, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  expectedPayloadType: 'application/vnd.synoi.sraid+json',
})
ok('expectedPayloadType mismatch: valid=false', rPinMismatch.valid === false)
ok('expectedPayloadType mismatch: payload-type-mismatch reason',
   rPinMismatch.reasons.includes('payload-type-mismatch'), JSON.stringify(rPinMismatch.reasons))

// ── Hybrid AND policy: missing one alg → invalid ──────────────────────────────

const edOnly: AttestationEnvelope = {
  payloadType, payload,
  signatures: [env.signatures[0]!],   // ed25519 only
}
const rEdOnly = verifyAttestation({ envelope: edOnly, ed25519_pub: edPub, ml_dsa_pub: mlPub })
ok('ed25519-only envelope: valid=false (AND policy)', rEdOnly.valid === false)
ok('ed25519-only envelope: missing-ml-dsa-65 reason',
   rEdOnly.reasons.includes('missing-ml-dsa-65'), JSON.stringify(rEdOnly.reasons))

const mlOnly: AttestationEnvelope = {
  payloadType, payload,
  signatures: [env.signatures[1]!],   // ml-dsa-65 only
}
const rMlOnly = verifyAttestation({ envelope: mlOnly, ed25519_pub: edPub, ml_dsa_pub: mlPub })
ok('ml-dsa-only envelope: valid=false (AND policy)', rMlOnly.valid === false)
ok('ml-dsa-only envelope: missing-ed25519 reason',
   rMlOnly.reasons.includes('missing-ed25519'), JSON.stringify(rMlOnly.reasons))

// ── Tampered payload → both invalid ───────────────────────────────────────────

const tampered: AttestationEnvelope = {
  payloadType,
  payload: canonicalize({ tenant_id: 't-home', action: 'open_door', risk: 'C' }), // changed
  signatures: env.signatures,
}
const rTamper = verifyAttestation({ envelope: tampered, ed25519_pub: edPub, ml_dsa_pub: mlPub })
ok('tampered payload: valid=false', rTamper.valid === false)
ok('tampered payload: both invalid',
   rTamper.reasons.includes('ed25519-invalid') && rTamper.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(rTamper.reasons))

// ── Tampered ed25519 sig only → only ed invalid ───────────────────────────────

const tamperedEdSig = new Uint8Array(Buffer.from(env.signatures[0]!.sig, 'base64'))
tamperedEdSig[0] = (tamperedEdSig[0]! ^ 0xff) & 0xff
const partial: AttestationEnvelope = {
  payloadType, payload,
  signatures: [
    { alg: ALG_ED25519, sig: toB64(tamperedEdSig) },
    env.signatures[1]!,
  ],
}
const rPartial = verifyAttestation({ envelope: partial, ed25519_pub: edPub, ml_dsa_pub: mlPub })
ok('tampered ed sig: valid=false', rPartial.valid === false)
ok('tampered ed sig: ed25519-invalid present, ml-dsa-invalid absent',
   rPartial.reasons.includes('ed25519-invalid') && !rPartial.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(rPartial.reasons))

// ── Wrong ed pub → only ed invalid ────────────────────────────────────────────

const otherEdPub = ed25519.getPublicKey(new Uint8Array(randomBytes(32)))
const rWrong = verifyAttestation({ envelope: env, ed25519_pub: otherEdPub, ml_dsa_pub: mlPub })
ok('wrong ed pub: valid=false', rWrong.valid === false)
ok('wrong ed pub: only ed25519-invalid',
   rWrong.reasons.includes('ed25519-invalid') && !rWrong.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(rWrong.reasons))

// ── Malformed envelope ─────────────────────────────────────────────────────────

const rMal = verifyAttestation({
  envelope: { payloadType, payload } as unknown as AttestationEnvelope,
  ed25519_pub: edPub, ml_dsa_pub: mlPub,
})
ok('malformed envelope (no signatures[]): valid=false', rMal.valid === false)
ok('malformed envelope: envelope-malformed reason',
   rMal.reasons.includes('envelope-malformed'), JSON.stringify(rMal.reasons))

// ── Malformed base64 in a sig → reject, NEVER throws out of verify ──────────────
//
// Strict base64 throws inside fromBase64; verifyAttestation must catch it and
// map to a *-malformed reason, not propagate. '@' is outside the alphabet, so
// the old Buffer.from would silently truncate; strict decode rejects it.

const badB64: AttestationEnvelope = {
  payloadType, payload,
  signatures: [
    { alg: ALG_ED25519, sig: 'not@@valid@@base64' },
    env.signatures[1]!,
  ],
}
let badThrew = false
let rBad: ReturnType<typeof verifyAttestation> | undefined
try {
  rBad = verifyAttestation({ envelope: badB64, ed25519_pub: edPub, ml_dsa_pub: mlPub })
} catch { badThrew = true }
ok('malformed base64 sig: verifyAttestation does NOT throw', badThrew === false)
ok('malformed base64 sig: valid=false', rBad?.valid === false, JSON.stringify(rBad))
ok('malformed base64 sig: ed25519-malformed reason',
   !!rBad?.reasons.includes('ed25519-malformed'), JSON.stringify(rBad?.reasons))

// ── Done ────────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
