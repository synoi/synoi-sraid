/**
 * test/signature.test.ts — hybrid Ed25519 + ML-DSA-65 sign/verify.
 *
 * Generates ephemeral keypairs, signs known bytes with both algorithms,
 * verifies with verifySignature(), and confirms tamper detection on
 * each branch.
 */

import { webcrypto, randomBytes } from 'node:crypto'

// Polyfill globalThis.crypto for older Node before @noble loads.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { verifySignature } from '../src/signature.js'
import type { SignatureEnvelope } from '../src/types.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64')
}

// ── Key generation ────────────────────────────────────────────────────────

// Ed25519 — private is any 32 random bytes; pub is derived.
const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)

// ML-DSA-65 — keygen requires a 32-byte seed.
const mlSeed = new Uint8Array(randomBytes(32))
const mlKeys = ml_dsa65.keygen(mlSeed)
const mlPriv = mlKeys.secretKey
const mlPub = mlKeys.publicKey

// ── Sign + verify round-trip ─────────────────────────────────────────────

const payload = { tenant_id: 't-home', action: 'open_door', risk: 'B' as const }
const canonical = canonicalize(payload)
const message = new TextEncoder().encode(canonical)

const edSig = ed25519.sign(message, edPriv)
const mlSig = ml_dsa65.sign(message, mlPriv)

const envelope: SignatureEnvelope = {
  ed25519: toB64(edSig),
  ml_dsa_65: toB64(mlSig),
  signer_kid: 'test-key-2026-05',
}

const verifyResult = verifySignature({
  canonical,
  envelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlPub,
})
ok('sign + verify round trip: valid=true', verifyResult.valid === true, JSON.stringify(verifyResult))
ok('sign + verify round trip: no reasons', verifyResult.reasons.length === 0, JSON.stringify(verifyResult.reasons))

// ── verifySignature also accepts bytes for canonical ──────────────────────

const byteResult = verifySignature({
  canonical: message,
  envelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlPub,
})
ok('verifySignature accepts Uint8Array canonical', byteResult.valid === true)

// ── Tampered payload → BOTH signatures invalid ───────────────────────────

const tamperedCanonical = canonicalize({ ...payload, risk: 'C' })  // changed
const tamperedResult = verifySignature({
  canonical: tamperedCanonical,
  envelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlPub,
})
ok('tampered payload → valid=false', tamperedResult.valid === false)
ok('tampered payload → ed25519-invalid in reasons',
   tamperedResult.reasons.includes('ed25519-invalid'),
   JSON.stringify(tamperedResult.reasons))
ok('tampered payload → ml-dsa-invalid in reasons',
   tamperedResult.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(tamperedResult.reasons))

// ── Tampered Ed25519 signature only → only ed25519 invalid ───────────────

const tamperedEd = new Uint8Array(edSig)
tamperedEd[0] = (tamperedEd[0]! ^ 0xff) & 0xff
const partialEnvelope: SignatureEnvelope = {
  ed25519: toB64(tamperedEd),
  ml_dsa_65: toB64(mlSig),
  signer_kid: 'test-key-2026-05',
}
const partialResult = verifySignature({
  canonical,
  envelope: partialEnvelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlPub,
})
ok('ed25519 tamper → valid=false', partialResult.valid === false)
ok('ed25519 tamper → reasons contains ed25519-invalid',
   partialResult.reasons.includes('ed25519-invalid'),
   JSON.stringify(partialResult.reasons))
ok('ed25519 tamper → reasons does NOT contain ml-dsa-invalid',
   !partialResult.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(partialResult.reasons))

// ── Malformed envelope rejected ──────────────────────────────────────────

const malformed = verifySignature({
  canonical,
  envelope: { ed25519: 'x', signer_kid: 'k' } as unknown as SignatureEnvelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlPub,
})
ok('malformed envelope → valid=false', malformed.valid === false)
ok('malformed envelope → reasons includes envelope-malformed',
   malformed.reasons.includes('envelope-malformed'),
   JSON.stringify(malformed.reasons))

// ── Wrong public key → invalid ───────────────────────────────────────────

const otherEdPriv = new Uint8Array(randomBytes(32))
const otherEdPub = ed25519.getPublicKey(otherEdPriv)
const wrongKeyResult = verifySignature({
  canonical,
  envelope,
  ed25519_pub: otherEdPub,
  ml_dsa_pub: mlPub,
})
ok('wrong ed25519 pub → valid=false', wrongKeyResult.valid === false)
ok('wrong ed25519 pub → ml-dsa still verifies (only ed reason)',
   wrongKeyResult.reasons.includes('ed25519-invalid') &&
   !wrongKeyResult.reasons.includes('ml-dsa-invalid'),
   JSON.stringify(wrongKeyResult.reasons))

// ── Malformed base64 sig → reject, NEVER throws out of verify ──────────────
//
// Strict base64 throws inside fromBase64; verifySignature must catch it and map
// to a *-malformed reason. '@' is outside the alphabet — the old Buffer.from
// silently truncated; strict decode rejects.

const badB64Envelope: SignatureEnvelope = {
  ed25519: 'not@@valid@@base64',
  ml_dsa_65: toB64(mlSig),
  signer_kid: 'test-key-2026-05',
}
let sigBadThrew = false
let sigBad: ReturnType<typeof verifySignature> | undefined
try {
  sigBad = verifySignature({
    canonical, envelope: badB64Envelope, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
} catch { sigBadThrew = true }
ok('malformed base64 sig → verifySignature does NOT throw', sigBadThrew === false)
ok('malformed base64 sig → valid=false', sigBad?.valid === false, JSON.stringify(sigBad))
ok('malformed base64 sig → ed25519-malformed reason',
   !!sigBad?.reasons.includes('ed25519-malformed'), JSON.stringify(sigBad?.reasons))

// ── Done ──────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
