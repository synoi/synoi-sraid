/**
 * test/mldsa-kat.test.ts — ML-DSA-65 cross-implementation known-answer test.
 *
 * The correctness gate for the native node:crypto ML-DSA-65 fast path: the
 * native path (Node 24+ / OpenSSL 3.5) and the @noble/post-quantum fallback
 * MUST produce identical accept/reject decisions. A signature minted by one
 * implementation verifies identically under the other; tampered signatures and
 * wrong-key cases fail under both.
 *
 * Two layers:
 *   1. Frozen vectors (test/vectors/mldsa-kat.json) — one signature minted by
 *      each implementation on Node 24, asserted to verify under BOTH the active
 *      path (verifyMlDsa65) and @noble directly. This is the conformance anchor;
 *      it is runtime-independent, so on Node < 24 it still proves a
 *      native-minted signature verifies under @noble.
 *   2. Dynamic agreement — fresh keypairs and a battery of positive/negative
 *      cases, asserting verifyMlDsa65 (active path) and @noble agree on EVERY
 *      decision. When native is available this directly pits native against
 *      @noble; both directions (native-minted→@noble, @noble-minted→native) are
 *      exercised.
 */

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { webcrypto, randomBytes, createPublicKey, verify as nodeVerify } from 'node:crypto'

// Polyfill globalThis.crypto for older Node before @noble loads.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { verifyMlDsa65, isNativeMlDsaAvailable } from '../src/mldsa.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

const fromHex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'))
const fromB64 = (b: string) => new Uint8Array(Buffer.from(b, 'base64'))

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(path.join(__dirname, 'vectors', 'mldsa-kat.json'), 'utf-8'),
)

process.stdout.write(
  `\nML-DSA-65 verify path under test: ${isNativeMlDsaAvailable() ? 'NATIVE (node:crypto / OpenSSL)' : '@noble (fallback)'}\n\n`,
)

const msg = new TextEncoder().encode(vectors.message_utf8)

// ── Layer 1: frozen cross-impl vectors ──────────────────────────────────────

for (const variant of ['noble_minted', 'native_minted'] as const) {
  const pub = fromHex(vectors[variant].public_key_hex)
  const sig = fromB64(vectors[variant].signature_b64)

  // Active path accepts.
  ok(`frozen ${variant}: verifyMlDsa65 accepts`, verifyMlDsa65(sig, msg, pub) === true)
  // @noble directly accepts (cross-impl: sig minted by one verifies under @noble).
  ok(`frozen ${variant}: @noble accepts`, ml_dsa65.verify(sig, msg, pub) === true)

  // Tampered signature → rejected by BOTH.
  const tampered = new Uint8Array(sig)
  tampered[10] = (tampered[10]! ^ 0xff) & 0xff
  ok(`frozen ${variant}: verifyMlDsa65 rejects tampered sig`, verifyMlDsa65(tampered, msg, pub) === false)
  ok(`frozen ${variant}: @noble rejects tampered sig`, ml_dsa65.verify(tampered, msg, pub) === false)

  // Wrong key → rejected by BOTH.
  const wrong = fromHex(vectors.wrong_public_key_hex)
  ok(`frozen ${variant}: verifyMlDsa65 rejects wrong key`, verifyMlDsa65(sig, msg, wrong) === false)
  ok(`frozen ${variant}: @noble rejects wrong key`, ml_dsa65.verify(sig, msg, wrong) === false)

  // Tampered message → rejected by BOTH.
  const wrongMsg = new TextEncoder().encode(vectors.message_utf8 + ' ')
  ok(`frozen ${variant}: verifyMlDsa65 rejects wrong message`, verifyMlDsa65(sig, wrongMsg, pub) === false)
  ok(`frozen ${variant}: @noble rejects wrong message`, ml_dsa65.verify(sig, wrongMsg, pub) === false)
}

// ── Layer 2: dynamic agreement across a battery of cases ────────────────────
//
// For every case, the active path (verifyMlDsa65) and @noble MUST return the
// SAME boolean. When native is available this is native-vs-@noble agreement.

const kp = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
const pub = kp.publicKey
const dynMsg = new TextEncoder().encode('dynamic-cross-impl-agreement-message')
const sig = ml_dsa65.sign(dynMsg, kp.secretKey)
const otherPub = ml_dsa65.keygen(new Uint8Array(randomBytes(32))).publicKey

const tamperedSig = new Uint8Array(sig); tamperedSig[0] = (tamperedSig[0]! ^ 0xff) & 0xff
const shortSig = sig.slice(0, sig.length - 1)
const shortKey = pub.slice(0, pub.length - 1)

const cases: Array<{ name: string; sig: Uint8Array; msg: Uint8Array; key: Uint8Array; expect: boolean }> = [
  { name: 'valid',          sig,            msg: dynMsg, key: pub,      expect: true },
  { name: 'tampered-sig',   sig: tamperedSig, msg: dynMsg, key: pub,    expect: false },
  { name: 'wrong-key',      sig,            msg: dynMsg, key: otherPub, expect: false },
  { name: 'wrong-message',  sig,            msg: new TextEncoder().encode('different'), key: pub, expect: false },
  { name: 'malformed-sig',  sig: shortSig,  msg: dynMsg, key: pub,      expect: false },
  { name: 'malformed-key',  sig,            msg: dynMsg, key: shortKey, expect: false },
]

for (const cse of cases) {
  const active = verifyMlDsa65(cse.sig, cse.msg, cse.key)
  let reference: boolean
  try { reference = ml_dsa65.verify(cse.sig, cse.msg, cse.key) } catch { reference = false }
  ok(`dynamic ${cse.name}: active === @noble (${active})`, active === reference, `active=${active} noble=${reference}`)
  ok(`dynamic ${cse.name}: decision === expected`, active === cse.expect, `active=${active} expected=${cse.expect}`)
}

// ── Layer 2b: both-direction interop (only meaningful when native present) ───
//
// @noble-minted sig must verify under the NATIVE KeyObject path, and a
// native-minted sig must verify under @noble. verifyMlDsa65 already routes the
// @noble→native direction above; here we add the native→@noble direction.

if (isNativeMlDsaAvailable()) {
  const PREFIX = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex')
  // @noble-minted sig, verified by a native KeyObject directly.
  const ko = createPublicKey({ key: Buffer.concat([PREFIX, Buffer.from(pub)]), format: 'der', type: 'spki' })
  ok('interop: @noble-minted sig verifies under native KeyObject', nodeVerify(null, dynMsg, ko, sig) === true)
  ok('interop: native KeyObject rejects tampered @noble sig', nodeVerify(null, dynMsg, ko, tamperedSig) === false)
} else {
  process.stdout.write('SKIP native-direction interop (native ML-DSA-65 unavailable on this runtime)\n')
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
