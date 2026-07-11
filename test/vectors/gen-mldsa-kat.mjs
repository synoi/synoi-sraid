/**
 * test/vectors/gen-mldsa-kat.mjs — regenerate the ML-DSA-65 cross-impl KAT.
 *
 * Mints one frozen signature from EACH implementation (native node:crypto and
 * @noble/post-quantum), self-verifies that every vector is accepted by BOTH
 * implementations, and only then writes test/vectors/mldsa-kat.json.
 *
 * Run on a runtime with native ML-DSA-65 (Node 24+ / OpenSSL 3.5+):
 *   node test/vectors/gen-mldsa-kat.mjs
 *
 * The committed JSON is the conformance anchor consumed by mldsa-kat.test.ts;
 * you should not need to regenerate it unless the vector format changes.
 */
import * as c from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const PREFIX = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex')
const RAW_LEN = 1952

// Native ML-DSA-65 must be present to mint the native side of the KAT.
let nativeKp
try {
  nativeKp = c.generateKeyPairSync('ml-dsa-65')
} catch (e) {
  console.error('Native ML-DSA-65 unavailable on this runtime; run on Node 24+:', e.message)
  process.exit(1)
}

// Representative canonical-receipt message (UTF-8).
const MSG = '{"action":"open_door","risk":"B","tenant_id":"t-home","ts":"2026-06-10T00:00:00Z"}'
const msg = Buffer.from(MSG, 'utf-8')

// @noble keypair (deterministic from a fixed seed) + a @noble-minted signature.
const seed = Buffer.alloc(32); for (let i = 0; i < 32; i++) seed[i] = i + 1
const nobleKp = ml_dsa65.keygen(new Uint8Array(seed))
const noblePub = Buffer.from(nobleKp.publicKey)
const sigNoble = Buffer.from(ml_dsa65.sign(new Uint8Array(msg), nobleKp.secretKey))

// Native keypair + a native-minted signature.
const nativeSpki = nativeKp.publicKey.export({ format: 'der', type: 'spki' })
const nativePub = Buffer.from(nativeSpki.subarray(nativeSpki.length - RAW_LEN))
const sigNative = c.sign(null, msg, nativeKp.privateKey)

// An unrelated key for negative vectors.
const wrongPub = Buffer.from(ml_dsa65.keygen(new Uint8Array(Buffer.alloc(32, 0xab))).publicKey)

const koFromRaw = (raw) =>
  c.createPublicKey({ key: Buffer.concat([PREFIX, raw]), format: 'der', type: 'spki' })

// Self-verify EVERY vector under BOTH implementations before freezing.
const checks = {
  'noble-sig / noble-impl': ml_dsa65.verify(new Uint8Array(sigNoble), new Uint8Array(msg), new Uint8Array(noblePub)),
  'noble-sig / native-impl': c.verify(null, msg, koFromRaw(noblePub), sigNoble),
  'native-sig / native-impl': c.verify(null, msg, koFromRaw(nativePub), sigNative),
  'native-sig / noble-impl': ml_dsa65.verify(new Uint8Array(sigNative), new Uint8Array(msg), new Uint8Array(nativePub)),
}
for (const [k, v] of Object.entries(checks)) {
  console.log(`${v ? 'OK  ' : 'FAIL'} ${k}`)
  if (!v) { console.error('Refusing to write a vector that does not cross-verify.'); process.exit(1) }
}

const out = {
  _comment:
    'Cross-implementation ML-DSA-65 (FIPS 204) known-answer vectors. Each signature ' +
    'is minted by one implementation and MUST verify identically under the other. ' +
    'Regenerate with test/vectors/gen-mldsa-kat.mjs on Node 24+.',
  alg: 'ml-dsa-65',
  message_utf8: MSG,
  noble_minted: { public_key_hex: noblePub.toString('hex'), signature_b64: sigNoble.toString('base64') },
  native_minted: { public_key_hex: nativePub.toString('hex'), signature_b64: sigNative.toString('base64') },
  wrong_public_key_hex: wrongPub.toString('hex'),
}

const dir = path.dirname(fileURLToPath(import.meta.url))
writeFileSync(path.join(dir, 'mldsa-kat.json'), JSON.stringify(out, null, 2) + '\n')
console.log('\nWrote test/vectors/mldsa-kat.json')
