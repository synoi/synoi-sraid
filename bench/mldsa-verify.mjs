/**
 * bench/mldsa-verify.mjs — native node:crypto vs @noble ML-DSA-65 verify.
 *
 * Run on Node 24+ / OpenSSL 3.5+ to see both paths:  node bench/mldsa-verify.mjs
 * On older runtimes only the @noble number is reported (native unavailable).
 */
import * as c from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const PREFIX = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex')
const N = 2000

const kp = ml_dsa65.keygen(new Uint8Array(c.randomBytes(32)))
const msg = Buffer.from('benchmark-message-for-ml-dsa-65-verify')
const sig = Buffer.from(ml_dsa65.sign(new Uint8Array(msg), kp.secretKey))
const pub = Buffer.from(kp.publicKey)

function timeUs(fn) {
  for (let i = 0; i < 200; i++) fn() // warmup
  const t0 = process.hrtime.bigint()
  for (let i = 0; i < N; i++) fn()
  const t1 = process.hrtime.bigint()
  return Number(t1 - t0) / 1000 / N
}

const noble = timeUs(() => ml_dsa65.verify(new Uint8Array(sig), new Uint8Array(msg), new Uint8Array(pub)))

let nativeKo = null
try { nativeKo = c.createPublicKey({ key: Buffer.concat([PREFIX, pub]), format: 'der', type: 'spki' }) } catch {}

console.log(`@noble  ML-DSA-65 verify: ${noble.toFixed(1)} µs`)
if (nativeKo) {
  const native = timeUs(() => c.verify(null, msg, nativeKo, sig))
  console.log(`native  ML-DSA-65 verify: ${native.toFixed(1)} µs`)
  console.log(`speedup: ${(noble / native).toFixed(2)}x`)
} else {
  console.log('native  ML-DSA-65 verify: unavailable (Node 24+/OpenSSL 3.5 required)')
}
