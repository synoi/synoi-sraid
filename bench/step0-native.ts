/**
 * bench/step0-native.ts — Step 0 re-baseline with NATIVE crypto.
 *
 * Mirrors step0-baseline.ts but replaces the pure-JS @noble primitives with
 * native OpenSSL (Node crypto) for the operations that HAVE a native path:
 *   - SHA-256  -> node:crypto createHash
 *   - ed25519  -> node:crypto sign/verify (KeyObject)
 *   - ML-DSA-65 -> still @noble (NO native path in Node/OpenSSL today)
 *
 * This is the DEFENSIBLE denominator for the xN ratio: an optimized software
 * baseline. Benchmarking a DPU against the pure-JS baseline would report a
 * fake speedup that is really just "JS is slow." This file does NOT touch the
 * shipped @synoi/sraid library; swapping its crypto core is a separate, tested
 * change.
 *
 * Run:  npx tsx bench/step0-native.ts
 */

import { webcrypto, randomBytes, createHash, generateKeyPairSync, sign as nsign, verify as nverify } from 'node:crypto'
// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { cdroContentCore } from '../src/oid.js'
import { pae } from '../src/attestation.js'

const cdro = {
  type: 'agp.decision_receipt',
  cof_version: '1',
  tenant_id: 't-home-4821',
  created_at_ms: 1733760000000,
  created_by: 'did:synoi:gateway-edge-01',
  body: {
    action: 'open_door', actor: 'agent:home-assistant', resource: 'device:front-door',
    decision: 'ALLOW', risk: 'B', policy_id: 'pol-residential-default-v7',
    reasons: ['within-schedule', 'actor-authorized', 'no-drift'],
    context: {
      observed_state_oid: 'sha256:9f2a' + 'c'.repeat(60),
      authorized_state_oid: 'sha256:9f2a' + 'c'.repeat(60),
      drift: false, session: 'sess-7f3a91', geo: 'home-lan', mfa: true,
    },
  },
  authority: { grant_oid: 'sha256:aa11' + 'b'.repeat(60), capability: 'device.door.open', decision: 'permit' },
  prev: 'sha256:1234' + 'd'.repeat(60),
  links: [{ rel: 'derived_from', oid: 'sha256:5678' + 'e'.repeat(60) }],
}

const core = cdroContentCore(cdro)
const canonical = canonicalize(core)
const canonicalBytes = Buffer.from(canonical, 'utf8')

// Native OID = canonicalize + native SHA-256.
function oidNative(): string {
  return 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(core), 'utf8')).digest('hex')
}

// Native ed25519 keypair (timing baseline; keys need not match the JS variant).
const { publicKey: edPub, privateKey: edPriv } = generateKeyPairSync('ed25519')

// ML-DSA stays @noble (no native path).
const mlKeys = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
const mlPriv = mlKeys.secretKey
const mlPub = mlKeys.publicKey

const payloadType = 'application/vnd.synoi.sraid+json'
const paeBytes = pae(payloadType, canonical)
const paeBuf = Buffer.from(paeBytes)
const edSig = nsign(null, paeBuf, edPriv)
const mlSig = ml_dsa65.sign(paeBytes, mlPriv)

// Sanity.
if (!nverify(null, paeBuf, edPub, edSig)) { console.error('FATAL native ed25519 verify failed'); process.exit(1) }
if (!ml_dsa65.verify(mlSig, paeBytes, mlPub)) { console.error('FATAL ml-dsa verify failed'); process.exit(1) }

interface Result { name: string; nsPerOp: number; opsPerSec: number }
function bench(name: string, fn: () => void, targetMs = 1200): Result {
  let iters = 1
  for (;;) {
    const t0 = process.hrtime.bigint()
    for (let i = 0; i < iters; i++) fn()
    const dt = Number(process.hrtime.bigint() - t0) / 1e6
    if (dt >= 50) { iters = Math.max(1, Math.floor(iters * (targetMs / dt))); break }
    iters *= 4
  }
  let best = Infinity
  for (let r = 0; r < 3; r++) {
    const t0 = process.hrtime.bigint()
    for (let i = 0; i < iters; i++) fn()
    const ns = Number(process.hrtime.bigint() - t0) / iters
    if (ns < best) best = ns
  }
  return { name, nsPerOp: best, opsPerSec: 1e9 / best }
}

let sink = 0
let sinkStr = ''
const results: Result[] = []
results.push(bench('canonicalize (RFC 8785, JS)', () => { sinkStr = canonicalize(core) }))
results.push(bench('oidNative (canon + native SHA-256)', () => { sinkStr = oidNative() }))
results.push(bench('ed25519 verify (native)', () => { sink += nverify(null, paeBuf, edPub, edSig) ? 1 : 0 }))
results.push(bench('ml-dsa-65 verify (@noble, no native)', () => { sink += ml_dsa65.verify(mlSig, paeBytes, mlPub) ? 1 : 0 }))
results.push(bench('hybrid verify (native ed + noble ml)', () => {
  const a = nverify(null, paeBuf, edPub, edSig)
  const b = ml_dsa65.verify(mlSig, paeBytes, mlPub)
  sink += (a && b) ? 1 : 0
}))

console.log('')
console.log('SRAID Step 0 — NATIVE re-baseline (defensible denominator)')
console.log('node', process.version, '|', process.platform, process.arch)
console.log('canonical payload size:', canonicalBytes.length, 'bytes')
console.log('')
const pad = (s: string, n: number) => s.padEnd(n)
const padL = (s: string, n: number) => s.padStart(n)
console.log(pad('operation', 38), padL('ns/op', 12), padL('ops/sec', 14))
console.log('-'.repeat(38 + 12 + 14))
for (const r of results) {
  console.log(pad(r.name, 38), padL(r.nsPerOp.toFixed(1), 12), padL(Math.round(r.opsPerSec).toLocaleString('en-US'), 14))
}
// Amdahl: OID-routing share of the full verify-bound pass.
const oid = results[1].nsPerOp
const hybrid = results[4].nsPerOp
console.log('')
console.log(`OID-routing share of verify-bound pass: ${(100 * oid / (oid + hybrid)).toFixed(2)}%  (oid ${oid.toFixed(0)}ns / pass ${(oid + hybrid).toFixed(0)}ns)`)
console.log(`-> a 135x speedup on OID routing improves the verify-bound pass by ${(100 * (oid - oid / 135) / (oid + hybrid)).toFixed(2)}%`)
console.log('// sink', sink, sinkStr.length)
