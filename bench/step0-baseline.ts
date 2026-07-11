/**
 * bench/step0-baseline.ts — Step 0 software baseline for the SRAID-on-DPU xN thesis.
 *
 * PURPOSE (see v2/TRUSTED_COMPUTE_AND_STACK_IN_RUNTIME.md, section 7):
 * Measure the per-operation cost of the SRAID-native datapath operations IN
 * SOFTWARE on a host CPU. This is the denominator of the xN ratio. The
 * numerator (DPU hardware) comes later on a real BlueField. This file makes
 * NO performance claim about hardware; it only establishes the software floor
 * and labels which ops are plausibly DPU-offloadable.
 *
 * The ops, in datapath order:
 *   1. canonicalize       — RFC 8785 JCS serialization (recursive; NOT match-action shaped)
 *   2. oidOf              — canonicalize + SHA-256 = the content-addressed routing key
 *   3. map-lookup         — exact-match on the OID (the CAM op; trivial in SW)
 *   4. ed25519 verify     — classical signature verify
 *   5. ml-dsa-65 verify   — post-quantum signature verify (heavy)
 *   6. verifyAttestation  — full hybrid DSSE verify (ed25519 AND ml-dsa-65)
 *
 * Run:  npx tsx bench/step0-baseline.ts
 */

import { webcrypto, randomBytes } from 'node:crypto'
// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { oidOf, cdroContentCore } from '../src/oid.js'
import { pae, verifyAttestation, ALG_ED25519, ALG_ML_DSA_65 } from '../src/attestation.js'
import type { AttestationEnvelope } from '../src/types.js'

// ── A representative CDRO: a GAP decision receipt ───────────────────────────
// Realistic shape and size for the workload we actually care about (governance
// at the wire). Adjust `body.context` to grow/shrink payload if needed.
const cdro = {
  type: 'agp.decision_receipt',
  cof_version: '1',
  tenant_id: 't-home-4821',
  created_at_ms: 1733760000000,
  created_by: 'did:synoi:gateway-edge-01',
  body: {
    action: 'open_door',
    actor: 'agent:home-assistant',
    resource: 'device:front-door',
    decision: 'ALLOW',
    risk: 'B',
    policy_id: 'pol-residential-default-v7',
    reasons: ['within-schedule', 'actor-authorized', 'no-drift'],
    context: {
      observed_state_oid: 'sha256:9f2a' + 'c'.repeat(60),
      authorized_state_oid: 'sha256:9f2a' + 'c'.repeat(60),
      drift: false,
      session: 'sess-7f3a91',
      geo: 'home-lan',
      mfa: true,
    },
  },
  authority: {
    grant_oid: 'sha256:aa11' + 'b'.repeat(60),
    capability: 'device.door.open',
    decision: 'permit',
  },
  prev: 'sha256:1234' + 'd'.repeat(60),
  links: [
    { rel: 'derived_from', oid: 'sha256:5678' + 'e'.repeat(60) },
  ],
}

const core = cdroContentCore(cdro)
const canonical = canonicalize(core)
const canonicalBytes = new TextEncoder().encode(canonical)

// ── Keys + a valid hybrid attestation to verify ─────────────────────────────
const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)
const mlKeys = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
const mlPriv = mlKeys.secretKey
const mlPub = mlKeys.publicKey

const payloadType = 'application/vnd.synoi.sraid+json'
const paeBytes = pae(payloadType, canonical)
const edSig = ed25519.sign(paeBytes, edPriv)
const mlSig = ml_dsa65.sign(paeBytes, mlPriv)
const toB64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const envelope: AttestationEnvelope = {
  payloadType,
  payload: canonical,
  signatures: [
    { alg: ALG_ED25519, keyid: 'k1', sig: toB64(edSig) },
    { alg: ALG_ML_DSA_65, keyid: 'k1', sig: toB64(mlSig) },
  ],
}

// Sanity: the attestation must verify, or the numbers are meaningless.
{
  const r = verifyAttestation({ envelope, ed25519_pub: edPub, ml_dsa_pub: mlPub })
  if (!r.valid) {
    console.error('FATAL: sample attestation did not verify:', r.reasons)
    process.exit(1)
  }
}

// An OID table to exercise the exact-match lookup (the CAM op).
const TABLE_SIZE = 100_000
const table = new Map<string, number>()
for (let i = 0; i < TABLE_SIZE; i++) table.set(oidOf({ n: i }), i)
const lookupKey = oidOf(core) // not in table; worst-case miss path is fine for timing

// ── Auto-calibrating microbenchmark ─────────────────────────────────────────
interface Result { name: string; nsPerOp: number; opsPerSec: number; offload: string }

function bench(name: string, fn: () => void, offload: string, targetMs = 1200): Result {
  // Warm up + calibrate iteration count to ~targetMs.
  let iters = 1
  for (;;) {
    const t0 = process.hrtime.bigint()
    for (let i = 0; i < iters; i++) fn()
    const dt = Number(process.hrtime.bigint() - t0) / 1e6 // ms
    if (dt >= 50) {
      iters = Math.max(1, Math.floor(iters * (targetMs / dt)))
      break
    }
    iters *= 4
  }
  // Three measured rounds; take the best (min ns/op = least noise).
  let best = Infinity
  for (let round = 0; round < 3; round++) {
    const t0 = process.hrtime.bigint()
    for (let i = 0; i < iters; i++) fn()
    const ns = Number(process.hrtime.bigint() - t0) / iters
    if (ns < best) best = ns
  }
  return { name, nsPerOp: best, opsPerSec: 1e9 / best, offload }
}

// Sinks to prevent dead-code elimination.
let sink = 0
let sinkStr = ''

const results: Result[] = []
results.push(bench('canonicalize (RFC 8785)', () => { sinkStr = canonicalize(core) }, 'partial — Arm cores, not match-action'))
results.push(bench('oidOf (canonicalize + SHA-256)', () => { sinkStr = oidOf(core) }, 'STRONG — SHA offload + CAM key'))
results.push(bench('map lookup (exact-match / CAM op)', () => { sink += table.has(lookupKey) ? 1 : 0 }, 'STRONG — native CAM in HW'))
results.push(bench('ed25519 verify', () => { sink += ed25519.verify(edSig, paeBytes, edPub) ? 1 : 0 }, 'partial — PK crypto engine'))
results.push(bench('ml-dsa-65 verify', () => { sink += ml_dsa65.verify(mlSig, paeBytes, mlPub) ? 1 : 0 }, 'weak — PQ, likely no HW accel yet'))
results.push(bench('verifyAttestation (hybrid)', () => {
  const r = verifyAttestation({ envelope, ed25519_pub: edPub, ml_dsa_pub: mlPub })
  sink += r.valid ? 1 : 0
}, 'mixed (sum of the two verifies)'))

// ── Report ──────────────────────────────────────────────────────────────────
console.log('')
console.log('SRAID Step 0 — software baseline (host CPU)')
console.log('node', process.version, '|', process.platform, process.arch)
console.log('canonical payload size:', canonicalBytes.length, 'bytes')
console.log('ed25519 sig:', edSig.length, 'B | ml-dsa-65 sig:', mlSig.length, 'B | ml-dsa pub:', mlPub.length, 'B')
console.log('')
const pad = (s: string, n: number) => s.padEnd(n)
const padL = (s: string, n: number) => s.padStart(n)
console.log(pad('operation', 34), padL('ns/op', 12), padL('ops/sec', 14), '  DPU-offload')
console.log('-'.repeat(34 + 12 + 14 + 24))
for (const r of results) {
  console.log(
    pad(r.name, 34),
    padL(r.nsPerOp.toFixed(1), 12),
    padL(Math.round(r.opsPerSec).toLocaleString('en-US'), 14),
    '  ' + r.offload,
  )
}
console.log('')
console.log('// sink', sink, sinkStr.length)
