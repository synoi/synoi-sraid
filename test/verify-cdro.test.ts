/**
 * test/verify-cdro.test.ts — the single consumer entry point.
 *
 * The headline case is STAPLE: a cryptographically valid attestation attached
 * to an unrelated CDRO. `verifyAttestation` returns valid:true for it and
 * `validateCdro` returns ok:true for it, because neither is told they are
 * meant to be about the same object. That is panel finding 4.9. `verifyCdro`
 * must reject it, and the test asserts BOTH halves — that the old primitives
 * still accept it, and that the new entry point does not — so the reason this
 * function exists cannot quietly evaporate.
 */

import { canonicalize } from '../src/canonicalize.js'
import { cdroOid, cdroContentCore } from '../src/oid.js'
import { pae, verifyAttestation, verifyCdro, validateCdro } from '../src/index.js'
import type { AttestationEnvelope, CDRO } from '../src/types.js'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes, webcrypto } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail = ''): void {
  if (cond) { console.log('OK  ', label); passed++ }
  else { console.error('FAIL', label, detail); failed++ }
}

const PT = 'application/vnd.synoi.sraid+json'
const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)
const ml = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))

function mint(body: unknown, over: Record<string, unknown> = {}) {
  const core = {
    type: 'obs', sraid_version: '2.0' as const, tenant_id: 't-a',
    created_at_ms: 1767225600000, created_by: 'actor:demo', body, ...over,
  }
  const cdro: Record<string, unknown> = { oid: cdroOid(core), ...core }
  const payload = canonicalize(cdroContentCore(cdro))
  const msg = pae(PT, payload)
  const attestation: AttestationEnvelope = {
    payloadType: PT,
    payload,
    signatures: [
      { alg: 'ed25519', sig: Buffer.from(ed25519.sign(msg, edPriv)).toString('base64') },
      { alg: 'ml-dsa-65', sig: Buffer.from(ml_dsa65.sign(msg, ml.secretKey)).toString('base64') },
    ],
  }
  return { ...cdro, attestation } as unknown as CDRO
}

const keys = { ed25519_pub: edPub, ml_dsa_pub: ml.publicKey }
const good = mint({ hr: 72 })
const other = mint({ hr: 999 })

// ── happy path ───────────────────────────────────────────────────────────────
const r = verifyCdro({ cdro: good, ...keys, expectedPayloadType: PT })
ok('valid CDRO verifies', r.valid, JSON.stringify(r.reasons))
ok('all four checks reported true',
   r.shape_ok && r.binding_ok && r.oid_ok && r.signature_ok)
ok('computed_oid matches the stamped oid',
   r.computed_oid === (good as unknown as Record<string, unknown>)['oid'])

// ── STAPLE: the forgery the old primitives accept (panel 4.9) ────────────────
const stapled = {
  ...(other as unknown as Record<string, unknown>),
  attestation: (good as unknown as Record<string, unknown>)['attestation'],
}
ok('PRECONDITION: verifyAttestation alone accepts the stapled envelope',
   verifyAttestation({ envelope: stapled['attestation'] as AttestationEnvelope, ...keys }).valid)
ok('PRECONDITION: validateCdro alone accepts the stapled object',
   validateCdro(stapled).ok)
const s = verifyCdro({ cdro: stapled, ...keys })
ok('verifyCdro REJECTS the stapled envelope', !s.valid)
ok('  and names binding-mismatch', s.reasons.includes('binding-mismatch'), s.reasons.join(','))
ok('  and does not report signature_ok (gated before crypto)', s.signature_ok === false)

// ── tampered body: oid and binding both move ────────────────────────────────
const tampered = { ...(good as unknown as Record<string, unknown>), body: { hr: 99 } }
const t = verifyCdro({ cdro: tampered, ...keys })
ok('tampered body rejected', !t.valid)
ok('  binding-mismatch reported', t.reasons.includes('binding-mismatch'))

// ── stamped oid lying about honest content ──────────────────────────────────
const badOid = { ...(good as unknown as Record<string, unknown>), oid: 'sha256:' + 'b'.repeat(64) }
const b = verifyCdro({ cdro: badOid, ...keys })
ok('wrong stamped oid rejected', !b.valid)
ok('  oid-mismatch reported', b.reasons.includes('oid-mismatch'), b.reasons.join(','))

// ── payloadType pinning ──────────────────────────────────────────────────────
const pt = verifyCdro({ cdro: good, ...keys, expectedPayloadType: 'application/vnd.other+json' })
ok('payloadType mismatch rejected', !pt.valid)
ok('  payload-type-mismatch reported', pt.reasons.includes('payload-type-mismatch'), pt.reasons.join(','))

// ── the __proto__ collision shape is refused at the shape gate ──────────────
const polluted = JSON.parse(
  JSON.stringify(good).replace(/^\{/, '{"__proto__":{"escalated":true},'),
)
const p = verifyCdro({ cdro: polluted, ...keys })
ok('__proto__ object rejected at the shape gate', !p.valid)
ok('  [E17] reported, nothing hashed', p.reasons.some((x: string) => x.includes('[E17]')), p.reasons.join(','))

// ── missing attestation, and never throws ───────────────────────────────────
const { attestation: _drop, ...noAtt } = good as unknown as Record<string, unknown>
ok('missing attestation rejected', verifyCdro({ cdro: noAtt, ...keys }).reasons.includes('missing-attestation'))
for (const [label, bad] of [['null', null], ['string', 'x'], ['array', [1]]] as [string, unknown][]) {
  let threw = false
  try { verifyCdro({ cdro: bad, ...keys }) } catch { threw = true }
  ok(`verifyCdro(${label}) returns rather than throws`, !threw)
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
