/**
 * test/readme-example.test.ts — runs the exact code from README.md so the
 * documented example cannot drift from the implementation.
 *
 * This file runs as part of `npm test` (test/run-all.ts globs *.test.ts) and
 * therefore as part of `prepublishOnly`.
 *
 * It asserts the IDENTITY INVARIANT, not just that the calls succeed:
 * `cdro.oid` MUST equal `cdroOid(cdro)`, and MUST stay equal after an
 * attestation is attached. A previous version of this file checked only
 * `validateCdro().ok`, which is a shape check and passes even when the
 * stamped OID is wrong (validate.ts does not recompute the hash).
 */

import {
  canonicalize,
  cdroOid,
  cdroContentCore,
  pae,
  verifyAttestation,
  validateCdro,
  type AttestationEnvelope,
  type CDRO,
} from '../src/index.js'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes, webcrypto } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

let failed = false
function ok(name: string, cond: boolean, detail = '') {
  if (cond) {
    console.log(`OK   ${name}`)
  } else {
    failed = true
    console.error(`FAIL ${name}${detail ? ' — ' + detail : ''}`)
  }
}

// ── README: Minimal example ─────────────────────────────────────────────────

// 1. Build the CDRO content core: every field EXCEPT the detached envelope
//    fields (oid, signature, attestation, ...).
const core = {
  type: 'gap:capability_declaration',
  sraid_version: '2.0' as const,
  tenant_id: 't-home',
  created_at_ms: Date.now(),
  created_by: 'actor:skill:demo',
  body: { capability: 'door.unlock', risk_class: 'B' },
}

// 2. Identity is the hash of the WHOLE content core, not just the body.
const cdro: CDRO<typeof core.body> = { oid: cdroOid(core), ...core }

ok('validateCdro passes', validateCdro(cdro).ok, JSON.stringify(validateCdro(cdro).errors))
ok('cdro.oid === cdroOid(cdro)', cdro.oid === cdroOid(cdro))

// 3. Sign the canonical content core through DSSE PAE (type-bound).
const payloadType = 'application/vnd.synoi.sraid+json'
const payload = canonicalize(cdroContentCore(cdro))
const signedBytes = pae(payloadType, payload)

const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)
const mlKeys = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))

const attestation: AttestationEnvelope = {
  payloadType,
  payload,
  signatures: [
    {
      alg: 'ed25519',
      sig: Buffer.from(ed25519.sign(signedBytes, edPriv)).toString('base64'),
      keyid: 'synoi-demo-2026-05',
    },
    {
      alg: 'ml-dsa-65',
      sig: Buffer.from(ml_dsa65.sign(signedBytes, mlKeys.secretKey)).toString('base64'),
      keyid: 'synoi-demo-2026-05',
    },
  ],
}

// 4. Attaching the attestation does not change identity.
const attested = { ...cdro, attestation }
ok('OID invariant across signing', cdroOid(attested) === cdro.oid)

// 5. Verify. Both signatures must pass.
const v = verifyAttestation({
  envelope: attestation,
  ed25519_pub: edPub,
  ml_dsa_pub: mlKeys.publicKey,
  expectedPayloadType: payloadType,
})
ok('verifyAttestation valid', v.valid, JSON.stringify(v.reasons))

// ── Regression guard for the 0.3.0 defect ───────────────────────────────────
// The old README did `oidOf(body)`. Prove that is NOT the CDRO identity, so
// this test fails loudly if anyone reintroduces it.
const { oidOf } = await import('../src/index.js')
ok('oidOf(body) is NOT the CDRO oid (0.3.0 defect)', oidOf(core.body) !== cdroOid(cdro))

if (failed) {
  console.error('README example: FAILED')
  process.exit(1)
}
console.log('README example: OK')
process.exit(0)
