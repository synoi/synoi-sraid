/**
 * test/readme-example.test.ts — runs the exact code from README.md to
 * ensure documentation stays in sync with the implementation. Not part of
 * the default `npm test` chain — invoked manually during release prep.
 */

import {
  canonicalize,
  oidOf,
  verifySignature,
  validateCdro,
  type CDRO,
  type SignatureEnvelope,
} from '../src/index.js'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes, webcrypto } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

const body = { capability: 'door.unlock', risk_class: 'B' }
const oid = oidOf(body)

const cdro: CDRO<typeof body> = {
  oid,
  type: 'gap:capability_declaration',
  sraid_version: '2.0',
  tenant_id: 't-home',
  created_at_ms: Date.now(),
  created_by: 'actor:skill:demo',
  body,
}

const validation = validateCdro(cdro)
if (!validation.ok) {
  console.error('validateCdro failed:', validation.errors)
  process.exit(1)
}

const canonical = canonicalize(cdro.body)
const message = new TextEncoder().encode(canonical)

const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)
const mlKeys = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))

const envelope: SignatureEnvelope = {
  ed25519: Buffer.from(ed25519.sign(message, edPriv)).toString('base64'),
  ml_dsa_65: Buffer.from(ml_dsa65.sign(message, mlKeys.secretKey)).toString('base64'),
  signer_kid: 'synoi-demo-2026-05',
}

const v = verifySignature({
  canonical,
  envelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlKeys.publicKey,
})

if (!v.valid) {
  console.error('verifySignature failed:', v.reasons)
  process.exit(1)
}

console.log('README example: OK')
process.exit(0)
