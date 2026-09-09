/**
 * test/gtm-gates.test.ts — the three findings that gate going to market.
 *
 * Written BEFORE the fixes and expected to fail. Each pins a defect the v2
 * panel found and a shipped-artifact audit confirmed still live in 0.5.0.
 *
 * 4.1  SIGNATURE-LIST MALLEABILITY. `signatures[]` is entirely outside the
 *      signed bytes: PAE covers `payloadType` and `payload` only. `findSig`
 *      returns the FIRST entry matching an alg, so prepending a bogus
 *      `{alg:'ed25519', sig:<zeros>}` makes a cryptographically valid receipt
 *      verify as INVALID. Two uses: any party in the delivery or storage path
 *      silently destroys a counterparty's ability to verify a receipt they
 *      hold, with no evidence of tampering; and an issuer can do it to its own
 *      receipt and later claim it never verified. For a product selling
 *      settlement-grade non-repudiation that is a business defect.
 *
 *      The fix here is DENIAL-OF-SERVICE ONLY and deliberately changes no
 *      signed bytes: try every entry for an alg and accept if any verifies.
 *      An attacker still cannot forge a signature, so extra entries become
 *      inert instead of destructive. DSSE is itself an OR-of-signatures
 *      envelope; SynOI's AND policy is across ALGORITHMS, not across entries.
 *
 *      NOT fixed here: `keyid` is unauthenticated and rewritable (4.1b). That
 *      genuinely requires committing the ordered {alg, keyid} list into the
 *      signed bytes, which changes the wire format. See the note at the end.
 *
 * 4.3  BASE64 MALLEABILITY. `internal/base64-validate.ts` checks alphabet,
 *      length modulo 4 and padding position, but not that the unused trailing
 *      bits are zero (RFC 4648 §3.5). An Ed25519 signature is 64 bytes, so the
 *      final quantum has FOUR free bits: 16 distinct `sig` strings decode to
 *      the same signature and all 16 verify. Exposure is anywhere a serialized
 *      receipt is treated as unique — transparency-log leaves, Merkle batches,
 *      dedup and idempotency keys.
 *
 * 4.8  OID VALIDATED BY PREFIX ONLY. `validateCdro` checks `oid` and `prev`
 *      with `.startsWith('sha256:')`, so the literal string `"sha256:"` passes.
 *      `supersedes` already uses the strict regex; these two did not.
 */

import { validateCdro, verifyAttestation, pae } from '../src/index.js'
import { canonicalize } from '../src/canonicalize.js'
import type { AttestationEnvelope } from '../src/types.js'
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
const payload = canonicalize({ decision: 'allow', amount_minor: 1299 })
const msg = pae(PT, payload)
const edSig = Buffer.from(ed25519.sign(msg, edPriv)).toString('base64')
const mlSig = Buffer.from(ml_dsa65.sign(msg, ml.secretKey)).toString('base64')
const keys = { ed25519_pub: edPub, ml_dsa_pub: ml.publicKey }

const env = (sigs: AttestationSig[]): AttestationEnvelope =>
  ({ payloadType: PT, payload, signatures: sigs }) as AttestationEnvelope
type AttestationSig = { alg: string; sig: string; keyid?: string }
const good: AttestationSig[] = [
  { alg: 'ed25519', sig: edSig },
  { alg: 'ml-dsa-65', sig: mlSig },
]
const verify = (sigs: AttestationSig[]) => verifyAttestation({ envelope: env(sigs), ...keys }).valid

// ── baseline ─────────────────────────────────────────────────────────────────
ok('baseline: a well-formed hybrid envelope verifies', verify(good))

// ── 4.1 signature-list malleability ──────────────────────────────────────────
const ZERO64 = Buffer.alloc(64).toString('base64')
const ZERO_ML = Buffer.alloc(3309).toString('base64')

ok('4.1 prepended bogus ed25519 entry must NOT invalidate',
   verify([{ alg: 'ed25519', sig: ZERO64 }, ...good]))
ok('4.1 prepended bogus ml-dsa-65 entry must NOT invalidate',
   verify([{ alg: 'ml-dsa-65', sig: ZERO_ML }, ...good]))
ok('4.1 bogus entries on BOTH algs must NOT invalidate',
   verify([{ alg: 'ed25519', sig: ZERO64 }, { alg: 'ml-dsa-65', sig: ZERO_ML }, ...good]))
ok('4.1 appended bogus entries must NOT invalidate (regression: already held)',
   verify([...good, { alg: 'ed25519', sig: ZERO64 }]))
ok('4.1 reordering the genuine entries must NOT invalidate',
   verify([good[1]!, good[0]!]))
ok('4.1 an unknown alg alongside the pair must NOT invalidate',
   verify([{ alg: 'rsa-2048', sig: ZERO64 }, ...good]))

// The AND policy is across ALGORITHMS and must still hold.
ok('4.1 GUARD: ed25519 alone still fails the AND policy',
   verify([good[0]!]) === false)
ok('4.1 GUARD: ml-dsa-65 alone still fails the AND policy',
   verify([good[1]!]) === false)
ok('4.1 GUARD: all-bogus entries still fail',
   verify([{ alg: 'ed25519', sig: ZERO64 }, { alg: 'ml-dsa-65', sig: ZERO_ML }]) === false)
ok('4.1 GUARD: a signature over DIFFERENT bytes still fails',
   (() => {
     const other = pae(PT, canonicalize({ decision: 'deny' }))
     return verify([
       { alg: 'ed25519', sig: Buffer.from(ed25519.sign(other, edPriv)).toString('base64') },
       good[1]!,
     ]) === false
   })())

// ── 4.3 base64 malleability ──────────────────────────────────────────────────
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const raw = Buffer.from(edSig, 'base64')
const variants = ALPHA.split('')
  .map((c) => edSig.slice(0, -3) + c + '==')
  .filter((v) => v !== edSig && Buffer.from(v, 'base64').equals(raw))
ok('4.3 PRECONDITION: non-canonical encodings of the same bytes exist',
   variants.length === 15, `found ${variants.length}`)
const accepted = variants.filter((v) => verify([{ alg: 'ed25519', sig: v }, good[1]!]))
ok('4.3 non-canonical base64 must be rejected',
   accepted.length === 0, `${accepted.length} of ${variants.length} still verify`)
ok('4.3 GUARD: the canonical encoding still verifies', verify(good))

// ── 4.8 strict OID validation ────────────────────────────────────────────────
const cdro = (over: Record<string, unknown>) => ({
  oid: 'sha256:' + 'a'.repeat(64), type: 'o', sraid_version: '2.0',
  tenant_id: 't', created_at_ms: 1, created_by: 'a', body: {}, ...over,
})
ok('4.8 bare "sha256:" is not a valid oid', validateCdro(cdro({ oid: 'sha256:' })).ok === false)
ok('4.8 non-hex oid is rejected', validateCdro(cdro({ oid: 'sha256:not-a-hash' })).ok === false)
ok('4.8 short-hex oid is rejected', validateCdro(cdro({ oid: 'sha256:abc' })).ok === false)
ok('4.8 uppercase-hex oid is rejected', validateCdro(cdro({ oid: 'sha256:' + 'A'.repeat(64) })).ok === false)
ok('4.8 non-hex prev is rejected', validateCdro(cdro({ prev: 'sha256:placeholder' })).ok === false)
ok('4.8 GUARD: a canonical oid is still accepted', validateCdro(cdro({})).ok === true,
   JSON.stringify(validateCdro(cdro({})).errors))
ok('4.8 GUARD: a canonical prev is still accepted',
   validateCdro(cdro({ prev: 'sha256:' + 'b'.repeat(64) })).ok === true)
ok('4.8 GUARD: prev may still be null (root object)',
   validateCdro(cdro({ prev: null })).ok === true)

console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) {
  console.error(
    '\n4.1: findSig returns the FIRST entry for an alg, so a prepended bogus\n' +
      '     entry hijacks verification. Scan all candidates and accept if any\n' +
      '     verifies. No signed bytes change.\n' +
      '4.3: base64-validate.ts does not check that unused trailing bits are\n' +
      '     zero (RFC 4648 3.5).\n' +
      '4.8: validate.ts checks oid/prev with startsWith; use CANONICAL_OID_RE.',
  )
}
process.exit(failed > 0 ? 1 : 0)
