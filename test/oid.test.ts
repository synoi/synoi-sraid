/**
 * test/oid.test.ts — OID derivation.
 *
 * OID = "sha256:" + hex(sha256(canonicalize(content))).
 * Must match synoi-gateway/src/gap/oid.ts byte-for-byte.
 */

import { createHash } from 'node:crypto'
import { canonicalize } from '../src/canonicalize.js'
import { oidOf, oidOfCanonical, cdroOid, cdroContentCore, CDRO_ENVELOPE_FIELDS } from '../src/oid.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Format ────────────────────────────────────────────────────────────────

const o = oidOf({ a: 1 })
ok('oid starts with "sha256:"', o.startsWith('sha256:'), o)
ok('oid hex portion is 64 chars', o.length === 'sha256:'.length + 64, o)
ok('oid is lowercase hex', /^sha256:[0-9a-f]{64}$/.test(o), o)

// ── Key-order independence ────────────────────────────────────────────────

ok(
  'oidOf({a:1,b:2}) === oidOf({b:2,a:1})',
  oidOf({ a: 1, b: 2 }) === oidOf({ b: 2, a: 1 }),
)

// ── Different content → different OID ─────────────────────────────────────

ok('oidOf({a:1}) !== oidOf({a:2})', oidOf({ a: 1 }) !== oidOf({ a: 2 }))
ok('oidOf({a:1}) !== oidOf({a:1, b:undefined})',
   oidOf({ a: 1 }) === oidOf({ a: 1, b: undefined }),
   'undefined fields must be omitted from canonical form, so OIDs should match',
)

// ── Match against the manually-computed reference value ──────────────────

const refCanonical = canonicalize({ a: 1, b: 2 })
const refHash = createHash('sha256').update(refCanonical).digest('hex')
const refOid = 'sha256:' + refHash
ok(
  'oidOf({a:1, b:2}) matches manual sha256 reference',
  oidOf({ a: 1, b: 2 }) === refOid,
  `${oidOf({ a: 1, b: 2 })} vs ${refOid}`,
)

// ── oidOfCanonical accepts both string and Uint8Array ────────────────────

const stringOid = oidOfCanonical(refCanonical)
const bytesOid = oidOfCanonical(new TextEncoder().encode(refCanonical))
ok('oidOfCanonical(string) === oidOfCanonical(bytes)', stringOid === bytesOid)
ok('oidOfCanonical matches oidOf for same input', stringOid === oidOf({ a: 1, b: 2 }))

// ── Null and primitive inputs ────────────────────────────────────────────

ok('oidOf(null) is stable', oidOf(null) === oidOf(null))
ok('oidOf("hi") is stable', oidOf('hi') === oidOf('hi'))
ok('oidOf("hi") !== oidOf("bye")', oidOf('hi') !== oidOf('bye'))

// ── Gateway compatibility vector ─────────────────────────────────────────
//
// Reproduces the gateway's computeGapOid for a representative GAP body.
// If this drifts, GAP objects produced elsewhere stop verifying.

function gatewayComputeGapOid(body: unknown): string {
  function canon(v: unknown): string {
    if (v === null || typeof v !== 'object') return JSON.stringify(v)
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']'
    const obj = v as Record<string, unknown>
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canon(obj[k])).join(',') + '}'
  }
  return 'sha256:' + createHash('sha256').update(canon(body)).digest('hex')
}

const agpBody = {
  actor_type: 'skill',
  actor_id: 'demo',
  actor_name: 'demo skill',
  actor_version: '1.0.0',
  capabilities: [{ capability: 'file.read', safety_class: 'A' }],
}
ok(
  'oidOf matches gateway computeGapOid for representative GAP body',
  oidOf(agpBody) === gatewayComputeGapOid(agpBody),
  `${oidOf(agpBody)} vs ${gatewayComputeGapOid(agpBody)}`,
)

function throws(label: string, fn: () => unknown): void {
  let threw = false
  try { fn() } catch (_e) { threw = true }
  ok(label, threw)
}

// ── ADR_019: normative CDRO OID projection ────────────────────────────────
//
// The single normative projection strips EXACTLY the six detached
// signature / envelope fields and keeps everything else (gap_version,
// supersedes, authority, sensitivity, prev, links, body, ...).

ok(
  'CDRO_ENVELOPE_FIELDS is the exact six-field strip-set',
  JSON.stringify([...CDRO_ENVELOPE_FIELDS].sort()) ===
    JSON.stringify(
      ['oid', 'signature', 'ml_dsa_signature', 'signature_key_id', 'signature_algorithm', 'attestation'].sort(),
    ),
  [...CDRO_ENVELOPE_FIELDS].join(','),
)

// A representative full CDRO with gap_version + supersedes + authority.
const baseCdro = {
  type: 'gap:decision_receipt',
  sraid_version: '2.0' as const,
  gap_version: '1.0',
  tenant_id: 'tenant-x',
  created_at_ms: 1_720_000_000_000,
  created_by: 'sha256:' + 'c'.repeat(64),
  body: { decision: 'allow', amount_minor: 1299 },
  authority: { grant_oid: 'sha256:' + 'a'.repeat(64), decision: 'allow' as const },
  supersedes: 'sha256:' + 'b'.repeat(64),
}

// ── THE KEYSTONE VECTOR: pre-attestation OID === post-attestation OID ──────
//
// The whole "portable, independently verifiable receipt" thesis rests on this:
// a third party who recomputes the OID of a SIGNED receipt (which carries an
// attestation / signature the signer attached AFTER hashing) must get the SAME
// value the signer stamped. cdroContentCore strips those detached fields, so
// cdroOid is invariant across signing.

const preAttestation = { ...baseCdro }
const postAttestation = {
  ...baseCdro,
  oid: 'sha256:' + 'f'.repeat(64), // signer-stamped output
  attestation: {
    payloadType: 'application/vnd.synoi.sraid+json',
    payload: canonicalize(cdroContentCore(baseCdro)),
    signatures: [
      { alg: 'ed25519', sig: 'AAAA', keyid: 'k1' },
      { alg: 'ml-dsa-65', sig: 'BBBB', keyid: 'k1' },
    ],
  },
  signature: { ed25519: 'AAAA', ml_dsa_65: 'BBBB', signer_kid: 'k1' },
  ml_dsa_signature: 'BBBB',
  signature_key_id: 'k1',
  signature_algorithm: 'ed25519+ml-dsa-65',
}

ok(
  'KEYSTONE: cdroOid(pre-attestation) === cdroOid(post-attestation)',
  cdroOid(preAttestation) === cdroOid(postAttestation),
  `${cdroOid(preAttestation)} vs ${cdroOid(postAttestation)}`,
)

// Print the keystone vector value for the record (source-of-truth for SDKs).
process.stdout.write(`     cdroOid(baseCdro) = ${cdroOid(baseCdro)}\n`)

// content core must contain none of the six envelope fields and all content.
const core = cdroContentCore(postAttestation)
for (const f of CDRO_ENVELOPE_FIELDS) {
  ok(`content core omits envelope field "${f}"`, !(f in core))
}
ok('content core keeps gap_version', core.gap_version === '1.0')
ok('content core keeps supersedes', core.supersedes === 'sha256:' + 'b'.repeat(64))
ok('content core keeps authority', typeof core.authority === 'object')
ok('content core keeps body', typeof core.body === 'object')

// ── supersedes IS in identity: changing it changes the OID ────────────────

const supersedesA = cdroOid({ ...baseCdro, supersedes: 'sha256:' + 'b'.repeat(64) })
const supersedesB = cdroOid({ ...baseCdro, supersedes: 'sha256:' + 'e'.repeat(64) })
ok('changing supersedes changes the OID (supersedes IS in identity)', supersedesA !== supersedesB)

const withSupersedes = cdroOid(baseCdro)
const withoutSupersedes = cdroOid((() => { const { supersedes, ...rest } = baseCdro; return rest })())
ok('dropping supersedes changes the OID (supersedes IS in identity)', withSupersedes !== withoutSupersedes)

// ── gap_version IS in identity: a protocol downgrade is OID-detectable ─────

const gvA = cdroOid({ ...baseCdro, gap_version: '1.0' })
const gvB = cdroOid({ ...baseCdro, gap_version: '0.9' })
ok('changing gap_version changes the OID (protocol downgrade detectable)', gvA !== gvB)

// ── float-bearing CDRO is REJECTED (ADR_019 number rule) ──────────────────

throws(
  'cdroOid rejects a float-bearing body (amount as 12.99)',
  () => cdroOid({ ...baseCdro, body: { decision: 'allow', amount: 12.99 } }),
)
throws(
  'cdroOid rejects a nested float',
  () => cdroOid({ ...baseCdro, body: { rate: { pct: 0.5 } } }),
)

// ── Done ──────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
