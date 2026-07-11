/**
 * test/validate.test.ts — shape validators for CDRO, SRO, SignatureEnvelope.
 */

import {
  validateCdro,
  validateSro,
  validateSignatureEnvelope,
  validateAttestationEnvelope,
} from '../src/validate.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Well-formed CDRO ──────────────────────────────────────────────────────

const goodCdro = {
  oid: 'sha256:' + 'a'.repeat(64),
  type: 'sraid:test',
  sraid_version: '2.0',
  tenant_id: 't-home',
  created_at_ms: 1716840000000,
  created_by: 'actor:test',
  body: { hello: 'world' },
}
const goodResult = validateCdro(goodCdro)
ok('valid CDRO → ok=true', goodResult.ok === true, JSON.stringify(goodResult.errors))
ok('valid CDRO → no errors', goodResult.errors.length === 0)

// CDRO with optional supersedes + signature
const goodWithExtras = {
  ...goodCdro,
  supersedes: 'sha256:' + 'b'.repeat(64),
  signature: {
    ed25519: 'AAAA',
    ml_dsa_65: 'BBBB',
    signer_kid: 'kid-1',
  },
}
ok('valid CDRO with supersedes + signature → ok=true',
   validateCdro(goodWithExtras).ok === true,
   JSON.stringify(validateCdro(goodWithExtras).errors))

// ── Empty object → fails ─────────────────────────────────────────────────

const emptyResult = validateCdro({})
ok('validateCdro({}) → ok=false', emptyResult.ok === false)
ok('validateCdro({}) → multiple specific errors', emptyResult.errors.length >= 5,
   `errors=${JSON.stringify(emptyResult.errors)}`)

// Check specific error codes are surfaced
const expectedCodes = ['[E02]', '[E04]', '[E05]', '[E06]', '[E07]', '[E08]', '[E09]']
for (const code of expectedCodes) {
  ok(
    `validateCdro({}) → error includes ${code}`,
    emptyResult.errors.some((e) => e.startsWith(code)),
    JSON.stringify(emptyResult.errors),
  )
}

// ── Non-object inputs ────────────────────────────────────────────────────

ok('validateCdro(null) → ok=false', validateCdro(null).ok === false)
ok('validateCdro("hi") → ok=false', validateCdro('hi').ok === false)
ok('validateCdro([]) → ok=false', validateCdro([]).ok === false)
ok('validateCdro(undefined) → ok=false', validateCdro(undefined).ok === false)

// ── oid format ───────────────────────────────────────────────────────────

const badOid = validateCdro({ ...goodCdro, oid: 'badhash' })
ok('oid without sha256: prefix → [E03] error', badOid.errors.some(e => e.startsWith('[E03]')))

// ── sraid_version ────────────────────────────────────────────────────────

// A downgrade to the retired v1 version value must fail-closed at [E05].
const badVersion = validateCdro({ ...goodCdro, sraid_version: '1.0' })
ok('sraid_version "1.0" (retired) → [E05] error', badVersion.errors.some(e => e.startsWith('[E05]')))

// The retired key itself (cof_version) must also fail-closed: absence of
// sraid_version, not presence of the old key, is what [E05] checks.
const { sraid_version: _drop, ...goodCdroSansVersion } = goodCdro
const badKey = validateCdro({ ...goodCdroSansVersion, cof_version: '2.0' })
ok('cof_version key (retired) present, sraid_version absent → [E05] error',
   badKey.errors.some(e => e.startsWith('[E05]')))

// ── created_at_ms ─────────────────────────────────────────────────────────

ok(
  'created_at_ms negative → [E07] error',
  validateCdro({ ...goodCdro, created_at_ms: -1 }).errors.some(e => e.startsWith('[E07]')),
)
ok(
  'created_at_ms fractional → [E07] error',
  validateCdro({ ...goodCdro, created_at_ms: 1.5 }).errors.some(e => e.startsWith('[E07]')),
)
ok(
  'created_at_ms not-a-number → [E07] error',
  validateCdro({ ...goodCdro, created_at_ms: 'now' }).errors.some(e => e.startsWith('[E07]')),
)

// ── supersedes: canonical OID required (F26) ─────────────────────────────

// A1: valid 64-hex sha256 OID accepted
ok(
  'supersedes with valid canonical OID → ok=true',
  validateCdro({ ...goodCdro, supersedes: 'sha256:' + 'a'.repeat(64) }).ok === true,
)

// A2: non-hex suffix rejected → [E10]
const badSupersedes = validateCdro({ ...goodCdro, supersedes: 'sha256:notahash' })
ok('supersedes non-hex suffix → [E10] error', badSupersedes.errors.some(e => e.startsWith('[E10]')))

// A3: uppercase hex rejected (oidOf always emits lowercase)
ok(
  'supersedes uppercase hex → [E10] error',
  validateCdro({ ...goodCdro, supersedes: 'sha256:' + 'A'.repeat(64) })
    .errors.some(e => e.startsWith('[E10]')),
)

// A4: 63 hex chars (too short) rejected
ok(
  'supersedes 63-char hex → [E10] error',
  validateCdro({ ...goodCdro, supersedes: 'sha256:' + 'a'.repeat(63) })
    .errors.some(e => e.startsWith('[E10]')),
)

// A5 (regression from previous guard): empty string still rejected
ok(
  'supersedes empty string → [E10] error',
  validateCdro({ ...goodCdro, supersedes: '' }).errors.some(e => e.startsWith('[E10]')),
)

// ── signature envelope nested ────────────────────────────────────────────

const badSig = validateCdro({
  ...goodCdro,
  signature: { ed25519: 'a', signer_kid: 'k' },   // missing ml_dsa_65
})
ok('CDRO with malformed signature → ok=false', badSig.ok === false)
ok('CDRO with malformed signature → [E11] error', badSig.errors.some(e => e.startsWith('[E11]')))

// ── SignatureEnvelope validator ──────────────────────────────────────────

ok('validateSignatureEnvelope({}) → ok=false',
   validateSignatureEnvelope({}).ok === false)
ok('validateSignatureEnvelope(null) → ok=false',
   validateSignatureEnvelope(null).ok === false)
ok(
  'validateSignatureEnvelope happy → ok=true',
  validateSignatureEnvelope({ ed25519: 'a', ml_dsa_65: 'b', signer_kid: 'c' }).ok === true,
)

// ── DSSE attestation envelope validator (L2) ──────────────────────────────

const goodAttestation = {
  payloadType: 'application/vnd.synoi.sraid+json',
  payload: '{"a":1}',
  signatures: [
    { alg: 'ed25519', keyid: 'k1', sig: 'AAAA' },
    { alg: 'ml-dsa-65', keyid: 'k1', sig: 'BBBB' },
  ],
}
ok('validateAttestationEnvelope happy → ok=true',
   validateAttestationEnvelope(goodAttestation).ok === true,
   JSON.stringify(validateAttestationEnvelope(goodAttestation).errors))

ok('validateAttestationEnvelope({}) → ok=false',
   validateAttestationEnvelope({}).ok === false)
ok('validateAttestationEnvelope(null) → ok=false',
   validateAttestationEnvelope(null).ok === false)
ok('attestation missing payloadType → ok=false',
   validateAttestationEnvelope({ payload: 'x', signatures: [] }).ok === false)
ok('attestation signatures not array → ok=false',
   validateAttestationEnvelope({ payloadType: 't', payload: 'x', signatures: {} }).ok === false)
ok('attestation signature entry missing sig → ok=false',
   validateAttestationEnvelope({
     payloadType: 't', payload: 'x', signatures: [{ alg: 'ed25519' }],
   }).ok === false)

// CDRO with a DSSE attestation field validates and surfaces [E15] when bad.
ok('valid CDRO with attestation → ok=true',
   validateCdro({ ...goodCdro, attestation: goodAttestation }).ok === true,
   JSON.stringify(validateCdro({ ...goodCdro, attestation: goodAttestation }).errors))
ok('CDRO with malformed attestation → [E15] error',
   validateCdro({ ...goodCdro, attestation: { payloadType: 't' } })
     .errors.some(e => e.startsWith('[E15]')))

// ── SRO validator ────────────────────────────────────────────────────────

const goodSro = {
  oid: 'sha256:' + 'c'.repeat(64),
  type: 'sraid:sro',
  sraid_version: '2.0',
  tenant_id: 't-home',
  created_at_ms: 1716840000000,
  created_by: 'actor:operator',
  body: {
    predecessor_oid: 'sha256:' + 'a'.repeat(64),
    successor_oid: 'sha256:' + 'b'.repeat(64),
    reason: 'policy update',
    authorized_by: 'actor:operator',
  },
}
ok('valid SRO → ok=true', validateSro(goodSro).ok === true,
   JSON.stringify(validateSro(goodSro).errors))

// Wrong type field
const wrongTypeSro = { ...goodSro, type: 'sraid:not-sro' }
ok('SRO with wrong type → [S02] error',
   validateSro(wrongTypeSro).errors.some(e => e.startsWith('[S02]')))

// A5-SRO: non-canonical predecessor_oid rejected → [S03]
ok(
  'SRO with non-canonical predecessor_oid → [S03] error',
  validateSro({ ...goodSro, body: { ...goodSro.body, predecessor_oid: 'sha256:short' } })
    .errors.some(e => e.startsWith('[S03]')),
)

// A6-SRO: non-canonical successor_oid rejected → [S04]
ok(
  'SRO with non-canonical successor_oid → [S04] error',
  validateSro({ ...goodSro, body: { ...goodSro.body, successor_oid: 'sha256:' + 'B'.repeat(64) } })
    .errors.some(e => e.startsWith('[S04]')),
)

// Missing predecessor_oid (regression — empty string still rejected)
const noPredSro = { ...goodSro, body: { ...goodSro.body, predecessor_oid: '' } }
ok('SRO with empty predecessor_oid → [S03] error',
   validateSro(noPredSro).errors.some(e => e.startsWith('[S03]')))

// evidence_oids array of strings
const goodEvidence = {
  ...goodSro,
  body: { ...goodSro.body, evidence_oids: ['sha256:' + 'd'.repeat(64)] },
}
ok('SRO with evidence_oids → ok=true', validateSro(goodEvidence).ok === true,
   JSON.stringify(validateSro(goodEvidence).errors))

const badEvidence = {
  ...goodSro,
  body: { ...goodSro.body, evidence_oids: ['ok', '', 42] },
}
ok('SRO with mixed evidence_oids → [S07] error',
   validateSro(badEvidence).errors.some(e => e.startsWith('[S07]')))

// ── Lineage independence (F26 A7) ────────────────────────────────────────
// supersedes + prev + links[] all present and valid → ok=true (no cross-check)
const threeLineage = validateCdro({
  ...goodCdro,
  supersedes: 'sha256:' + 'e'.repeat(64),
  prev:       'sha256:' + 'f'.repeat(64),
  links: [
    { rel: 'derived_from', oid: 'sha256:' + '1'.repeat(64) },
  ],
})
ok(
  'CDRO with supersedes + prev + links all canonical → ok=true (lineage fields independent)',
  threeLineage.ok === true,
  JSON.stringify(threeLineage.errors),
)

// ── Done ──────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
