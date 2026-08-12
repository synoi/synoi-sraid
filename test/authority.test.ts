/**
 * test/authority.test.ts — L4 authority block: shape validation + the
 * verifyAuthority verifier (structure / binding / signature / coverage,
 * plus the resolver-dependent revocation/existence path).
 *
 * Builds REAL signed grant CDROs so the signature + binding checks are
 * exercised against genuine crypto, not stubs.
 */

import { webcrypto, randomBytes } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { cdroOid, cdroContentCore } from '../src/oid.js'
import { pae } from '../src/attestation.js'
import { validateCdro, validateAuthorityBlock } from '../src/validate.js'
import {
  verifyAuthority,
  capabilityCovers,
  type AuthorityResolver,
  type GrantStatus,
} from '../src/authority.js'
import type { CDRO, AttestationEnvelope } from '../src/types.js'
import type { GrantBodyShape } from '../src/authority.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

const toB64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')

// ── Keys ──────────────────────────────────────────────────────────────────
const edPriv = new Uint8Array(randomBytes(32))
const edPub = ed25519.getPublicKey(edPriv)
const ml = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
const mlPub = ml.publicKey

// ── Build a real signed grant CDRO ──────────────────────────────────────────
function buildGrant(body: GrantBodyShape & Record<string, unknown>): CDRO<GrantBodyShape> {
  const core = {
    type: 'gap:capability_grant',
    sraid_version: '2.0' as const,
    tenant_id: 'acme-prod',
    created_at_ms: 1716840000000,
    created_by: 'sha256:' + 'f'.repeat(64),
    body,
  }
  const oid = cdroOid(core)
  const canonical = canonicalize(core) // content core == core (no oid/signature yet)
  const msg = new TextEncoder().encode(canonical)
  const sig = {
    ed25519: toB64(ed25519.sign(msg, edPriv)),
    ml_dsa_65: toB64(ml_dsa65.sign(msg, ml.secretKey)),
    signer_kid: 'grantor-2026',
  }
  return { ...core, oid, signature: sig } as CDRO<GrantBodyShape>
}

const grant = buildGrant({
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: 1816840000000,
})

// Object authorized by the grant.
const obj: CDRO = {
  oid: 'sha256:' + '1'.repeat(64),
  type: 'althing:decision_receipt',
  sraid_version: '2.0',
  tenant_id: 'acme-prod',
  created_at_ms: 1716840001000,
  created_by: 'sha256:' + '2'.repeat(64),
  body: { action: 'delete thread 8821' },
  authority: {
    grant_oid: grant.oid,
    decision: 'allow',
    intent_oid: 'sha256:' + '3'.repeat(64),
  },
}

// ── capabilityCovers unit checks ────────────────────────────────────────────
ok('capabilityCovers exact', capabilityCovers('email.bulk_delete', 'email.bulk_delete'))
ok('capabilityCovers star-all', capabilityCovers('*', 'anything.at.all'))
ok('capabilityCovers boundary wildcard', capabilityCovers('email.*', 'email.bulk_delete'))
ok('capabilityCovers rejects non-boundary', !capabilityCovers('emai*', 'email.bulk_delete'))
ok('capabilityCovers rejects mismatch', !capabilityCovers('skill.create', 'skill.update'))

// ── validateAuthorityBlock ──────────────────────────────────────────────────
ok('valid authority block ok', validateAuthorityBlock({ grant_oid: 'sha256:' + 'a'.repeat(64), decision: 'allow' }).ok)
ok('authority decision null allowed', validateAuthorityBlock({ grant_oid: 'sha256:' + 'a'.repeat(64), decision: null }).ok)
ok('authority bad decision rejected', !validateAuthorityBlock({ grant_oid: 'sha256:x', decision: 'maybe' }).ok)
ok('authority bad grant_oid prefix rejected', !validateAuthorityBlock({ grant_oid: 'notahash' }).ok)
ok('authority non-object rejected', !validateAuthorityBlock(null).ok)
ok('authority all six verbs valid', ['allow', 'deny', 'defer', 'step_up', 'delegate', 'revoke'].every(
  d => validateAuthorityBlock({ grant_oid: 'sha256:' + 'a'.repeat(64), decision: d }).ok))

// validateCdro folds in authority via [E12]
const cdroBadAuth = validateCdro({
  oid: 'sha256:' + '1'.repeat(64), type: 't', sraid_version: '2.0',
  tenant_id: 'x', created_at_ms: 1, created_by: 'y', body: {},
  authority: { decision: 'nope' },
})
ok('validateCdro surfaces [E12] for bad authority', cdroBadAuth.errors.some(e => e.startsWith('[E12]')))

// authority is hashed into the OID — stripping it changes identity.
const withAuth = cdroOid({ type: 't', sraid_version: '2.0', tenant_id: 'x', created_at_ms: 1, created_by: 'y', body: {}, authority: { grant_oid: 'sha256:' + 'a'.repeat(64) } })
const without = cdroOid({ type: 't', sraid_version: '2.0', tenant_id: 'x', created_at_ms: 1, created_by: 'y', body: {} })
ok('authority changes the OID (cannot be stripped silently)', withAuth !== without)

// ── verifyAuthority: structure only (no grant) ──────────────────────────────
const sOnly = verifyAuthority({ object: obj })
ok('structure-only: structure_ok', sOnly.structure_ok)
ok('structure-only: not authorized (no grant)', sOnly.authorized === false)
ok('structure-only: grant_supplied false', sOnly.grant_supplied === false)

const noAuthObj: CDRO = { ...obj, authority: undefined }
ok('object with no authority: structure fails', verifyAuthority({ object: noAuthObj }).structure_ok === false)

// ── verifyAuthority: full happy path ────────────────────────────────────────
const full = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('full: authorized', full.authorized === true, JSON.stringify(full.reasons))
ok('full: binding_ok', full.binding_ok)
ok('full: signature_checked + signature_ok', full.signature_checked && full.signature_ok)
ok('full: coverage_ok', full.coverage_ok)
// HONESTY: local-only verification must NOT claim live revocation/existence.
ok('full: revocation NOT checked without resolver', full.revocation_checked === false)
ok('full: existence NOT checked without resolver', full.existence_checked === false)

// ── binding: tampered grant body under same OID reference ───────────────────
const tamperedGrant = { ...grant, body: { capability_scopes: [{ capability: '*' }] } as GrantBodyShape }
const tamp = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant: tamperedGrant as CDRO<GrantBodyShape>,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('tampered grant body: binding fails', tamp.binding_ok === false)
ok('tampered grant body: not authorized', tamp.authorized === false)

// ── signature: wrong key fails ──────────────────────────────────────────────
const wrongPub = ed25519.getPublicKey(new Uint8Array(randomBytes(32)))
const badSig = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant,
  grant_ed25519_pub: wrongPub, grant_ml_dsa_pub: mlPub,
})
ok('wrong signing key: signature_ok false', badSig.signature_ok === false)
ok('wrong signing key: not authorized', badSig.authorized === false)

// ── coverage: action not covered ────────────────────────────────────────────
const uncovered = verifyAuthority({
  object: obj, action: 'fs.delete_all', grant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('uncovered action: coverage_ok false', uncovered.coverage_ok === false)
ok('uncovered action: not authorized', uncovered.authorized === false)

// ── coverage: expired grant ─────────────────────────────────────────────────
const expiredGrant = buildGrant({ capability_scopes: [{ capability: 'email.*' }], expires_at_ms: 1000 })
const expiredObj: CDRO = { ...obj, authority: { ...obj.authority!, grant_oid: expiredGrant.oid } }
const expired = verifyAuthority({
  object: expiredObj, action: 'email.bulk_delete', grant: expiredGrant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('expired grant: coverage_ok false', expired.coverage_ok === false)
ok('expired grant: not authorized', expired.authorized === false)

// ── regression: single-grant happy path unperturbed by chain work ───────────
// K2 added verifyDelegationChain alongside this verifier; the single-hop
// verifyAuthority verdict must be unchanged.
const regression = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('regression: single-grant verifyAuthority still authorized', regression.authorized === true, JSON.stringify(regression.reasons))
ok('regression: single-grant revocation still not checked', regression.revocation_checked === false)

// ── resolver path (resolver-dependent live checks) ──────────────────────────
async function resolverTests(): Promise<void> {
  const liveResolver: AuthorityResolver = {
    resolveGrantStatus(): GrantStatus { return { exists: true, revoked: false } },
  }
  const revokedResolver: AuthorityResolver = {
    resolveGrantStatus(): GrantStatus { return { exists: true, revoked: true, revoked_at_ms: 1716840002000 } },
  }
  const missingResolver: AuthorityResolver = {
    resolveGrantStatus(): GrantStatus { return { exists: false } },
  }

  const live = await verifyAuthority({
    object: obj, action: 'email.bulk_delete', grant,
    grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub, resolver: liveResolver,
  })
  ok('resolver live: revocation_checked true', live.revocation_checked === true)
  ok('resolver live: existence_checked true', live.existence_checked === true)
  ok('resolver live: authorized', live.authorized === true, JSON.stringify(live.reasons))

  const revoked = await verifyAuthority({
    object: obj, action: 'email.bulk_delete', grant,
    grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub, resolver: revokedResolver,
  })
  ok('resolver revoked: not_revoked false', revoked.not_revoked === false)
  ok('resolver revoked: not authorized', revoked.authorized === false)

  const missing = await verifyAuthority({
    object: obj, action: 'email.bulk_delete', grant,
    grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub, resolver: missingResolver,
  })
  ok('resolver missing: existence_ok false', missing.existence_ok === false)
  ok('resolver missing: not authorized', missing.authorized === false)

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

// ── F1 tests: BINDING/SIGNATURE canonicalization parity ─────────────────────
// Build a grant CDRO with a DSSE attestation (DSSE path) and optionally with
// a legacy signature too (mixed path). Uses the same key material as above.

const GRANT_PT = 'application/vnd.synoi.sraid+json'

/** Build a grant with a legacy signature signed over cdroContentCore (post-fix canonical). */
function buildGrantLegacySigned(body: GrantBodyShape & Record<string, unknown>): CDRO<GrantBodyShape> {
  const core = {
    type: 'gap:capability_grant',
    sraid_version: '2.0' as const,
    tenant_id: 'acme-prod',
    created_at_ms: 1716840000000,
    created_by: 'sha256:' + 'f'.repeat(64),
    body,
  }
  const oid = cdroOid(core)
  // Post-fix: sign over cdroContentCore (strips oid, signature, attestation).
  const canonical = canonicalize(cdroContentCore(core))
  const msg = new TextEncoder().encode(canonical)
  const sig = {
    ed25519: toB64(ed25519.sign(msg, edPriv)),
    ml_dsa_65: toB64(ml_dsa65.sign(msg, ml.secretKey)),
    signer_kid: 'grantor-2026',
  }
  return { ...core, oid, signature: sig } as CDRO<GrantBodyShape>
}

/** Build a grant with a hybrid DSSE attestation over cdroContentCore. */
function buildGrantDsse(body: GrantBodyShape & Record<string, unknown>): CDRO<GrantBodyShape> {
  const core = {
    type: 'gap:capability_grant',
    sraid_version: '2.0' as const,
    tenant_id: 'acme-prod',
    created_at_ms: 1716840000000,
    created_by: 'sha256:' + 'f'.repeat(64),
    body,
  }
  const oid = cdroOid(core)
  const payload = canonicalize(cdroContentCore(core))
  const message = pae(GRANT_PT, payload)
  const attestation: AttestationEnvelope = {
    payloadType: GRANT_PT,
    payload,
    signatures: [
      { alg: 'ed25519', sig: toB64(ed25519.sign(message, edPriv)) },
      { alg: 'ml-dsa-65', sig: toB64(ml_dsa65.sign(message, ml.secretKey)) },
    ],
  }
  return { ...core, oid, attestation } as CDRO<GrantBodyShape>
}

const scopeBody: GrantBodyShape & Record<string, unknown> = {
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: 1816840000000,
}

// T1: grant carrying both a valid DSSE attestation AND a valid legacy signature.
// The attestation was computed over cdroContentCore (correct). Post-fix, the
// dispatch takes the DSSE path and succeeds. Pre-fix, it tried to verify the
// legacy signature with canonicalContentCore (which did NOT strip `attestation`),
// so the canonical bytes differed from what the signer signed -> spurious failure.
const grantDsseFull = buildGrantDsse(scopeBody)
// Also attach a legacy signature (signed over cdroContentCore, matching post-fix rule).
const t1CorePayload = canonicalize(cdroContentCore({
  type: 'gap:capability_grant', sraid_version: '2.0' as const,
  tenant_id: 'acme-prod', created_at_ms: 1716840000000,
  created_by: 'sha256:' + 'f'.repeat(64), body: scopeBody,
}))
const t1Msg = new TextEncoder().encode(t1CorePayload)
const t1LegacySig = {
  ed25519: toB64(ed25519.sign(t1Msg, edPriv)),
  ml_dsa_65: toB64(ml_dsa65.sign(t1Msg, ml.secretKey)),
  signer_kid: 'grantor-2026',
}
const grantWithAttAndSig: CDRO<GrantBodyShape> = {
  ...grantDsseFull,
  signature: t1LegacySig,
}
const objForAttGrant: CDRO = {
  oid: 'sha256:' + '9'.repeat(64),
  type: 'althing:decision_receipt',
  sraid_version: '2.0',
  tenant_id: 'acme-prod',
  created_at_ms: 1716840001000,
  created_by: 'sha256:' + '2'.repeat(64),
  body: { action: 'email.send' },
  authority: { grant_oid: grantWithAttAndSig.oid, decision: 'allow' },
}
const t1 = verifyAuthority({
  object: objForAttGrant, action: 'email.send',
  grant: grantWithAttAndSig, grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('T1: attestation-carrying grant verifies via DSSE path', t1.signature_ok, JSON.stringify(t1.reasons))

// T2: BINDING and SIGNATURE operate on identical bytes for attestation-carrying grant.
const t2recomputedOid = cdroOid(grantWithAttAndSig)
ok('T2: cdroOid(grant) equals claimed OID (binding honest)', t2recomputedOid === grantWithAttAndSig.oid)
ok('T2: binding_ok true for attestation-carrying grant', t1.binding_ok)

// T3: DSSE attestation only (no legacy signature) — happy path.
const grantDsse = buildGrantDsse(scopeBody)
const objForDsse: CDRO = {
  oid: 'sha256:' + '8'.repeat(64),
  type: 'althing:decision_receipt',
  sraid_version: '2.0',
  tenant_id: 'acme-prod',
  created_at_ms: 1716840001000,
  created_by: 'sha256:' + '2'.repeat(64),
  body: { action: 'email.send' },
  authority: { grant_oid: grantDsse.oid, decision: 'allow' },
}
const t3 = verifyAuthority({
  object: objForDsse, action: 'email.send',
  grant: grantDsse, grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('T3: DSSE-only grant: signature_checked', t3.signature_checked, JSON.stringify(t3.reasons))
ok('T3: DSSE-only grant: signature_ok', t3.signature_ok, JSON.stringify(t3.reasons))
ok('T3: DSSE-only grant: authorized', t3.authorized, JSON.stringify(t3.reasons))

// T4: DSSE attestation with wrong payload (payload-swap guard).
const grantDsseSwapped: CDRO<GrantBodyShape> = {
  ...grantDsse,
  attestation: { ...grantDsse.attestation!, payload: 'wrong-payload' } as AttestationEnvelope,
}
const objForSwap: CDRO = {
  ...objForDsse,
  authority: { grant_oid: grantDsseSwapped.oid, decision: 'allow' },
}
const t4 = verifyAuthority({
  object: objForSwap, action: 'email.send',
  grant: grantDsseSwapped, grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('T4: payload-swap: signature_ok false', t4.signature_ok === false)
ok('T4: payload-swap: reasons mention payload mismatch', t4.reasons.some(r => r.includes('payload')))

// T5: keys supplied but grant carries neither signature nor attestation.
const grantNoSig = buildGrantLegacySigned(scopeBody)
const grantStripped: CDRO<GrantBodyShape> = {
  ...grantNoSig,
  signature: undefined,
} as unknown as CDRO<GrantBodyShape>
const objForNoSig: CDRO = {
  ...objForDsse,
  authority: { grant_oid: grantStripped.oid, decision: 'allow' },
}
const t5 = verifyAuthority({
  object: objForNoSig, action: 'email.send',
  grant: grantStripped, grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('T5: no sig or attestation: signature_checked true', t5.signature_checked)
ok('T5: no sig or attestation: signature_ok false', t5.signature_ok === false)

// T6: regression — legacy grant with NO attestation field still works.
const t6 = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('T6: no-attestation legacy grant: signature_ok unchanged', t6.signature_ok)

void resolverTests()

// ── WALL-CLOCK EXPIRY (now_ms) ───────────────────────────────────────────────
// Regression cover for the object-time expiry gap: expiry was evaluated ONLY
// against `object.created_at_ms`, a caller-supplied field. A caller able to
// choose that value also chose the instant its own expiry check ran.

// A grant that expired at epoch ms 1000 (1970).
const staleGrant = buildGrant({
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: 1000,
})
// An object BACKDATED to before that expiry — the attack shape.
const backdatedObj: CDRO = {
  ...obj,
  created_at_ms: 500,
  authority: { ...obj.authority!, grant_oid: staleGrant.oid },
}

// W1: documents the DEFAULT (replay) semantics. Without a clock the verifier
// answers "was this authorized when it says it was", and by the object's own
// account it was. This is intentionally still true — it is the reason the
// wall-clock check has to be a separate, explicit gate.
const w1 = verifyAuthority({
  object: backdatedObj, action: 'email.bulk_delete', grant: staleGrant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('W1: backdated object, no now_ms: coverage_ok true (object-time semantics)',
  w1.coverage_ok === true)
ok('W1: backdated object, no now_ms: expiry_checked_at_now false',
  w1.expiry_checked_at_now === false)

// W2: THE FIX. Same inputs, wall clock supplied — the backdating no longer
// helps, because the clock check does not consult created_at_ms at all.
const w2 = verifyAuthority({
  object: backdatedObj, action: 'email.bulk_delete', grant: staleGrant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
  now_ms: 1_800_000_000_000,
})
ok('W2: backdated object + now_ms: coverage_ok false', w2.coverage_ok === false)
ok('W2: backdated object + now_ms: not_expired_at_now false',
  w2.not_expired_at_now === false)
ok('W2: backdated object + now_ms: expiry_checked_at_now true',
  w2.expiry_checked_at_now === true)
ok('W2: backdated object + now_ms: authorized false', w2.authorized === false)
ok('W2: reason names the wall clock',
  w2.reasons.some(r => r.includes('wall-clock')))

// W3: a live grant under a wall clock still authorizes.
const w3 = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
  now_ms: 1_716_840_002_000,
})
ok('W3: live grant + now_ms: authorized true', w3.authorized === true)
ok('W3: live grant + now_ms: expiry_checked_at_now true',
  w3.expiry_checked_at_now === true)
ok('W3: live grant + now_ms: not_expired_at_now true',
  w3.not_expired_at_now === true)

// W4: additive-only. Omitting now_ms must reproduce the prior verdict exactly,
// so no existing caller's result changes.
const w4 = verifyAuthority({
  object: obj, action: 'email.bulk_delete', grant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
})
ok('W4: omitting now_ms leaves authorized unchanged', w4.authorized === w3.authorized)
ok('W4: omitting now_ms reports the clock as NOT consulted',
  w4.expiry_checked_at_now === false)

// W5: an unbounded grant passes the clock check, and reports that it ran —
// "vacuously passed" must be distinguishable from "never tested".
const foreverGrant = buildGrant({ capability_scopes: [{ capability: 'email.*' }] })
const foreverObj: CDRO = {
  ...obj, authority: { ...obj.authority!, grant_oid: foreverGrant.oid },
}
const w5 = verifyAuthority({
  object: foreverObj, action: 'email.bulk_delete', grant: foreverGrant,
  grant_ed25519_pub: edPub, grant_ml_dsa_pub: mlPub,
  now_ms: 1_800_000_000_000,
})
ok('W5: unbounded grant + now_ms: coverage_ok true', w5.coverage_ok === true)
ok('W5: unbounded grant + now_ms: expiry_checked_at_now true',
  w5.expiry_checked_at_now === true)
