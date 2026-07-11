/**
 * test/delegation-chain.test.ts — K2: verifyDelegationChain (verify-only).
 *
 * Builds REAL signed grant CDROs carrying hybrid DSSE attestations and
 * exercises the offline delegation-chain verifier against genuine crypto.
 *
 * Scope is verify-only (no enforcement, no resolver): every result MUST
 * report revocation_checked === false and existence_checked === false. The
 * function is synchronous and offline — caller supplies ancestors and the
 * per-link verifier keys, the verifier never fetches anything.
 *
 * The gate, in order (depth checked BEFORE any crypto):
 *   0. depth cap (<= MAX_DELEGATION_DEPTH)
 *   1. OID hash-honesty, every link
 *   2. per-hop structure: granted_by linkage, scope attenuation, expiry narrowing
 *   3. hybrid DSSE signature, every link (both ed25519 + ml-dsa-65)
 *   4. root anchor: terminal link signer key == rootPubkeys
 */

import { webcrypto, randomBytes } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { cdroOid, cdroContentCore } from '../src/oid.js'
import { pae } from '../src/attestation.js'
import {
  verifyDelegationChain,
  MAX_DELEGATION_DEPTH,
  type LinkPubkeys,
} from '../src/authority.js'
import type { GrantBodyShape } from '../src/authority.js'
import type { CDRO, AttestationEnvelope } from '../src/types.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

const toB64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')
const GRANT_PT = 'application/vnd.synoi.sraid+json'

// ── A signing principal: a hybrid (ed25519 + ml-dsa-65) keypair ──────────────
interface Principal {
  edPriv: Uint8Array
  edPub: Uint8Array
  mlPub: Uint8Array
  mlSecret: Uint8Array
  actor_oid: string
}
function newPrincipal(tag: string): Principal {
  const edPriv = new Uint8Array(randomBytes(32))
  const edPub = ed25519.getPublicKey(edPriv)
  const ml = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
  return {
    edPriv, edPub, mlPub: ml.publicKey, mlSecret: ml.secretKey,
    actor_oid: 'sha256:' + Buffer.from(tag.padEnd(32, tag[0] ?? 'a')).toString('hex').slice(0, 64).padEnd(64, '0'),
  }
}

// ── Build a real signed grant CDRO with a hybrid DSSE attestation ────────────
// issuer signs; grantee is the actor the grant is issued to.
function buildGrant(
  issuer: Principal,
  body: GrantBodyShape & Record<string, unknown>,
  createdMs = 1716840000000,
): CDRO<GrantBodyShape> {
  const core = {
    type: 'gap:capability_grant',
    sraid_version: '2.0' as const,
    tenant_id: 'acme-prod',
    created_at_ms: createdMs,
    created_by: issuer.actor_oid,
    body,
  }
  const oid = cdroOid(core)
  const payload = canonicalize(cdroContentCore(core))
  const message = pae(GRANT_PT, payload)
  const attestation: AttestationEnvelope = {
    payloadType: GRANT_PT,
    payload,
    signatures: [
      { alg: 'ed25519', sig: toB64(ed25519.sign(message, issuer.edPriv)) },
      { alg: 'ml-dsa-65', sig: toB64(ml_dsa65.sign(message, issuer.mlSecret)) },
    ],
  }
  return { ...core, oid, attestation } as CDRO<GrantBodyShape>
}

const pub = (p: Principal): LinkPubkeys => ({ ed25519: p.edPub, ml_dsa: p.mlPub })

// ── Principals: root issues to A, A issues to B, B issues to leaf-holder ──────
const root = newPrincipal('root')
const a = newPrincipal('actA')
const b = newPrincipal('actB')

// root -> A : email.*  (unbounded expiry)
const grantA = buildGrant(root, {
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: null,
  granted_by: root.actor_oid,
  grantee: { actor_oid: a.actor_oid },
  parent_grant_oid: null,
})
// A -> B : email.read  (bounded)
const grantB = buildGrant(a, {
  capability_scopes: [{ capability: 'email.read' }],
  expires_at_ms: 1816840000000,
  granted_by: a.actor_oid,
  grantee: { actor_oid: b.actor_oid },
  parent_grant_oid: grantA.oid,
})
// B -> leaf : email.read (narrower-or-equal expiry)
const leaf = buildGrant(b, {
  capability_scopes: [{ capability: 'email.read' }],
  expires_at_ms: 1716900000000,
  granted_by: b.actor_oid,
  grantee: { actor_oid: 'sha256:' + 'c'.repeat(64) },
  parent_grant_oid: grantB.oid,
})

// links order is leaf -> ... -> root, so ancestors = [grantB, grantA].
const validInput = {
  leaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
}

// ── 1. valid 3-hop chain ─────────────────────────────────────────────────────
const v = verifyDelegationChain(validInput)
ok('valid chain: authorized', v.authorized === true, JSON.stringify(v.reasons))
ok('valid chain: depth 3', v.depth === 3)
ok('valid chain: depth_ok', v.depth_ok)
ok('valid chain: links_ok', v.links_ok)
ok('valid chain: attenuation_ok', v.attenuation_ok)
ok('valid chain: expiry_ok', v.expiry_ok)
ok('valid chain: signatures_ok + checked', v.signatures_ok && v.signatures_checked)
ok('valid chain: oids_ok', v.oids_ok)
ok('valid chain: root_ok', v.root_ok)
// HONESTY invariant: verify-only never asserts a live claim.
ok('valid chain: revocation_checked false', v.revocation_checked === false)
ok('valid chain: existence_checked false', v.existence_checked === false)
ok('valid chain: not_revoked false', v.not_revoked === false)

// ── 2. single-hop chain equals single-grant semantics ────────────────────────
const single = buildGrant(root, {
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: null,
  granted_by: root.actor_oid,
  grantee: { actor_oid: a.actor_oid },
  parent_grant_oid: null,
})
const oneHop = verifyDelegationChain({
  leaf: single,
  ancestors: [],
  linkPubkeys: [pub(root)],
  rootPubkeys: pub(root),
})
ok('single-hop: authorized', oneHop.authorized === true, JSON.stringify(oneHop.reasons))
ok('single-hop: depth 1', oneHop.depth === 1)
ok('single-hop: root_ok', oneHop.root_ok)

// ── 3. scope-escalation: child widens parent ─────────────────────────────────
// child leaf claims email.* (wider) under parent grantB email.read (narrower)
const wideLeaf = buildGrant(b, {
  capability_scopes: [{ capability: 'email.*' }],
  expires_at_ms: 1716900000000,
  granted_by: b.actor_oid,
  grantee: { actor_oid: 'sha256:' + 'c'.repeat(64) },
  parent_grant_oid: grantB.oid,
})
const esc = verifyDelegationChain({
  leaf: wideLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('scope-escalation: attenuation_ok false', esc.attenuation_ok === false)
ok('scope-escalation: not authorized', esc.authorized === false)

// ── 4. broken signer link: child.granted_by != parent.grantee.actor_oid ──────
// leaf claims to be granted by the WRONG actor (root, not B).
const wrongParentLeaf = buildGrant(b, {
  capability_scopes: [{ capability: 'email.read' }],
  expires_at_ms: 1716900000000,
  granted_by: root.actor_oid, // should be b.actor_oid to chain under grantB
  grantee: { actor_oid: 'sha256:' + 'c'.repeat(64) },
  parent_grant_oid: grantB.oid,
})
const broken = verifyDelegationChain({
  leaf: wrongParentLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('broken-signer-link: links_ok false', broken.links_ok === false)
ok('broken-signer-link: not authorized', broken.authorized === false)

// ── 5a. expiry-widening: numeric child > parent ──────────────────────────────
const lateLeaf = buildGrant(b, {
  capability_scopes: [{ capability: 'email.read' }],
  expires_at_ms: 1916840000000, // later than grantB's 1816840000000
  granted_by: b.actor_oid,
  grantee: { actor_oid: 'sha256:' + 'c'.repeat(64) },
  parent_grant_oid: grantB.oid,
})
const late = verifyDelegationChain({
  leaf: lateLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('expiry-widening (numeric): expiry_ok false', late.expiry_ok === false)
ok('expiry-widening (numeric): not authorized', late.authorized === false)

// ── 5b. expiry-widening: null child under bounded parent ─────────────────────
const unboundedLeaf = buildGrant(b, {
  capability_scopes: [{ capability: 'email.read' }],
  expires_at_ms: null, // unbounded under grantB's bounded expiry == widening
  granted_by: b.actor_oid,
  grantee: { actor_oid: 'sha256:' + 'c'.repeat(64) },
  parent_grant_oid: grantB.oid,
})
const unbounded = verifyDelegationChain({
  leaf: unboundedLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('expiry-widening (null child/bounded parent): expiry_ok false', unbounded.expiry_ok === false)
ok('expiry-widening (null child): not authorized', unbounded.authorized === false)

// ── 6. forged/unknown root: terminal signer != rootPubkeys ───────────────────
const forgedRoot = newPrincipal('frgd')
const forged = verifyDelegationChain({
  ...validInput,
  rootPubkeys: pub(forgedRoot),
})
ok('forged-root: root_ok false', forged.root_ok === false)
ok('forged-root: not authorized', forged.authorized === false)

// ── 7. tampered link body under fixed OID ────────────────────────────────────
const tamperedLeaf = {
  ...leaf,
  body: { ...leaf.body, capability_scopes: [{ capability: 'email.read' }], extra: 'mutated' },
} as CDRO<GrantBodyShape>
const tampered = verifyDelegationChain({
  leaf: tamperedLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('tampered-link-body: oids_ok false', tampered.oids_ok === false)
ok('tampered-link-body: not authorized', tampered.authorized === false)

// ── 8. depth exceeded: 9-hop chain rejected pre-crypto ───────────────────────
// Build a long chain of self-consistent grants (structure does not matter:
// depth gate must fire BEFORE any crypto work).
function fillerGrant(): CDRO<GrantBodyShape> {
  return buildGrant(root, {
    capability_scopes: [{ capability: 'email.read' }],
    expires_at_ms: null,
    granted_by: root.actor_oid,
    grantee: { actor_oid: a.actor_oid },
    parent_grant_oid: null,
  })
}
const nineAncestors = Array.from({ length: 8 }, () => fillerGrant()) // leaf + 8 = depth 9
const deep = verifyDelegationChain({
  leaf,
  ancestors: nineAncestors,
  linkPubkeys: Array.from({ length: 9 }, () => pub(root)),
  rootPubkeys: pub(root),
})
ok('depth-exceeded: depth 9', deep.depth === 9)
ok('depth-exceeded: depth_ok false', deep.depth_ok === false)
ok('depth-exceeded: not authorized', deep.authorized === false)
ok('depth-exceeded: cap is 8', MAX_DELEGATION_DEPTH === 8)
// pre-crypto guard: no signature work attempted on an over-depth chain.
ok('depth-exceeded: signatures_checked false (no crypto run)', deep.signatures_checked === false)
ok('depth-exceeded: reason names the cap', deep.reasons.some(r => /depth/.test(r) && /8/.test(r)))

// ── 9. ml-dsa stripped mid-chain ─────────────────────────────────────────────
// Remove the ml-dsa-65 signature from grantB's attestation: hybrid AND fails.
const strippedB: CDRO<GrantBodyShape> = {
  ...grantB,
  attestation: {
    ...grantB.attestation!,
    signatures: grantB.attestation!.signatures.filter(s => s.alg !== 'ml-dsa-65'),
  },
}
const stripped = verifyDelegationChain({
  leaf,
  ancestors: [strippedB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('ml-dsa-stripped: signatures_ok false', stripped.signatures_ok === false)
ok('ml-dsa-stripped: not authorized', stripped.authorized === false)

// ── 10. missing attestation entirely -> signatures_checked false ─────────────
const noAttLeaf = { ...leaf } as CDRO<GrantBodyShape>
delete (noAttLeaf as Record<string, unknown>).attestation
const noAtt = verifyDelegationChain({
  leaf: noAttLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('missing-attestation: signatures_checked false', noAtt.signatures_checked === false)
ok('missing-attestation: not authorized', noAtt.authorized === false)

// ── 11. payload-swap guard: attestation.payload != link content core ─────────
const swappedPayloadLeaf: CDRO<GrantBodyShape> = {
  ...leaf,
  attestation: { ...leaf.attestation!, payload: canonicalize({ not: 'the core' }) },
}
const swapped = verifyDelegationChain({
  leaf: swappedPayloadLeaf,
  ancestors: [grantB, grantA],
  linkPubkeys: [pub(b), pub(a), pub(root)],
  rootPubkeys: pub(root),
})
ok('payload-swap: signatures_ok false', swapped.signatures_ok === false)
ok('payload-swap: not authorized', swapped.authorized === false)

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
