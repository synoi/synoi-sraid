# @synoi/sraid

Reference TypeScript implementation of **SRAID**, the SynOI content-addressed
object format. MIT-licensed.

SRAID is a name, not an acronym. It has been expanded two different ways in two
different places; neither expansion added anything, so this package no longer
expands it. What it does is below.

SRAID defines:

- a content-addressed object envelope, the **CDRO** (Canonical Data-Rich Object),
- a deterministic canonical object serializer used as input to hashing and signing,
- a content-derived **OID** (`sha256:` followed by 64 hex chars) over the canonical bytes,
- a hybrid **Ed25519 + ML-DSA-65** signature envelope,
- a **Merkle-DAG lineage** layer (`prev` edge + typed `links[]`), hashed into the OID so a head id commits its whole reachable history.

Supersession is expressed by two things, both identity-bound because
`cdroContentCore` hashes them: the `prev`/`links[]` Merkle edges, and the legacy
self-asserted `supersedes` string. `latestWins` resolves a version set to its
single head by following the identity-bound edges, giving a verifier a
**latest-wins / monotone** rule instead of an unwitnessed pointer. Given the
complete version set it will not name a superseded object as head; full
rollback-replay resistance additionally requires that the superseding object
cannot be withheld, which is a Resolver / transparency-log property (DESIGN, not
yet deployed). `set_complete` on `LatestWinsResult` is the local signal letting a
caller detect an incomplete (potentially withheld) set.

The standalone **SRO** was removed in 0.4.0 — see the CHANGELOG.

This package is object identity: canonical bytes, OIDs, hybrid signature
verification, lineage. It has no storage, no HTTP surface, and no policy.

It verifies **signatures, not identities**: `signer_kid` is an opaque string this
package never resolves, and nothing here checks revocation. Deciding whether a
key was trusted at signing time needs a key directory, which is a caller
concern.

## Install

```bash
npm install @synoi/sraid
```

## Minimal example

```ts
import {
  canonicalize,
  cdroOid,
  cdroContentCore,
  pae,
  verifyAttestation,
  validateCdro,
  type AttestationEnvelope,
  type CDRO,
} from '@synoi/sraid'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from 'node:crypto'

// 1. Build the CDRO content core: every field EXCEPT the detached
//    envelope fields (oid, signature, attestation, ...).
const core = {
  type: 'gap:capability_declaration',
  sraid_version: '2.0' as const,
  tenant_id: 't-home',
  created_at_ms: Date.now(),
  created_by: 'actor:skill:demo',
  body: { capability: 'door.unlock', risk_class: 'B' },
}

// 2. Identity is the hash of the WHOLE content core, not just the body.
//    Use cdroOid(core) — NOT oidOf(core.body).
const cdro: CDRO<typeof core.body> = { oid: cdroOid(core), ...core }

console.log(validateCdro(cdro))            // { ok: true, errors: [] }
console.log(cdro.oid === cdroOid(cdro))    // true

// 3. Sign the canonical content core through the DSSE PAE, which binds
//    payloadType into the signed bytes (prevents cross-type replay).
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

// 4. Attaching the attestation does NOT change identity — the six detached
//    envelope fields are stripped before hashing.
const attested = { ...cdro, attestation }
console.log(cdroOid(attested) === cdro.oid) // true

// 5. Verify. `valid` is true only when BOTH signatures verify over the PAE.
const v = verifyAttestation({
  envelope: attestation,
  ed25519_pub: edPub,
  ml_dsa_pub: mlKeys.publicKey,
  expectedPayloadType: payloadType,
})
console.log(v)                             // { valid: true, reasons: [] }
```

> **Identity is over the content core, not the body.** `oidOf(cdro.body)` is
> *not* a CDRO's OID; use `cdroOid`. `verifySignature` / `SignatureEnvelope`
> (bare-bytes, no payload-type binding) remain exported for compatibility but
> are superseded by the attestation path above.

## Surface

```ts
canonicalize(value: unknown): string

// CDRO identity — hash the content core. THIS is an object's OID.
cdroOid(cdro: unknown): string
cdroContentCore(cdro: unknown): Record<string, unknown>
CDRO_ENVELOPE_FIELDS: readonly string[]   // the six stripped fields

// Value-level hashing. oidOf(cdro.body) is NOT the CDRO's OID.
oidOf(canonical: unknown): string
oidOfCanonical(canonical: string | Uint8Array): string

// DSSE attestation — payload-type bound, both signatures required.
verifyAttestation(input): { valid: boolean; reasons: string[] }
pae(payloadType: string, payload: string | Uint8Array): Uint8Array

verifySignature(args: {
  canonical:   string | Uint8Array
  envelope:    SignatureEnvelope
  ed25519_pub: Uint8Array
  ml_dsa_pub:  Uint8Array
}): { valid: boolean; reasons: string[] }

validateCdro(x: unknown): { ok: boolean; errors: string[] }
validateSro(x: unknown): { ok: boolean; errors: string[] }
validateSignatureEnvelope(x: unknown): { ok: boolean; errors: string[] }

// Types
interface CDRO<TBody>            { /* envelope */ }
interface SignatureEnvelope      { ed25519: string; ml_dsa_65: string; signer_kid: string }
```

## Browser, Chrome extension, service worker

The default (`.`) entry statically imports `node:crypto` in three places
(`ed25519.ts`, `mldsa.ts`, `oid.ts`), so `import '@synoi/sraid'` breaks any
browser bundle. Import the `./verify-browser` subpath instead. It carries exactly
what a v2 hybrid DSSE receipt verifier needs, with no static `node:crypto`
anywhere in its graph.

```ts
import { verifyAttestation, canonicalize, cdroContentCore } from '@synoi/sraid/verify-browser'

const v = await verifyAttestation({
  envelope:            receipt.attestation,
  ed25519_pub,                                   // raw 32 bytes
  ml_dsa_pub,                                    // raw 1952 bytes
  expectedPayloadType: 'application/vnd.synoi.gap+json',
})
// { valid: true, reasons: [] } only when BOTH signatures verify over the PAE
```

```ts
// The subpath surface. Four of these are ASYNC where the node entry is sync,
// because WebCrypto is Promise-based. Everything else is shared byte-for-byte
// with the node entry, so the two agree on the same input.
verifyAttestation(input): Promise<{ valid: boolean; reasons: string[] }>   // ASYNC
cdroOid(cdro: unknown): Promise<string>                                    // ASYNC
oidOf(canonical: unknown): Promise<string>                                 // ASYNC
oidOfCanonical(canonical: string | Uint8Array): Promise<string>            // ASYNC

canonicalize(value: unknown): string          // pure, identical to the node entry
cdroContentCore(cdro: unknown): Record<string, unknown>
pae(payloadType: string, payload: string | Uint8Array): Uint8Array
CDRO_ENVELOPE_FIELDS: readonly string[]
ALG_ED25519, ALG_ML_DSA_65
```

Crypto backends, since browsers have no native ML-DSA and no `node:crypto`:
Ed25519 verify on WebCrypto (RFC 8032 cofactored, matching the node path) with a
`@noble/curves` fallback below the WebCrypto-Ed25519 support floor; ML-DSA-65
verify on `@noble/post-quantum`; SHA-256 on WebCrypto `subtle.digest`.

The node default entry is unchanged and keeps its synchronous `node:crypto` fast
paths. This subpath is purely additive. Added in 0.3.0; earlier versions export
only `.` and `./canonicalize`.

## Authority verification

Capability-grant and delegation-chain verification is NOT in this package. It is
authorization policy, not object identity, and it moved to
[`@synoi/authority-verify`](https://github.com/synoi/synoi-authority-verify) in
0.4.0.

`capabilityCovers`, `AuthorityResolver` and `GrantStatus` did NOT move - they are
a pure string predicate and a live-status contract, and remain in the surface
above.

## Canonical form

The canonical form is a strict RFC 8785 (JCS) profile, tested against the
RFC 8785 vectors (`test/rfc8785-conformance.test.ts`):

- primitives via `JSON.stringify`,
- objects emit keys in lexicographic order,
- `undefined` properties are omitted,
- arrays preserve order,
- no whitespace.

This canonical form is a wire contract. **Any byte-level change to the
serializer changes every OID and invalidates every previously-created
signature.** Treat it as frozen for SRAID v2.0; evolve it only via a new,
explicitly versioned canonical profile.

## OID format

```
OID = "sha256:" + lowercase_hex( sha256( canonicalize(content) ) )
```

The hash input is the object MINUS the six detached envelope fields
(`oid`, `signature`, `ml_dsa_signature`, `signature_key_id`,
`signature_algorithm`, `attestation`) — see `CDRO_ENVELOPE_FIELDS`. Everything
else is hashed, including `authority`, `sensitivity`, `prev`, `links` and
`supersedes`, so those are identity-bound and cannot be silently stripped.
Signing or rotating a signature never changes the OID.

## Why hybrid signatures

SRAID objects are signed with both Ed25519 and ML-DSA-65. The classical
Ed25519 path is fast and ubiquitously verifiable today; the post-quantum
ML-DSA-65 path future-proofs receipts against quantum attacks. `verifySignature`
in this package returns `valid: true` only when BOTH succeed.

## License

MIT, see [`LICENSE`](./LICENSE).
