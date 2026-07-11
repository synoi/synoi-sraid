# @synoi/sraid

Reference TypeScript implementation of **SRAID (Self-Routing Addressable
Identity Data)** — L0 of the SynOI SRAID Stack. MIT-licensed.

SRAID defines:

- a content-addressed object envelope, the **CDRO** (Canonical Data-Rich Object),
- a deterministic canonical object serializer used as input to hashing and signing,
- a content-derived **OID** (`sha256:` followed by 64 hex chars) over the canonical bytes,
- a hybrid **Ed25519 + ML-DSA-65** signature envelope,
- an **L3 Merkle-DAG lineage** layer (`prev` edge + typed `links[]`), hashed into the OID so a head id commits its whole reachable history, and
- a supersession record, the **SRO** (Supersession Record Object), that links a successor CDRO to its predecessor.

The three legacy supersession mechanisms — the self-asserted `supersedes`
string, the standalone SRO, and the `prev` edge — are unified by the lineage
helpers (`lineageLinks`, `supersededOids`, `latestWins`). `latestWins` resolves
a set of versions to its single head by following the identity-bound `prev`/
`links` edges, giving a verifier a **latest-wins / monotone** rule instead of an
unwitnessed pointer. Given the complete version set, `latestWins` will not name
a superseded object as head; full rollback-replay resistance additionally
requires that the superseding object cannot be withheld, which is a Resolver /
transparency-log property (DESIGN, not yet deployed). The `set_complete` field
on `LatestWinsResult` is the local signal that lets a caller detect an
incomplete (potentially withheld) set.

Higher layers — Vault/Resolver (L1), Inference Broker/Resonance (L2), GAP (L3)
— are built on SRAID objects. This package is intentionally tiny and has no
storage, no HTTP surface, and no governance logic.

## Install

```bash
npm install @synoi/sraid
```

## Minimal example

```ts
import {
  canonicalize,
  oidOf,
  verifySignature,
  validateCdro,
  type CDRO,
  type SignatureEnvelope,
} from '@synoi/sraid'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from 'node:crypto'

// 1. Build a CDRO body and derive its OID.
const body = { capability: 'door.unlock', risk_class: 'B' }
const oid = oidOf(body)                          // sha256:<64 hex chars>

const cdro: CDRO<typeof body> = {
  oid,
  type: 'gap:capability_declaration',
  sraid_version: '2.0',
  tenant_id: 't-home',
  created_at_ms: Date.now(),
  created_by: 'actor:skill:demo',
  body,
}

console.log(validateCdro(cdro))                  // { ok: true, errors: [] }

// 2. Sign the canonical bytes with both Ed25519 and ML-DSA-65.
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

// 3. Verify.
const v = verifySignature({
  canonical,
  envelope,
  ed25519_pub: edPub,
  ml_dsa_pub: mlKeys.publicKey,
})
console.log(v)                                   // { valid: true, reasons: [] }
```

## Surface

```ts
canonicalize(value: unknown): string
oidOf(canonical: unknown): string
oidOfCanonical(canonical: string | Uint8Array): string

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
interface SRO                    { /* supersession record */ }
interface SignatureEnvelope      { ed25519: string; ml_dsa_65: string; signer_kid: string }
```

## Canonical form

The canonical form is recursive JCS-lite JSON:

- primitives via `JSON.stringify`,
- objects emit keys in lexicographic order,
- `undefined` properties are omitted,
- arrays preserve order,
- no whitespace.

This canonical form is a wire contract. **Any byte-level change to the
serializer changes every OID and invalidates every previously-created
signature.** Treat it as frozen for SRAID v1.0; evolve it only via a new,
explicitly versioned canonical profile.

## OID format

```
OID = "sha256:" + lowercase_hex( sha256( canonicalize(content) ) )
```

The hash input is the OBJECT MINUS its own `oid` and `signature` fields, so
signature rotation does not change the OID.

## Why hybrid signatures

SRAID objects are signed with both Ed25519 and ML-DSA-65. The classical
Ed25519 path is fast and ubiquitously verifiable today; the post-quantum
ML-DSA-65 path future-proofs receipts against quantum attacks. `verifySignature`
in this package returns `valid: true` only when BOTH succeed.

## License

MIT — see [`LICENSE`](./LICENSE).
