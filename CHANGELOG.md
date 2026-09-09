# Changelog

## 0.5.0 (2026-09-09)

### SECURITY: signature-list malleability (4.1, denial-of-service half)

`signatures[]` is entirely outside the signed bytes - PAE covers `payloadType`
and `payload` only - and the verifier took the FIRST entry matching an
algorithm. Prepending `{alg:'ed25519', sig:<zeros>}` therefore turned a
cryptographically valid receipt into an INVALID one, without changing the
object's OID or failing any binding check.

Two uses, both bad for a product selling settlement-grade non-repudiation: any
party in the delivery or storage path silently destroys a counterparty's
ability to verify a receipt they hold, with no evidence of tampering; and an
issuer can do it to its own receipt and later claim it never verified.

The verifier now tries EVERY entry for an algorithm and accepts if any
verifies, so extra entries are inert rather than destructive. This weakens
nothing: an attacker still cannot produce a signature that verifies under a key
they do not hold, and DSSE is itself an OR-of-signatures envelope. The SynOI
AND policy is across ALGORITHMS - both ed25519 and ml-dsa-65 must verify - and
is unchanged, with explicit guards pinning that a single algorithm, all-bogus
entries, and a signature over different bytes all still fail.

NO signed bytes change. Both entries fixed identically.

NOT fixed: `keyid` remains unauthenticated and rewritable (4.1b). Binding it
requires committing the ordered {alg, keyid} list into the signed bytes, which
changes the wire format and is out of scope for a non-breaking release.

### SECURITY: base64 malleability (4.3)

`internal/base64-validate.ts` checked alphabet, length modulo 4 and pad
position, but not that the unused trailing bits of the final quantum are zero
(RFC 4648 section 3.5). An Ed25519 signature is 64 bytes, so its encoding ends
in `==` with FOUR free bits: 16 distinct `sig` strings decoded to the same
signature and ALL SIXTEEN verified.

That breaks uniqueness anywhere a SERIALIZED receipt is treated as the identity
of a thing - transparency-log leaves, Merkle batch membership, dedup and
idempotency keys. ML-DSA-65 at 3309 bytes is a multiple of 3, has no padding,
and is unaffected.

The old comment reasoned only about pad POSITION and concluded "no extra check
needed". Position was never the hazard; the free bits were.

### Strict OID validation (4.8)

`validateCdro` checked `oid` and `prev` with `startsWith('sha256:')`, so the
literal string `"sha256:"` passed, as did
`sha256:ceremony-verify-placeholder` - which travelled an entire real
sign-and-verify path undetected in the gateway's key-ceremony script. Both now
use the full `CANONICAL_OID_RE` that `supersedes` already used. The regex is an
allowlist and therefore fail-closed by construction.

BEHAVIOUR CHANGE: an object carrying a non-canonical `oid` or `prev` is now
rejected. That is the point, but it will surface placeholders that previously
passed.

### SECURITY: OID collision via `__proto__` (fixed)

Every published version (0.2.0, 0.3.0, 0.4.0) produces the SAME OID for two
objects with DIFFERENT content, and the binding check every consumer relies on
accepts the polluted one. All are deprecated on npm.

`internal/content-core.ts` built the content core with plain assignment
(`core[k] = v`). For `k === "__proto__"` that invokes the prototype SETTER
rather than creating an own property, so the member was silently dropped from
the core AND the accumulator's prototype became attacker-controlled.
`canonicalize` walks `Object.keys`, which DOES return an own `__proto__` -
exactly what `JSON.parse` produces. Two projections in one library disagreed:

    OID(clean) === OID(clean + __proto__)                    -> true
    canonicalize(core(clean)) === canonicalize(core(evil))   -> true   (binding bypass)
    cdroContentCore(evil).escalated                          -> true   (pollution lands)

The binding bypass is what made it serious rather than tidy. Nine to eleven
production call sites each independently guard with
`att.payload === canonicalize(cdroContentCore(x))`; both sides dropped the
member identically, so a polluted object passed the binding check, passed
`validateCdro`, carried the correct OID, and smuggled an arbitrary unsigned,
unhashed member past the defence in depth.

**The rule is REJECT.** An own `__proto__` member is not a legal CDRO content
key. `canonicalize` throws; `validateCdro` returns `[E17]` and returns early.
A rejected object has no canonical form, so there is nothing to collide with.

Hashing it instead would also close the collision and would match what non-JS
SDKs do naturally, but it leaves a member inside signed bytes that much of the
JS ecosystem mishandles. Reject is the only rule that cannot be implemented
inconsistently across languages.

**SHALLOW, deliberately.** The collision is structurally top-level: the
projection iterates only the envelope's own keys, and a nested `__proto__`
inside `body` does NOT collide (canonicalize serialises `body` as a value, so
the member survives - vector P-04). `body` is application-defined content per
SPEC section 7, so recursively policing its keys would be this layer
legislating over application data, at the cost of a full walk on every
canonicalize.

`cdroContentCore` now builds via `Object.fromEntries`, which uses
CreateDataProperty and therefore defines an own property instead of invoking a
setter. That is defence in depth, not the primary control: a caller who never
validates still cannot be handed a prototype-polluted object.

**Scoped precisely.** Only `__proto__` is affected. `constructor` and
`prototype` are ordinary own properties under plain assignment and continue to
be hashed - vectors P-06 and P-07 are negative controls guarding against an
over-broad fix.

Cross-language: an SDK derived from `PROJECTION_SPEC.md` treats `__proto__` as
an ordinary key and computes a DIFFERENT OID for the same bytes. That interop
split had no vector until now. `PROJECTION_SPEC.md` section 2 states the rule
normatively.

Vectors: `test/vectors/proto-pollution.json`, stored as raw JSON text so the
cases lift into synoi-conformance unchanged. 16 assertions; 9 failed before the
fix.

### `bodyOid(cdro)` - the payload id

Additive. One new function on each entry, no wire change, no format change, no
change to any existing id or signature.

`cdroOid` is ISSUANCE-addressed. Its input keeps `tenant_id`, `created_at_ms`
and `created_by`, so the same payload recorded twice - a millisecond apart, or
by two tenants - yields two unrelated OIDs:

    same body, t=1000       sha256:0fbe669f...
    same body, t=1001       sha256:b9bcccf7...
    same body, other tenant sha256:9f535fc0...

That is correct for a receipt: a CDRO attests that THIS actor recorded THIS
content at THIS time, and two such acts are two different events. But it means
`cdroOid` cannot answer "have I seen this payload before?" - not slowly, at
all. Dedup, idempotency keys, replay detection, cache keys and "is this the
same record that tenant already sent us" had no id to key on.

`bodyOid` is the complement: `oidOf` over `body` alone, invariant across the
actor, the timestamp and the tenant.

    cdroOid(obj)   this issuance - identity of the recording act
    bodyOid(obj)   this payload  - identity of the content recorded

Use `bodyOid` for dedup and cache keys. Use `cdroOid` for anything signed,
cited or linked. Never substitute one for the other: `bodyOid` deliberately
hashes nothing but the body, which is what makes it useful and what makes it
wrong as an identity.

DERIVED, NOT STORED. This is a function over an object you already hold, not a
new envelope field. A stored `body_oid` would be a second assertion that could
disagree with the body beside it, and redundant data inside a signed envelope
is a liability. Computing it costs one canonicalization and cannot lie. That
also makes this release non-breaking: no existing object changes, and nothing
needs re-signing.

LIMIT, stated rather than papered over: this needs the body. An object whose
body is absent or encrypted cannot be payload-addressed by a holder who cannot
read it. That case wants a signed field, not a derivation, and is deliberately
not solved here.

Available on both entries - `bodyOid` (sync) from the node entry, `bodyOid`
(async, WebCrypto) from `./verify-browser`, byte-identical for the same input
and pinned by a parity assertion in `test/body-oid.test.ts`.

## 0.4.0 (2026-09-04)

BREAKING. Two removals from the public surface. **No change to the canonical
serializer, the OID projection, the strip set, or any signature behaviour** - an
object that verified under 0.3.x verifies byte-identically here. What changes is
what this package CLAIMS to be.

### Removed: the standalone SRO

`SRO`, `SROBody` and `validateSro` are gone. The SRO (`type: 'sraid:sro'`) was
the third of three overlapping supersession mechanisms and the only one nothing
consumed: `lineage.ts` never handled it, no repo in the SynOI stack referenced it
in any language (TypeScript, Kotlin or Swift), and the canon had already retired
the term (ADR_022 section 0: "an earlier, retired object-format term").

Supersession is now exactly two things, both identity-bound because
`cdroContentCore` hashes them: the `prev`/`links[]` Merkle edges, resolved with
`latestWins`, and the legacy self-asserted `supersedes` string. A caller
recording WHY something was superseded should put that in the successor's own
`body`, where it is hashed and signed, rather than in a separate object whose
linkage was never verified.

### Moved: grant and delegation-chain verification

`verifyAuthority`, `verifyDelegationChain` and `MAX_DELEGATION_DEPTH` are no
longer exported from the core entry. They are authorization policy, not object
identity, and the core entry's own docstring claimed "no governance" while
exporting them.

They are GONE from this package entirely - no subpath, no bridge, no duplicate
copy. They live in `@synoi/authority-verify`, which depends on this package.

An earlier draft of this release kept a `@synoi/sraid/authority` bridge. That
was dropped: it meant shipping two copies of the same ~1000-line
security-relevant module in two repos, which drift. A clean cut is safer than a
deprecation window for a file nothing in production called.

**`capabilityCovers`, `AuthorityResolver` and `GrantStatus` did NOT move.** They
are a pure string predicate and a live-status contract - the leaf pieces a grant
store needs without pulling in a verifier - and now live in `src/capability.ts`,
still exported from the core entry. `synoi-app` imports them at two production
call sites; those imports are unaffected.

### Migration

| 0.3.x | 0.4.0 |
|---|---|
| `import { verifyAuthority } from '@synoi/sraid'` | `from '@synoi/authority-verify'` |
| `import { verifyDelegationChain } from '@synoi/sraid'` | `from '@synoi/authority-verify'` |
| `import { capabilityCovers } from '@synoi/sraid'` | unchanged |
| `import type { GrantStatus } from '@synoi/sraid'` | unchanged |
| `validateSro`, `SRO`, `SROBody` | removed, no replacement |

### Also

- The core entry docstring no longer describes the package by stack layer
  numbers (L0-L4), which were meaningless outside this repo. It now states scope
  directly, including the limit that matters: this package verifies SIGNATURES,
  NOT IDENTITIES. `signer_kid` is an opaque string nothing here resolves, and
  nothing checks revocation.
- README and SPEC.md updated for both removals.
- The acronym is no longer expanded. GitHub said "Signed Runtime-Agnostic
  Identity/Attestation Definition"; package.json said "Self-Routing Addressable
  Identity Data". Two expansions in two places, neither adding meaning, and the
  name had already flip-flopped once (ADR_020 records sraid-oid.ts to
  cof-oid.ts and back). SRAID is now a bare proper noun with a one-line
  functional description in its place.

## 0.3.1 (2026-09-04)

Documentation and type-comment fix. **No code path, wire format, canonical serializer, OID
projection, or signature behaviour changes in this release.** An object that verified under 0.3.0
verifies byte-identically here.

The README's minimal example derived a CDRO's `oid` with `oidOf(body)`, which hashes only the body.
A CDRO's identity is `cdroOid`, over the whole content core (the object minus the six detached
envelope fields). The two differ, and `validateCdro` does not catch the difference because it is a
shape check and never recomputes the hash — so the documented example produced an object whose
stamped `oid` was not its identity, and reported `{ ok: true, errors: [] }`.

- README: the minimal example now derives identity with `cdroOid` and signs through the DSSE
  attestation path (`pae` + `verifyAttestation`), which binds `payloadType` into the signed bytes.
  The legacy bare-bytes `verifySignature` / `SignatureEnvelope` remain exported and unchanged, but
  are no longer what the example teaches.
- README: `cdroOid`, `cdroContentCore`, `CDRO_ENVELOPE_FIELDS`, `verifyAttestation` and `pae` were
  exported but missing from the Surface section, so the correct identity function was undiscoverable
  from the landing page. Added.
- README: the OID section listed only `oid` and `signature` as stripped; it now names all six
  `CDRO_ENVELOPE_FIELDS` and states that `authority`, `sensitivity`, `prev`, `links` and
  `supersedes` are hashed and therefore identity-bound.
- README: the canonical form was described as "JCS-lite". It is a strict RFC 8785 profile tested
  against the RFC 8785 vectors; described as such, with the test named.
- README: the frozen-profile note said "SRAID v1.0". The protocol version is 2.0.
- `src/types.ts`: the `CDRO` docstring and the `oid` field comment repeated the same
  `canonicalize(body)` error. Both now point at `cdroContentCore` / `cdroOid`. Comments only; no
  type or runtime change.
- `src/lineage.ts`: the `lineageLinks` dedup key used a RAW U+0000 byte as its separator,
  written literally into the source rather than as the `backslash-u-0000` escape. That single byte made
  the file `data` rather than text, so git treated it as binary (no reviewable diffs) and
  grep/ripgrep skipped it entirely - the file was invisible to every grep-based review of this
  repo, and it ships in `src/` to npm. Replaced with the escape. The emitted JS still contains
  exactly one U+0000 separator, so the runtime string and all dedup behaviour are unchanged.

- `test/readme-example.test.ts`: previously asserted only `validateCdro().ok` and
  `verifySignature().valid`, so it passed while the example was wrong. It now asserts the identity
  invariant (`cdro.oid === cdroOid(cdro)`, preserved across attestation) and carries an explicit
  regression guard proving `oidOf(body) !== cdroOid(cdro)`. Its header also claimed it was excluded
  from `npm test`; `test/run-all.ts` globs every `*.test.ts`, so it always ran — the comment was
  wrong, not the wiring.

## 0.3.0 (2026-08-04)

Additive, no wire change. Nothing about the signed bytes, the OID projection, or the canonical
serializer moves in this release; an object that verified under 0.2.0 verifies identically here.

The one user-visible change is a NEW export subpath, `@synoi/sraid/verify-browser`. The default (`.`)
entry statically imports `node:crypto` in three places (`ed25519.ts`, `mldsa.ts`, `oid.ts`), so
`import '@synoi/sraid'` breaks any browser, service-worker, or Chrome-extension bundle. The new
subpath carries exactly what a v2 hybrid DSSE receipt verifier needs, with no static `node:crypto`
import anywhere in its graph:

- `verifyAttestation` - hybrid DSSE verify, Ed25519 AND ML-DSA-65 both required over the PAE. ASYNC
  here, because WebCrypto Ed25519 verify is Promise-based. Identical envelope shape, AND policy, PAE
  bytes and reason strings as the node entry.
- `cdroOid`, `oidOf`, `oidOfCanonical` - OID helpers over WebCrypto SHA-256. ASYNC for the same
  reason. Byte-identical results to the node entry for the same input.
- `canonicalize`, `cdroContentCore`, `CDRO_ENVELOPE_FIELDS`, `pae`, `ALG_ED25519`, `ALG_ML_DSA_65` -
  pure, shared byte-for-byte with the node entry via `internal/content-core` and
  `internal/attestation-core`.

Crypto backends, since browsers have no native ML-DSA and no `node:crypto`: Ed25519 verify on
WebCrypto (RFC 8032 cofactored, matching the node path) with a `@noble/curves` fallback below the
WebCrypto-Ed25519 support floor; ML-DSA-65 verify on `@noble/post-quantum`; SHA-256 on WebCrypto
`subtle.digest`.

The node default entry is unchanged and stays synchronous with its `node:crypto` fast paths. The only
surface difference is that the four functions above return Promises on the browser entry.

Also: `prepublishOnly` now runs `build` then `test`. `dist/` is gitignored and the tarball ships it,
so a publish previously depended on whatever happened to be in the working tree.

Source for this subpath merged to `main` on 2026-07-18 at `5433120` / `33ebf7f`, twelve days after
0.2.0 was cut, which is why 0.2.0 on the registry exports only `.` and `./canonicalize`.

## 0.2.0 (2026-07-05)

BREAKING (wire): migrates the L0 SRAID identifiers off the retired `cof` namespace onto `sraid`, per ADR_020 (internal).

Note on versioning: the PACKAGE version bumps `0.1.0` -> `0.2.0` (minor, pre-1.0 semver). The PROTOCOL version string carried on the wire bumps `1.0` -> `2.0` (major, because the signed bytes change). These two numbers are intentionally different: the package is still pre-1.0 and this is not treated as a package-major event, but the wire protocol version is self-describing and must jump a major so a downgrade is detectable at validate time ([E05]).

This is a CLEAN CUTOVER, no dual-accept. An object carrying the old `cof_version` key or the retired `sraid_version: '1.0'` value fails closed at [E05].

Changes:
- `type: 'cof:sro'` -> `type: 'sraid:sro'` (the SRO type discriminator).
- Signed field key `cof_version` -> `sraid_version`.
- Signed field value `'1.0'` -> `'2.0'` (the only defined `sraid_version` value).
- Serialization profile id `cof/json` -> `sraid/json` (SPEC.md, normative canonical format for v1.0).
- Serialization profile id `cof/cbor` -> `sraid/cbor` (SPEC.md, reserved binary profile).
- Stale prose examples `agp:capability_grant` / `agp:capability_declaration` in SPEC.md, README.md, and test fixtures updated to `gap:...` (the `agp:` -> `gap:` wire migration itself already shipped under ADR_007; these were leftover prose/test literals, not a new wire change).
- `PROJECTION_SPEC.md` keystone example (pre- vs post-attestation OID invariance) updated: field renamed and the pinned reference OID recomputed against the new bytes.
- Test-intent fix in `test/validate.test.ts`: the [E05] "wrong value" case previously asserted that `cof_version: '2.0'` (now the CORRECT value) was rejected. It now asserts the RETIRED value `sraid_version: '1.0'` is rejected, and separately that the retired key `cof_version` (with `sraid_version` absent) is rejected, preserving the original intent that a downgrade/legacy-key attempt must fail-closed.

Every SRAID/GAP-receipt OID and signature changes as a result of this migration. Bounded blast radius: only conformance test-key fixtures carry these bytes; there is no production-signed corpus (verified, see ADR_020 Section 8).
