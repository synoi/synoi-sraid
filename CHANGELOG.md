# Changelog

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
