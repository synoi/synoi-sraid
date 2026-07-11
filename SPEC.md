# SRAID - Self-Routing Addressable Identity Data, Core Object Specification

**Core Specification, Version 1.0**

> To the extent possible under law, SynOI Inc. has waived all copyright and related rights to this specification under the Creative Commons CC0 1.0 Universal Public Domain Dedication (https://creativecommons.org/publicdomain/zero/1.0/). The reference implementation `@synoi/sraid` is MIT-licensed; the conformance suite `@synoi/conformance` is Apache-2.0-licensed.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this document are to be interpreted as described in RFC 2119.

---

## 1. Overview

SRAID defines a **canonical, content-addressed object** (serialized in a canonical object format) and its **object identifier (OID)**. The goals are:

- **Determinism.** The same content yields the same canonical bytes and the same OID on any implementation.
- **Content addressing.** An object's identity is derived from its content, so identical content deduplicates and any party can recompute and check an OID.
- **Independent verification.** An object carries its own signatures, so a third party can verify authenticity offline, without contacting the issuer.

SRAID Core is intentionally small. It specifies the object envelope, the canonical form, the OID, and the signature requirement. Higher-level concerns (storage, retrieval, access control) are out of scope and are layered above SRAID by other specifications.

## 2. The SRAID object

A SRAID object (the Canonical Data Record Object, or **CDRO**) is a map with the following members:

| Member | Required | Meaning |
|---|---|---|
| `oid` | yes | The object's content identifier (Section 4). `"sha256:" + lowercase_hex(SHA-256(canonical bytes))`. Excluded from the OID input. |
| `type` | yes | Object type discriminator (a non-empty string, for example `"gap:capability_grant"` or `"sraid:sro"`). |
| `sraid_version` | yes | SRAID protocol version. The only defined value is the string `"2.0"`. |
| `tenant_id` | yes | Non-empty string identifying the tenant that owns the object. |
| `created_at_ms` | yes | Unix-millisecond creation timestamp (a positive integer). |
| `created_by` | yes | OID or other non-empty string identifying the actor (skill, user, device) that created the object. |
| `body` | yes | The type-specific payload. May be any JSON value, but the member MUST be present. |
| `supersedes` | optional | If present, a canonical OID (`sha256:` followed by exactly 64 lowercase hex characters) of the previous version this object supersedes. |
| `sensitivity` | optional | If present, a **coarse, opaque sensitivity tier** (Section 7): one of `"s0"`, `"s1"`, `"s2"`, `"s3"`, `"s4"` (lowest to highest). It MUST NOT be a literal content category (for example `"phi"` or `"financial"`). Part of the canonical content, so it is hashed into the OID and cannot be silently stripped or downgraded. |
| `attestation` | optional | If present, a detached **DSSE attestation envelope** (Section 6) carrying one or more signatures over the object's PAE-encoded canonical bytes. This is the preferred signing form. May be absent on draft or unsigned objects. |
| `signature` | optional | LEGACY. If present, a single detached hybrid signature envelope over the object's bare canonical bytes (Section 6.4). Retained for back-compat; new producers SHOULD emit `attestation` instead. May be absent on draft or unsigned objects. |

The `oid`, `attestation`, and `signature` members are excluded from the OID input (Section 4) so that the same content produces the same OID and re-signing never changes identity. All other members are part of the canonical content and therefore contribute to the OID.

**Lineage fields are independent.** An object MAY carry `supersedes`, `prev`, and one or more `links[]` simultaneously. `supersedes` asserts a version-replacement relationship (this object is the authoritative successor of the referenced OID); `prev` is the hash-chain backpointer for ordered append; `links[]` are typed semantic edges (L3). Each is validated for canonical-OID format in isolation. The validator does NOT enforce agreement among them (for example it does not require `supersedes === prev`), nor does it resolve or fetch the referenced objects. Higher layers (Vault/Resolver, GAP) are responsible for any cross-field lineage semantics. The signed supersession receipt (SRO, type `sraid:sro`) is distinct from the self-asserted `supersedes` field on a CDRO: the SRO is an independently signed object authored by a governing actor; `supersedes` is a producer-asserted claim inside the envelope. Both fields are format-validated but neither implies the other.

## 3. Canonical form

SRAID v1.0 defines one normative canonical object format, identified as **`sraid/json`** (strict RFC 8785 JCS):

1. Take the value to canonicalize. For OID derivation this is the CDRO with its `oid` and `signature` members removed (Section 4); for signing it is the same value the signer hashed.
2. Serialize it as JSON deterministically per RFC 8785:
   - **Objects** emit their keys sorted in ascending lexicographic (UTF-16 code-unit) order. Each member is `key:value` with no whitespace; members are joined by a bare `,`.
   - Object members whose value is `undefined` are OMITTED entirely (an absent member and a member set to `undefined` canonicalize identically).
   - **Arrays** preserve their element order; each element is recursively canonicalized and joined by a bare `,`.
   - **Strings** are emitted with standard JSON string escaping.
   - **Numbers** use the ECMAScript number-to-string serialization defined by RFC 8785 §3.2.2.3. An implementation MUST reject (throw an error for) any number value that is `NaN`, positive `Infinity`, or negative `Infinity` — these values are not representable in JSON and MUST NOT be silently coerced to `null` or any other value. The value `-0` MUST serialize as `"0"` (the positive-zero form) per RFC 8785 §3.2.2.3.
   - `null`, `true`, and `false` are emitted literally.
   - No insignificant whitespace appears anywhere; the only separators are bare `,` and `:`.
3. Encode the result as UTF-8. The resulting byte string is the object's **canonical bytes**.

The precise canonicalization is pinned by the test vectors in `@synoi/conformance` (Section 8); an implementation is canonical-correct if and only if it reproduces those vectors.

A binary profile, **`sraid/cbor`** (CBOR per RFC 8949 with COSE per RFC 9052 for signatures), is reserved for a future version. An implementation MUST declare which profile it produces; a v1.0 producer MUST produce `sraid/json`.

**Serialization format decision (closed, 2026-06-27).** `sraid/json` is the one normative format for v1.0. The choice is settled for this version; it is not under deliberation. Rationale: (a) RFC 8785 JCS specifies a single, deterministic output with no schema dependency, which is required because `body` may be any JSON value (Section 2); (b) the conformance vectors (Section 8) already pin the byte-exact output, establishing a concrete interoperability floor; (c) JSON tooling is universally available across the implementation environments SRAID targets. `sraid/cbor` is explicitly deferred to a post-v1.0 additive binary profile. When introduced, it MUST yield the same OID-bearing content model as `sraid/json` (identical member set and semantics), not a replacement format. A `sraid/cbor` producer is therefore still bound by all CDRO structural rules in Section 2.

## 4. The Object Identifier (OID)

> The OID is the single normative identifier of SRAID v1.0.

The OID is computed over the canonical bytes of the CDRO with its `oid`, `attestation`, and `signature` members excluded from the input (so signing or re-signing never changes the OID):

```
OID = "sha256:" + lowercase_hex( SHA-256( canonical_bytes ) )
```

- An OID MUST match the regular expression `^sha256:[0-9a-f]{64}$`.
- The OID is both the object's content identity and its deduplication key: two CDROs whose members are identical after removing `oid`, `attestation`, and `signature` MUST yield identical canonical bytes and therefore an identical OID.
- Deduplication, supersession, and any trust or truth decision MUST use the full OID. An implementation MUST NOT substitute a truncation of the hash for these purposes.
- The 64-hex `sha256:` OID is the sole normative object identifier. The class/schema-prefixed `[4+12]` short form of Section 5 is a non-normative routing prefix only and is never an object identity.

SHA-256 provides approximately 128-bit pre-image resistance against a quantum adversary (Grover) and approximately 128-bit collision resistance, so the OID does not require migration for post-quantum reasons. Algorithm agility (a self-describing multihash form) is reserved for a future version and, if introduced, MUST be a distinct, versioned change rather than a silent one.

## 5. Routing prefix (non-normative)

Implementations MAY derive a short, fixed-size **routing prefix** from an object for type-partitioned placement or fast bucketing. A routing prefix begins with class/schema bytes followed by a prefix of the object's SHA-256.

- A routing prefix MUST NOT be used as a security identity, nor for deduplication, supersession, or trust decisions; those use the full OID (Section 4). A routing-prefix collision is a placement event, resolved by comparing full OIDs.
- The exact byte layout of the routing prefix is not fixed by SRAID v1.0 and is reserved as a separate, non-normative profile.

## 6. Attestation (signatures)

An object MAY carry a detached **attestation envelope** that authenticates its canonical bytes. SRAID v1.0 defines a **hybrid signature suite** combining a classical and a post-quantum algorithm, BOTH required:

- **Ed25519** (RFC 8032), and
- **ML-DSA-65** (FIPS 204).

The preferred form is a **DSSE** (Dead Simple Signing Envelope) JSON-profile envelope in the optional `attestation` member (Section 6.1–6.3). A legacy bare-bytes envelope (the `signature` member) is retained for back-compat only (Section 6.4). The `attestation` and `signature` members are not part of the OID (Section 4), so an object may be re-signed without changing its identity.

### 6.1 The DSSE attestation envelope

The `attestation` member has three members:

- `payloadType` — a non-empty media-type string identifying the payload kind (for example `application/vnd.synoi.sraid+json`, or `application/vnd.in-toto+json` for an in-toto/SLSA supply-chain attestation),
- `payload` — the canonical UTF-8 string that is attested (the CDRO content core per Section 3–4, i.e. the object minus its `oid`, `attestation`, and `signature` members), and
- `signatures` — an array of signature entries, each with members `alg` (the algorithm identifier, e.g. `"ed25519"` or `"ml-dsa-65"`), `sig` (the base64-encoded signature bytes), and an optional `keyid` (an opaque string identifying the keypair).

### 6.2 Pre-Authentication Encoding (PAE) — type binding

Each signature in `attestation.signatures` is computed over the **PAE** of the envelope, NOT over the bare payload:

```
PAE(payloadType, payload) =
    "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

where `SP` is a single ASCII space (0x20), `LEN(x)` is the ASCII-decimal byte length of `x` in its UTF-8 encoding, and `payloadType` and `payload` are their raw UTF-8 bytes. Because `payloadType` (and both lengths) are inside the signed bytes, the payload TYPE is structurally bound into every signature. A signature minted for one `payloadType` therefore CANNOT verify against an envelope that claims a different `payloadType`, even if the `payload` bytes are identical. This closes the cross-type / confused-deputy hazard inherent in signing bare canonical bytes (where all object kinds are signed identically).

### 6.3 The both-required (AND) policy

DSSE is, by itself, an OR-of-signatures envelope. SRAID layers a stricter rule on top: a conformant SRAID attestation MUST carry both an `ed25519` and an `ml-dsa-65` entry over the same PAE, and a verifier MUST require BOTH to verify (against the supplied public keys) before the object is considered signed. The presence of additional `signatures` entries with other algorithms is permitted and ignored by a SRAID hybrid verifier. Signatures are base64-encoded (standard alphabet, with `=` padding).

### 6.4 Legacy bare-bytes envelope (`signature`) — deprecated

For back-compat, an object MAY instead carry the legacy `signature` member with three members `ed25519`, `ml_dsa_65` (both base64-encoded signatures), and `signer_kid` (an opaque non-empty string). In the legacy form both signatures are computed over the bare canonical bytes (the CDRO minus its `oid`, `attestation`, and `signature` members, per Section 4) with NO payload-type binding. A verifier MUST require BOTH signatures to verify. New producers SHOULD NOT emit the legacy form; it lacks the PAE type binding of Section 6.2 and is retained only so objects minted before DSSE adoption keep verifying.

### 6.5 Binary profile

The `sraid/cbor` binary profile (Section 3) reserves **COSE** (RFC 9052) as the CBOR-profile attestation form. It is reserved, not defined by SRAID v1.0.

## 7. Envelope metadata privacy

The envelope members other than `body` (notably `type`, `tenant_id`, `created_by`, `created_at_ms`, and `supersedes`) are part of the canonical, signed, NON-encrypted envelope. They are in the clear so that the system can route, deduplicate, and govern an object without decrypting its `body`.

Because those members are visible to anyone who can see the object, an implementation SHOULD treat the envelope as a public surface and keep semantically sensitive content inside `body` (which higher layers MAY encrypt) rather than in envelope members. In particular, the `type` discriminator SHOULD identify the structural object kind (for example `sraid:sro`) and SHOULD NOT encode a semantic content category (for example a literal `health` or `financial` label), so that the envelope does not leak the nature of the encrypted `body`.

### 7.1 The sensitivity tier — coarse and opaque

SRAID v1.0 defines an optional `sensitivity` member: a **coarse, opaque** tier drawn from the ordered, fixed ladder `"s0" < "s1" < "s2" < "s3" < "s4"` (lowest to highest). The tier is OPAQUE by construction. Because the envelope is a public surface, the member MUST NOT carry a literal content category (for example `"phi"`, `"health"`, or `"financial"`): such a label would leak the nature of an encrypted `body` to anyone who can see the object. The mapping from a real-world classification (PHI, PII, secret, …) to a tier is a higher-layer POLICY concern that is kept OFF the wire; the envelope only ever exposes the opaque level. An implementation MUST reject a `sensitivity` value that is not one of the five defined tiers.

The member is part of the canonical content (Section 4), so it is hashed into the OID. A producer therefore cannot strip it or downgrade it without changing the OID and invalidating any signature.

**Monotone carry-forward (`max`).** Sensitivity propagates monotonically through derivation. When an object is derived from one or more sources (for example a consolidated or summarized memory record built from raw records, linked by `consolidated_from`/`derived_from`), its tier MUST be at least the **maximum** tier among those sources. In other words a summary of higher-tier inputs MUST NOT be assigned a lower tier than its highest input. This is the standard lattice-based information-flow rule (Denning 1976): the join (`max`) of the source labels is the floor for the derived label. The reference implementation provides `sensitivityCarryForward` and `sensitivityMonotoneCheck` for this.

> **Note (reserved).** SRAID v1.0 does NOT define a commitment-based selective-disclosure scheme that would CONCEAL the tier itself; the reference implementation carries none. Concealing the opaque tier (so that even the level is hidden) is reserved for a future version (Section 9) and MUST NOT be assumed by a v1.0 implementation. The v1.0 tier is opaque as to CATEGORY, not hidden as to LEVEL.

## 8. Delegation chains

A **delegation chain** is an ordered sequence of capability grant CDROs of type `gap:capability_grant` (or any type that carries a `body.capability_scopes` array) that traces authority from a trusted root principal down to a leaf grantee. Delegation verification is OFFLINE (verify-only): the verifier makes NO live-revocation or existence claim. Those remain resolver-dependent.

### 8.1 Chain shape

A chain MUST contain at least one grant. The ordered sequence is `links = [leaf, ancestor_0, ..., root]`, where `links[i]` is the direct child of `links[i+1]` and `links[links.length - 1]` is the terminal root grant. A chain MUST NOT exceed `MAX_DELEGATION_DEPTH = 8` links; an over-depth chain MUST be rejected before any hashing or signature work (cheap DoS guard).

### 8.2 OID honesty

Every link's `oid` MUST equal `sha256: + lowercase_hex(SHA-256(canonicalize(cdroContentCore(link))))`. A link whose claimed OID does not match the recomputed value MUST be rejected.

### 8.3 Per-hop structure

For each child `links[i]` under parent `links[i+1]`:

**(a) Linkage.** `child.body.granted_by` MUST equal `parent.body.grantee.actor_oid`. A mismatch means the chain is broken and MUST be rejected.

**(b) Attenuation.** Every capability in `child.body.capability_scopes` MUST be covered by at least one capability in `parent.body.capability_scopes` (segment-boundary wildcard match, Section 6 of the capability matching spec). A child grant with an **empty `capability_scopes` array MUST be rejected** — an empty scope set is not vacuously attenuated and grants nothing. A child scope that widens beyond all parent scopes (not covered by any parent scope) MUST be rejected.

**(c) Expiry monotone narrowing.** A `null` parent expiry is unbounded; a `null` child expiry under a bounded parent is widening and MUST be rejected. When both are non-null, `child.body.expires_at_ms` MUST NOT exceed `parent.body.expires_at_ms`.

### 8.4 Hybrid DSSE attestation, every link

Every link MUST carry a valid hybrid DSSE attestation envelope (Section 6.1) over `PAE(payloadType, payload)` (Section 6.2) where `payload = canonicalize(cdroContentCore(link))`. Both Ed25519 AND ML-DSA-65 signatures are required (Section 6.3). A missing attestation or an attestation whose payload does not match the link's content core MUST cause the chain to fail.

### 8.5 Root anchor (caller-asserted)

The terminal link's issuer key MUST deep-equal the caller-supplied `rootPubkeys`. A mismatch means the chain does not anchor to a known trusted root and MUST be rejected.

### 8.6 Action coverage (optional)

When the verifier is called with an optional `action` string, the leaf grant's `capability_scopes` MUST cover that action (using the same segment-boundary wildcard match as Section 8.3(b)). An uncovered action MUST fail closed (`authorized: false`). When no `action` is supplied, coverage of a specific action is not checked (GATE 5 skipped; `action_checked: false`).

### 8.7 No live-state claims

Delegation verification MUST NOT assert revocation status or grant existence. Implementations MUST return literal `false` (not a computed boolean) for `revocation_checked`, `not_revoked`, and `existence_checked`. Those remain RESOLVER-DEPENDENT and are out of scope for offline verification.

## 9. Conformance

An implementation conforms to SRAID Core v1.0 if it:

1. Produces `sraid/json` canonical bytes that match the published vectors,
2. Computes OIDs per Section 4 that match the published vectors, and
3. Verifies signatures per Section 6.

The conformance vectors in `@synoi/conformance` are the normative test of conformance.

## 10. Reserved for future versions

The following are reserved by name so that independent implementations do not adopt incompatible forms:

- **`sraid/cbor`** - a CBOR + COSE binary profile (Section 3). Reserved as a future additive binary profile only. The v1.0 serialization format is settled as `sraid/json` (see Section 3 decision note, 2026-06-27); `sraid/cbor` is not a candidate for v1.0 and MUST NOT be interpreted as an open question for this version.
- **routing-prefix layout** - the exact byte layout of the non-normative routing prefix (Section 5).
- **algorithm agility** - a self-describing (multihash-style) OID form and additional signature suites (Sections 4, 6).
- **sensitivity concealment** - a commitment-based selective-disclosure scheme that CONCEALS the opaque sensitivity tier itself (Section 7.1). The coarse, opaque tier member and its monotone `max` carry-forward ARE defined in v1.0 (Section 7.1); only the mechanism to hide the level is reserved.

## 11. References

- RFC 2119 - Key words for use in RFCs.
- RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA), Ed25519.
- FIPS 204 - Module-Lattice-Based Digital Signature Standard (ML-DSA).
- RFC 8949 - Concise Binary Object Representation (CBOR).
- RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process.
- FIPS 180-4 - Secure Hash Standard (SHA-256).

## Appendix A. Closed design decisions

This appendix records decisions that were implicit in the spec text and have been explicitly closed. It exists so that future readers and implementers do not treat settled questions as still open.

| ID | Date | Decision | Status |
|---|---|---|---|
| DD-1 | 2026-06-27 | Serialization format for v1.0 is `sraid/json` (RFC 8785 JCS). `sraid/cbor` is deferred to a post-v1.0 additive binary profile. See Section 3 for rationale. | CLOSED |
