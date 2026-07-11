# SRAID CDRO OID Projection — Normative Specification

Status: Normative
Version: 1.0
Date: 2026-07-05
Authority: ADR_019 (L0 Normative Contract Unification), decisions 1-3.
License: CC0-1.0 (public domain). Non-TypeScript SDKs MUST derive from this
document; the TypeScript reference implementation is `@synoi/sraid`
(`src/oid.ts`, `src/canonicalize.ts`).

This document is the SINGLE NORMATIVE SOURCE of prose for:

1. the CDRO OID content-core projection (the field-set removed before hashing),
2. the number rule (finite integers only), and
3. the RFC 8785 (JCS) rules SRAID relies on.

Any implementation (TS, Python, Rust, Go, or other) that produces a byte
string different from the reference for the same input is non-conformant. The
cross-language ABI is enforced by the conformance vectors generated from the
reference implementation; this prose exists so a new SDK can be DERIVED from
one written source instead of re-inventing a divergent copy. There have been
four divergent projections and two number rules across the stack; this spec
collapses them to one.

---

## 1. The OID

A CDRO's OID (Object IDentifier) is:

```
OID = "sha256:" + lowercase_hex( SHA-256( canonicalize( cdroContentCore(object) ) ) )
```

- The hash is SHA-256 (FIPS 180-4). It stays quantum-relevant only via Grover,
  which halves preimage resistance to 2^128 — acceptable.
- The digest is emitted as exactly 64 lowercase hexadecimal characters.
- The prefix is the literal ASCII string `sha256:`. It is NEVER truncated. A
  bare hex string with no algorithm prefix is NOT a conformant OID.
- `canonicalize` is the RFC 8785 subset defined in §3.
- `cdroContentCore` is the projection defined in §2.

The OID is content-addressed: any byte-level change to the canonical content
core yields a different OID. Signatures are computed over the SAME canonical
bytes and attach AFTER hashing, so signing (or rotating a signature) never
changes the OID.

---

## 2. The content-core projection (`cdroContentCore`)

`cdroContentCore(object)` returns `object` with EXACTLY the following six
top-level fields REMOVED, and every other field KEPT unchanged:

| Field                 | Why it is removed                                        |
| --------------------- | -------------------------------------------------------- |
| `oid`                 | The projection OUTPUT; it cannot be an input to itself.  |
| `signature`           | Legacy hybrid `SignatureEnvelope`; attaches after hash.  |
| `ml_dsa_signature`    | Detached ML-DSA-65 signature; produced by the signer.    |
| `signature_key_id`    | Signer-stamped key id; produced by the signer.           |
| `signature_algorithm` | Signer-stamped algorithm id; produced by the signer.     |
| `attestation`         | DSSE `AttestationEnvelope`; attaches after hash.         |

### 2.1 The strip-set is SEMANTIC, not a per-surface enumeration

The removed set is defined by ONE rule: **remove every field the signer
produces AFTER canonicalization, plus the OID output itself.** The six names
above are the concrete realization of that rule for the current object shape.
An implementation MUST NOT maintain its own independent hand-listed strip-set;
it derives the set from this rule and this table. A field that a future signer
stamps post-hash is added here, in this one place, and nowhere else.

### 2.2 Everything else is KEPT and hashed into identity

In particular the following are IN the content core and therefore IN the OID:

- `gap_version` — IN identity so a protocol downgrade is OID-detectable. A
  receipt claiming `gap_version: "1.0"` cannot be silently re-presented as a
  different protocol version without changing its OID.
- `supersedes` — IN identity because the SRAID Merkle-DAG "head proves history"
  property requires every lineage edge to be inside the hash. Superseding mints
  a NEW object; it never mutates the superseded object's bytes, so keeping the
  pointer inside identity is safe and makes the lineage edge tamper-evident. An
  edge cannot be added, removed, or re-pointed without changing the OID.
- `prev`, `links` — L3 lineage edges, same rationale as `supersedes`.
- `authority` — the L4 authorized-axis block. IN identity so it cannot be
  stripped or swapped without breaking the OID and the signature.
- `sensitivity` — the coarse, opaque propagating tier. IN identity so a
  classification cannot be silently downgraded.
- `type`, `sraid_version`, `tenant_id`, `created_at_ms`, `created_by`, `body`,
  and every other content field.

### 2.3 Pre- vs post-attestation invariance (the keystone)

This is the property the entire "portable, independently verifiable receipt"
thesis depends on: **`cdroOid(object)` yields the SAME OID whether `object` is
pre-attestation (no signature fields) or post-attestation (signature fields
attached).** Because §2 strips the six detached fields, a third party who
recomputes the OID of a SIGNED receipt gets the byte-identical value the signer
stamped. A projection that hashes `attestation` (or any of the six) into the
OID breaks this: the third party recomputes a different OID and wrongly
concludes a valid receipt was tampered.

Reference conformance vector (from `test/oid.test.ts`, `baseCdro`):

```
cdroOid(pre-attestation)  == cdroOid(post-attestation)
                          == sha256:d1d5d5c51d2d5f80470089ff10b8b642e19fc76db6be298f4f346616528a087a
```

where the object is

```json
{
  "type": "gap:decision_receipt",
  "sraid_version": "2.0",
  "gap_version": "1.0",
  "tenant_id": "tenant-x",
  "created_at_ms": 1720000000000,
  "created_by": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "body": { "decision": "allow", "amount_minor": 1299 },
  "authority": { "grant_oid": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "decision": "allow" },
  "supersedes": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

The post-attestation form is the same object with `oid`, `attestation`,
`signature`, `ml_dsa_signature`, `signature_key_id`, and `signature_algorithm`
added; its `cdroOid` is byte-identical to the pre-attestation form's.

---

## 3. The number rule and the JCS rules (`canonicalize`)

`canonicalize(value)` is a STRICT SUBSET of RFC 8785 (JCS). It produces a
deterministic UTF-8 string, byte-identical across conformant implementations
for the same input.

### 3.1 Number rule — finite integers ONLY (ADR_019 decision 2)

A number is legal **iff it is a finite integer.** All of the following are
REJECTED with a typed error BEFORE any hashing:

- `NaN`, `+Infinity`, `-Infinity` (RFC 8785 already forbids non-finite).
- Any non-integer number (float), e.g. `1.5`, `0.1`, `2e-3`, `9.99`.

Rationale: the product is settlement-grade signed receipts. All money is
represented as integer minor units (e.g. cents); all timestamps are integer
milliseconds. No conformant SRAID object legitimately carries a float.
Forbidding floats removes the single hardest RFC 8785 cross-language trap
(shortest-round-trip float serialization) from a signed byte string, with
near-zero blast radius.

Notes:

- `-0` is an integer and serializes as `"0"` (`JSON.stringify(-0) === "0"`).
  There is NO bespoke `-0` special-case in the reference implementation; the
  integer path handles it. Implementations MUST NOT add a separate `-0` branch
  (it is a divergence source and cannot fire on legal input differently).
- A source token like `56.0` that a JSON parser collapses to the integer `56`
  is legal (it IS the integer 56 after parsing). The rule constrains the parsed
  numeric VALUE, not the source lexeme.
- Legal integers serialize via the ECMAScript number-to-string of RFC 8785
  §3.2.2.3, which for integers is the plain decimal form (`1000`, `-42`, `0`).

### 3.2 JCS rules SRAID relies on (MUST NOT regress)

- **Object key ordering:** keys are sorted in ascending UTF-16 code-unit order
  (RFC 8785 §3.2.3 for UTF-16 host languages; this is JS `Array.prototype.sort`
  default order). This is verified byte-for-byte against the RFC 8785 reference
  vectors (`arrays`, `french`, `structures`, `unicode`, `weird`).
- **String escaping:** minimal JSON string escaping — only the characters JSON
  requires be escaped are escaped, using the shortest form. No locale, no
  Unicode normalization (the input's code points are emitted as-is; e.g. an
  unnormalized `A` + combining ring is NOT normalized).
- **No whitespace:** separators are bare `,` and `:`; no spaces or newlines.
- **`null`:** emitted as the literal `null`. Booleans as `true` / `false`.
- **Arrays:** element order preserved; each element recursively canonicalized.

### 3.3 Reject-loud domain (out-of-domain values throw, never coerce)

A typed error is thrown, never a silent wrong/invalid form, for:

- non-integer / non-finite numbers (§3.1),
- `undefined` / function / symbol / bigint as any value, INCLUDING an array
  element (which would otherwise produce invalid JSON like `[1,,2]`),
- a sparse array hole,
- any object exposing a `toJSON()` method (e.g. `Date`, `Buffer`, decimal
  libraries) — convert to a JSON value (e.g. an ISO string) first.

Object properties whose value is `undefined` are OMITTED (matching the JSON
data model). An `undefined` ARRAY element throws (omitting it would shift
indices and silently change meaning).

### 3.4 Relationship to full RFC 8785

SRAID's number domain is a DOCUMENTED NARROWING of RFC 8785: the RFC permits
non-integer numbers with a defined serialization; SRAID forbids them. SRAID is
therefore RFC 8785 conformant on ordering and string escaping (proven against
the reference vectors), and INTENTIONALLY stricter on numbers. A general-purpose
RFC 8785 float vector (e.g. the reference `values` vector) is expected to be
REJECTED by a conformant SRAID canonicalizer, not to round-trip a float.

---

## 4. Firewalls — schemes that are NOT this projection

Two adjacent schemes look similar and MUST NOT be merged into this normative
CDRO projection. Confusing them is signature confusion, which is fatal.

### 4.1 The v1 flat-scalar receipt projection (legacy, separate)

The gateway's legacy v1 flat signer uses a DIFFERENT strip-set (its
`GAP_SIGNING_EXCLUDED` set additionally excludes `gap_version` and
`supersedes`, and folds the body to flat scalars). That is a SEPARATE, LEGACY
signing shape gated behind the `receipt_scheme` discriminator. It is NOT the
CDRO content core and MUST NOT be used to recompute a CDRO OID. The live v2
signer uses THIS projection (`@synoi/sraid`'s `cdroContentCore`); the v1 flat
scheme is retained only for objects minted before v2 and is never confused for
a content core.

### 4.2 The Vault L1 binary-TLV canonical hash (separate identity contract)

The Vault L1 `canonical_hash` (a binary TLV encoding, `@synoi/vault`) is a
DISTINCT, deliberately-frozen identity contract governing a different layer. It
is explicitly OUT OF SCOPE and firewalled — NOT merged with this JSON/JCS
projection. A Vault L1 identity and a CDRO OID are computed by different rules
by design.

---

## 5. Conformance

An implementation is conformant iff, for every generated conformance vector:

1. its `cdroContentCore` removes exactly the six §2 fields and keeps all others,
2. `cdroOid(pre-attestation) == cdroOid(post-attestation)` (§2.3),
3. every float-bearing input is REJECTED (§3.1),
4. changing `supersedes` or `gap_version` changes the OID (§2.2),
5. its `canonicalize` matches the RFC 8785 reference ordering/escaping vectors
   byte-for-byte (§3.2).

The reference vectors are generated from `@synoi/sraid` and consumed
byte-for-byte by all SDKs, the gateway signer, and the verifiers in CI. A
divergent strip-set, number rule, or canonicalize turns a vector red.
