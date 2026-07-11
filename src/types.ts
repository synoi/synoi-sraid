/**
 * @synoi/sraid — types.ts
 *
 * Type definitions for the SRAID (Self-Routing Addressable Identity Data) protocol — L0 of the
 * SRAID Stack. Mirrors the shapes used by synoi-gateway and @synoi/vault so
 * external implementations can interoperate without depending on the
 * internal packages.
 *
 * CDRO objects are content-addressed: the OID is derived from the canonical
 * form of the object (minus signature fields), so any byte-level change to
 * the canonical content yields a different OID. Signatures are computed
 * over the canonical bytes and attached after — they are NOT in the hash
 * input, so signature rotation does not change the OID.
 */

// ── L4 authority block ────────────────────────────────────────────────────────

/**
 * The six GAP decision verbs. Authority records carry the full verb set;
 * they are NOT folded to allow/deny/defer before persistence (SRAID
 * Foundation Punch List item A4). When an authority block describes a
 * decision (e.g. a Decision Receipt), `decision` is one of these.
 *
 *   allow    — the action was permitted outright
 *   deny     — the action was refused
 *   defer    — the decision was postponed (queued / pending)
 *   step_up  — additional authentication / HITL was required
 *   delegate — authority was passed to another actor
 *   revoke   — a prior grant/decision was withdrawn
 *
 * The clean-sheet model (OBJECT_MODEL_CLEANSHEET §3.5) shows the core four
 * (allow|deny|defer|step_up); delegate/revoke complete the AARM verb set
 * so the enum does not have to widen later.
 */
export type AuthorityDecision =
  | 'allow'
  | 'deny'
  | 'defer'
  | 'step_up'
  | 'delegate'
  | 'revoke'

/**
 * L4 GOVERNANCE — the authority block (the "authorized axis").
 *
 * This is the structural realization of the authorized axis
 * (OBJECT_MODEL_CLEANSHEET §3.5, SRAID_FOUNDATION_PUNCHLIST A1): a state
 * change or event is *normal* iff a governing authority record explains
 * it. Every CDRO MAY carry an `authority` block referencing the GAP grant,
 * the decision verb, and the session intent anchor that authorized it.
 *
 * IMPORTANT — identity-bound. The authority block lives physically INSIDE
 * the hashed content core (it is one of the L4 fields hashed into the OID),
 * so it cannot be silently stripped or swapped without changing the OID and
 * therefore breaking the signature. Use `cdroOid` / `cdroContentCore` in
 * `oid.ts` to compute identity over the content core (which includes
 * `authority`), never `oidOf(body)` alone for a full CDRO.
 *
 * `decision` is `null`-able by design: a `state:change_event` carries
 * `authority` with a null/absent decision until a correlation pass binds it
 * to an authorizing receipt — a null authorized axis IS the orphan test
 * (OBJECT_MODEL_CLEANSHEET R2.4). An absent `authority` field means the
 * object asserts no authority; a present block with `grant_oid` asserts one.
 */
export interface AuthorityBlock {
  /**
   * OID of the GAP capability grant (or decision/intent record) that
   * permitted this object to exist. `sha256:<hex>` form. Optional only for
   * an as-yet-uncorrelated state-change event; for any object that claims
   * to be authorized, this MUST be present.
   */
  grant_oid?: string
  /**
   * The decision verb, when this object IS (or records) a decision. One of
   * the six GAP verbs. May be null/absent for objects that merely reference
   * an authorizing grant without themselves being a decision, or for an
   * uncorrelated state-change event.
   */
  decision?: AuthorityDecision | null
  /**
   * OID of the session / task intent anchor under which the authority was
   * exercised. `sha256:<hex>` form. Optional.
   */
  intent_oid?: string
}

// ── L3 lineage (Merkle-DAG) ───────────────────────────────────────────────────

/**
 * Typed lineage edge relations (OBJECT_MODEL_CLEANSHEET §3.3,
 * SRAID_FOUNDATION_PUNCHLIST A2). A `links[]` edge names *why* one object
 * points at another. The taxonomy is the union the four products need; it
 * is OPEN (a verifier ignores rels it does not understand) but these are the
 * named, reserved relations.
 *
 *   supersedes        — this object replaces the target (the unified, witnessed
 *                       form of the legacy self-asserted `supersedes` string and
 *                       the standalone SRO). Combined with `prev`, gives a
 *                       verifier a latest-wins / monotone rule instead of an
 *                       unwitnessed pointer (fixes SRAID F10 / Adversary A3).
 *   derived_from      — this object was derived/transformed from the target.
 *   snapshot_of       — this object is a checkpoint snapshot of the target chain.
 *   consolidated_from — Saga: a consolidated memory record built from raw chunks.
 *   predecessor       — generic prior-version edge (when not a full supersession).
 *   encounter_of      — Vitni: an encounter/disclosure references a prior one.
 *   subject_digest    — Hlif: the content digest of the attested artifact.
 *   invocation_of     — Althing: the GAP capability invocation this records.
 *   hitl_evidence     — Althing: a HITL channel event backing a decision.
 *   entity_of         — state-drift: the entity state-spine head this observes.
 *   prev_observation  — state-drift: the prior observation of the same entity.
 *
 * Unknown rels are permitted (forward-compatible); validation only checks
 * that each edge is well-formed (a non-empty `rel` + a `sha256:` `oid`).
 */
export type LinkRel =
  | 'supersedes'
  | 'derived_from'
  | 'snapshot_of'
  | 'consolidated_from'
  | 'predecessor'
  | 'encounter_of'
  | 'subject_digest'
  | 'invocation_of'
  | 'hitl_evidence'
  | 'entity_of'
  | 'prev_observation'
  | (string & {})

/**
 * L3 LINEAGE — one typed Merkle-DAG edge.
 *
 * Both `prev` and every `links[]` edge are HASHED INTO THE OID (they live in
 * the content core, see `cdroContentCore` in oid.ts), so lineage is
 * identity-bound and tamper-evident: a node's OID transitively commits its
 * entire reachable history (the Git/IPFS "head hash proves all history"
 * property, OBJECT_MODEL_CLEANSHEET §3.3). An edge cannot be added, removed,
 * or re-pointed without changing the OID and invalidating the signature.
 */
export interface LineageLink {
  /** Why this edge exists. One of the reserved `LinkRel`s, or any string. */
  rel: LinkRel
  /** OID of the target object. `sha256:<hex>` form. */
  oid: string
}

// ── L4 sensitivity (propagating, opaque tier) ─────────────────────────────────

export type { SensitivityTier } from './sensitivity.js'
import type { SensitivityTier } from './sensitivity.js'

// ── Core CDRO envelope ────────────────────────────────────────────────────────

/**
 * Hybrid signature envelope — LEGACY. Carries an Ed25519 signature
 * (classical) and an ML-DSA-65 signature (post-quantum), both computed over
 * the bare canonical bytes with NO payload-type binding. `verifySignature`
 * in this package requires BOTH to be valid before returning `valid: true`.
 *
 * DEPRECATED in favour of the DSSE `AttestationEnvelope` (the L2 attestation
 * layer). The bare-bytes form has no `payloadType` binding, which allows a
 * signature minted for one object type to be replayed against a different
 * type whose canonical bytes match (SRAID F7 / Adversary A4). New objects
 * SHOULD carry an `attestation` (DSSE) envelope; `SignatureEnvelope` is
 * retained only so existing callers and stored objects keep verifying during
 * the migration.
 *
 * Encoded as base64 (standard, with `=` padding). `signer_kid` is a
 * stable string that identifies which keypair produced the signatures.
 */
export interface SignatureEnvelope {
  /** Base64-encoded 64-byte Ed25519 signature. */
  ed25519: string
  /** Base64-encoded ML-DSA-65 signature. */
  ml_dsa_65: string
  /** Key ID — opaque string identifying which keypair signed. */
  signer_kid: string
}

// ── L2 attestation (DSSE) ──────────────────────────────────────────────────────

/**
 * One signature entry inside a DSSE `AttestationEnvelope`. The signature is
 * computed over the envelope's PAE (Pre-Authentication Encoding) — see
 * `pae()` / `verifyAttestation()` in attestation.ts — so the `payloadType`
 * is structurally bound into what each signature covers.
 */
export interface AttestationSignature {
  /**
   * Algorithm identifier. SynOI requires both `'ed25519'` and `'ml-dsa-65'`
   * to be present (the hybrid AND policy). Other algs are ignored by the
   * SynOI verifier but permitted in the array (DSSE is forward-compatible).
   */
  alg: 'ed25519' | 'ml-dsa-65' | (string & {})
  /** Base64-encoded signature bytes over the PAE. */
  sig: string
  /** Optional key ID — opaque string identifying which keypair signed. */
  keyid?: string
}

/**
 * L2 ATTESTATION — a DSSE (Dead Simple Signing Envelope), JSON profile.
 *
 * Replaces the legacy `SignatureEnvelope`. Each signature in `signatures[]`
 * covers `PAE(payloadType, payload)` rather than the bare payload bytes, so
 * the payload TYPE is bound into the signed bytes — closing the cross-type
 * confusion gap (SRAID F7 / Adversary A4). The hybrid both-required rule is
 * preserved: a conformant SRAID attestation MUST carry both an `ed25519` and
 * an `ml-dsa-65` entry over the same PAE, and `verifyAttestation` requires
 * both to verify.
 *
 * `payload` is the canonical UTF-8 string of the content core (the same
 * bytes `canonicalize()` produces and `oidOf` hashes). Because the envelope
 * is detached (it is the CDRO's `attestation` field, excluded from the OID
 * hash), adding/rotating a signature never changes the OID.
 *
 * A future CBOR profile would use COSE (RFC 9052); it is reserved, not
 * implemented in this package.
 */
export interface AttestationEnvelope {
  /**
   * The payload media type, bound into the PAE. SynOI objects use
   * `application/vnd.synoi.sraid+json`; Hlif supply-chain attestations use
   * `application/vnd.in-toto+json` for in-toto/SLSA/Sigstore interop.
   */
  payloadType: string
  /** Canonical UTF-8 payload string (the signed content core). */
  payload: string
  /** Detached signatures, each over `PAE(payloadType, payload)`. */
  signatures: AttestationSignature[]
}

/**
 * CDRO — Canonical Data Record Object.
 *
 * The base shape every signed CDRO object takes. The `oid` field is
 * `sha256:` + hex(sha256(canonicalize(body))) where the body is the CDRO
 * minus the `oid` and `signature` fields.
 *
 * Mirrors `GapCdroEnvelope` in synoi-gateway so a GAP object IS a CDRO.
 * Higher-layer packages narrow `body` with their own type.
 */
export interface CDRO<TBody = unknown> {
  /** "sha256:" + hex(sha256(canonicalize(cdro_minus_oid_and_signature))). */
  oid: string
  /** Object type discriminator (e.g. "gap:capability_grant"). */
  type: string
  /** SRAID protocol version. v2 is the only defined version today. */
  sraid_version: '2.0'
  /** Tenant that owns this object. */
  tenant_id: string
  /** Unix ms timestamp of creation. */
  created_at_ms: number
  /** OID of the actor (skill, user, device, …) that created the object. */
  created_by: string
  /** Body — type-specific payload. Higher layers narrow this. */
  body: TBody
  /**
   * Optional L4 authority block — the authorized axis (§3.5). When present
   * it is HASHED INTO THE OID (it is part of the content core), so it cannot
   * be stripped without changing identity. See `AuthorityBlock` and the
   * `cdroOid` helper in oid.ts.
   */
  authority?: AuthorityBlock
  /**
   * Optional L4 propagating sensitivity tier — a COARSE, OPAQUE level
   * (`s0`..`s4`, lowest-to-highest), NOT a literal content category (§3.4,
   * SRAID_FOUNDATION_PUNCHLIST A5). It is OPAQUE on purpose: SPEC §7 forbids
   * leaking the nature of an encrypted `body` via the public, signed
   * envelope, so a literal label like `"phi"`/`"health"` is NOT allowed here;
   * the regulatory-category → tier mapping is private higher-layer policy.
   *
   * HASHED INTO THE OID (it is a content-core field, see `cdroContentCore` in
   * oid.ts), so the tier cannot be silently stripped or downgraded without
   * changing identity and invalidating the signature. Carry-forward is
   * monotone (`max`): a consolidated/summarized object inherits the HIGHEST
   * tier among its sources — see `sensitivityCarryForward` in sensitivity.ts
   * and the Vault consolidation path. Absent means "unclassified" (the floor,
   * `s0`); it does not assert low sensitivity, only that none was declared.
   */
  sensitivity?: SensitivityTier
  /**
   * Optional L3 lineage — the Merkle edge to the immediately superseded
   * version (null/absent at a root object). HASHED INTO THE OID (it is part
   * of the content core), so the predecessor link is identity-bound: a node's
   * OID transitively commits its predecessor's OID and therefore its whole
   * reachable history. This is the unified, witnessed replacement for the
   * legacy self-asserted `supersedes` string — see `lineageLinks` /
   * `latestWins` in lineage.ts for the latest-wins / monotone rule.
   */
  prev?: string
  /**
   * Optional L3 lineage — typed Merkle-DAG edges (§3.3). HASHED INTO THE OID
   * (content core), so every edge is identity-bound and tamper-evident. The
   * standalone SRO and the self-asserted `supersedes` pointer both become
   * expressible here as `{ rel: 'supersedes', oid }` edges, unifying the
   * three legacy supersession mechanisms onto one model.
   */
  links?: LineageLink[]
  /**
   * Legacy supersession pointer — OID of the previous version. RETAINED for
   * back-compat. It is now routed through the unified lineage model: treat it
   * as equivalent to `prev` (and to a `{ rel: 'supersedes' }` link). New
   * objects SHOULD set `prev`/`links` instead; `lineageLinks` in lineage.ts
   * coalesces all three so a verifier sees one set of typed edges. Still
   * hashed into the OID (it is a content-core field).
   */
  supersedes?: string
  /**
   * Optional L2 attestation — the DSSE envelope (the preferred signing path).
   * Carries `payloadType` + `signatures[]`, each over `PAE(payloadType,
   * payload)`. Detached: NOT part of the OID hash (see `cdroContentCore` in
   * oid.ts), so adding/rotating a signature never changes identity.
   */
  attestation?: AttestationEnvelope
  /**
   * Optional LEGACY signature envelope (bare-bytes, no payload-type binding).
   * Retained for back-compat with objects/callers minted before the DSSE
   * `attestation` envelope. New objects SHOULD use `attestation`. May be
   * absent on draft / unsigned objects.
   */
  signature?: SignatureEnvelope
}

// ── SRO ───────────────────────────────────────────────────────────────────────

/**
 * SRO — Mutation / Supersession Record.
 *
 * Links a successor CDRO to its predecessor and the actor that authorized
 * the supersession. SROs are themselves CDRO objects (so they're CDROs with
 * an `oid` and `signature`), but they have a specific body shape.
 *
 * Where CDROs are the "what" of the system, SROs are the "what changed."
 * They form an append-only chain: every supersedes pointer in a CDRO is
 * accompanied by an SRO that explains and witnesses the change.
 */
export interface SROBody {
  /** OID of the predecessor object being superseded. */
  predecessor_oid: string
  /** OID of the successor object that supersedes it. */
  successor_oid: string
  /** Why the predecessor was superseded. Free-form short string. */
  reason: string
  /** OID of the actor that authorized this mutation. */
  authorized_by: string
  /** Optional list of supporting evidence OIDs (audit trail). */
  evidence_oids?: string[]
}

/** SRO is just a CDRO with a fixed body type. */
export type SRO = CDRO<SROBody> & { type: 'sraid:sro' }
