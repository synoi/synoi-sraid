/**
 * @synoi/sraid — authority.ts
 *
 * L4 authority VERIFIER for CDRO objects (the authorized axis).
 *
 * This is deliberately more than a shape check. Per the Adversary review
 * (panel A6: "ship a verifier, not just a schema"), an attacker who can
 * attach any well-shaped `authority` block to an object would otherwise
 * forge authorization for free. So this module verifies, locally and
 * offline, the parts of authorization that ARE locally checkable:
 *
 *   1. STRUCTURE  — the object carries a present, well-formed authority
 *      block (grant reference present; decision verb, if any, is a valid
 *      GAP verb; intent ref well-formed).
 *   2. BINDING    — the object's authority block actually references the
 *      supplied grant (the grant's OID matches `authority.grant_oid`),
 *      AND the grant is itself a hash-honest CDRO whose recomputed OID
 *      equals its claimed OID (so the grant body cannot be swapped under
 *      a fixed OID reference).
 *   3. SIGNATURE  — the grant carries a valid hybrid (Ed25519 + ML-DSA-65)
 *      signature over its own content core, when grant signing material
 *      and verifier public keys are supplied. A grant with no/invalid
 *      signature does not authorize.
 *   4. COVERAGE   — the grant's capability scopes cover the requested
 *      object type / action (dotted-taxonomy match with segment-boundary
 *      wildcards), and the grant has not expired relative to the object's
 *      creation time. Both are computable from the bytes in hand.
 *
 * What this module does NOT and CANNOT do offline — stated honestly,
 * never silently assumed (CLAIMS_DISCIPLINE):
 *
 *   - LIVE REVOCATION  — whether the grant has since been revoked.
 *   - EXISTENCE        — whether the grant OID actually resolves to a
 *                        published, retrievable grant at all (when the
 *                        caller did not supply the grant material).
 *
 * Both require the OID Resolver, which is presently undeployed
 * (SRAID_FOUNDATION_PUNCHLIST C). This module DEFINES the resolver
 * interface (`AuthorityResolver`) and, when a resolver is supplied, calls
 * it and folds its answer into the result — but when no resolver is
 * supplied, the result is explicitly marked `revocation_checked: false`
 * and `existence_checked: false` so a caller can never mistake a
 * locally-passing verification for a live one.
 *
 * DELEGATION CHAINS (`verifyDelegationChain`, K2) — VERIFY-ONLY. This module
 * also carries a synchronous, offline delegation-chain verifier. It is
 * deliberately scoped to verification with NO enforcement wiring and NO
 * resolver: the caller supplies the ordered ancestors and the per-link
 * verifier keys, and the function makes NO live claim. It ALWAYS returns
 * `revocation_checked: false`, `not_revoked: false`, and
 * `existence_checked: false` — those fields are LITERAL-TYPED `false` so the
 * type system itself forbids a future edit from quietly asserting a live,
 * resolver-backed claim from an offline function (CLAIMS_DISCIPLINE made
 * structural). Synchronicity is intentional: with no Promise overload there is
 * no place for a resolver call, which is what makes the no-live-claim
 * guarantee structural rather than merely documented.
 */

import { cdroOid, cdroContentCore } from './oid.js'
import { verifySignature } from './signature.js'
import { verifyAttestation } from './attestation.js'
import type {
  AuthorityBlock,
  AuthorityDecision,
  CDRO,
  SignatureEnvelope,
} from './types.js'

// ── Valid verb set (mirrors AuthorityDecision in types.ts) ────────────────────

const VALID_DECISIONS: ReadonlySet<string> = new Set<AuthorityDecision>([
  'allow',
  'deny',
  'defer',
  'step_up',
  'delegate',
  'revoke',
])

// ── Capability pattern matching ───────────────────────────────────────────────

/**
 * Match a capability `target` against a grant `pattern`. Pure string logic,
 * re-stated here so L0 stays dependency-free (the same rule lives in
 * `@synoi/gap-types` `capabilityMatches`; L0 must not depend on L3).
 *
 *   - exact match → true
 *   - '*' → match-all
 *   - 'skill.*' matches 'skill.create' and deeper (segment-boundary only).
 *     A non-boundary 'admin.us*' must NOT match 'admin.users.delete'
 *     (privilege-escalation footgun) — only a '.'-anchored '*' is a wildcard.
 */
export function capabilityCovers(pattern: string, target: string): boolean {
  if (pattern === target) return true
  if (pattern === '*') return true
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -1) // keep trailing '.', e.g. 'skill.'
    return target.startsWith(prefix)
  }
  return false
}

// ── Resolver interface (live revocation / existence — resolver-dependent) ─────

/**
 * The live-state interface that the OID Resolver implements. It is the ONLY
 * source of truth for the two properties that cannot be checked offline:
 * whether a grant currently exists (resolves) and whether it has been
 * revoked. RESOLVER-DEPENDENT: undeployed today
 * (SRAID_FOUNDATION_PUNCHLIST C). Defined here so callers and a future
 * resolver agree on the contract; verifyAuthority works without it but
 * marks the corresponding result fields as not-checked.
 */
export interface AuthorityResolver {
  /**
   * Resolve a grant OID to its current status. Implementations should
   * return `{ exists: false }` for an unknown OID and `{ exists: true,
   * revoked: true, revoked_at_ms }` for a revoked one.
   */
  resolveGrantStatus(grantOid: string): Promise<GrantStatus> | GrantStatus
}

export interface GrantStatus {
  /** Whether the grant OID resolves to a known, published grant. */
  exists: boolean
  /** Whether the grant has been revoked. Only meaningful when `exists`. */
  revoked?: boolean
  /** When the revocation took effect, if revoked. */
  revoked_at_ms?: number
}

// ── verifyAuthority ───────────────────────────────────────────────────────────

export interface VerifyAuthorityInput {
  /**
   * The object whose authority block is being verified. Its `authority`
   * field is read; the object's `type` is used as the action target for the
   * coverage check unless `action` overrides it.
   */
  object: CDRO
  /**
   * The capability / action the object claims to perform, for the coverage
   * check. Defaults to `object.type`. For an Althing receipt this is
   * typically the invoked capability (e.g. `email.bulk_delete`).
   */
  action?: string
  /**
   * The authorizing grant CDRO, when available. Supplying it enables the
   * BINDING, SIGNATURE, and COVERAGE checks. Omit it to do STRUCTURE-only
   * verification (then `grant_supplied: false`).
   */
  grant?: CDRO<GrantBodyShape>
  /** Verifier public keys for the grant's hybrid signature. */
  grant_ed25519_pub?: Uint8Array
  grant_ml_dsa_pub?: Uint8Array
  /**
   * Expected DSSE payloadType for the grant's attestation envelope. Defaults
   * to `'application/vnd.synoi.sraid+json'`. Override when the grant was
   * issued with a custom media type.
   */
  grant_payload_type?: string
  /**
   * Optional live-state resolver. When supplied, revocation + existence are
   * checked and folded into the result; when omitted those remain
   * explicitly unchecked (resolver-dependent).
   */
  resolver?: AuthorityResolver
}

/**
 * The minimum grant body shape this verifier reads for coverage + expiry.
 * A superset of `@synoi/gap-types` `CapabilityGrantBody`; kept structural so
 * L0 does not depend on L3.
 */
export interface GrantBodyShape {
  capability_scopes?: Array<{ capability?: unknown }>
  expires_at_ms?: number | null
  /**
   * Issuer of this grant. Mirrors the gateway `CapabilityGrantBody.granted_by`
   * (synoi-gateway/src/gap/types.ts). VERIFY-ONLY: read by
   * `verifyDelegationChain` to check that a child's issuer equals its parent's
   * grantee. Kept OPTIONAL/structural so L0 stays L3-independent.
   */
  granted_by?: string
  /**
   * Subject this grant is issued to. Mirrors the gateway
   * `CapabilityGrantBody.grantee.actor_oid`. VERIFY-ONLY: a child grant chains
   * under this grant iff `child.granted_by === this.grantee.actor_oid`.
   */
  grantee?: { actor_oid?: string }
  /**
   * OID of the parent grant in a delegation chain. Absent/null = a root grant.
   * VERIFY-ONLY linkage field; it is NOT consulted for any enforcement here.
   * The chain order and ancestry are caller-supplied to `verifyDelegationChain`
   * (the verifier never fetches), so this is informational/auditable, not a
   * resolution hook.
   */
  parent_grant_oid?: string | null
}

export interface VerifyAuthorityResult {
  /**
   * True only when every LOCALLY CHECKABLE step that was attempted passed.
   * NOTE: this is `false` for `valid` does NOT imply the grant is revoked;
   * read the per-check fields. Crucially, `authorized === true` from this
   * function means "locally authorized" — it is NOT a claim about live
   * revocation unless `revocation_checked` is also true.
   */
  authorized: boolean
  /** Structure check: authority block present + well-formed. */
  structure_ok: boolean
  /** Whether a grant was supplied (enables binding/signature/coverage). */
  grant_supplied: boolean
  /** Binding check: object.authority.grant_oid === grant's recomputed OID. */
  binding_ok: boolean
  /** Signature check: grant carries a valid hybrid signature (when keys given). */
  signature_ok: boolean
  /** Whether signature was actually checked (keys + grant present). */
  signature_checked: boolean
  /** Coverage check: grant scope covers the action AND grant not expired. */
  coverage_ok: boolean
  /** RESOLVER-DEPENDENT — true only if a resolver confirmed the grant exists. */
  existence_checked: boolean
  existence_ok: boolean
  /** RESOLVER-DEPENDENT — true only if a resolver confirmed not-revoked. */
  revocation_checked: boolean
  not_revoked: boolean
  /** Human-readable failure reasons. Empty when fully authorized. */
  reasons: string[]
}

const DEFAULT_GRANT_PAYLOAD_TYPE = 'application/vnd.synoi.sraid+json'

/**
 * Verify the authority of a CDRO object. Synchronous local checks plus an
 * optional resolver call. When a resolver is supplied this returns a
 * Promise; otherwise it returns the result directly.
 */
export function verifyAuthority(
  input: VerifyAuthorityInput & { resolver?: undefined },
): VerifyAuthorityResult
export function verifyAuthority(
  input: VerifyAuthorityInput & { resolver: AuthorityResolver },
): Promise<VerifyAuthorityResult>
export function verifyAuthority(
  input: VerifyAuthorityInput,
): VerifyAuthorityResult | Promise<VerifyAuthorityResult> {
  const reasons: string[] = []
  const auth: AuthorityBlock | undefined = input.object?.authority

  // ── 1. STRUCTURE ──────────────────────────────────────────────────────────
  let structure_ok = true
  if (auth === undefined || auth === null || typeof auth !== 'object') {
    structure_ok = false
    reasons.push('authority block absent — object asserts no authority')
  } else {
    if (auth.grant_oid !== undefined) {
      if (typeof auth.grant_oid !== 'string' || !auth.grant_oid.startsWith('sha256:')) {
        structure_ok = false
        reasons.push('authority.grant_oid must be a "sha256:" OID')
      }
    } else {
      // grant_oid is the only thing that ties an object to an authorizer.
      // Its absence is allowed ONLY for an uncorrelated state-change event,
      // which is the orphan case — not "authorized".
      structure_ok = false
      reasons.push('authority.grant_oid absent — orphaned / uncorrelated authority')
    }
    if (
      auth.decision !== undefined &&
      auth.decision !== null &&
      !VALID_DECISIONS.has(auth.decision)
    ) {
      structure_ok = false
      reasons.push(`authority.decision "${String(auth.decision)}" is not a valid GAP verb`)
    }
    if (
      auth.intent_oid !== undefined &&
      (typeof auth.intent_oid !== 'string' || !auth.intent_oid.startsWith('sha256:'))
    ) {
      structure_ok = false
      reasons.push('authority.intent_oid, if present, must be a "sha256:" OID')
    }
  }

  // ── 2-4. BINDING / SIGNATURE / COVERAGE (need the grant) ─────────────────────
  const grant = input.grant
  const grant_supplied = grant !== undefined && grant !== null
  let binding_ok = false
  let signature_ok = false
  let signature_checked = false
  let coverage_ok = false

  if (structure_ok && grant_supplied) {
    // BINDING — recompute the grant's OID over its content core and require it
    // to equal both the grant's own claimed OID and the object's reference.
    // This defeats "swap the grant body under a fixed OID reference".
    let recomputed: string | null = null
    try {
      recomputed = cdroOid(grant)
    } catch {
      recomputed = null
    }
    const claimedOid = (grant as CDRO).oid
    const referenced = auth?.grant_oid
    if (recomputed === null) {
      reasons.push('grant content core not hashable')
    } else if (recomputed !== claimedOid) {
      reasons.push('grant OID does not match its content (tampered grant body)')
    } else if (recomputed !== referenced) {
      reasons.push('object.authority.grant_oid does not reference the supplied grant')
    } else {
      binding_ok = true
    }

    // SIGNATURE — verify the grant's hybrid signature over its content core.
    // BINDING and SIGNATURE must hash identical bytes: both route through
    // cdroContentCore (strips oid, signature, attestation) so they are
    // provably the same bytes.
    if (
      input.grant_ed25519_pub !== undefined &&
      input.grant_ml_dsa_pub !== undefined
    ) {
      signature_checked = true
      const att = (grant as CDRO).attestation
      const sig: SignatureEnvelope | undefined = (grant as CDRO).signature

      // Compute the canonical content core once — shared by both paths.
      let canonical: string | null = null
      try {
        canonical = canonicalize(cdroContentCore(grant))
      } catch {
        canonical = null
      }

      if (canonical === null) {
        reasons.push('grant content core not canonicalizable for signature check')
      } else if (att) {
        // DSSE attestation path — prefer when present.
        // payload-swap guard: the signed payload MUST equal this grant's content core.
        if (att.payload !== canonical) {
          signature_ok = false
          reasons.push('grant attestation payload does not match its content core (payload swap)')
        } else {
          const expectedPayloadType = input.grant_payload_type ?? DEFAULT_GRANT_PAYLOAD_TYPE
          const r = verifyAttestation({
            envelope: att,
            ed25519_pub: input.grant_ed25519_pub,
            ml_dsa_pub: input.grant_ml_dsa_pub,
            expectedPayloadType,
          })
          signature_ok = r.valid
          if (!r.valid) reasons.push(`grant attestation invalid: ${r.reasons.join(',')}`)
        }
      } else if (sig) {
        // Legacy signature envelope path.
        const r = verifySignature({
          canonical,
          envelope: sig,
          ed25519_pub: input.grant_ed25519_pub,
          ml_dsa_pub: input.grant_ml_dsa_pub,
        })
        signature_ok = r.valid
        if (!r.valid) reasons.push(`grant signature invalid: ${r.reasons.join(',')}`)
      } else {
        reasons.push('grant carries no signature or attestation')
      }
    }

    // COVERAGE — scope covers the action, and grant not expired at object time.
    const action = input.action ?? input.object.type
    const scopes = grant.body?.capability_scopes
    let covered = false
    if (Array.isArray(scopes)) {
      for (const s of scopes) {
        if (s && typeof s.capability === 'string' && capabilityCovers(s.capability, action)) {
          covered = true
          break
        }
      }
    }
    if (!covered) {
      reasons.push(`grant scope does not cover action "${action}"`)
    }
    const expires = grant.body?.expires_at_ms
    let notExpired = true
    if (typeof expires === 'number') {
      if (input.object.created_at_ms > expires) {
        notExpired = false
        reasons.push('grant had expired at the object creation time')
      }
    }
    coverage_ok = covered && notExpired
  } else if (structure_ok && !grant_supplied) {
    reasons.push('grant not supplied — binding/signature/coverage not checked')
  }

  // Local verdict: every attempted local check passed. Signature counts only
  // if it was checked; resolver checks are handled below.
  const localAuthorized =
    structure_ok &&
    grant_supplied &&
    binding_ok &&
    coverage_ok &&
    (!signature_checked || signature_ok)

  const base: VerifyAuthorityResult = {
    authorized: localAuthorized,
    structure_ok,
    grant_supplied,
    binding_ok,
    signature_ok,
    signature_checked,
    coverage_ok,
    existence_checked: false,
    existence_ok: false,
    revocation_checked: false,
    not_revoked: false,
    reasons,
  }

  // ── 5. RESOLVER (live revocation + existence) — resolver-dependent ──────────
  if (input.resolver && auth?.grant_oid) {
    const grantOid = auth.grant_oid
    return Promise.resolve(input.resolver.resolveGrantStatus(grantOid)).then(
      (status): VerifyAuthorityResult => {
        const existence_ok = status.exists === true
        const not_revoked = existence_ok && status.revoked !== true
        if (!existence_ok) base.reasons.push('resolver: grant does not exist')
        if (existence_ok && status.revoked === true) {
          base.reasons.push('resolver: grant has been revoked')
        }
        return {
          ...base,
          existence_checked: true,
          existence_ok,
          revocation_checked: true,
          not_revoked,
          authorized: localAuthorized && existence_ok && not_revoked,
        }
      },
    )
  }

  return base
}

// ── verifyDelegationChain (K2) — VERIFY-ONLY delegation-chain verifier ────────

/**
 * Hard cap on delegation depth. Checked BEFORE any hashing or signature work,
 * so an over-long chain is a cheap rejection (DoS guard) and never triggers
 * crypto. A chain of `links.length > MAX_DELEGATION_DEPTH` fails closed.
 */
export const MAX_DELEGATION_DEPTH = 8

/** The hybrid verifier public keys for one link's issuer. */
export interface LinkPubkeys {
  /** Raw 32-byte Ed25519 public key. */
  ed25519: Uint8Array
  /** Raw ML-DSA-65 public key bytes. */
  ml_dsa: Uint8Array
}

/**
 * Per-hop result. Index `i` describes child `links[i]` verified UNDER parent
 * `links[i+1]`. The terminal link (root) has no parent hop, so `per_hop` has
 * `depth - 1` entries.
 */
export interface HopResult {
  /** Index of the child link in the leaf->root `links` array. */
  child_index: number
  /** child.body.granted_by === parent.body.grantee.actor_oid. */
  granted_by_ok: boolean
  /** Every child scope is covered by some parent scope (no widening). */
  attenuation_ok: boolean
  /** Child expiry does not widen the parent's (monotone narrowing). */
  expiry_ok: boolean
}

export interface VerifyDelegationChainInput {
  /** The leaf grant (most-attenuated, end of the chain). */
  leaf: CDRO<GrantBodyShape>
  /**
   * Ancestors, ordered leaf-adjacent -> root: the leaf's parent first, the
   * root grant last. The full chain is `links = [leaf, ...ancestors]`, so
   * `links[i]` is the child of `links[i+1]` and `links[links.length-1]` is the
   * terminal root grant.
   */
  ancestors: CDRO<GrantBodyShape>[]
  /**
   * Hybrid verifier keys, index-aligned to `links` (so `linkPubkeys[i]` is the
   * issuer key of `links[i]`). Caller-supplied: the verifier never fetches
   * keys. `linkPubkeys[links.length-1]` MUST equal `rootPubkeys`.
   */
  linkPubkeys: LinkPubkeys[]
  /**
   * The trusted root principal's keys. The terminal link's signer key MUST
   * deep-equal these, else the chain does not anchor to a known root.
   */
  rootPubkeys: LinkPubkeys
  /**
   * Pin the DSSE payloadType for every link. Defaults to the SRAID grant
   * media type.
   */
  attestationPayloadType?: string
  /**
   * Optional requested action. When supplied, the leaf grant's capability
   * scopes MUST cover this action (GATE 5). If uncovered, `authorized` is
   * false and `action_ok` is false. When omitted, GATE 5 is skipped and
   * `action_checked` is false (vacuous pass — existing callers unaffected).
   */
  action?: string
}

/**
 * Result of `verifyDelegationChain`. Mirrors `VerifyAuthorityResult`'s
 * honesty discipline: the three live-claim fields are LITERAL-TYPED `false`
 * so the type system itself forbids a future edit from quietly asserting a
 * resolver-backed claim from this offline, verify-only function.
 */
export interface VerifyDelegationChainResult {
  /** True iff every hop check, every link signature, and the root anchor passed. */
  authorized: boolean
  /** Number of grants in the chain (`links.length`). */
  depth: number
  /** depth >= 1 && depth <= MAX_DELEGATION_DEPTH. Checked before any crypto. */
  depth_ok: boolean
  /** Every child.granted_by === parent.grantee.actor_oid. */
  links_ok: boolean
  /** Every child scope covered by some parent scope, all hops (no widening). */
  attenuation_ok: boolean
  /** Monotone expiry narrowing, all hops. */
  expiry_ok: boolean
  /** Every link carried a valid hybrid DSSE attestation over its content core. */
  signatures_ok: boolean
  /** False if any link lacked an attestation, or if no crypto ran (over-depth). */
  signatures_checked: boolean
  /** Every link OID is hash-honest (recomputed === claimed). */
  oids_ok: boolean
  /** Terminal link signer key == rootPubkeys. */
  root_ok: boolean
  /**
   * True iff the requested action is covered by some leaf scope.
   * When `action` was not supplied, this is true (vacuous pass).
   */
  action_ok: boolean
  /**
   * True when an `action` was supplied and GATE 5 ran; false when the caller
   * omitted `action` (GATE 5 skipped).
   */
  action_checked: boolean
  /** ALWAYS false — verify-only, no live revocation claim (literal type). */
  revocation_checked: false
  /** ALWAYS false — verify-only (literal type). */
  not_revoked: false
  /** ALWAYS false — no resolver, no existence claim (literal type). */
  existence_checked: false
  /** Per-hop breakdown; index i = child links[i] under parent links[i+1]. */
  per_hop: HopResult[]
  /** Human-readable failure reasons. Empty when fully authorized. */
  reasons: string[]
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

/** Extract string capabilities from a grant body's scope array. */
function scopeCaps(grant: CDRO<GrantBodyShape> | undefined): string[] {
  const scopes = grant?.body?.capability_scopes
  if (!Array.isArray(scopes)) return []
  const out: string[] = []
  for (const s of scopes) {
    if (s && typeof s.capability === 'string') out.push(s.capability)
  }
  return out
}

/**
 * Verify a delegation chain OFFLINE (K2). VERIFY-ONLY: there is no enforcement
 * wiring and no resolver — the caller supplies the ordered ancestors and the
 * per-link verifier keys, and this function makes NO live claim. It ALWAYS
 * returns `revocation_checked: false` and `existence_checked: false`; those
 * remain RESOLVER-DEPENDENT (SRAID_FOUNDATION_PUNCHLIST C) and are explicitly
 * out of scope here. The function is synchronous (no Promise overload), which
 * is what makes "no live claim" structural rather than merely documented.
 *
 * The gate runs in this fixed order; DEPTH is checked BEFORE any crypto:
 *
 *   GATE 0  DEPTH CAP    — depth in [1, MAX_DELEGATION_DEPTH]; else return with
 *                          NO hashing or signature work (cheap DoS guard).
 *   GATE 1  OID HONESTY  — every link's recomputed content-core OID equals its
 *                          claimed `oid` (rejects a body swapped under a fixed
 *                          OID reference).
 *   GATE 2  PER-HOP      — for each child links[i] under parent links[i+1]:
 *                          (a) granted_by linkage, (b) scope attenuation (every
 *                          child scope covered by some parent scope; empty
 *                          child scopes = FAIL — a grant of nothing is not
 *                          vacuously attenuated), (c) expiry monotone narrowing
 *                          (null parent = unbounded; null child under a bounded
 *                          parent = widening = FAIL).
 *   GATE 3  SIGNATURES   — every link carries a hybrid DSSE attestation
 *                          (ed25519 AND ml-dsa-65) over PAE(payloadType,
 *                          payload), and the attestation payload equals
 *                          canonicalize(cdroContentCore(link)) (payload-swap
 *                          guard). A missing attestation sets signatures_checked
 *                          false for that link and fails.
 *   GATE 4  ROOT ANCHOR  — the terminal link's issuer key deep-equals
 *                          rootPubkeys.
 *
 * `authorized` is the AND of every gate.
 */
export function verifyDelegationChain(
  input: VerifyDelegationChainInput,
): VerifyDelegationChainResult {
  const reasons: string[] = []
  const links = [input.leaf, ...input.ancestors]
  const depth = links.length
  const expectedPayloadType = input.attestationPayloadType ?? DEFAULT_GRANT_PAYLOAD_TYPE

  const fail = (
    over: Partial<VerifyDelegationChainResult>,
  ): VerifyDelegationChainResult => ({
    authorized: false,
    depth,
    depth_ok: false,
    links_ok: false,
    attenuation_ok: false,
    expiry_ok: false,
    signatures_ok: false,
    signatures_checked: false,
    oids_ok: false,
    root_ok: false,
    action_ok: false,
    action_checked: false,
    revocation_checked: false,
    not_revoked: false,
    existence_checked: false,
    per_hop: [],
    reasons,
    ...over,
  })

  // ── GATE 0 — DEPTH CAP (before any hashing or signature work) ──────────────
  const depth_ok = depth >= 1 && depth <= MAX_DELEGATION_DEPTH
  if (!depth_ok) {
    if (depth < 1) reasons.push('empty chain — no leaf grant supplied')
    else reasons.push(`chain depth ${depth} exceeds cap ${MAX_DELEGATION_DEPTH}`)
    // RETURN with no crypto run: signatures_checked stays false.
    return fail({ depth_ok: false })
  }

  if (input.linkPubkeys.length !== depth) {
    reasons.push(
      `linkPubkeys length ${input.linkPubkeys.length} does not match chain depth ${depth}`,
    )
    return fail({ depth_ok })
  }

  // ── GATE 1 — OID HASH-HONESTY, every link ──────────────────────────────────
  let oids_ok = true
  for (let i = 0; i < depth; i++) {
    const link = links[i] as CDRO<GrantBodyShape>
    let recomputed: string | null = null
    try {
      recomputed = cdroOid(link)
    } catch {
      recomputed = null
    }
    if (recomputed === null || recomputed !== link.oid) {
      oids_ok = false
      reasons.push(`link ${i} OID does not match its content (tampered grant body)`)
    }
  }

  // ── GATE 2 — PER-HOP STRUCTURE (child links[i] under parent links[i+1]) ─────
  let links_ok = true
  let attenuation_ok = true
  let expiry_ok = true
  const per_hop: HopResult[] = []

  for (let i = 0; i < depth - 1; i++) {
    const child = links[i] as CDRO<GrantBodyShape>
    const parent = links[i + 1] as CDRO<GrantBodyShape>

    // (a) GRANTED_BY linkage
    const childGrantedBy = child.body?.granted_by
    const parentGrantee = parent.body?.grantee?.actor_oid
    const granted_by_ok =
      typeof childGrantedBy === 'string' &&
      typeof parentGrantee === 'string' &&
      childGrantedBy === parentGrantee
    if (!granted_by_ok) {
      links_ok = false
      reasons.push(
        `hop ${i}: child.granted_by does not equal parent.grantee.actor_oid (broken signer link)`,
      )
    }

    // (b) ATTENUATION — every child scope covered by some parent scope.
    const childCaps = scopeCaps(child)
    const parentCaps = scopeCaps(parent)
    let hopAtten = true
    if (childCaps.length === 0) {
      // A grant that grants nothing is REJECTED (conservative default), not
      // treated as vacuously attenuated. (Flagged for founder review.)
      hopAtten = false
      reasons.push(`hop ${i}: child grant has no capability scopes (rejected)`)
    } else {
      for (const c of childCaps) {
        const covered = parentCaps.some((p) => capabilityCovers(p, c))
        if (!covered) {
          hopAtten = false
          reasons.push(`hop ${i}: child scope "${c}" widens parent (not attenuated)`)
        }
      }
    }
    if (!hopAtten) attenuation_ok = false

    // (c) EXPIRY MONOTONE-NARROWING
    const pe = parent.body?.expires_at_ms
    const ce = child.body?.expires_at_ms
    let hopExpiry = true
    if (pe === null || pe === undefined) {
      // unbounded parent: any child OK
      hopExpiry = true
    } else if (typeof pe === 'number') {
      if (ce === null || ce === undefined) {
        hopExpiry = false
        reasons.push(`hop ${i}: child expiry is unbounded under a bounded parent (widening)`)
      } else if (typeof ce === 'number') {
        if (ce > pe) {
          hopExpiry = false
          reasons.push(`hop ${i}: child expiry ${ce} is later than parent ${pe} (widening)`)
        }
      }
    }
    if (!hopExpiry) expiry_ok = false

    per_hop.push({
      child_index: i,
      granted_by_ok,
      attenuation_ok: hopAtten,
      expiry_ok: hopExpiry,
    })
  }

  // ── GATE 3 — HYBRID DSSE SIGNATURE, every link ─────────────────────────────
  let signatures_ok = true
  let signatures_checked = true
  for (let i = 0; i < depth; i++) {
    const link = links[i] as CDRO<GrantBodyShape>
    const att = link.attestation
    if (!att) {
      signatures_checked = false
      signatures_ok = false
      reasons.push(`link ${i} carries no DSSE attestation`)
      continue
    }
    // payload-swap guard: the signed payload MUST equal this link's content core.
    let expectedPayload: string | null = null
    try {
      expectedPayload = canonicalize(cdroContentCore(link))
    } catch {
      expectedPayload = null
    }
    if (expectedPayload === null || att.payload !== expectedPayload) {
      signatures_ok = false
      reasons.push(`link ${i} attestation payload does not match its content core (payload swap)`)
      continue
    }
    const keys = input.linkPubkeys[i] as LinkPubkeys
    const r = verifyAttestation({
      envelope: att,
      ed25519_pub: keys.ed25519,
      ml_dsa_pub: keys.ml_dsa,
      expectedPayloadType,
    })
    if (!r.valid) {
      signatures_ok = false
      reasons.push(`link ${i} hybrid signature invalid: ${r.reasons.join(',')}`)
    }
  }

  // ── GATE 4 — ROOT ANCHOR ───────────────────────────────────────────────────
  const terminalKeys = input.linkPubkeys[depth - 1] as LinkPubkeys
  const root_ok =
    bytesEqual(terminalKeys.ed25519, input.rootPubkeys.ed25519) &&
    bytesEqual(terminalKeys.ml_dsa, input.rootPubkeys.ml_dsa)
  if (!root_ok) {
    reasons.push('terminal link signer key does not equal rootPubkeys (forged/unknown root)')
  }

  // ── GATE 5 — ACTION COVERAGE (optional) ────────────────────────────────────
  // When the caller supplies `action`, the leaf's capability scopes MUST cover
  // it. Leaf = links[0]. Attenuation (GATE 2) already proved every ancestor
  // covers the leaf, so leaf coverage + attenuation transitively proves the
  // whole chain covers the action. Checking every hop would be redundant.
  let action_ok = true
  let action_checked = false
  if (input.action !== undefined) {
    action_checked = true
    const leafCaps = scopeCaps(input.leaf)
    const covered = leafCaps.some((s) => capabilityCovers(s, input.action as string))
    if (!covered) {
      action_ok = false
      reasons.push(
        `requested action "${input.action}" not covered by leaf grant`,
      )
    }
  }

  const authorized =
    depth_ok &&
    oids_ok &&
    links_ok &&
    attenuation_ok &&
    expiry_ok &&
    signatures_ok &&
    signatures_checked &&
    root_ok &&
    action_ok

  return {
    authorized,
    depth,
    depth_ok,
    links_ok,
    attenuation_ok,
    expiry_ok,
    signatures_ok,
    signatures_checked,
    oids_ok,
    root_ok,
    action_ok,
    action_checked,
    revocation_checked: false,
    not_revoked: false,
    existence_checked: false,
    per_hop,
    reasons,
  }
}

import { canonicalize } from './canonicalize.js'
