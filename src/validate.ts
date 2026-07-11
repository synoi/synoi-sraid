/**
 * @synoi/sraid — validate.ts
 *
 * Non-throwing shape validators for CDRO objects. Returns `{ ok, errors }`
 * so callers can collect every violation in one pass.
 *
 * Validation here is intentionally LOW-LEVEL — it checks the CDRO
 * envelope shape, not the semantics of a specific `body`. Higher-layer
 * packages (GAP, Vault, …) layer their own validators on top.
 *
 * Style mirrors the hand-rolled validators in synoi-mcp-server (no zod,
 * no heavy validation library) — kept tiny on purpose.
 */

import type {
  AttestationEnvelope,
  AttestationSignature,
  AuthorityBlock,
  CDRO,
  LineageLink,
  LinkRel,
  SignatureEnvelope,
  SRO,
} from './types.js'
import { SENSITIVITY_TIERS, isSensitivityTier } from './sensitivity.js'

const VALID_AUTHORITY_DECISIONS: ReadonlySet<string> = new Set([
  'allow',
  'deny',
  'defer',
  'step_up',
  'delegate',
  'revoke',
])

// Matches the output of oidOf(): "sha256:" followed by exactly 64 lowercase hex chars.
const CANONICAL_OID_RE = /^sha256:[0-9a-f]{64}$/
function isCanonicalOid(v: unknown): v is string {
  return typeof v === 'string' && CANONICAL_OID_RE.test(v)
}

export interface ValidationResult {
  ok: boolean
  errors: string[]
}

// ── CDRO validation ──────────────────────────────────────────────────────────

/**
 * Validate that `x` matches the CDRO envelope shape. Does not verify the
 * signature — use `verifySignature` for that. Does not recompute the
 * OID — use `oidOf` and compare for that.
 *
 *   [E01] not an object / null
 *   [E02] oid missing or not a non-empty string
 *   [E03] oid missing "sha256:" prefix
 *   [E04] type missing or not a non-empty string
 *   [E05] sraid_version not "2.0"
 *   [E06] tenant_id missing or not a non-empty string
 *   [E07] created_at_ms not a positive integer
 *   [E08] created_by missing or not a non-empty string
 *   [E09] body field absent (it may be any value, but must be present)
 *   [E10] supersedes, if present, not a canonical OID (sha256:<64 hex>)
 *   [E11] signature, if present, malformed envelope
 *   [E12] authority, if present, malformed block
 *   [E13] prev, if present, not a non-empty "sha256:" string
 *   [E14] links, if present, not an array of well-formed typed edges
 *   [E15] attestation, if present, malformed DSSE envelope
 *   [E16] sensitivity, if present, not a known opaque tier (s0..s4)
 */
export function validateCdro(x: unknown): ValidationResult {
  const errors: string[] = []

  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    return { ok: false, errors: ['[E01] CDRO must be a plain object'] }
  }
  const o = x as Record<string, unknown>

  if (typeof o['oid'] !== 'string' || (o['oid'] as string).length === 0) {
    errors.push('[E02] oid must be a non-empty string')
  } else if (!(o['oid'] as string).startsWith('sha256:')) {
    errors.push('[E03] oid must start with "sha256:"')
  }

  if (typeof o['type'] !== 'string' || (o['type'] as string).length === 0) {
    errors.push('[E04] type must be a non-empty string')
  }

  if (o['sraid_version'] !== '2.0') {
    errors.push('[E05] sraid_version must be "2.0"')
  }

  if (typeof o['tenant_id'] !== 'string' || (o['tenant_id'] as string).length === 0) {
    errors.push('[E06] tenant_id must be a non-empty string')
  }

  const createdAt = o['created_at_ms']
  if (typeof createdAt !== 'number' || !Number.isInteger(createdAt) || createdAt <= 0) {
    errors.push('[E07] created_at_ms must be a positive integer (Unix ms)')
  }

  if (typeof o['created_by'] !== 'string' || (o['created_by'] as string).length === 0) {
    errors.push('[E08] created_by must be a non-empty string')
  }

  if (!('body' in o)) {
    errors.push('[E09] body field must be present')
  }

  if (o['supersedes'] !== undefined) {
    if (!isCanonicalOid(o['supersedes'])) {
      errors.push('[E10] supersedes, if present, must be a canonical OID (sha256:<64 hex>)')
    }
  }

  if (o['prev'] !== undefined && o['prev'] !== null) {
    if (typeof o['prev'] !== 'string' || (o['prev'] as string).length === 0) {
      errors.push('[E13] prev, if present, must be a non-empty string')
    } else if (!(o['prev'] as string).startsWith('sha256:')) {
      errors.push('[E13] prev must start with "sha256:"')
    }
  }

  if (o['links'] !== undefined) {
    const linkErrors = validateLinksShape(o['links'])
    for (const e of linkErrors) errors.push('[E14] ' + e)
  }

  if (o['signature'] !== undefined) {
    const envErrors = validateSignatureEnvelopeShape(o['signature'])
    for (const e of envErrors) errors.push('[E11] ' + e)
  }

  if (o['authority'] !== undefined) {
    const authErrors = validateAuthorityBlockShape(o['authority'])
    for (const e of authErrors) errors.push('[E12] ' + e)
  }

  if (o['attestation'] !== undefined) {
    const attErrors = validateAttestationEnvelopeShape(o['attestation'])
    for (const e of attErrors) errors.push('[E15] ' + e)
  }

  if (o['sensitivity'] !== undefined && o['sensitivity'] !== null) {
    if (!isSensitivityTier(o['sensitivity'])) {
      errors.push(
        `[E16] sensitivity, if present, must be one of ${SENSITIVITY_TIERS.join('|')} ` +
          '(a coarse, opaque tier — NOT a literal category like "phi"; SPEC §7)',
      )
    }
  }

  return { ok: errors.length === 0, errors }
}

// ── Authority block validation (L4) ───────────────────────────────────────────

/**
 * Validate the shape of an L4 AuthorityBlock. This is a SHAPE check only —
 * it does NOT verify that the referenced grant exists, is signed, covers
 * the action, or is unrevoked. For real authorization verification use
 * `verifyAuthority` in authority.ts (it does binding/signature/coverage
 * locally and marks revocation/existence as resolver-dependent).
 */
export function validateAuthorityBlock(x: unknown): ValidationResult {
  const errors = validateAuthorityBlockShape(x)
  return { ok: errors.length === 0, errors }
}

function validateAuthorityBlockShape(x: unknown): string[] {
  const errors: string[] = []
  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    return ['authority must be a plain object']
  }
  const o = x as Record<string, unknown>

  if (o['grant_oid'] !== undefined) {
    if (typeof o['grant_oid'] !== 'string' || (o['grant_oid'] as string).length === 0) {
      errors.push('authority.grant_oid, if present, must be a non-empty string')
    } else if (!(o['grant_oid'] as string).startsWith('sha256:')) {
      errors.push('authority.grant_oid must start with "sha256:"')
    }
  }

  // decision may be null (the orphan / uncorrelated case) or a valid verb.
  if (o['decision'] !== undefined && o['decision'] !== null) {
    if (
      typeof o['decision'] !== 'string' ||
      !VALID_AUTHORITY_DECISIONS.has(o['decision'] as string)
    ) {
      errors.push(
        'authority.decision must be one of allow|deny|defer|step_up|delegate|revoke (or null)',
      )
    }
  }

  if (o['intent_oid'] !== undefined) {
    if (typeof o['intent_oid'] !== 'string' || (o['intent_oid'] as string).length === 0) {
      errors.push('authority.intent_oid, if present, must be a non-empty string')
    } else if (!(o['intent_oid'] as string).startsWith('sha256:')) {
      errors.push('authority.intent_oid must start with "sha256:"')
    }
  }

  return errors
}

// ── Lineage validation (L3) ───────────────────────────────────────────────────

/**
 * Validate a single L3 lineage edge ({ rel, oid }). Shape check only — it
 * does NOT resolve the target OID or check it exists / is signed / is
 * unrevoked (resolver concern). `rel` is an OPEN taxonomy: any non-empty
 * string is accepted so the format stays forward-compatible.
 */
export function validateLineageLink(x: unknown): ValidationResult {
  const errors = validateLineageLinkShape(x)
  return { ok: errors.length === 0, errors }
}

function validateLineageLinkShape(x: unknown): string[] {
  const errors: string[] = []
  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    return ['link must be a plain object { rel, oid }']
  }
  const o = x as Record<string, unknown>
  if (typeof o['rel'] !== 'string' || (o['rel'] as string).length === 0) {
    errors.push('link.rel must be a non-empty string')
  }
  if (typeof o['oid'] !== 'string' || (o['oid'] as string).length === 0) {
    errors.push('link.oid must be a non-empty string')
  } else if (!(o['oid'] as string).startsWith('sha256:')) {
    errors.push('link.oid must start with "sha256:"')
  }
  return errors
}

function validateLinksShape(x: unknown): string[] {
  if (!Array.isArray(x)) return ['links, if present, must be an array']
  const errors: string[] = []
  for (let i = 0; i < x.length; i++) {
    const edgeErrors = validateLineageLinkShape(x[i])
    for (const e of edgeErrors) errors.push(`links[${i}]: ${e}`)
  }
  return errors
}

// ── Signature envelope validation ────────────────────────────────────────────

/**
 * Validate the shape of a SignatureEnvelope. Useful when verifying a
 * detached signature or when a caller wants a quick sanity check before
 * a more expensive verifySignature() call.
 */
export function validateSignatureEnvelope(x: unknown): ValidationResult {
  const errors = validateSignatureEnvelopeShape(x)
  return { ok: errors.length === 0, errors }
}

function validateSignatureEnvelopeShape(x: unknown): string[] {
  const errors: string[] = []
  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    return ['signature envelope must be a plain object']
  }
  const o = x as Record<string, unknown>
  if (typeof o['ed25519'] !== 'string' || (o['ed25519'] as string).length === 0) {
    errors.push('signature.ed25519 must be a non-empty base64 string')
  }
  if (typeof o['ml_dsa_65'] !== 'string' || (o['ml_dsa_65'] as string).length === 0) {
    errors.push('signature.ml_dsa_65 must be a non-empty base64 string')
  }
  if (typeof o['signer_kid'] !== 'string' || (o['signer_kid'] as string).length === 0) {
    errors.push('signature.signer_kid must be a non-empty string')
  }
  return errors
}

// ── DSSE attestation envelope validation (L2) ─────────────────────────────────

/**
 * Validate the shape of a DSSE `AttestationEnvelope`. Shape check only — it
 * does NOT verify the signatures (use `verifyAttestation` in attestation.ts
 * for that) and does NOT enforce the hybrid both-required policy (the
 * verifier does). It checks: `payloadType` is a non-empty string, `payload`
 * is a string, and `signatures` is an array of well-formed `{ alg, sig }`
 * entries.
 */
export function validateAttestationEnvelope(x: unknown): ValidationResult {
  const errors = validateAttestationEnvelopeShape(x)
  return { ok: errors.length === 0, errors }
}

function validateAttestationEnvelopeShape(x: unknown): string[] {
  const errors: string[] = []
  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    return ['attestation must be a plain object']
  }
  const o = x as Record<string, unknown>
  if (typeof o['payloadType'] !== 'string' || (o['payloadType'] as string).length === 0) {
    errors.push('attestation.payloadType must be a non-empty string')
  }
  if (typeof o['payload'] !== 'string') {
    errors.push('attestation.payload must be a string')
  }
  if (!Array.isArray(o['signatures'])) {
    errors.push('attestation.signatures must be an array')
  } else {
    const sigs = o['signatures'] as unknown[]
    for (let i = 0; i < sigs.length; i++) {
      const s = sigs[i]
      if (s === null || typeof s !== 'object' || Array.isArray(s)) {
        errors.push(`attestation.signatures[${i}] must be a plain object { alg, sig }`)
        continue
      }
      const se = s as Record<string, unknown>
      if (typeof se['alg'] !== 'string' || (se['alg'] as string).length === 0) {
        errors.push(`attestation.signatures[${i}].alg must be a non-empty string`)
      }
      if (typeof se['sig'] !== 'string' || (se['sig'] as string).length === 0) {
        errors.push(`attestation.signatures[${i}].sig must be a non-empty base64 string`)
      }
      if (se['keyid'] !== undefined && typeof se['keyid'] !== 'string') {
        errors.push(`attestation.signatures[${i}].keyid, if present, must be a string`)
      }
    }
  }
  return errors
}

// ── SRO validation ───────────────────────────────────────────────────────────

/**
 * Validate that `x` matches the SRO shape — a CDRO whose `type` is
 * "sraid:sro" and whose `body` carries predecessor/successor pointers and
 * an authorizer. Reuses validateCdro and layers SRO-specific checks on
 * top.
 *
 *   [S01] envelope is not a valid CDRO
 *   [S02] type is not "sraid:sro"
 *   [S03] body.predecessor_oid not a canonical OID (sha256:<64 hex>)
 *   [S04] body.successor_oid not a canonical OID (sha256:<64 hex>)
 *   [S05] body.reason not a non-empty string
 *   [S06] body.authorized_by not a non-empty string
 *   [S07] body.evidence_oids, if present, not an array of non-empty strings
 */
export function validateSro(x: unknown): ValidationResult {
  const cdroResult = validateCdro(x)
  if (!cdroResult.ok) {
    return { ok: false, errors: cdroResult.errors.map((e) => '[S01] ' + e) }
  }
  const errors: string[] = []
  const o = x as { type?: unknown; body?: unknown }

  if (o.type !== 'sraid:sro') {
    errors.push('[S02] type must be "sraid:sro" for an SRO')
  }
  if (o.body === null || typeof o.body !== 'object' || Array.isArray(o.body)) {
    errors.push('[S01] body must be an object')
    return { ok: false, errors }
  }
  const b = o.body as Record<string, unknown>

  if (!isCanonicalOid(b['predecessor_oid'])) {
    errors.push('[S03] body.predecessor_oid must be a canonical OID (sha256:<64 hex>)')
  }
  if (!isCanonicalOid(b['successor_oid'])) {
    errors.push('[S04] body.successor_oid must be a canonical OID (sha256:<64 hex>)')
  }
  if (typeof b['reason'] !== 'string' || (b['reason'] as string).length === 0) {
    errors.push('[S05] body.reason must be a non-empty string')
  }
  if (typeof b['authorized_by'] !== 'string' || (b['authorized_by'] as string).length === 0) {
    errors.push('[S06] body.authorized_by must be a non-empty string')
  }
  if (b['evidence_oids'] !== undefined) {
    if (!Array.isArray(b['evidence_oids'])) {
      errors.push('[S07] body.evidence_oids, if present, must be an array')
    } else {
      const arr = b['evidence_oids'] as unknown[]
      for (let i = 0; i < arr.length; i++) {
        if (typeof arr[i] !== 'string' || (arr[i] as string).length === 0) {
          errors.push(`[S07] body.evidence_oids[${i}] must be a non-empty string`)
        }
      }
    }
  }

  return { ok: errors.length === 0, errors }
}

// Type-only re-exports so consumers can do `import type { CDRO, SRO } from '@synoi/sraid'`
// after pulling validators from this module.
export type {
  AttestationEnvelope,
  AttestationSignature,
  AuthorityBlock,
  CDRO,
  LineageLink,
  LinkRel,
  SRO,
  SignatureEnvelope,
}
