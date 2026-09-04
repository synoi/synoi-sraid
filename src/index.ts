/**
 * @synoi/sraid — public surface.
 *
 * SRAID is the object-identity layer: it defines what a signed object IS and
 * how anyone re-derives and verifies its identity offline.
 *
 * Scope, precisely:
 *   IN   canonical serializer, OID computation, hybrid Ed25519 + ML-DSA-65
 *        attestation verification, lineage resolution, shape validators.
 *   OUT  storage, transport, key resolution, revocation, policy, enforcement.
 *
 * It verifies SIGNATURES, not IDENTITIES: `signer_kid` is an opaque string
 * this package never resolves, and nothing here checks revocation. Deciding
 * whether a key was trusted at signing time is a caller/directory concern.
 */

// Types
export type {
  AttestationEnvelope,
  AttestationSignature,
  AuthorityBlock,
  AuthorityDecision,
  CDRO,
  LineageLink,
  LinkRel,
  SensitivityTier,
  SignatureEnvelope,
} from './types.js'

// Canonical serializer — byte-identical to synoi-gateway + @synoi/vault.
export { canonicalize } from './canonicalize.js'

// OID computation — value-level and full-CDRO content-core helpers.
export { oidOf, oidOfCanonical, cdroOid, cdroContentCore, CDRO_ENVELOPE_FIELDS } from './oid.js'

// Hybrid Ed25519 + ML-DSA-65 signature verification (LEGACY bare-bytes path).
export {
  verifySignature,
  type VerifySignatureInput,
  type VerifySignatureResult,
} from './signature.js'

// ML-DSA-65 verification with a native node:crypto fast path (OpenSSL 3.5+ /
// Node 24+) and a transparent @noble fallback on older runtimes. Both paths
// are byte-identical; `isNativeMlDsaAvailable()` reports which is active.
export { verifyMlDsa65, isNativeMlDsaAvailable } from './mldsa.js'

// Coordinated key-cache revocation. The internal bounded LRU key caches
// (ed25519 + ml-dsa-65) are keyed by lowercase hex of the RAW public-key
// bytes; `evictKeyFromCaches(keyId)` drops that entry from every cache so a
// rotated or compromised key cannot be served stale on a later verify.
export { evictKeyFromCaches } from './internal/key-cache.js'

// DSSE attestation — PAE type-binding, hybrid Ed25519 + ML-DSA-65 both
// required. The preferred signing path (replaces the legacy bare-bytes
// SignatureEnvelope; closes the cross-type confusion gap SRAID F7 / A4).
export {
  verifyAttestation,
  pae,
  ALG_ED25519,
  ALG_ML_DSA_65,
  type VerifyAttestationInput,
  type VerifyAttestationResult,
} from './attestation.js'

// Lineage (Merkle-DAG) — unify the `supersedes` string with the identity-bound
// `prev`/`links` edges; latest-wins resolution over a version set.
export {
  lineageLinks,
  supersededOids,
  latestWins,
  type LatestWinsResult,
} from './lineage.js'

// Propagating sensitivity — coarse, opaque tier + monotone max() carry-forward.
export {
  SENSITIVITY_TIERS,
  SENSITIVITY_DEFAULT,
  isSensitivityTier,
  sensitivityRank,
  sensitivityMax,
  sensitivityCarryForward,
  sensitivityMonotoneCheck,
} from './sensitivity.js'

// Capability matching + the live-grant-status contract. The leaf primitive a
// grant store needs: pure string logic, no crypto, no I/O, no live claim.
export { capabilityCovers } from './capability.js'
export type { AuthorityResolver, GrantStatus } from './capability.js'

// Shape validators.
export {
  validateCdro,
  validateSignatureEnvelope,
  validateAttestationEnvelope,
  validateAuthorityBlock,
  validateLineageLink,
  type ValidationResult,
} from './validate.js'

// MOVED IN 0.4.0 — the grant and delegation-chain VERIFIERS (`verifyAuthority`,
// `verifyDelegationChain`, `MAX_DELEGATION_DEPTH`) are authorization policy,
// not object identity, and are no longer exported from this entry. They live
// at the `@synoi/sraid/authority` subpath, unchanged and still verify-only.
//
// `capabilityCovers`, `AuthorityResolver` and `GrantStatus` did NOT move: they
// are the leaf primitive and the contract, and are exported above.
//
// REMOVED IN 0.4.0 — `validateSro`, `SRO`, `SROBody`. See CHANGELOG 0.4.0.
