/**
 * @synoi/sraid — public surface.
 *
 * SRAID (Self-Routing Addressable Identity Data) is L0 of the SynOI SRAID Stack:
 *
 *   L0 SRAID            ← this package
 *   L1 Vault / Resolver
 *   L2 Inference Broker / Resonance
 *   L3 GAP (Governed Action Protocol)
 *   L4 Apps
 *
 * This package is intentionally small: types, canonical serializer,
 * OID computation, hybrid signature verification, and shape validators.
 * No storage, no HTTP, no governance — those are higher layers.
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
  SRO,
  SROBody,
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

// L2 DSSE attestation — PAE type-binding, hybrid Ed25519 + ML-DSA-65 both
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

// L3 lineage (Merkle-DAG) — unify supersedes/SRO/prev; latest-wins resolution.
export {
  lineageLinks,
  supersededOids,
  latestWins,
  type LatestWinsResult,
} from './lineage.js'

// L4 propagating sensitivity — coarse, opaque tier + monotone max() carry-forward.
export {
  SENSITIVITY_TIERS,
  SENSITIVITY_DEFAULT,
  isSensitivityTier,
  sensitivityRank,
  sensitivityMax,
  sensitivityCarryForward,
  sensitivityMonotoneCheck,
} from './sensitivity.js'

// L4 authority verification (the authorized axis).
export {
  verifyAuthority,
  capabilityCovers,
  type VerifyAuthorityInput,
  type VerifyAuthorityResult,
  type AuthorityResolver,
  type GrantStatus,
  type GrantBodyShape,
} from './authority.js'

// L4 delegation-chain verification (K2) — VERIFY-ONLY, offline, no enforcement.
// Always reports revocation_checked/existence_checked false (no live claim).
export {
  verifyDelegationChain,
  MAX_DELEGATION_DEPTH,
  type VerifyDelegationChainInput,
  type VerifyDelegationChainResult,
  type HopResult,
  type LinkPubkeys,
} from './authority.js'

// Shape validators.
export {
  validateCdro,
  validateSro,
  validateSignatureEnvelope,
  validateAttestationEnvelope,
  validateAuthorityBlock,
  validateLineageLink,
  type ValidationResult,
} from './validate.js'
