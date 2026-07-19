/**
 * @synoi/sraid — internal/mldsa-browser.ts
 *
 * Browser-safe ML-DSA-65 (FIPS 204) verification. NO node:crypto.
 *
 * Browsers ship no native ML-DSA, so there is only one path here: the pure-JS
 * `@noble/post-quantum` implementation, which is fully browser-safe. The node
 * default entry (mldsa.ts) uses a native OpenSSL fast path with this same
 * @noble impl as its fallback, so both entries are byte-for-byte interoperable.
 *
 * IMPORTANT: import `ml_dsa65` DIRECTLY from `@noble/post-quantum/ml-dsa.js`,
 * NOT from ./mldsa.ts — that module statically imports `node:crypto` (for its
 * native fast path and the globalThis.crypto polyfill), which would poison a
 * browser bundle. No globalThis.crypto polyfill is needed here: browsers,
 * workers, and MV3 service workers all provide it natively, and ml_dsa65.verify
 * is deterministic (it never calls getRandomValues; only keygen/sign do).
 *
 * Verification is SYNCHRONOUS. Returns false (never throws) on any malformed
 * input or verification failure, matching the node `verifyMlDsa65` contract.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

/**
 * Verify a raw ML-DSA-65 signature over `message` against a raw 1952-byte
 * public key using @noble/post-quantum. Returns false on any malformed input or
 * verification failure; never throws.
 */
export function verifyMlDsa65Browser(
  signature: Uint8Array,
  message: Uint8Array,
  publicKeyRaw: Uint8Array,
): boolean {
  try {
    return ml_dsa65.verify(signature, message, publicKeyRaw)
  } catch {
    return false
  }
}
