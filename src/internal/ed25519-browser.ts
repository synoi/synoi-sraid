/**
 * @synoi/sraid — internal/ed25519-browser.ts
 *
 * Browser-safe Ed25519 verification. NO node:crypto.
 *
 * Primary path: WebCrypto (`globalThis.crypto.subtle`), which uses RFC 8032
 * cofactored verification — the SAME rule OpenSSL/node:crypto uses on the node
 * default entry, so the browser verifier accepts/rejects exactly what the node
 * verifier does for every real signature.
 *
 * Fallback path: `@noble/curves` ed25519 (pure JS), used only when WebCrypto
 * Ed25519 is unavailable (older embedded webviews / Chrome extensions below the
 * WebCrypto-Ed25519 support floor, ~Chrome 137). @noble defaults to ZIP-215
 * verification rules, which agree with cofactored on every well-formed
 * signature and can differ only on deliberately malformed/malleable points that
 * real signers never produce (see ed25519.ts for the same note). SynOI signs
 * canonically, so the fallback is behavior-equivalent for legitimate inputs.
 *
 * ASYNC: WebCrypto verify is Promise-based, so this returns a Promise<boolean>.
 * The browser attestation verifier is async as a result; the node path stays
 * synchronous and unchanged.
 *
 * Returns false (never throws) on any malformed input or verification failure,
 * matching the node `verifyEd25519` contract, so callers get a clean boolean.
 */

import { ed25519 } from '@noble/curves/ed25519.js'

// Fixed DER prefix for an Ed25519 SubjectPublicKeyInfo (RFC 8410):
//   SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (32 raw bytes) }
// A plain Uint8Array literal (NOT Buffer, which is undefined in browsers). Used
// only for the SPKI import fallback below.
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])

const ED25519_ALG = { name: 'Ed25519' } as const

// Return type is inferred (webcrypto.CryptoKey); the bare `CryptoKey` global is
// not declared by @types/node ^20, so it is deliberately left un-annotated.
async function importPublicKey(publicKeyRaw: Uint8Array) {
  const subtle = globalThis.crypto.subtle
  try {
    // Preferred: raw 32-byte import (Secure Curves spec).
    return await subtle.importKey('raw', publicKeyRaw, ED25519_ALG, false, ['verify'])
  } catch {
    // Some engines only accept SPKI for Ed25519 import; wrap the raw key.
    const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + publicKeyRaw.length)
    spki.set(ED25519_SPKI_PREFIX, 0)
    spki.set(publicKeyRaw, ED25519_SPKI_PREFIX.length)
    return await subtle.importKey('spki', spki, ED25519_ALG, false, ['verify'])
  }
}

/**
 * Verify a raw 64-byte Ed25519 signature over `message` against a raw 32-byte
 * public key. Prefers WebCrypto (cofactored, matching the node path); falls
 * back to @noble/curves only when WebCrypto Ed25519 is not supported. Returns
 * false on any malformed input or verification failure; never throws.
 */
export async function verifyEd25519Browser(
  signature: Uint8Array,
  message: Uint8Array,
  publicKeyRaw: Uint8Array,
): Promise<boolean> {
  if (publicKeyRaw.length !== 32) return false

  const subtle = globalThis.crypto?.subtle
  if (subtle) {
    try {
      const key = await importPublicKey(publicKeyRaw)
      return await subtle.verify(ED25519_ALG, key, signature, message)
    } catch {
      // Fall through to @noble. A WebCrypto throw here is either an
      // unsupported-algorithm signal or a malformed input; @noble resolves both
      // correctly (a real bad signature/key verifies as false there too).
    }
  }

  try {
    return ed25519.verify(signature, message, publicKeyRaw)
  } catch {
    return false
  }
}
