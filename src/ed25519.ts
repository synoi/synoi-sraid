/**
 * @synoi/sraid — ed25519.ts
 *
 * Native Ed25519 verification via node:crypto (OpenSSL). Verifying RFC 8032
 * Ed25519 signatures with the platform crypto is materially faster than a
 * pure-JS implementation (~30x on the verify op) and produces the same
 * accept/reject result for all standard signatures.
 *
 * NOTE on verification semantics: node:crypto / OpenSSL uses RFC 8032
 * cofactored verification. Some pure-JS libraries (e.g. @noble) default to
 * ZIP-215 batch-compatible rules, which accept a slightly larger set of
 * non-canonical edge-case points. The two agree on every well-formed
 * signature; they can differ only on deliberately malformed/malleable points
 * that real signers never produce. SynOI signs canonically, so this is a
 * tightening, not a behavior change, but it is called out for maintainers.
 *
 * The public API takes a RAW 32-byte Ed25519 public key; this module wraps it
 * in the fixed SPKI DER prefix to build a KeyObject.
 */

import { createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto'

import { BoundedKeyCache, KEY_CACHE_MAX } from './internal/key-cache.js'

// Fixed DER prefix for an Ed25519 SubjectPublicKeyInfo (RFC 8410):
//   SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (32 raw bytes) }
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

// Small bounded LRU: building a KeyObject parses DER, so cache by raw-key hex.
// Bounded so an attacker streaming distinct keys cannot grow it without limit.
const keyCache = new BoundedKeyCache<KeyObject>(KEY_CACHE_MAX)

function keyObjectFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error('ed25519 public key must be 32 bytes')
  const hex = Buffer.from(raw).toString('hex')
  let ko = keyCache.get(hex)
  if (!ko) {
    const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)])
    ko = createPublicKey({ key: der, format: 'der', type: 'spki' })
    keyCache.set(hex, ko)
  }
  return ko
}

/**
 * Verify a raw 64-byte Ed25519 signature over `message` against a raw 32-byte
 * public key. Returns false (never throws) on any malformed input or
 * verification failure, so callers get a clean boolean.
 */
export function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKeyRaw: Uint8Array,
): boolean {
  try {
    return nodeVerify(null, message, keyObjectFromRaw(publicKeyRaw), signature)
  } catch {
    return false
  }
}
