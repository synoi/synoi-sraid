/**
 * @synoi/sraid — mldsa.ts
 *
 * ML-DSA-65 (FIPS 204) verification with a native fast path.
 *
 * When the runtime ships OpenSSL 3.5+ (Node 24+), node:crypto exposes a
 * native `ml-dsa-65` key type whose verify is materially faster than the
 * pure-JS @noble/post-quantum implementation: ~207µs vs ~1.6ms verify, a
 * ~7.8x op-level speedup measured on Node 24.16.0 / OpenSSL 3.5.6
 * (bench/mldsa-verify.mjs).
 *
 * This module feature-detects native ML-DSA-65 support ONCE at first use and
 * routes verification accordingly:
 *   • native available  → node:crypto (OpenSSL)
 *   • native absent      → @noble/post-quantum fallback
 *
 * Both paths are byte-for-byte interoperable: a signature minted by either
 * implementation verifies identically under the other, and tampered or
 * wrong-key inputs fail under both (see test/mldsa-kat.test.ts cross-impl
 * known-answer vectors). The native path is therefore a transparent
 * performance swap, NOT a behavior change. Node < 24 keeps working unchanged.
 *
 * The public API takes a RAW ML-DSA-65 public key (1952 bytes) and a RAW
 * signature (3309 bytes), matching the @noble surface. The native path wraps
 * the raw key in the fixed SubjectPublicKeyInfo DER prefix to build a
 * KeyObject; @noble consumes the raw bytes directly.
 */

import { createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto'

import { webcrypto } from 'node:crypto'
// Node 18 doesn't expose globalThis.crypto.getRandomValues by default, and the
// @noble libraries expect it during module initialization. Idempotent polyfill
// — MUST run BEFORE the @noble/post-quantum import below so ml_dsa65's
// module-init sees a populated globalThis.crypto.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { BoundedKeyCache, KEY_CACHE_MAX } from './internal/key-cache.js'

// Fixed DER prefix for an ML-DSA-65 SubjectPublicKeyInfo
// (draft-ietf-lamps-dilithium-certificates):
//   SEQUENCE {
//     SEQUENCE { OID 2.16.840.1.101.3.4.3.18  (id-ml-dsa-65) }
//     BIT STRING (0 unused bits || 1952 raw public-key bytes)
//   }
// The only variable part is the 1952-byte key, so the 22-byte header is
// constant for every ML-DSA-65 key.
const MLDSA65_SPKI_PREFIX = Buffer.from(
  '308207b2300b0609608648016503040312038207a100',
  'hex',
)
const MLDSA65_PUBKEY_LEN = 1952

// One-time capability detection. `undefined` = not yet probed.
let nativeAvailable: boolean | undefined

/**
 * Detect (once, then cache) whether this runtime's node:crypto can build a
 * native ML-DSA-65 public key. We probe by constructing a KeyObject from a
 * structurally-valid dummy SPKI: OpenSSL 3.5+ accepts it and reports
 * asymmetricKeyType === 'ml-dsa-65'; older OpenSSL throws ("Failed to read
 * asymmetric key"). The probe does NOT verify anything, so a dummy key body
 * is fine — only the algorithm support is being detected.
 */
function detectNative(): boolean {
  if (nativeAvailable !== undefined) return nativeAvailable
  try {
    const dummy = Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.alloc(MLDSA65_PUBKEY_LEN)])
    const ko = createPublicKey({ key: dummy, format: 'der', type: 'spki' })
    // @types/node ^20 predates the ml-dsa-* key types, so widen to string.
    nativeAvailable = (ko.asymmetricKeyType as string) === 'ml-dsa-65'
  } catch {
    nativeAvailable = false
  }
  return nativeAvailable
}

/**
 * True when this runtime verifies ML-DSA-65 via native node:crypto (OpenSSL
 * 3.5+, Node 24+). False when it falls back to @noble/post-quantum. Exposed
 * for benchmarks, diagnostics, and tests that must exercise both paths.
 */
export function isNativeMlDsaAvailable(): boolean {
  return detectNative()
}

// Small bounded LRU: building a KeyObject parses DER, so cache by raw-key hex.
// Bounded so an attacker streaming distinct keys cannot grow it without limit.
const keyCache = new BoundedKeyCache<KeyObject>(KEY_CACHE_MAX)

function keyObjectFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== MLDSA65_PUBKEY_LEN) {
    throw new Error(`ml-dsa-65 public key must be ${MLDSA65_PUBKEY_LEN} bytes`)
  }
  const hex = Buffer.from(raw).toString('hex')
  let ko = keyCache.get(hex)
  if (!ko) {
    const der = Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.from(raw)])
    ko = createPublicKey({ key: der, format: 'der', type: 'spki' })
    keyCache.set(hex, ko)
  }
  return ko
}

/**
 * Verify a raw ML-DSA-65 signature over `message` against a raw 1952-byte
 * public key. Uses the native node:crypto path when available, otherwise
 * @noble/post-quantum. Returns false (never throws) on any malformed input or
 * verification failure, so callers get a clean boolean.
 */
export function verifyMlDsa65(
  signature: Uint8Array,
  message: Uint8Array,
  publicKeyRaw: Uint8Array,
): boolean {
  if (detectNative()) {
    try {
      return nodeVerify(null, message, keyObjectFromRaw(publicKeyRaw), signature)
    } catch {
      return false
    }
  }
  try {
    return ml_dsa65.verify(signature, message, publicKeyRaw)
  } catch {
    return false
  }
}
