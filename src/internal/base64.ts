/**
 * @synoi/sraid — internal/base64.ts
 *
 * Strict standard-base64 (RFC 4648 §4, with `=` padding) decode.
 *
 * INTERNAL: not exported from index.ts.
 *
 * Why strict: `Buffer.from(s, 'base64')` silently TRUNCATES at the first byte
 * outside the alphabet and tolerates missing/extra padding. On a signature-
 * verification path that is dangerous — a malformed envelope must be rejected
 * loudly, not decoded to a short prefix that then "verifies" against something
 * unintended. `decodeBase64Strict` validates the alphabet, length, and padding
 * BEFORE decoding and throws on any deviation.
 *
 * Canonical inputs carry no surrounding whitespace, so no trim is applied;
 * leading/trailing whitespace is itself a rejection.
 */

// Standard base64 alphabet; `=` only as 1-2 trailing pad chars. Total length
// must be a multiple of 4.
const STD_B64 = /^[A-Za-z0-9+/]*={0,2}$/

/**
 * Validate strict standard base64. Throws Error('base64-malformed') on any
 * non-conforming input.
 */
export function assertBase64(s: string): void {
  if (typeof s !== 'string') throw new Error('base64-malformed')
  if (s.length % 4 !== 0) throw new Error('base64-malformed')
  if (!STD_B64.test(s)) throw new Error('base64-malformed')
  // `=` may appear only in the final 1-2 positions. The regex `={0,2}` anchored
  // at end already guarantees pad chars are contiguous and trailing, but a pad
  // char earlier in the body would have been rejected by the alphabet class —
  // so an in-body `=` cannot pass STD_B64. No extra check needed.
}

/**
 * Strictly decode standard base64 to raw bytes. Throws
 * Error('base64-malformed') on any non-conforming input.
 */
export function decodeBase64Strict(s: string): Uint8Array {
  assertBase64(s)
  return new Uint8Array(Buffer.from(s, 'base64'))
}
