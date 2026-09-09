/**
 * @synoi/sraid — internal/base64-validate.ts
 *
 * Pure strict standard-base64 (RFC 4648 §4, with `=` padding) VALIDATION.
 *
 * INTERNAL: not exported from any public entry.
 *
 * This is the Buffer-free, node:crypto-free half of base64 handling, split out
 * so the browser decoder (./base64-browser.ts) can validate without importing
 * ./base64.ts (whose `decodeBase64Strict` uses the node `Buffer` global — safe
 * in node, a runtime `ReferenceError` in a browser). The node decoder re-uses
 * this same validator, so both paths reject exactly the same inputs.
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
  // so an in-body `=` cannot pass STD_B64.

  // CANONICAL ENCODING: the unused trailing bits of the final quantum MUST be
  // zero (RFC 4648 §3.5). Without this, one byte string has MANY valid base64
  // encodings and every one of them decodes identically:
  //
  //   1 pad char  ("...X=")  the last data char carries 4 real bits + 2 free
  //   2 pad chars ("...X==") the last data char carries 2 real bits + 4 free
  //
  // An Ed25519 signature is 64 bytes, so its encoding ends in `==` and has
  // FOUR free bits: 16 distinct `sig` strings decode to the same signature and,
  // before this check, all 16 verified. That breaks uniqueness anywhere a
  // SERIALIZED receipt is treated as the identity of a thing — transparency-log
  // leaves, Merkle batch membership, dedup and idempotency keys — because the
  // same signature can be presented under 16 different strings.
  //
  // ML-DSA-65 at 3309 bytes is a multiple of 3, so it has no padding and is
  // unaffected; the check is a no-op there.
  //
  // An earlier version of this comment reasoned only about pad POSITION and
  // concluded "no extra check needed". That was wrong: position was never the
  // hazard, the free bits were.
  const padded = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0
  if (padded !== 0) {
    const lastData = s.charCodeAt(s.length - padded - 1)
    const value = B64_VALUE[lastData]
    if (value === undefined) throw new Error('base64-malformed')
    // 2 pad chars leave 4 free low bits; 1 pad char leaves 2 free low bits.
    const freeBitMask = padded === 2 ? 0b001111 : 0b000011
    if ((value & freeBitMask) !== 0) throw new Error('base64-malformed')
  }
}

/**
 * Char code -> 6-bit value for the standard alphabet. Built once; `undefined`
 * for any char outside it (those are already rejected by STD_B64, so the lookup
 * is a defensive second gate rather than the primary one).
 */
const B64_VALUE: Record<number, number> = (() => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const table: Record<number, number> = {}
  for (let i = 0; i < alphabet.length; i++) table[alphabet.charCodeAt(i)] = i
  return table
})()
