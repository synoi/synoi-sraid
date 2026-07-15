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
  // so an in-body `=` cannot pass STD_B64. No extra check needed.
}
