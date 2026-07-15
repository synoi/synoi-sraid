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
 *
 * The strict VALIDATION (alphabet/length/padding) lives in the pure, Buffer-
 * free ./base64-validate.ts so the browser decoder can share it; this module
 * adds the node `Buffer`-based decode on top and re-exports `assertBase64` so
 * existing importers of `./base64.js` are unchanged.
 */

import { assertBase64 } from './base64-validate.js'

export { assertBase64 }

/**
 * Strictly decode standard base64 to raw bytes. Throws
 * Error('base64-malformed') on any non-conforming input.
 */
export function decodeBase64Strict(s: string): Uint8Array {
  assertBase64(s)
  return new Uint8Array(Buffer.from(s, 'base64'))
}
