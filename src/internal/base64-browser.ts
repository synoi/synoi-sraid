/**
 * @synoi/sraid — internal/base64-browser.ts
 *
 * Strict standard-base64 (RFC 4648 §4, with `=` padding) decode for the
 * BROWSER verify surface.
 *
 * INTERNAL: not exported from any public entry.
 *
 * Why a separate decoder: the node decoder (./base64.ts `decodeBase64Strict`)
 * finishes with `Buffer.from(s, 'base64')`. `Buffer` is a NODE global that does
 * not exist in a browser / service-worker / Chrome-extension context — and,
 * crucially, it is NOT a `node:` specifier, so an esbuild `node:`-reference scan
 * would NOT catch it. A `Buffer`-based decode would bundle clean yet throw
 * `ReferenceError: Buffer is not defined` at runtime. This decoder is
 * Buffer-free: it reuses the pure `assertBase64` validation (regex/length/
 * padding only, from ./base64-validate.js — NOT ./base64.js, whose graph pulls
 * in the `Buffer` decode) and decodes via the standard `atob` global, which IS
 * available in browsers, dedicated/shared workers, and MV3 extension service
 * workers.
 *
 * Same strict contract as the node path: throws Error('base64-malformed') on
 * any deviation (illegal char, bad length, bad padding) rather than silently
 * truncating, so a malformed signature is rejected loudly, never decoded to a
 * short prefix that then "verifies" against something unintended.
 */

import { assertBase64 } from './base64-validate.js'

/**
 * Strictly decode standard base64 to raw bytes using only browser-safe globals.
 * Throws Error('base64-malformed') on any non-conforming input.
 */
export function decodeBase64StrictBrowser(s: string): Uint8Array {
  assertBase64(s)
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
