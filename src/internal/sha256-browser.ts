/**
 * @synoi/sraid — internal/sha256-browser.ts
 *
 * Browser-safe SHA-256 via WebCrypto (`globalThis.crypto.subtle.digest`). NO
 * node:crypto. Used by the browser OID helpers in verify-browser.ts.
 *
 * ASYNC: subtle.digest is Promise-based, so the browser OID helpers are async
 * (the node oid.ts helpers stay synchronous via node:crypto createHash and are
 * unchanged). SHA-256 is byte-identical across any conformant implementation,
 * so a browser-computed OID equals the node-computed one for the same input.
 */

function toHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] as number).toString(16).padStart(2, '0')
  }
  return out
}

/**
 * Compute `sha256:` + lowercase hex of SHA-256(bytes) using WebCrypto. Mirrors
 * the `sha256:`-prefixed output of the node oid.ts helpers.
 */
export async function sha256HexPrefixed(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  return 'sha256:' + toHex(new Uint8Array(digest))
}
