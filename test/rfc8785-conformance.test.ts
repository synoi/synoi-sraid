/**
 * test/rfc8785-conformance.test.ts — strict RFC 8785 (JCS) conformance.
 *
 * Runs the OFFICIAL reference test vectors from the RFC 8785 reference
 * implementation (cyberphone/json-canonicalization, testdata/) against our
 * `canonicalize`. Each `vectors/rfc8785/input/<name>.json` is parsed and
 * canonicalized; the result MUST equal `vectors/rfc8785/output/<name>.json`
 * byte-for-byte.
 *
 * This is the credibility gate for publishing the canonicalizer as an open
 * standard: it proves conformance against the spec's own reference suite,
 * not just hand-written examples. See vectors/rfc8785/SOURCE.md.
 *
 * NUMBER DOMAIN (ADR_019). The SynOI SRAID serializer is a DOCUMENTED SUBSET
 * of RFC 8785: it forbids non-integer numbers (floats). The parts of JCS that
 * SRAID relies on — UTF-16 code-unit key ordering and minimal string escaping
 * — are conformed byte-for-byte here. The `values` reference vector carries a
 * genuine float array; SRAID forbids floats, so it is asserted to REJECT
 * (throw) rather than to match a float output. (`structures` carries `56.0`,
 * but JSON.parse collapses that to the integer 56 before canonicalize ever
 * sees it, so it canonicalizes cleanly and stays a byte-for-byte MATCH.) This
 * is not a JCS regression on ordering/escaping; it is the number-domain
 * narrowing the ADR mandates.
 */

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize } from '../src/canonicalize.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const dir = path.join(__dirname, 'vectors', 'rfc8785')

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// Structural / string / ordering vectors: MUST match the reference output
// byte-for-byte (this is the JCS key-ordering + escaping conformance the ADR
// says NOT to regress).
const MATCH_NAMES = ['arrays', 'french', 'structures', 'unicode', 'weird']

// Genuine-float reference vector: SRAID forbids non-integer numbers
// (ADR_019), so canonicalizing this MUST throw. `values` carries
// [333333333.33333329, 1E30, 4.50, 2e-3, 1e-27]. (`structures`'s 56.0 is not
// here: JSON.parse collapses it to the integer 56, so it is a MATCH vector.)
const REJECT_NAMES = ['values']

for (const name of MATCH_NAMES) {
  const input = readFileSync(path.join(dir, 'input', `${name}.json`), 'utf8')
  const expected = readFileSync(path.join(dir, 'output', `${name}.json`), 'utf8').replace(/\n$/, '')
  let got: string
  try {
    got = canonicalize(JSON.parse(input))
  } catch (e) {
    ok(`RFC 8785 vector "${name}"`, false, `threw ${(e as Error).message}`)
    continue
  }
  let detail: string | undefined
  if (got !== expected) {
    let i = 0
    while (i < Math.min(got.length, expected.length) && got[i] === expected[i]) i++
    detail = `first diff @${i}: expected ${JSON.stringify(expected.slice(i, i + 20))} got ${JSON.stringify(got.slice(i, i + 20))}`
  }
  ok(`RFC 8785 vector "${name}" matches reference output byte-for-byte`, got === expected, detail)
}

for (const name of REJECT_NAMES) {
  const input = readFileSync(path.join(dir, 'input', `${name}.json`), 'utf8')
  let threw = false
  try {
    canonicalize(JSON.parse(input))
  } catch (_e) {
    threw = true
  }
  ok(`RFC 8785 float vector "${name}" is REJECTED (floats forbidden, ADR_019)`, threw)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
