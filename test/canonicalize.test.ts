/**
 * test/canonicalize.test.ts — deterministic JSON canonicalization.
 *
 * Critical contract: the bytes produced here MUST match the recursive
 * canonicalizer in synoi-gateway (src/inference/receipts.ts +
 * src/gap/oid.ts). If these tests start producing different output,
 * every existing signed receipt and every existing GAP OID stops
 * verifying.
 */

import { createHash } from 'node:crypto'
import { canonicalize } from '../src/canonicalize.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Key-order independence ────────────────────────────────────────────────

const a = canonicalize({ b: 2, a: 1 })
const b = canonicalize({ a: 1, b: 2 })
ok('object key order does not affect output', a === b, `${a} vs ${b}`)
ok('canonical form of {a:1,b:2} is "{\\"a\\":1,\\"b\\":2}"', a === '{"a":1,"b":2}', a)

// ── Round-trip ────────────────────────────────────────────────────────────

const sample = { foo: 'hello', bar: [1, 2, 3], nested: { z: true, a: null } }
const cstr = canonicalize(sample)
const parsed = JSON.parse(cstr)
// Round-trip definition: re-canonicalizing the parsed object yields the
// same bytes. (Comparing raw JSON.stringify output would fail because the
// original retains its insertion order while the canonical form sorts —
// that's the point of canonicalization, not a round-trip violation.)
ok(
  'canonicalize round-trips through JSON.parse without losing information',
  canonicalize(parsed) === cstr,
  `canonical=${cstr} re-canonical=${canonicalize(parsed)}`,
)

// ── undefined is omitted ──────────────────────────────────────────────────

ok(
  'undefined property is omitted',
  canonicalize({ a: undefined, b: 1 }) === '{"b":1}',
  canonicalize({ a: undefined, b: 1 }),
)
ok(
  'undefined-only object yields {}',
  canonicalize({ a: undefined }) === '{}',
  canonicalize({ a: undefined }),
)

// ── null is preserved ────────────────────────────────────────────────────

ok('null is preserved as null', canonicalize({ a: null }) === '{"a":null}')
ok('top-level null', canonicalize(null) === 'null')

// ── Primitives ────────────────────────────────────────────────────────────

ok('string', canonicalize('hi') === '"hi"')
ok('number', canonicalize(42) === '42')
ok('boolean true', canonicalize(true) === 'true')
ok('boolean false', canonicalize(false) === 'false')

// ── Arrays preserve order ─────────────────────────────────────────────────

ok('arrays preserve order', canonicalize([3, 1, 2]) === '[3,1,2]')
ok('nested arrays', canonicalize([[1, 2], [3, 4]]) === '[[1,2],[3,4]]')

// ── Fixed vector test (proves byte-level match with gateway impl) ────────
//
// The bytes for canonicalize({foo:1, bar:"hi"}) are LOAD-BEARING. They
// match what synoi-gateway/src/gap/oid.ts produces today. If this
// changes, every existing GAP OID stops verifying.

const vector = canonicalize({ foo: 1, bar: 'hi' })
ok(
  'canonicalize({foo:1, bar:"hi"}) === \'{"bar":"hi","foo":1}\'',
  vector === '{"bar":"hi","foo":1}',
  vector,
)

// Match gateway's exact recursive form for a more complex case.
function gatewayCanonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(gatewayCanonicalize).join(',') + ']'
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + gatewayCanonicalize(obj[k])).join(',') + '}'
}

const complex = {
  z: [1, { c: 3, a: { y: 2, x: 1 } }, null],
  a: 'first',
  m: { quoted: '"escaped"', newline: 'line\nbreak', emoji: '😀' },
  flag: false,
}
ok(
  'complex value matches gateway impl byte-for-byte',
  canonicalize(complex) === gatewayCanonicalize(complex),
  `ours=${canonicalize(complex)}\n   their=${gatewayCanonicalize(complex)}`,
)

// And produces stable SHA-256 over the bytes (sanity check that the
// downstream hash is also deterministic).
const h1 = createHash('sha256').update(canonicalize({ a: 1, b: 2 })).digest('hex')
const h2 = createHash('sha256').update(canonicalize({ b: 2, a: 1 })).digest('hex')
ok('sha256 of canonical form is stable across key permutations', h1 === h2, `${h1} vs ${h2}`)

// ── Strict RFC 8785: NaN and Infinity MUST be rejected ───────────────────
//
// RFC 8785 §3.2.2.3 forbids non-finite numbers. The previous "JCS-lite"
// behavior silently coerced them to null, which would corrupt an OID or
// signature. The strict implementation throws instead.

function throws(label: string, fn: () => unknown): void {
  let threw = false
  try { fn() } catch (_e) { threw = true }
  ok(label, threw)
}

throws('canonicalize(NaN) throws TypeError', () => canonicalize(NaN))
throws('canonicalize(Infinity) throws TypeError', () => canonicalize(Infinity))
throws('canonicalize(-Infinity) throws TypeError', () => canonicalize(-Infinity))
throws('canonicalize({a: NaN}) throws TypeError', () => canonicalize({ a: NaN }))
throws('canonicalize([1, Infinity, 2]) throws TypeError', () => canonicalize([1, Infinity, 2]))

// ── ADR_019: non-integer numbers (floats) are FORBIDDEN ──────────────────
//
// A number is legal iff it is a finite integer. Floats are rejected BEFORE
// hashing so a float-bearing object cannot mint an OID on one surface that
// another declares malformed (matches GAP-TS / GAP-Python). This removes the
// hardest RFC 8785 cross-language serialization trap on a signed byte string.

throws('canonicalize(1.5) throws (float forbidden)', () => canonicalize(1.5))
throws('canonicalize(0.1) throws (float forbidden)', () => canonicalize(0.1))
throws('canonicalize(2e-3) throws (float forbidden)', () => canonicalize(2e-3))
throws('canonicalize({amount: 9.99}) throws (float forbidden)', () => canonicalize({ amount: 9.99 }))
throws('canonicalize([1, 2.5, 3]) throws (float array element)', () => canonicalize([1, 2.5, 3]))
throws('canonicalize(nested float throws)', () => canonicalize({ a: { b: [{ c: 3.14 }] } }))

// Integers of both signs are accepted and serialize plainly.
ok('canonicalize(1000) === "1000"', canonicalize(1000) === '1000', canonicalize(1000))
ok('canonicalize(-42) === "-42"', canonicalize(-42) === '-42', canonicalize(-42))
ok('canonicalize(0) === "0"', canonicalize(0) === '0', canonicalize(0))

// ── ADR_019: the -0 special-case is DELETED; -0 is an integer that
// JSON.stringify renders as "0", so the normative behavior is unchanged
// without a bespoke branch (one fewer divergence source).

ok('canonicalize(-0) === "0" (via integer path, no special-case)', canonicalize(-0) === '0', canonicalize(-0))
ok(
  'canonicalize({z: -0}) === \'{"z":0}\'',
  canonicalize({ z: -0 }) === '{"z":0}',
  canonicalize({ z: -0 }),
)

// ── Reject-loud: out-of-domain inputs throw, never corrupt the bytes ───────
//
// Regression for two confirmed defects:
//   (1) an undefined / function / symbol ARRAY element produced invalid JSON
//       like "[1,,2]" (unparseable, index-shifting).
//   (2) a Date (or any toJSON-bearing object) silently canonicalized to "{}",
//       forking the OID vs JSON.stringify / RFC 8785.
// Both now throw a TypeError instead of emitting a wrong/invalid form.

throws('undefined array element throws (no "[1,,2]")', () => canonicalize([1, undefined, 2]))
throws('function array element throws', () => canonicalize([1, () => {}, 2]))
throws('symbol array element throws', () => canonicalize([Symbol('x')]))
throws('nested undefined array element throws', () => canonicalize({ a: [1, undefined] }))
throws('Date throws (must serialize first, not "{}")', () => canonicalize(new Date('2026-01-01T00:00:00.000Z')))
throws('object with a Date value throws', () => canonicalize({ when: new Date('2026-01-01T00:00:00.000Z') }))
throws('object with a custom toJSON throws', () => canonicalize({ toJSON: () => 'x', a: 1 }))
throws('bare undefined throws', () => canonicalize(undefined))
throws('bigint throws', () => canonicalize(10n))

// Sparse-array HOLES are distinct from an explicit `undefined` element and were
// not caught by the map()-based walk (map skips holes entirely), so a hole slid
// through to join() and emitted invalid JSON like "[1,,2]". A hole is now
// rejected loudly, exactly as an explicit undefined element is.
// eslint-disable-next-line no-sparse-arrays
throws('sparse array hole throws (no "[1,,2]")', () => canonicalize([1, , 2]))
throws('leading sparse hole throws', () => canonicalize(Array(2)))
// eslint-disable-next-line no-sparse-arrays
throws('trailing sparse hole throws', () => canonicalize([1, 2, , ]))
// eslint-disable-next-line no-sparse-arrays
throws('nested sparse hole throws', () => canonicalize({ a: [1, , 3] }))

// Positive controls: the things that must STILL work.
ok('null array element is preserved', canonicalize([1, null, 2]) === '[1,null,2]', canonicalize([1, null, 2]))
ok('undefined OBJECT property is still omitted', canonicalize({ a: undefined, b: 1 }) === '{"b":1}', canonicalize({ a: undefined, b: 1 }))
ok(
  'plain nested object still canonicalizes',
  canonicalize({ b: [1, 2], a: { z: null } }) === '{"a":{"z":null},"b":[1,2]}',
  canonicalize({ b: [1, 2], a: { z: null } }),
)

// ── Done ──────────────────────────────────────────────────────────────────

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
