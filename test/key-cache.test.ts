/**
 * test/key-cache.test.ts — BoundedKeyCache LRU + coordinated eviction + strict
 * base64 decode.
 *
 * Proves: oldest-out eviction at capacity, LRU-on-access promotion, identity
 * preservation on hit, evictKeyFromCaches fan-out + no-op safety, and that
 * decodeBase64Strict rejects malformed input that Buffer.from would silently
 * truncate.
 */

import { BoundedKeyCache, evictKeyFromCaches } from '../src/internal/key-cache.js'
import { decodeBase64Strict, assertBase64 } from '../src/internal/base64.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Oldest-out eviction at capacity ──────────────────────────────────────────
{
  const c = new BoundedKeyCache<number>(1000)
  for (let i = 0; i < 1001; i++) c.set(`k${i}`, i)
  ok('cap 1000: size === 1000 after 1001 inserts', c.size === 1000, String(c.size))
  ok('cap 1000: oldest (k0) evicted', c.get('k0') === undefined)
  ok('cap 1000: newest (k1000) present', c.get('k1000') === 1000)
}

// ── LRU-on-access promotion ──────────────────────────────────────────────────
{
  const c = new BoundedKeyCache<number>(1000)
  for (let i = 0; i < 1000; i++) c.set(`k${i}`, i)
  // Touch k0 → promotes it to MRU. k1 is now the oldest.
  ok('promote: k0 readable before overflow', c.get('k0') === 0)
  c.set('k1000', 1000) // overflow by one → evicts current oldest
  ok('promote: k0 SURVIVES (was promoted)', c.get('k0') === 0)
  ok('promote: k1 EVICTED (became oldest)', c.get('k1') === undefined)
}

// ── Identity preservation on hit ─────────────────────────────────────────────
{
  const c = new BoundedKeyCache<{ id: number }>(10)
  const obj = { id: 42 }
  c.set('a', obj)
  ok('hit returns SAME reference', c.get('a') === obj)
}

// ── Coordinated eviction fan-out + no-op safety ──────────────────────────────
{
  const a = new BoundedKeyCache<number>(10)
  const b = new BoundedKeyCache<number>(10)
  a.set('shared-hex', 1)
  // b never held it; evict must remove from a and be a harmless no-op on b.
  evictKeyFromCaches('shared-hex')
  ok('evict removes from holding cache', a.get('shared-hex') === undefined)
  let threw = false
  try { evictKeyFromCaches('never-existed') } catch { threw = true }
  ok('evict of absent key does not throw', threw === false)
  ok('evict no-op leaves b untouched', b.size === 0)
}

// ── decodeBase64Strict: valid input round-trips ──────────────────────────────
{
  const raw = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f])
  const b64 = Buffer.from(raw).toString('base64') // '3q2+7wB/'
  const back = decodeBase64Strict(b64)
  ok('valid base64 decodes byte-identically',
     back.length === raw.length && back.every((v, i) => v === raw[i]),
     b64)
}

// ── decodeBase64Strict: rejects malformed (Buffer.from would TRUNCATE) ────────
{
  // '@' is outside the alphabet. Buffer.from('AA@AAAAA','base64') silently
  // truncates; strict decode must throw 'base64-malformed'.
  const cases = [
    'AA@AAAAA',      // illegal char mid-string
    'AAA',           // length not multiple of 4
    'AAAAA',         // length not multiple of 4
    'A===',          // too much padding
    '====',          // pad-only
    'AB=A',          // pad not trailing
    ' AAAA',         // leading whitespace
    'AAAA ',         // trailing whitespace
  ]
  for (const c of cases) {
    let msg = ''
    try { decodeBase64Strict(c); msg = '<no throw>' } catch (e) { msg = (e as Error).message }
    ok(`reject ${JSON.stringify(c)} → base64-malformed`, msg === 'base64-malformed', msg)
  }
  // assertBase64 accepts a canonical padded value.
  let assertThrew = false
  try { assertBase64('3q2+7wB/') } catch { assertThrew = true }
  ok('assertBase64 accepts valid padded base64', assertThrew === false)
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
