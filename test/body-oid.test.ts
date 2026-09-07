/**
 * test/body-oid.test.ts — the payload id.
 *
 * `cdroOid` is ISSUANCE-addressed: its input keeps `tenant_id`,
 * `created_at_ms` and `created_by`, so the same payload recorded twice gives
 * two unrelated ids. That is right for a receipt and useless for dedup.
 * `bodyOid` is the complement: the id of the content, invariant across who
 * recorded it and when.
 *
 * These tests pin BOTH halves of that. The invariance cases are the point of
 * the function; the divergence cases are the reason it had to be separate.
 */

import { bodyOid, cdroOid, oidOf } from '../src/index.js'
import { bodyOid as browserBodyOid } from '../src/verify-browser.js'
import { webcrypto } from 'node:crypto'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log('OK  ', label)
    passed++
  } else {
    console.error('FAIL', label, detail)
    failed++
  }
}

const body = { patient: 'p-1', hr: 72 }
const mk = (over: Record<string, unknown> = {}) => ({
  type: 'obs',
  sraid_version: '2.0' as const,
  tenant_id: 't-a',
  created_at_ms: 1000,
  created_by: 'actor:demo',
  body,
  ...over,
})

// ── bodyOid is invariant across the issuance fields ──────────────────────────

const base = mk()
ok('same payload, later timestamp → same bodyOid',
   bodyOid(base) === bodyOid(mk({ created_at_ms: 1001 })))
ok('same payload, other tenant → same bodyOid',
   bodyOid(base) === bodyOid(mk({ tenant_id: 't-b' })))
ok('same payload, other actor → same bodyOid',
   bodyOid(base) === bodyOid(mk({ created_by: 'actor:other' })))
ok('same payload, other type → same bodyOid',
   bodyOid(base) === bodyOid(mk({ type: 'other' })))

// ── cdroOid is NOT invariant — this is why both exist ────────────────────────

ok('same payload, later timestamp → DIFFERENT cdroOid',
   cdroOid(base) !== cdroOid(mk({ created_at_ms: 1001 })))
ok('same payload, other tenant → DIFFERENT cdroOid',
   cdroOid(base) !== cdroOid(mk({ tenant_id: 't-b' })))

// ── bodyOid still tracks the payload ─────────────────────────────────────────

ok('different payload → different bodyOid',
   bodyOid(base) !== bodyOid(mk({ body: { patient: 'p-1', hr: 73 } })))
ok('key order in body is irrelevant (JCS sorts)',
   bodyOid(mk({ body: { a: 1, b: 2 } })) === bodyOid(mk({ body: { b: 2, a: 1 } })))

// ── it is exactly oidOf(body), and never equal to the identity ───────────────

ok('bodyOid(obj) === oidOf(obj.body)', bodyOid(base) === oidOf(body))
ok('bodyOid !== cdroOid for the same object', bodyOid(base) !== cdroOid(base))

// ── attaching an attestation changes neither ─────────────────────────────────

const attested = { ...base, attestation: { payloadType: 't', payload: 'p', signatures: [] } }
ok('bodyOid invariant across signing', bodyOid(attested) === bodyOid(base))
ok('cdroOid invariant across signing', cdroOid(attested) === cdroOid(base))

// ── rejects bad input rather than inventing an id ────────────────────────────

for (const [label, input] of [
  ['null', null], ['string', 'nope'], ['array', [1, 2]], ['number', 7],
] as [string, unknown][]) {
  let threw = false
  try { bodyOid(input) } catch { threw = true }
  ok(`bodyOid(${label}) throws`, threw)
}
let noBodyThrew = false
try { bodyOid({ type: 'obs' }) } catch { noBodyThrew = true }
ok('bodyOid on an object with no body throws', noBodyThrew)

// A body that is legitimately null/false is hashable, not an error.
ok('body: null is hashable', typeof bodyOid(mk({ body: null })) === 'string')

// ── node / browser parity ────────────────────────────────────────────────────

const parity = await browserBodyOid(base)
ok('browser bodyOid === node bodyOid', parity === bodyOid(base), `${parity} vs ${bodyOid(base)}`)

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
