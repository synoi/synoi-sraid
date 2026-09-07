/**
 * test/proto-pollution.test.ts — the __proto__ OID collision.
 *
 * WRITTEN BEFORE THE FIX. This file is EXPECTED TO FAIL against <=0.4.0. Its
 * job is to state the defect executably, so the fix has an oracle and so a
 * regression cannot pass silently. Panel recommendation 2: no vector, no claim.
 *
 * The defect: internal/content-core.ts builds the core with plain assignment
 * (`core[k] = v`). For `k === '__proto__'` that invokes the prototype setter
 * instead of creating an own property, so the member is dropped. `canonicalize`
 * uses `Object.keys`, which DOES return an own `__proto__` (which is exactly
 * what `JSON.parse` produces). The library's two projections disagree, so two
 * objects with different content share one OID — and the binding check
 * `att.payload === canonicalize(cdroContentCore(x))` accepts the polluted
 * object because BOTH sides drop the member identically.
 *
 * Vectors live in test/vectors/proto-pollution.json as RAW JSON TEXT so the
 * same cases can be lifted into synoi-conformance for the Rust / Python / Go
 * SDKs, which treat `__proto__` as an ordinary key and therefore compute a
 * DIFFERENT OID for the same bytes today — a hard interop split with no vector
 * covering it until now.
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { cdroOid, cdroContentCore, validateCdro } from '../src/index.js'
import { canonicalize } from '../src/canonicalize.js'

const here = dirname(fileURLToPath(import.meta.url))
const V = JSON.parse(readFileSync(join(here, 'vectors', 'proto-pollution.json'), 'utf8'))

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

/** Does the object carry `__proto__` as its OWN member? */
function hasOwnProto(o: unknown): boolean {
  return typeof o === 'object' && o !== null && Object.keys(o as object).includes('__proto__')
}

const clean = JSON.parse(V.clean_object_json)
const cleanOid = cdroOid(clean)
const byId = new Map<string, unknown>()
for (const c of V.cases) byId.set(c.id, JSON.parse(c.object_json))

for (const c of V.cases) {
  const obj = byId.get(c.id)!
  const e = c.expect

  if (e.must_not_collide_with_clean) {
    ok(
      `${c.id} ${c.name}`,
      cdroOid(obj) !== cleanOid,
      `both are ${cleanOid}`,
    )
  }

  if (e.must_not_collide_with_case) {
    const other = byId.get(e.must_not_collide_with_case)!
    ok(
      `${c.id} must not collide with ${e.must_not_collide_with_case}`,
      cdroOid(obj) !== cdroOid(other),
      `both are ${cdroOid(obj)}`,
    )
  }

  if (e.projections_must_agree) {
    // canonicalize sees the member; cdroContentCore must not silently drop it.
    const inCanonical = canonicalize(obj).includes('__proto__')
    const inCore = hasOwnProto(cdroContentCore(obj))
    ok(
      `${c.id} canonicalize and cdroContentCore agree on __proto__`,
      inCanonical === inCore,
      `canonicalize=${inCanonical} core=${inCore}`,
    )
  }

  if (e.core_must_not_be_prototype_polluted) {
    const core = cdroContentCore(obj) as Record<string, unknown>
    ok(
      `${c.id} content core is not prototype-polluted`,
      Object.getPrototypeOf(core) === Object.prototype && core['escalated'] === undefined,
      `escalated=${String(core['escalated'])}`,
    )
  }

  if (e.binding_must_reject) {
    // The check every production consumer performs before trusting an object.
    const payload = canonicalize(cdroContentCore(clean))
    ok(
      `${c.id} binding check rejects the polluted object`,
      payload !== canonicalize(cdroContentCore(obj)),
      'polluted object produced the clean payload',
    )
  }

  if (e.reject === true) {
    ok(
      `${c.id} validateCdro rejects an own __proto__ member`,
      validateCdro(obj).ok === false,
      'accepted with zero errors',
    )
  }

  if (e.reject === false) {
    ok(
      `${c.id} validateCdro accepts (negative control)`,
      validateCdro(obj).ok === true,
      JSON.stringify(validateCdro(obj).errors),
    )
  }

  if (e.member_must_survive_into_core) {
    const k = e.member_must_survive_into_core as string
    ok(
      `${c.id} '${k}' survives into the content core and is hashed`,
      Object.keys(cdroContentCore(obj)).includes(k),
      `core keys: ${Object.keys(cdroContentCore(obj)).join(', ')}`,
    )
  }
}

console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) {
  console.error(
    '\nEXPECTED against <=0.4.0. internal/content-core.ts uses plain assignment,\n' +
      'so an own __proto__ member is dropped from the core while canonicalize\n' +
      'still sees it. Fix: build the core with a null-prototype accumulator or\n' +
      'Object.fromEntries over filtered entries, and reject __proto__ in\n' +
      'validateCdro and canonicalize.',
  )
}
process.exit(failed > 0 ? 1 : 0)
