/**
 * test/proto-pollution.test.ts — the __proto__ OID collision.
 *
 * Written BEFORE the fix (it failed 9 assertions against <=0.4.0) and now
 * passing. It states the defect executably so a regression cannot pass
 * silently. Panel recommendation 2: no vector, no claim.
 *
 * THE RULE: an own `__proto__` member is REJECTED. `canonicalize` and
 * `validateCdro` ([E17]) both refuse it, so a polluted object has no canonical
 * form and therefore no OID to collide with. `cdroContentCore` additionally
 * builds via `Object.fromEntries`, so a caller who never validates still
 * cannot be handed a prototype-polluted object. Shallow by design: see the
 * note in canonicalize.ts, and vector P-04.
 *
 * The defect it fixes: internal/content-core.ts built the core with assignment
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

/**
 * OID of an object, or the sentinel REJECTED if the library refuses to
 * canonicalize it. Under the REJECT rule a polluted object has no canonical
 * form at all, which satisfies "must not collide" more strongly than a merely
 * different hash would: there is nothing to collide with.
 */
const REJECTED = Symbol('rejected')
function oidOrRejected(o: unknown): string | symbol {
  try {
    return cdroOid(o)
  } catch {
    return REJECTED
  }
}

/** Does the object carry `__proto__` as its OWN member? */
function hasOwnProto(o: unknown): boolean {
  return typeof o === 'object' && o !== null && Object.keys(o as object).includes('__proto__')
}

const clean = JSON.parse(V.clean_object_json)
const cleanOid = cdroOid(clean) // the clean object must always canonicalize
const byId = new Map<string, unknown>()
for (const c of V.cases) byId.set(c.id, JSON.parse(c.object_json))

for (const c of V.cases) {
  const obj = byId.get(c.id)!
  const e = c.expect

  if (e.must_not_collide_with_clean) {
    const got = oidOrRejected(obj)
    ok(
      `${c.id} ${c.name}`,
      got !== cleanOid,
      `both are ${cleanOid}`,
    )
  }

  if (e.must_not_collide_with_case) {
    const other = byId.get(e.must_not_collide_with_case)!
    const a = oidOrRejected(obj)
    const b = oidOrRejected(other)
    // Two REJECTED objects have no OID, so they cannot collide.
    ok(
      `${c.id} must not collide with ${e.must_not_collide_with_case}`,
      a === REJECTED || b === REJECTED || a !== b,
      `both are ${String(a)}`,
    )
  }

  if (e.projections_must_agree) {
    // Either BOTH projections reject it, or both see the member. What must
    // never happen again is one dropping it while the other hashes it.
    let canonicalRejected = false
    let inCanonical = false
    try {
      inCanonical = canonicalize(obj).includes('__proto__')
    } catch {
      canonicalRejected = true
    }
    const inCore = hasOwnProto(cdroContentCore(obj))
    ok(
      `${c.id} canonicalize and cdroContentCore agree on __proto__`,
      canonicalRejected || inCanonical === inCore,
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
    // A throw is the strongest possible rejection.
    const payload = canonicalize(cdroContentCore(clean))
    let bindingRejects: boolean
    try {
      bindingRejects = payload !== canonicalize(cdroContentCore(obj))
    } catch {
      bindingRejects = true
    }
    ok(
      `${c.id} binding check rejects the polluted object`,
      bindingRejects,
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
