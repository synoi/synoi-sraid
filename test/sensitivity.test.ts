/**
 * test/sensitivity.test.ts — L4 propagating sensitivity (SRAID A5, SPEC §7):
 * the coarse OPAQUE tier ladder, the monotone max() lattice, carry-forward
 * over a mix of tiers, the no-downgrade guard, validation of the field, and
 * the identity-binding of the tier into the OID.
 */

import {
  SENSITIVITY_TIERS,
  SENSITIVITY_DEFAULT,
  isSensitivityTier,
  sensitivityRank,
  sensitivityMax,
  sensitivityCarryForward,
  sensitivityMonotoneCheck,
} from '../src/sensitivity.js'
import { validateCdro } from '../src/validate.js'
import { cdroOid } from '../src/oid.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

// ── Tier ladder is coarse, ordered, opaque ────────────────────────────────

ok('tiers: five coarse levels s0..s4', SENSITIVITY_TIERS.length === 5)
ok('tiers: ordinal opaque (no literal category strings)',
   SENSITIVITY_TIERS.every((t) => /^s[0-4]$/.test(t)))
ok('tiers: default is the floor s0', SENSITIVITY_DEFAULT === 's0')
ok('tiers: ranks are strictly increasing',
   sensitivityRank('s0') < sensitivityRank('s1') &&
   sensitivityRank('s1') < sensitivityRank('s2') &&
   sensitivityRank('s2') < sensitivityRank('s3') &&
   sensitivityRank('s3') < sensitivityRank('s4'))

// ── isSensitivityTier guard ───────────────────────────────────────────────

ok('isSensitivityTier: accepts s3', isSensitivityTier('s3'))
ok('isSensitivityTier: rejects literal category "phi"', !isSensitivityTier('phi'))
ok('isSensitivityTier: rejects "s5"', !isSensitivityTier('s5'))
ok('isSensitivityTier: rejects non-string', !isSensitivityTier(3))

// ── sensitivityMax: the lattice join ──────────────────────────────────────

ok('max(s1,s3) = s3 (higher wins)', sensitivityMax('s1', 's3') === 's3')
ok('max(s3,s1) = s3 (order-independent)', sensitivityMax('s3', 's1') === 's3')
ok('max(s2,s2) = s2 (idempotent)', sensitivityMax('s2', 's2') === 's2')

// ── sensitivityCarryForward: the core proof (mix of tiers → max) ──────────

ok('carry-forward: mix [s1,s3,s0,s2] → s3 (highest wins)',
   sensitivityCarryForward(['s1', 's3', 's0', 's2']) === 's3')
ok('carry-forward: mix [s0,s4,s1] → s4 (highest wins)',
   sensitivityCarryForward(['s0', 's4', 's1']) === 's4')
ok('carry-forward: absent/null sources do not pull result down',
   sensitivityCarryForward(['s2', undefined, null]) === 's2')
ok('carry-forward: empty set → floor s0',
   sensitivityCarryForward([]) === SENSITIVITY_DEFAULT)
ok('carry-forward: cannot be downgraded by summarization (all-high in stays high)',
   sensitivityCarryForward(['s4', 's4']) === 's4')
let threw = false
try { sensitivityCarryForward(['s1', 'phi' as never]) } catch { threw = true }
ok('carry-forward: throws on an unknown (literal) tier, never silently floors', threw)

// ── sensitivityMonotoneCheck: the no-downgrade guard ──────────────────────

const downgrade = sensitivityMonotoneCheck('s1', ['s3', 's0'])
ok('monotone-check: labeling a summary of s3 inputs as s1 is REJECTED',
   downgrade.ok === false && downgrade.floor === 's3')
const honored = sensitivityMonotoneCheck('s3', ['s3', 's1'])
ok('monotone-check: labeling at the carry-forward floor is allowed', honored.ok === true)
const raised = sensitivityMonotoneCheck('s4', ['s2'])
ok('monotone-check: raising above the floor is allowed', raised.ok === true)

// ── validateCdro: the field is validated as an opaque tier ─────────────────

const baseCdro = {
  oid: 'sha256:' + '0'.repeat(64),
  type: 'sraid:test',
  sraid_version: '2.0' as const,
  tenant_id: 't1',
  created_at_ms: 1,
  created_by: 'sha256:' + 'a'.repeat(64),
  body: { hello: 'world' },
}

ok('validateCdro: valid sensitivity s3 → ok',
   validateCdro({ ...baseCdro, sensitivity: 's3' }).ok)
ok('validateCdro: absent sensitivity → ok (optional)',
   validateCdro(baseCdro).ok)
const litRes = validateCdro({ ...baseCdro, sensitivity: 'phi' })
ok('validateCdro: literal category "phi" → [E16] (leak-prevention)',
   !litRes.ok && litRes.errors.some((e) => e.startsWith('[E16]')))
const badRes = validateCdro({ ...baseCdro, sensitivity: 's9' })
ok('validateCdro: out-of-range tier "s9" → [E16]',
   !badRes.ok && badRes.errors.some((e) => e.startsWith('[E16]')))

// ── Identity-binding: the tier is hashed into the OID ─────────────────────

ok('OID changes when sensitivity is added (identity-bound)',
   cdroOid(baseCdro) !== cdroOid({ ...baseCdro, sensitivity: 's2' }))
ok('OID changes when sensitivity is downgraded (no silent strip/downgrade)',
   cdroOid({ ...baseCdro, sensitivity: 's3' }) !==
   cdroOid({ ...baseCdro, sensitivity: 's1' }))
ok('OID stable for identical sensitivity',
   cdroOid({ ...baseCdro, sensitivity: 's2' }) ===
   cdroOid({ ...baseCdro, sensitivity: 's2' }))

// ── Summary ────────────────────────────────────────────────────────────────
process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
