/**
 * test/lineage.test.ts — L3 lineage (Merkle-DAG): typed links, prev edge,
 * supersession unification, latest-wins / monotone resolution, and the
 * identity-binding of lineage into the OID.
 */

import { lineageLinks, supersededOids, latestWins } from '../src/lineage.js'
import { validateCdro, validateLineageLink } from '../src/validate.js'
import { cdroOid } from '../src/oid.js'

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' — ' + detail : ''}\n`) }
}

const A = 'sha256:' + 'a'.repeat(64)
const B = 'sha256:' + 'b'.repeat(64)
const C = 'sha256:' + 'c'.repeat(64)

// ── lineageLinks: unify prev + supersedes + links ─────────────────────────

ok('lineageLinks: prev → supersedes edge',
   JSON.stringify(lineageLinks({ prev: A })) === JSON.stringify([{ rel: 'supersedes', oid: A }]))

ok('lineageLinks: legacy supersedes → supersedes edge',
   JSON.stringify(lineageLinks({ supersedes: A })) === JSON.stringify([{ rel: 'supersedes', oid: A }]))

ok('lineageLinks: prev + identical supersedes coalesce to one edge',
   lineageLinks({ prev: A, supersedes: A }).length === 1)

ok('lineageLinks: explicit supersedes link not duplicated',
   lineageLinks({ prev: A, links: [{ rel: 'supersedes', oid: A }] }).length === 1)

const mixed = lineageLinks({
  prev: A,
  links: [{ rel: 'derived_from', oid: B }, { rel: 'consolidated_from', oid: C }],
})
ok('lineageLinks: keeps typed non-supersedes edges', mixed.length === 3)
ok('lineageLinks: supersession edge first', mixed[0]?.rel === 'supersedes' && mixed[0]?.oid === A)

ok('lineageLinks: empty when no lineage', lineageLinks({}).length === 0)

// ── supersededOids ────────────────────────────────────────────────────────

ok('supersededOids: from prev + supersedes link',
   JSON.stringify(supersededOids({ prev: A, links: [{ rel: 'supersedes', oid: B }] })) ===
   JSON.stringify([A, B]))

ok('supersededOids: ignores non-supersedes rels',
   supersededOids({ links: [{ rel: 'derived_from', oid: A }] }).length === 0)

// ── latestWins: in-set supersession resolution ────────────────────────────

// v2 supersedes v1; v3 supersedes v2. Head must be v3.
const v1 = { oid: A }
const v2 = { oid: B, prev: A }
const v3 = { oid: C, prev: B }

const r3 = latestWins([v1, v2, v3])
ok('latestWins: linear chain → single head (latest)',
   r3.ok === true && r3.head === C, JSON.stringify(r3))

// Order independence — presenting the set in any order yields the same head.
const rShuffled = latestWins([v3, v1, v2])
ok('latestWins: order-independent head', rShuffled.ok === true && rShuffled.head === C)

// Replayed predecessor alone is NOT the head once a superseding object is present.
const rReplay = latestWins([v1, v3, v2])
ok('latestWins: in-set superseded version is not head',
   rReplay.head !== A && rReplay.head === C)

// A single object is trivially the head.
ok('latestWins: single version → itself is head',
   latestWins([v1]).head === A)

// Fork: two objects each supersede v1 → no single latest.
const forkX = { oid: B, prev: A }
const forkY = { oid: C, prev: A }
const rFork = latestWins([v1, forkX, forkY])
ok('latestWins: fork (concurrent heads) → ok=false', rFork.ok === false)
ok('latestWins: fork reason mentions fork',
   rFork.reasons.some((s) => s.includes('fork')), JSON.stringify(rFork.reasons))

// Cycle: B supersedes A, A supersedes B → no head.
const cycA = { oid: A, prev: B }
const cycB = { oid: B, prev: A }
const rCycle = latestWins([cycA, cycB])
ok('latestWins: supersession cycle → ok=false', rCycle.ok === false)
// Both OIDs of the cycle must appear in the reason (CLAIMS_DISCIPLINE).
ok('latestWins: cycle reason includes both offending OIDs',
   rCycle.reasons.some((s) => s.includes(A) && s.includes(B)),
   JSON.stringify(rCycle.reasons))

// Self-supersession is rejected.
const selfSup = { oid: A, prev: A }
ok('latestWins: self-supersession → ok=false', latestWins([selfSup]).ok === false)

// Edge pointing outside the set does not disqualify the in-hand object as head.
const orphanPrev = { oid: B, prev: A } // A not in set
ok('latestWins: edge to out-of-set predecessor still yields a head',
   latestWins([orphanPrev]).ok === true && latestWins([orphanPrev]).head === B)

ok('latestWins: empty set → ok=false', latestWins([]).ok === false)

// Legacy `supersedes` string participates in latest-wins identically to prev.
const legacyOld = { oid: A }
const legacyNew = { oid: B, supersedes: A }
ok('latestWins: legacy supersedes string resolves head',
   latestWins([legacyOld, legacyNew]).head === B)

// ── set_complete: reachability from head ──────────────────────────────────

// Linear chain: set_complete must be true when ok.
ok('latestWins: linear chain → set_complete true', r3.set_complete === true)

// Fork: set_complete false (no single head means no complete reachability).
ok('latestWins: fork → set_complete false', rFork.set_complete === false)

// Cycle (caught by head=0): set_complete false.
ok('latestWins: cycle → set_complete false', rCycle.set_complete === false)

// Diamond merge: head D supersedes B and C; both B and C supersede A.
// D → B → A, D → C → A. Two predecessors at the top, shared ancestor — legal.
const D = 'sha256:' + 'd'.repeat(64)
const diamA = { oid: A }
const diamB = { oid: B, prev: A }
const diamC = { oid: C, prev: A }
const diamD = { oid: D, links: [{ rel: 'supersedes' as const, oid: B }, { rel: 'supersedes' as const, oid: C }] }
const rDiamond = latestWins([diamA, diamB, diamC, diamD])
ok('latestWins: diamond merge → ok=true (not a cycle)',
   rDiamond.ok === true && rDiamond.head === D, JSON.stringify(rDiamond))
ok('latestWins: diamond merge → set_complete true', rDiamond.set_complete === true)

// Cycle on a non-preds[0] branch: head H supersedes P0 (clean) and P1;
// P1 creates a cycle P1 → Q → P1. The old preds[0]-only walk would descend P0
// and miss the cycle. New DFS must catch it.
const H = 'sha256:' + 'e'.repeat(64)
const P0 = 'sha256:' + 'f'.repeat(64)
const P1 = 'sha256:' + '1'.repeat(64)
const Q  = 'sha256:' + '2'.repeat(64)
// H supersedes P0 (preds[0]) and P1; P1 supersedes Q; Q supersedes P1 — cycle.
const hiddenCycH  = { oid: H,  links: [{ rel: 'supersedes' as const, oid: P0 }, { rel: 'supersedes' as const, oid: P1 }] }
const hiddenCycP0 = { oid: P0 }
const hiddenCycP1 = { oid: P1, prev: Q }
const hiddenCycQ  = { oid: Q,  prev: P1 }
const rHiddenCyc = latestWins([hiddenCycH, hiddenCycP0, hiddenCycP1, hiddenCycQ])
ok('latestWins: cycle on non-preds[0] branch → ok=false (regression proof)',
   rHiddenCyc.ok === false, JSON.stringify(rHiddenCyc))
ok('latestWins: hidden cycle reason includes cycle OIDs (P1 and Q)',
   rHiddenCyc.reasons.some((s) => s.includes(P1) && s.includes(Q)),
   JSON.stringify(rHiddenCyc.reasons))

// Note: ok=true with set_complete=false is structurally impossible in a sound
// version set. Any in-set node that is not a head must be superseded by some
// in-set node, which is itself reachable from the head (otherwise it would be
// a second head, creating a fork). So set_complete=false always co-occurs with
// ok=false. The fork and cycle cases above cover the set_complete=false path.

// ── Validation of prev + links ────────────────────────────────────────────

const baseCdro = {
  oid: 'sha256:' + 'd'.repeat(64),
  type: 'sraid:test',
  sraid_version: '2.0' as const,
  tenant_id: 't-home',
  created_at_ms: 1716840000000,
  created_by: 'actor:test',
  body: { x: 1 },
}

ok('validateCdro: valid prev + links → ok',
   validateCdro({ ...baseCdro, prev: A, links: [{ rel: 'derived_from', oid: B }] }).ok === true)

const badPrev = validateCdro({ ...baseCdro, prev: 'not-a-sha' })
ok('validateCdro: bad prev → [E13]',
   badPrev.ok === false && badPrev.errors.some((e) => e.startsWith('[E13]')))

const badLinks = validateCdro({ ...baseCdro, links: [{ rel: '', oid: 'nope' }] })
ok('validateCdro: malformed link → [E14]',
   badLinks.ok === false && badLinks.errors.some((e) => e.startsWith('[E14]')))

const badLinksType = validateCdro({ ...baseCdro, links: 'not-an-array' })
ok('validateCdro: links not array → [E14]',
   badLinksType.ok === false && badLinksType.errors.some((e) => e.startsWith('[E14]')))

ok('validateLineageLink: well-formed edge ok',
   validateLineageLink({ rel: 'supersedes', oid: A }).ok === true)
ok('validateLineageLink: rejects non-sha256 oid',
   validateLineageLink({ rel: 'supersedes', oid: 'x' }).ok === false)
ok('validateLineageLink: accepts unknown rel (open taxonomy)',
   validateLineageLink({ rel: 'some_future_rel', oid: A }).ok === true)

// ── Identity-binding: lineage is hashed into the OID ──────────────────────

const noLineage = { ...baseCdro }
const withPrev = { ...baseCdro, prev: A }
const withLinks = { ...baseCdro, links: [{ rel: 'derived_from', oid: B }] }
const withPrevRepointed = { ...baseCdro, prev: C }

ok('OID changes when prev is added (lineage identity-bound)',
   cdroOid(noLineage) !== cdroOid(withPrev))
ok('OID changes when links are added (lineage identity-bound)',
   cdroOid(noLineage) !== cdroOid(withLinks))
ok('OID changes when prev is re-pointed (no silent rollback)',
   cdroOid(withPrev) !== cdroOid(withPrevRepointed))
ok('OID stable for identical lineage',
   cdroOid({ ...baseCdro, prev: A }) === cdroOid({ ...baseCdro, prev: A }))

// ── Summary ────────────────────────────────────────────────────────────────
process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
