/**
 * @synoi/sraid — sensitivity.ts
 *
 * L4 GOVERNANCE — the propagating sensitivity label (OBJECT_MODEL_CLEANSHEET
 * §3.4, SRAID_FOUNDATION_PUNCHLIST A5). A single coarse, OPAQUE tier on the
 * CDRO that retrieval, summarization, and consolidation MUST carry forward
 * monotonically: a derived object inherits the HIGHEST tier among its sources,
 * so a summary of high-sensitivity inputs cannot be downgraded.
 *
 * ── Why the tiers are OPAQUE ORDINALS, not literal categories ───────────────
 *
 * SPEC §7 is normative and explicit: the envelope is a NON-encrypted, signed,
 * publicly visible surface. A literal classification label (e.g. `"phi"`,
 * `"health"`, `"financial"`) on that surface would LEAK the nature of the
 * encrypted `body` — an observer who cannot read the ciphertext could still
 * read "this is health data" off the envelope. SPEC §7 therefore requires a
 * "coarse, OPAQUE sensitivity classifier", and the §9 reserved note says the
 * same.
 *
 * So the tier set here is a small, COARSE, ORDERED ladder of opaque levels
 * (`s0` < `s1` < `s2` < `s3` < `s4`). It carries an ORDERING (needed for the
 * monotone `max()` lattice — standard lattice-based information-flow labeling,
 * Denning 1976) but NO semantic category. The mapping from a regulatory
 * category (PHI, PII, secret, …) to a tier is a higher-layer POLICY concern
 * kept OFF the public envelope: an operator's policy decides "PHI → s3"
 * privately; the wire only ever shows `s3`. This is the "coarse, opaque tier
 * (or opaque policy-scope handle)" required by the task and SPEC §7.
 *
 * The field is hashed into the OID (it is a content-core field; see
 * `cdroContentCore` in oid.ts), so it cannot be silently stripped or
 * downgraded without changing the OID and breaking the signature.
 *
 * NOTE on maturity (CLAIMS_DISCIPLINE): this module ships the FIELD, the
 * lattice, the monotone `max()` carry-forward, and the validator, with
 * vectors. The commitment-based selective-disclosure scheme that would
 * CONCEAL the tier itself (SPEC §7 / §9) is reserved and NOT built here.
 */

/**
 * The coarse, opaque sensitivity tiers, lowest to highest. These are ORDINAL
 * and OPAQUE by design — they convey relative sensitivity for the monotone
 * propagation lattice WITHOUT naming a content category (per SPEC §7, a
 * literal category on the public envelope would leak what the encrypted body
 * is). The mapping of a real-world classification to a tier is private policy,
 * not part of this taxonomy.
 *
 *   s0 — lowest / unclassified (the default floor; freely shareable)
 *   s1 — low
 *   s2 — moderate
 *   s3 — high
 *   s4 — highest / most restricted
 *
 * Five coarse levels is deliberate: enough granularity for a useful lattice,
 * few enough to stay coarse (so the tier alone is weakly distinguishing).
 */
export type SensitivityTier = 's0' | 's1' | 's2' | 's3' | 's4'

/**
 * The ordered tier ladder, lowest-first. The index IS the rank used by the
 * `max()` lattice. Frozen so the ordering is immutable at runtime.
 */
export const SENSITIVITY_TIERS: readonly SensitivityTier[] = Object.freeze([
  's0',
  's1',
  's2',
  's3',
  's4',
] as const)

/** The default tier for an object that declares none — the lattice floor. */
export const SENSITIVITY_DEFAULT: SensitivityTier = 's0'

const RANK: ReadonlyMap<string, number> = new Map(
  SENSITIVITY_TIERS.map((t, i) => [t, i]),
)

/** True iff `x` is a defined `SensitivityTier`. */
export function isSensitivityTier(x: unknown): x is SensitivityTier {
  return typeof x === 'string' && RANK.has(x)
}

/**
 * The ordinal rank of a tier (0 = lowest). Throws on an unknown tier so a
 * typo can never silently rank as the floor (which would be a downgrade
 * footgun in the lattice).
 */
export function sensitivityRank(tier: SensitivityTier): number {
  const r = RANK.get(tier)
  if (r === undefined) {
    throw new RangeError(`sensitivityRank: "${String(tier)}" is not a known tier`)
  }
  return r
}

/**
 * The monotone lattice join: the HIGHER (more restricted) of two tiers.
 * `max('s1','s3') === 's3'`. This is the per-pair operation behind
 * carry-forward.
 */
export function sensitivityMax(
  a: SensitivityTier,
  b: SensitivityTier,
): SensitivityTier {
  return sensitivityRank(a) >= sensitivityRank(b) ? a : b
}

/**
 * Carry-forward over a set of source tiers: the highest tier present.
 *
 * This is the rule that makes sensitivity MONOTONE under derivation
 * (retrieval / summarization / consolidation): a derived object's tier =
 * max(tiers of all its `consolidated_from` / `derived_from` sources). It can
 * only ever go UP, never down — a summary of high-sensitivity inputs stays at
 * the highest input tier.
 *
 * `undefined`/absent source tiers are treated as the floor (`s0`): a source
 * that declared no tier cannot pull the result down, and an explicit higher
 * source always wins. An empty input set returns the floor.
 */
export function sensitivityCarryForward(
  sources: ReadonlyArray<SensitivityTier | undefined | null>,
): SensitivityTier {
  let acc: SensitivityTier = SENSITIVITY_DEFAULT
  for (const s of sources) {
    if (s === undefined || s === null) continue
    if (!isSensitivityTier(s)) {
      throw new RangeError(
        `sensitivityCarryForward: "${String(s)}" is not a known tier`,
      )
    }
    acc = sensitivityMax(acc, s)
  }
  return acc
}

/**
 * Guard a proposed sensitivity assignment against monotone violation: the
 * `proposed` tier of a derived object MUST be at least as high as the
 * carry-forward of its `sources`. Returns the floor the derived object is NOT
 * allowed to fall below, plus whether `proposed` honors it.
 *
 * Use this to REJECT an attempt to label a summary of `s3` inputs as `s1`.
 */
export function sensitivityMonotoneCheck(
  proposed: SensitivityTier,
  sources: ReadonlyArray<SensitivityTier | undefined | null>,
): { ok: boolean; floor: SensitivityTier; proposed: SensitivityTier } {
  const floor = sensitivityCarryForward(sources)
  return {
    ok: sensitivityRank(proposed) >= sensitivityRank(floor),
    floor,
    proposed,
  }
}
