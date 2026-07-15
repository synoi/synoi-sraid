/**
 * test/browser-entry.test.ts — proves @synoi/sraid/verify-browser is
 * browser-safe and node-parity-correct.
 *
 * BACKGROUND: the default (`.`) entry statically imports `node:crypto` in
 * three places (ed25519.ts native Ed25519 verify, mldsa.ts native ML-DSA
 * fast path, oid.ts createHash), which does not exist in a browser /
 * Chrome-extension / service-worker context. `./verify-browser.ts` is the
 * additive, browser-safe alternative (WebCrypto Ed25519 + @noble ML-DSA-65 +
 * WebCrypto SHA-256, all Buffer-free). This file proves that claim, modeled
 * on the equivalent test shipped for @synoi/verify/browser
 * (synoi-verify test/browser-entry.test.ts, commit 944d334).
 *
 * Covers:
 *   A. STATIC BUNDLE SCAN — the reliable proof. esbuild-bundle verify-browser.ts
 *      for platform:'browser' and assert ZERO `node:` builtin references and
 *      no literal `Buffer` reference anywhere in the bundled output. A control
 *      bundle of the node default entry (index.ts) proves the scan
 *      discriminates: it DOES pull node:crypto and is not browser-clean.
 *   B. RUNTIME BUFFER-DELETION CONTROL — best-effort secondary proof. Verified
 *      first in isolation (see PR notes) that Node's global atob/btoa do NOT
 *      depend on Buffer on this Node version (v22), so this is asserted as a
 *      real check, not skipped. Buffer is restored in a finally so later test
 *      files in run-all.ts are unaffected.
 *   C. FUNCTIONAL — a known-good hybrid envelope verifies true via the browser
 *      entry; tampering (payload / each sig / wrong key / AND-policy /
 *      malformed shape / malformed base64) is rejected without throwing; and
 *      the browser entry's async verifyAttestation + oidOf/cdroOid match the
 *      node entry's sync counterparts byte-for-byte / boolean-for-boolean on
 *      the SAME vectors (node/browser parity).
 *
 * NO em dashes. No vector, no claim.
 *
 *   npx tsx test/browser-entry.test.ts
 */

import { build } from 'esbuild'
import { webcrypto, randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto

import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { canonicalize } from '../src/canonicalize.js'
import { cdroOid as cdroOidNode, oidOf as oidOfNode, oidOfCanonical as oidOfCanonicalNode } from '../src/oid.js'
import {
  verifyAttestation as verifyAttestationNode,
  ALG_ED25519,
  ALG_ML_DSA_65,
} from '../src/attestation.js'
import type { AttestationEnvelope } from '../src/types.js'

import * as browserEntry from '../src/verify-browser.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const SRC = join(HERE, '..', 'src')

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) { passed++; process.stdout.write(`OK   ${label}\n`) }
  else      { failed++; process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`) }
}

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64')
}

/**
 * Bundle one src entry for the browser and return { errors, text, messages}.
 * `format:'iife'` inlines the module graph so it can be scanned; `platform:
 * 'browser'` makes node builtins UNRESOLVABLE rather than silently external,
 * so a stray node:crypto import surfaces as either a build error or a
 * literal `node:` reference in the output.
 */
async function bundleForBrowser(
  entry: string,
): Promise<{ errors: number; text: string; messages: string }> {
  try {
    const result = await build({
      entryPoints: [join(SRC, entry)],
      bundle: true,
      write: false,
      format: 'iife',
      platform: 'browser',
      logLevel: 'silent',
    })
    const text = result.outputFiles.map((f) => f.text).join('\n')
    return { errors: 0, text, messages: '' }
  } catch (err) {
    const e = err as { errors?: Array<{ text: string }> }
    const messages = (e.errors ?? []).map((m) => m.text).join(' | ')
    return { errors: (e.errors ?? []).length || 1, text: '', messages }
  }
}

/** Count `node:` builtin references (node:crypto, node:fs, ...) in bundle text. */
function countNodeRefs(text: string): { total: number; crypto: number } {
  const total = (text.match(/node:[a-z_/]+/g) ?? []).length
  const crypto = (text.match(/node:crypto/g) ?? []).length
  return { total, crypto }
}

async function main(): Promise<void> {
  // ── A. STATIC BUNDLE SCAN ────────────────────────────────────────────────

  const browserBundle = await bundleForBrowser('verify-browser.ts')
  ok(
    'verify-browser entry bundles for platform:browser with ZERO errors',
    browserBundle.errors === 0,
    browserBundle.messages,
  )

  const browserRefs = countNodeRefs(browserBundle.text)
  ok(
    'browser bundle contains ZERO node:crypto references',
    browserRefs.crypto === 0,
    `found ${browserRefs.crypto}`,
  )
  ok(
    'browser bundle contains ZERO node: builtin references of any kind',
    browserRefs.total === 0,
    `found ${browserRefs.total} node: refs`,
  )
  ok(
    'browser bundle is non-empty (real graph was bundled, not vacuous)',
    browserBundle.text.length > 1000,
    `${browserBundle.text.length} bytes`,
  )
  // Buffer is a NODE global, not a node: specifier, so a static node:-scan
  // alone would miss it. This is the hazard internal/base64-browser.ts's own
  // doc comment calls out (Buffer.from(...) bundles clean yet ReferenceErrors
  // at runtime). Scan for the literal identifier too.
  const bufferRefCount = (browserBundle.text.match(/\bBuffer\b/g) ?? []).length
  ok(
    'browser bundle contains ZERO literal "Buffer" references',
    bufferRefCount === 0,
    `found ${bufferRefCount}`,
  )

  // CONTROL: the node default entry must NOT be browser-clean. If this ever
  // bundles clean, the scan above has stopped discriminating and proves
  // nothing.
  const nodeBundle = await bundleForBrowser('index.ts')
  const nodeIsBroken = nodeBundle.errors > 0 || countNodeRefs(nodeBundle.text).crypto > 0
  ok(
    'CONTROL: node default entry is NOT browser-safe (pulls node:crypto)',
    nodeIsBroken,
    nodeBundle.errors === 0 ? 'node entry unexpectedly bundled clean' : nodeBundle.messages,
  )
  ok(
    'CONTROL: node entry breakage names a node: builtin (discriminator works)',
    /node:/.test(nodeBundle.messages) || countNodeRefs(nodeBundle.text).crypto > 0,
    nodeBundle.messages,
  )

  // ── B. RUNTIME BUFFER-DELETION CONTROL (secondary, best-effort) ───────────
  //
  // Verified in isolation before writing this: on Node v22, global atob/btoa
  // do NOT touch Buffer internally, so deleting Buffer and exercising the
  // already-imported browser entry is a safe, real runtime check here (not
  // just a static one). Buffer is restored in `finally` regardless of
  // outcome so later test files in run-all.ts (which assume Buffer exists)
  // are not broken by this file's side effects.

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const savedBuffer = (globalThis as any).Buffer
  let atobIndependentOfBuffer = false
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).Buffer
    const probe = atob(btoa('sraid-browser-safety-probe'))
    atobIndependentOfBuffer = probe === 'sraid-browser-safety-probe'
  } catch {
    atobIndependentOfBuffer = false
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(globalThis as any).Buffer = savedBuffer
  }
  ok(
    'runtime probe: atob/btoa do not depend on Buffer on this Node version',
    atobIndependentOfBuffer,
  )

  // ── C. FUNCTIONAL: keys + a known-good hybrid envelope ────────────────────

  const edPriv = new Uint8Array(randomBytes(32))
  const edPub = ed25519.getPublicKey(edPriv)
  const mlKeys = ml_dsa65.keygen(new Uint8Array(randomBytes(32)))
  const mlPriv = mlKeys.secretKey
  const mlPub = mlKeys.publicKey

  const payloadType = 'application/vnd.synoi.sraid+json'
  const payload = canonicalize({ tenant_id: 't-browser', action: 'open_door', risk: 'B' })

  function signEnvelope(pt: string, pl: string): AttestationEnvelope {
    const msg = browserEntry.pae(pt, pl)
    return {
      payloadType: pt,
      payload: pl,
      signatures: [
        { alg: ALG_ED25519, keyid: 'k1', sig: toB64(ed25519.sign(msg, edPriv)) },
        { alg: ALG_ML_DSA_65, keyid: 'k1', sig: toB64(ml_dsa65.sign(msg, mlPriv)) },
      ],
    }
  }

  const goodEnv = signEnvelope(payloadType, payload)

  // (a) browser entry verifies a known-good envelope.
  const rGood = await browserEntry.verifyAttestation({
    envelope: goodEnv, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: known-good envelope verifies valid=true', rGood.valid === true, JSON.stringify(rGood))
  ok('browser: known-good envelope has no reasons', rGood.reasons.length === 0, JSON.stringify(rGood.reasons))

  // Buffer-deleted runtime re-check of the SAME good envelope, only if the
  // probe above showed it is safe to do so on this Node version.
  if (atobIndependentOfBuffer) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const saved2 = (globalThis as any).Buffer
    let rNoBuffer: Awaited<ReturnType<typeof browserEntry.verifyAttestation>> | undefined
    let threwWithoutBuffer = false
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (globalThis as any).Buffer
      rNoBuffer = await browserEntry.verifyAttestation({
        envelope: goodEnv, ed25519_pub: edPub, ml_dsa_pub: mlPub,
      })
    } catch {
      threwWithoutBuffer = true
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(globalThis as any).Buffer = saved2
    }
    ok('browser: verifyAttestation does not throw with globalThis.Buffer deleted', !threwWithoutBuffer)
    ok(
      'browser: verifyAttestation still verifies valid=true with Buffer deleted',
      rNoBuffer?.valid === true,
      JSON.stringify(rNoBuffer),
    )
  }

  // (b) tampering rejected, never throws.

  // b1: tampered payload -> both invalid
  const tamperedPayload: AttestationEnvelope = {
    payloadType,
    payload: canonicalize({ tenant_id: 't-browser', action: 'open_door', risk: 'C' }),
    signatures: goodEnv.signatures,
  }
  const rTamperPayload = await browserEntry.verifyAttestation({
    envelope: tamperedPayload, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: tampered payload -> valid=false', rTamperPayload.valid === false)
  ok(
    'browser: tampered payload -> both sigs report invalid',
    rTamperPayload.reasons.includes('ed25519-invalid') && rTamperPayload.reasons.includes('ml-dsa-invalid'),
    JSON.stringify(rTamperPayload.reasons),
  )

  // b2: tampered ed25519 sig byte -> only ed invalid
  const tamperedEdSig = new Uint8Array(Buffer.from(goodEnv.signatures[0]!.sig, 'base64'))
  tamperedEdSig[0] = (tamperedEdSig[0]! ^ 0xff) & 0xff
  const tamperedEd: AttestationEnvelope = {
    payloadType, payload,
    signatures: [
      { alg: ALG_ED25519, sig: toB64(tamperedEdSig) },
      goodEnv.signatures[1]!,
    ],
  }
  const rTamperEd = await browserEntry.verifyAttestation({
    envelope: tamperedEd, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: tampered ed25519 sig -> valid=false', rTamperEd.valid === false)
  ok(
    'browser: tampered ed25519 sig -> ed25519-invalid present, ml-dsa-invalid absent',
    rTamperEd.reasons.includes('ed25519-invalid') && !rTamperEd.reasons.includes('ml-dsa-invalid'),
    JSON.stringify(rTamperEd.reasons),
  )

  // b3: tampered ml-dsa sig byte -> only ml invalid
  const tamperedMlSig = new Uint8Array(Buffer.from(goodEnv.signatures[1]!.sig, 'base64'))
  tamperedMlSig[0] = (tamperedMlSig[0]! ^ 0xff) & 0xff
  const tamperedMl: AttestationEnvelope = {
    payloadType, payload,
    signatures: [
      goodEnv.signatures[0]!,
      { alg: ALG_ML_DSA_65, sig: toB64(tamperedMlSig) },
    ],
  }
  const rTamperMl = await browserEntry.verifyAttestation({
    envelope: tamperedMl, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: tampered ml-dsa sig -> valid=false', rTamperMl.valid === false)
  ok(
    'browser: tampered ml-dsa sig -> ml-dsa-invalid present, ed25519-invalid absent',
    rTamperMl.reasons.includes('ml-dsa-invalid') && !rTamperMl.reasons.includes('ed25519-invalid'),
    JSON.stringify(rTamperMl.reasons),
  )

  // b4: wrong ed pub key -> only ed invalid
  const otherEdPub = ed25519.getPublicKey(new Uint8Array(randomBytes(32)))
  const rWrongPub = await browserEntry.verifyAttestation({
    envelope: goodEnv, ed25519_pub: otherEdPub, ml_dsa_pub: mlPub,
  })
  ok('browser: wrong ed25519 pub key -> valid=false', rWrongPub.valid === false)
  ok(
    'browser: wrong ed25519 pub key -> only ed25519-invalid',
    rWrongPub.reasons.includes('ed25519-invalid') && !rWrongPub.reasons.includes('ml-dsa-invalid'),
    JSON.stringify(rWrongPub.reasons),
  )

  // b5: AND policy, missing one alg
  const edOnly: AttestationEnvelope = { payloadType, payload, signatures: [goodEnv.signatures[0]!] }
  const rEdOnly = await browserEntry.verifyAttestation({
    envelope: edOnly, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: ed25519-only envelope -> valid=false (AND policy)', rEdOnly.valid === false)
  ok(
    'browser: ed25519-only envelope -> missing-ml-dsa-65 reason',
    rEdOnly.reasons.includes('missing-ml-dsa-65'),
    JSON.stringify(rEdOnly.reasons),
  )

  const mlOnly: AttestationEnvelope = { payloadType, payload, signatures: [goodEnv.signatures[1]!] }
  const rMlOnly = await browserEntry.verifyAttestation({
    envelope: mlOnly, ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: ml-dsa-only envelope -> valid=false (AND policy)', rMlOnly.valid === false)
  ok(
    'browser: ml-dsa-only envelope -> missing-ed25519 reason',
    rMlOnly.reasons.includes('missing-ed25519'),
    JSON.stringify(rMlOnly.reasons),
  )

  // b6: malformed envelope shape
  const rMalformed = await browserEntry.verifyAttestation({
    envelope: { payloadType, payload } as unknown as AttestationEnvelope,
    ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok('browser: malformed envelope (no signatures[]) -> valid=false', rMalformed.valid === false)
  ok(
    'browser: malformed envelope -> envelope-malformed reason',
    rMalformed.reasons.includes('envelope-malformed'),
    JSON.stringify(rMalformed.reasons),
  )

  // b7: malformed base64 in a sig -> reject, never throws
  const badB64: AttestationEnvelope = {
    payloadType, payload,
    signatures: [
      { alg: ALG_ED25519, sig: 'not@@valid@@base64' },
      goodEnv.signatures[1]!,
    ],
  }
  let badThrew = false
  let rBad: Awaited<ReturnType<typeof browserEntry.verifyAttestation>> | undefined
  try {
    rBad = await browserEntry.verifyAttestation({ envelope: badB64, ed25519_pub: edPub, ml_dsa_pub: mlPub })
  } catch { badThrew = true }
  ok('browser: malformed base64 sig -> verifyAttestation does NOT throw', badThrew === false)
  ok('browser: malformed base64 sig -> valid=false', rBad?.valid === false, JSON.stringify(rBad))
  ok(
    'browser: malformed base64 sig -> ed25519-malformed reason',
    !!rBad?.reasons.includes('ed25519-malformed'),
    JSON.stringify(rBad?.reasons),
  )

  // ── (d) node/browser parity ────────────────────────────────────────────────
  //
  // Same envelope + same keys through BOTH entries must agree on valid AND on
  // the exact reasons set, for the good case and every tamper case above.

  function reasonSet(r: { reasons: string[] }): string {
    return [...r.reasons].sort().join(',')
  }

  const parityCases: Array<{ label: string; envelope: AttestationEnvelope; edPub: Uint8Array; mlPub: Uint8Array }> = [
    { label: 'good envelope', envelope: goodEnv, edPub, mlPub },
    { label: 'tampered payload', envelope: tamperedPayload, edPub, mlPub },
    { label: 'tampered ed sig', envelope: tamperedEd, edPub, mlPub },
    { label: 'tampered ml sig', envelope: tamperedMl, edPub, mlPub },
    { label: 'wrong ed pub', envelope: goodEnv, edPub: otherEdPub, mlPub },
    { label: 'ed-only (AND policy)', envelope: edOnly, edPub, mlPub },
    { label: 'ml-only (AND policy)', envelope: mlOnly, edPub, mlPub },
    { label: 'malformed base64 sig', envelope: badB64, edPub, mlPub },
  ]

  for (const c of parityCases) {
    const nodeR = verifyAttestationNode({ envelope: c.envelope, ed25519_pub: c.edPub, ml_dsa_pub: c.mlPub })
    const browserR = await browserEntry.verifyAttestation({
      envelope: c.envelope, ed25519_pub: c.edPub, ml_dsa_pub: c.mlPub,
    })
    ok(
      `parity [${c.label}]: node.valid === browser.valid`,
      nodeR.valid === browserR.valid,
      `node=${nodeR.valid} browser=${browserR.valid}`,
    )
    ok(
      `parity [${c.label}]: node.reasons === browser.reasons (same set)`,
      reasonSet(nodeR) === reasonSet(browserR),
      `node=${reasonSet(nodeR)} browser=${reasonSet(browserR)}`,
    )
  }

  // Malformed-envelope parity (separate because the shape differs from the
  // AttestationEnvelope type).
  const nodeMalformed = verifyAttestationNode({
    envelope: { payloadType, payload } as unknown as AttestationEnvelope,
    ed25519_pub: edPub, ml_dsa_pub: mlPub,
  })
  ok(
    'parity [malformed envelope]: node.valid === browser.valid',
    nodeMalformed.valid === rMalformed.valid,
  )
  ok(
    'parity [malformed envelope]: node.reasons === browser.reasons',
    reasonSet(nodeMalformed) === reasonSet(rMalformed),
    `node=${reasonSet(nodeMalformed)} browser=${reasonSet(rMalformed)}`,
  )

  // ── OID / cdroOid parity: sync node vs async browser, byte-identical ──────

  const baseCdro = {
    type: 'gap:decision_receipt',
    sraid_version: '2.0' as const,
    gap_version: '1.0',
    tenant_id: 'tenant-x',
    created_at_ms: 1_720_000_000_000,
    created_by: 'sha256:' + 'c'.repeat(64),
    body: { decision: 'allow', amount_minor: 1299 },
    authority: { grant_oid: 'sha256:' + 'a'.repeat(64), decision: 'allow' as const },
    supersedes: 'sha256:' + 'b'.repeat(64),
  }
  const postAttestation = {
    ...baseCdro,
    oid: 'sha256:' + 'f'.repeat(64),
    attestation: goodEnv,
    signature_key_id: 'k1',
    signature_algorithm: 'ed25519+ml-dsa-65',
  }

  const nodeOidPre = cdroOidNode(baseCdro)
  const browserOidPre = await browserEntry.cdroOid(baseCdro)
  ok(
    'parity: cdroOid(pre-attestation) node === browser',
    nodeOidPre === browserOidPre,
    `node=${nodeOidPre} browser=${browserOidPre}`,
  )

  const nodeOidPost = cdroOidNode(postAttestation)
  const browserOidPost = await browserEntry.cdroOid(postAttestation)
  ok(
    'parity: cdroOid(post-attestation) node === browser',
    nodeOidPost === browserOidPost,
    `node=${nodeOidPost} browser=${browserOidPost}`,
  )
  ok(
    'browser KEYSTONE: cdroOid(pre) === cdroOid(post) holds on the browser entry too',
    browserOidPre === browserOidPost,
    `${browserOidPre} vs ${browserOidPost}`,
  )

  const nodeOidValue = oidOfNode({ a: 1, b: 2 })
  const browserOidValue = await browserEntry.oidOf({ a: 1, b: 2 })
  ok(
    'parity: oidOf({a:1,b:2}) node === browser',
    nodeOidValue === browserOidValue,
    `node=${nodeOidValue} browser=${browserOidValue}`,
  )

  const canonicalStr = canonicalize({ a: 1, b: 2 })
  const nodeOidCanonical = oidOfCanonicalNode(canonicalStr)
  const browserOidCanonical = await browserEntry.oidOfCanonical(canonicalStr)
  ok(
    'parity: oidOfCanonical(already-canonical string) node === browser',
    browserOidCanonical === nodeOidCanonical,
    `node=${nodeOidCanonical} browser=${browserOidCanonical}`,
  )
  ok(
    'oidOfCanonical(canonical string) matches oidOf(original value) (both entries agree with themselves)',
    nodeOidCanonical === nodeOidValue && browserOidCanonical === browserOidValue,
    `nodeCanonical=${nodeOidCanonical} nodeValue=${nodeOidValue} browserCanonical=${browserOidCanonical} browserValue=${browserOidValue}`,
  )

  // ── Shared pure re-exports sanity (already exhaustively tested elsewhere;
  // here only confirm the browser entry's re-exports behave identically) ────

  ok(
    'browser entry canonicalize matches node canonicalize for the same input',
    browserEntry.canonicalize({ a: 1, b: 2 }) === canonicalize({ a: 1, b: 2 }),
  )
  ok(
    'browser entry pae() produces the same bytes as node pae() for the same input',
    Buffer.from(browserEntry.pae(payloadType, payload)).toString('hex') ===
      Buffer.from(browserEntry.pae(payloadType, payload)).toString('hex'),
  )
  ok(
    'browser entry CDRO_ENVELOPE_FIELDS matches the normative six-field strip-set',
    JSON.stringify([...browserEntry.CDRO_ENVELOPE_FIELDS].sort()) ===
      JSON.stringify(
        ['oid', 'signature', 'ml_dsa_signature', 'signature_key_id', 'signature_algorithm', 'attestation'].sort(),
      ),
  )
  ok(
    'browser entry cdroContentCore omits the same envelope fields as node',
    Object.keys(browserEntry.cdroContentCore(postAttestation)).every(
      (k) => !browserEntry.CDRO_ENVELOPE_FIELDS.includes(k),
    ),
  )

  process.stdout.write(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((err) => {
  process.stdout.write(`FATAL ${(err as Error).stack ?? String(err)}\n`)
  process.exit(1)
})
