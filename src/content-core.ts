/**
 * @synoi/sraid/content-core — the OID projection, with no crypto attached.
 *
 * PURE. No `node:crypto`, no WebCrypto, no Buffer, no hashing, no dependencies
 * at all. Importable from Node, a browser, a service worker, an edge runtime,
 * or anything else that runs JavaScript.
 *
 * WHY THIS SUBPATH EXISTS
 *
 * The projection is the part that MUST be identical everywhere, and it is the
 * part that was independently reimplemented and independently got wrong.
 * `@synoi/gap` derived its own copy from `PROJECTION_SPEC.md` — faithfully,
 * with the correct six-name strip set — and still shipped the same
 * `core[k] = v` loop that silently drops an own `__proto__`, producing the same
 * OID collision in a package with no shared code. Two teams reading correct
 * prose wrote the same defect, because that prose translates into that loop.
 *
 * The reason for the copy was real: sraid's default entry imports
 * `node:crypto`, so a consumer that must stay portable could not take it. But
 * the PROJECTION never needed crypto — only the hashing did. This subpath
 * splits them, so a portable consumer can import the one thing that must not
 * vary and bring its own hash function:
 *
 *     import { cdroContentCore } from '@synoi/sraid/content-core'
 *     import { canonicalize }    from '@synoi/sraid/canonicalize'
 *     import { sha256 }          from '@noble/hashes/sha256'
 *
 *     const oid = 'sha256:' + hex(sha256(utf8(canonicalize(cdroContentCore(obj)))))
 *
 * That is byte-identical to `cdroOid` by construction rather than by
 * agreement, which is the only version of "these two implementations match"
 * that stays true.
 *
 * NOTE the canonicalizer REJECTS an own `__proto__` member, so a consumer
 * composing these two functions inherits the fix. A consumer that brings its
 * own canonicalizer does not — see PROJECTION_SPEC.md §2, which states the
 * rule normatively, and the vectors in test/vectors/proto-pollution.json.
 */

export {
  cdroContentCore,
  CDRO_ENVELOPE_FIELDS,
} from './internal/content-core.js'
