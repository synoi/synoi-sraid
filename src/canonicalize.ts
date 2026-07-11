/**
 * @synoi/sraid — canonicalize.ts
 *
 * Strict RFC 8785 (JCS) serializer for SRAID objects. Produces
 * byte-identical output to any other conformant RFC 8785 implementation
 * given the same input, making this the normative canonical form for OID
 * derivation and signing.
 *
 * Rules (strict RFC 8785 JCS):
 *   - Primitives are emitted via JSON.stringify (strings are escaped with
 *     standard JSON string escaping; booleans and null are literals).
 *   - Numbers must be FINITE INTEGERS (ADR_019 decision 2). NaN, Infinity
 *     (positive or negative), and any non-integer (float) are REJECTED with
 *     a thrown TypeError BEFORE hashing. Forbidding floats everywhere matches
 *     GAP-TS / GAP-Python and removes the hardest RFC 8785 cross-language
 *     serialization trap from the signed byte string; the product only emits
 *     integer minor-unit money and integer ms timestamps. Legal integers use
 *     the ECMAScript number-to-string serialization of RFC 8785 §3.2.2.3
 *     (equivalent to JS's default toString for integer values).
 *   - Arrays preserve element order; elements are recursively canonicalized.
 *   - Objects emit their keys sorted in ascending lexicographic
 *     (UTF-16 code-unit) order — this is the order produced by
 *     Array.prototype.sort(), which is exactly what RFC 8785 §3.2.3
 *     specifies for implementations whose host language uses UTF-16
 *     string encoding (including ECMAScript/TypeScript).
 *   - Object properties whose value is `undefined` are OMITTED entirely.
 *     (JSON has no undefined; this matches JSON.stringify semantics.)
 *   - No whitespace anywhere. Separators are bare `,` and `:`.
 *   - `null` is preserved as `null`.
 *
 * Stability invariant: any change to this function breaks every signed
 * receipt, every OID, every grant — so it must NEVER be changed without
 * a coordinated migration. The output bytes for a given input are a
 * cross-package contract.
 */

/**
 * Canonicalize an arbitrary JSON-compatible value into a deterministic
 * UTF-8 string following RFC 8785 (JCS). The output is suitable as input
 * to SHA-256 (or any other hash) for OID derivation and as the byte string
 * signed by Ed25519 / ML-DSA-65 envelopes.
 *
 * Reject-loud contract: a TypeError is thrown for any value that is not a
 * JSON value, rather than silently producing a wrong or invalid canonical
 * form (which would corrupt an OID or signature):
 *   - NaN / Infinity / -Infinity (RFC 8785 forbids non-finite numbers).
 *   - non-integer numbers / floats (ADR_019 forbids them; use integer minor
 *     units). e.g. 1.5, 0.1, 2e-3 all throw.
 *   - undefined / function / symbol / bigint anywhere they appear as a value,
 *     including as an ARRAY element (previously these produced invalid JSON
 *     like "[1,,2]").
 *   - objects with a toJSON() method (e.g. Date), which a bare keys-walk would
 *     silently mis-serialize (a Date became "{}"). Convert to a JSON value
 *     (e.g. an ISO string) first.
 * Object properties whose value is `undefined` are OMITTED (matches
 * JSON.stringify); an undefined array element throws (it cannot be omitted).
 *
 * @example
 *   canonicalize({ b: 2, a: 1 })            // '{"a":1,"b":2}'
 *   canonicalize({ a: undefined, b: 1 })    // '{"b":1}'  (object undefined omitted)
 *   canonicalize([3, 1, 2])                 // '[3,1,2]'
 *   canonicalize([1, null, 2])              // '[1,null,2]'
 *   canonicalize({ foo: 1, bar: 'hi' })     // '{"bar":"hi","foo":1}'
 *   canonicalize(NaN)                       // throws TypeError
 *   canonicalize(Infinity)                  // throws TypeError
 *   canonicalize(1.5)                       // throws TypeError (floats forbidden, ADR_019)
 *   canonicalize([1, undefined, 2])         // throws TypeError (no empty slots)
 *   canonicalize(new Date())                // throws TypeError (serialize first)
 */
export function canonicalize(value: unknown): string {
  const t = typeof value

  if (t === 'number') {
    if (!isFinite(value as number)) {
      throw new TypeError(
        `canonicalize: RFC 8785 forbids non-finite numbers; received ${String(value)}`,
      )
    }
    // ADR_019 decision 2: FORBID non-integer numbers everywhere. A number is
    // legal iff it is a finite integer. Floats are rejected BEFORE hashing,
    // matching GAP-TS / GAP-Python, so a float-bearing object cannot mint an
    // OID on one surface that another surface declares malformed. This kills
    // the hardest RFC 8785 cross-language trap (float shortest-round-trip
    // serialization) on a signed byte string; the product only ever emits
    // integer minor-unit money and integer millisecond timestamps.
    //
    // Number.isInteger(-0) is true and, with floats forbidden, -0 can only
    // arise as an explicit input; JSON.stringify(-0) === '0', so the former
    // -0 special-case is now redundant and is DELETED (removing a divergence
    // source per ADR_019 rather than carrying a rule that can never fire on
    // legal input).
    if (!Number.isInteger(value as number)) {
      throw new TypeError(
        `canonicalize: non-integer numbers are forbidden (ADR_019); received ${String(value)}. ` +
          'Represent fractional quantities as integer minor units (e.g. cents) before canonicalizing.',
      )
    }
    return JSON.stringify(value)
  }

  if (value === null) return 'null'
  if (t === 'string' || t === 'boolean') return JSON.stringify(value as string | boolean)

  // Reject-loud: a value that is not a JSON value MUST throw, never silently
  // produce wrong or invalid output. Previously these fell through to
  // JSON.stringify, which returns the JS value `undefined` for undefined /
  // function / symbol — corrupting an array element into invalid JSON like
  // "[1,,2]" — and throws for bigint. An OID/signature must never be derived
  // from a corrupted or out-of-domain canonical form.
  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new TypeError(
      `canonicalize: value of type "${t}" is not a JSON value and cannot be canonicalized`,
    )
  }

  // value is a non-null object from here.
  if (Array.isArray(value)) {
    // Each element is canonicalized recursively. We walk by index rather than
    // Array.prototype.map because map SKIPS holes in a sparse array — a hole
    // (`[1, , 2]`, distinct from an explicit `[1, undefined, 2]`) is never
    // visited by map, so it would slip past the reject-loud element checks and
    // join() would emit invalid, index-shifting JSON like "[1,,2]". A hole is
    // out-of-domain input (JSON has no concept of a missing element); per the
    // reject-loud contract it throws, exactly as an explicit undefined element
    // does, rather than silently coercing to null.
    const parts: string[] = []
    for (let i = 0; i < value.length; i++) {
      if (!(i in value)) {
        throw new TypeError(
          `canonicalize: sparse array hole at index ${i} is not a JSON value and ` +
            'cannot be canonicalized (it would produce invalid JSON like "[1,,2]"); ' +
            'fill the slot with an explicit value (e.g. null) before canonicalizing',
        )
      }
      parts.push(canonicalize(value[i]))
    }
    return '[' + parts.join(',') + ']'
  }

  // Reject objects that define their own JSON projection (Date, Buffer,
  // Decimal, BigNumber, ...). RFC 8785 / JSON.stringify call toJSON() first; a
  // bare keys-walk does not, so a Date would silently canonicalize to "{}" and
  // fork the OID. Callers must convert to a JSON value (e.g. an ISO string)
  // before canonicalizing.
  if (typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    throw new TypeError(
      'canonicalize: objects with a toJSON() method (e.g. Date) are not accepted; ' +
        'serialize them to a JSON value (e.g. an ISO string) before canonicalizing',
    )
  }

  const obj = value as Record<string, unknown>
  // Object properties whose value is `undefined` are OMITTED (matches
  // JSON.stringify and the JSON data model). This is the one omission we honor;
  // an undefined ARRAY element throws (above), because dropping it would shift
  // indices and silently change meaning.
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
  return (
    '{' +
    keys
      .map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k]))
      .join(',') +
    '}'
  )
}
