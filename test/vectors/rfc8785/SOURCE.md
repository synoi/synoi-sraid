# RFC 8785 (JCS) conformance vectors

Official reference test vectors from the RFC 8785 reference implementation:
https://github.com/cyberphone/json-canonicalization (testdata/input, testdata/output).

`input/<name>.json` is parsed with JSON.parse and run through `canonicalize`;
the result must equal `output/<name>.json` byte-for-byte. This proves the
`@synoi/sraid` canonicalizer is strict-RFC-8785 conformant against the spec's
own reference suite, not just hand-written examples.
