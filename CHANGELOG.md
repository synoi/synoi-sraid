# Changelog

## 0.2.0 (2026-07-05)

BREAKING (wire): migrates the L0 SRAID identifiers off the retired `cof` namespace onto `sraid`, per ADR_020 (internal).

Note on versioning: the PACKAGE version bumps `0.1.0` -> `0.2.0` (minor, pre-1.0 semver). The PROTOCOL version string carried on the wire bumps `1.0` -> `2.0` (major, because the signed bytes change). These two numbers are intentionally different: the package is still pre-1.0 and this is not treated as a package-major event, but the wire protocol version is self-describing and must jump a major so a downgrade is detectable at validate time ([E05]).

This is a CLEAN CUTOVER, no dual-accept. An object carrying the old `cof_version` key or the retired `sraid_version: '1.0'` value fails closed at [E05].

Changes:
- `type: 'cof:sro'` -> `type: 'sraid:sro'` (the SRO type discriminator).
- Signed field key `cof_version` -> `sraid_version`.
- Signed field value `'1.0'` -> `'2.0'` (the only defined `sraid_version` value).
- Serialization profile id `cof/json` -> `sraid/json` (SPEC.md, normative canonical format for v1.0).
- Serialization profile id `cof/cbor` -> `sraid/cbor` (SPEC.md, reserved binary profile).
- Stale prose examples `agp:capability_grant` / `agp:capability_declaration` in SPEC.md, README.md, and test fixtures updated to `gap:...` (the `agp:` -> `gap:` wire migration itself already shipped under ADR_007; these were leftover prose/test literals, not a new wire change).
- `PROJECTION_SPEC.md` keystone example (pre- vs post-attestation OID invariance) updated: field renamed and the pinned reference OID recomputed against the new bytes.
- Test-intent fix in `test/validate.test.ts`: the [E05] "wrong value" case previously asserted that `cof_version: '2.0'` (now the CORRECT value) was rejected. It now asserts the RETIRED value `sraid_version: '1.0'` is rejected, and separately that the retired key `cof_version` (with `sraid_version` absent) is rejected, preserving the original intent that a downgrade/legacy-key attempt must fail-closed.

Every SRAID/GAP-receipt OID and signature changes as a result of this migration. Bounded blast radius: only conformance test-key fixtures carry these bytes; there is no production-signed corpus (verified, see ADR_020 Section 8).
