# ADR 0002: Normative v1 parsing profile

- Status: accepted
- Date: 2026-07-26
- Track: T2

## Context

BAP v1 needs deterministic, bounded parsing before cryptographic verification. Generic JSON maps
cannot detect duplicate names after conversion, floating-point conversion can erase a raw number's
length and exact magnitude, JSON Schema string limits count Unicode code points rather than UTF-8
bytes, and a pre-verification key hint must not become a trust-selection or payload-parsing path.

The package boundary forbids runtime state, I/O, callbacks, supervision, and production
dependencies. Every accepted byte-level rule therefore needs a closed profile, an early bound, a
fixed public error, and mutation-red proof.

## Decision

1. Freeze the v1 fields, values, JSON algebra, URI rules, domain separators, encodings, hard
   maxima, and `{:error, :invalid}` result in `docs/protocol-v1.md`.
2. Use OTP's ordered JSON callbacks only after a bounded raw-number lexical pass. The pass skips
   strings, recognizes RFC 8259 number grammar, enforces the source lexeme byte limit, and compares
   exact decimal magnitude before OTP can normalize or round the token.
3. Build objects as ordered member lists and reject duplicate binary names at every depth before
   any map conversion or name atomization.
4. Keep `untrusted_key_locator/2` a narrow pre-verification surface: bound the complete compact
   input, require exactly three segments, decode and validate only the protected grant header, and
   return only `%KeyLocator{kid: ..., trust: :not_evaluated}`. Payload and signature segments stay
   opaque and receive no independent locator-specific size check.
5. Ship Draft 2020-12 schemas as structural companion artifacts. Validate them against the
   canonical meta-schema with the test-only pure-Elixir JSONSchex dependency. Use
   `x-bap-maximum-utf8-bytes` annotations to expose byte ceilings that standard `maxLength` cannot
   express; the normative decoder and vectors remain authoritative for byte-level conformance.
6. Keep runtime dependencies empty. JSONSchex and its JSON Pointer dependency are development/test
   tooling only and are excluded from the packed runtime dependency surface.
7. Bind architecture exceptions to exact compiled function/arity call counts and require a
   planted extra dynamic call to make the gate red.

## Consequences

- Duplicate names, raw numeric overages, exact-magnitude overages, and oversized structures fail
  before maps or cryptographic work.
- The locator cannot inspect authorization claims, signatures, trust stores, or host state.
- Schema validation proves structural agreement, while byte-boundary tests prove the stricter wire
  contract without misrepresenting JSON Schema semantics.
- The parser and locator APIs are public v1/SemVer surfaces; widening accepted fields, values,
  encodings, bounds, or error behavior requires an explicit new profile or compatible package
  change under the tracked versioning contract.
