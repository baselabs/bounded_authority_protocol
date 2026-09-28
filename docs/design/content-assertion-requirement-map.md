# Content-assertion profile requirement map

This map traces the normative `REQ-CA1-*` requirements in
[BAP Content Assertion Profile 1](../../spec/bap-content-assertion-v1.md).
The design is accepted by [ADR 0037](../adr/0037-content-assertion-profile.md).
The evidence column names the required checks. Local verification and package
publication are separate acceptance steps; the latter has not been authorized.

Corpus: `priv/conformance/attestation-profiles/content-assertion/v1`, revision 1;
131 assertion cases, 9 digest cases, and 14 successor cases. Frozen index SHA-256:
`14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876`.

OBSERVED local checks against this corpus: the Elixir corpus consumer, Python
`tests/test_content_assertion.py`, Go content-assertion tests, Rust
`cargo test --test content_assertion`, and TypeScript
`pnpm conformance:content-assertion` passed. The 131 assertions include seven URI
regressions added without rewriting the previous signed vectors. The independent
producer/assembly comparison covers 38 structurally valid assertions.

OBSERVED safety checks: `scripts/check_content_assertion_mutations.exs` killed
30 of 30 permissive changes. Python and TypeScript content-assertion mutation tests
and Go guard mutations passed. Rust killed 11 runtime guard mutations; deleting
marker comparisons survived because the markers have distinct singleton types.
Separate real-SDK compile checks accepted correct markers and rejected both swapped
markers with E0308. This is static type evidence, not a killed runtime mutant.

Source/test pointers: `test/bounded_authority_protocol/content_assertion/`,
`scripts/check_content_assertion.exs`, `scripts/check_content_assertion_mutations.exs`,
and each SDK's content-assertion tests and corpus runner. These observations prove
local source behavior. The required complete package gate and immutable companion
admission are separate acceptance requirements; this table is not a release receipt.

| Requirements (`REQ-CA1-` prefix) | Required evidence | Status |
|---|---|---|
| `CORE-identity`, `CORE-separation`, `CORE-no-dispatch` | Explicit namespace/type; bidirectional cross-profile corpus against every contract-major, loopback proof, and role attestation; architecture checks; old corpus verdicts retained. | local focused checks passed |
| `HEADER-closed` | Exact alg/kid/typ positive; missing/extra members, wrong alg/type, kid charset/length, signed-header tamper negatives. | local focused checks passed |
| `CLAIM-closed` | Each of thirteen members omitted separately; unknown/duplicate members; wrong scalar types; each integer float-lexeme negative; identifier bounds and StringOrUri cases; audience array rejection. | local focused checks passed |
| `CLAIM-digests` | Every digest field wrong-width, padding, alphabet, tagged-value, and noncanonical-base64url negatives. | local focused checks passed |
| `CLAIM-time`, `CLAIM-genesis` | iat/nbf ordering and empty/inverted windows; generation bounds; both incorrect zero-predecessor/genesis pairings through producer, decode, assembly, verify. | local focused checks passed |
| `CLAIM-canonical` | Canonical baseline; independently signed noncanonical header and payload; duplicate keys; exact producer bytes. | local focused checks passed |
| `BOUND-symmetry` | Tightened valid limits; widened limits refused; emitted JSON/segment/compact bounds agree with consumption; both signs of numeric magnitude; fixed widths cannot change. | local focused checks passed |
| `DIGEST-content` | Independent exact-byte/domain hash vectors; 1-byte and maximum content; empty/over-limit refusal; tightened content_bytes; changed byte changes digest. | local focused checks passed |
| `DIGEST-profile` | Exact opaque schema identity comparison; profile digest not interpreted or recomputed. | local focused checks passed |
| `DIGEST-assertion` | Exact compact SHA-256; malformed profile refusal before hashing; structurally valid bad-signature digest remains a non-verification result. | local focused checks passed |
| `VERIFY-context` | Wrong/null/incomplete context, malformed key/window/digests, fractional and over-magnitude times, invalid bounds fail with one closed error. | local focused checks passed |
| `VERIFY-key`, `VERIFY-identities`, `VERIFY-digests` | Each key ID and expected string/digest mismatch independently refused; matched baseline accepted; content-digest equality cannot be disabled. | local focused checks passed |
| `VERIFY-containment`, `VERIFY-now` | iat before key window; nbf before key window; exp beyond window; exp equal ceiling accepted; now equal nbf accepted and equal exp refused. | local focused checks passed |
| `VERIFY-signature` | Correct signature; changed meaningful signature bytes and wrong signer; ES256 confusion refused. | local focused checks passed |
| `VERIFY-pure`, `VERIFY-facts` | Purity checks; exact facts field set/markers/digest/fingerprint; redacted Inspect; no raw key/signature/decision/authorization field. | local focused checks passed |
| `SUCCESSOR-input` | Complete facts baseline; decoded/malformed/partial/forged-marker shapes refused; field types, bounds, genesis/time structure validated. | local focused checks passed |
| `SUCCESSOR-context`, `SUCCESSOR-generation`, `SUCCESSOR-predecessor` | Each stable context field mismatch; jumps/regression/overflow; exact prior compact digest mismatch. | local focused checks passed |
| `SUCCESSOR-time`, `SUCCESSOR-identity`, `SUCCESSOR-provenance` | Backdated issuance and repeated artifact ID refused; expired predecessor comparison accepted; changed signer/current content allowed; no current-time or provenance guarantee. | local focused checks passed |
| `API-complete`, `API-no-signer`, `API-decoded`, `API-assembly` | Every public surface/return shape; no private-key/callback input; decode marker distinct from facts; kind and assembly revalidation gates. | local focused checks passed |
| `SECURITY-not-authority`, `SECURITY-trust`, `SECURITY-knowledge` | Non-authorizing facts/pure boundary; documentation of explicit trust/windows and offline/restore knowledge limits; no implicit transition-derived trust. | local focused checks passed |
| `CONFORMANCE-pin`, `CONFORMANCE-cases` | Certified index/file hashes, exact case census, independent bytes/verdicts, and named red-capable mutation receipts. | local corpus and guard checks passed |
| `CONFORMANCE-sdks` | Elixir reference and independent Python/Rust/Go/TypeScript implementations against the same frozen corpus; graduated snapshot coordinated at freeze. | release gate |
| `CONFORMANCE-receipts` | Real companion-signer issuance plus independent non-Elixir consumption and content-digest equality against exact immutable candidate. | release gate |
| `IANA-template` | Matching registry and RFC 6838 source/rendered template; specification requests registration without claiming filing. | source-reviewed; filing gated |
| `RELEASE-immutable` | Exact reviewed source, package/checksum, corpus, full final gate, companion admission policy, and owner approval for exact publication. | release gate |

A structural traceability check only establishes that requirements have entries.
Execution receipts establish observed outcomes. Neither proves live revocation,
trust admission, durable replay state, restored-state continuity, content truth,
or a host's operational decision.
