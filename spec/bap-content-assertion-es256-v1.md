# BAP ES256 Content Assertion Profile 1

Document status: candidate normative contract for `bap-content-assertion-es256/1`.
It is a sibling attestation profile under
[governance § Byte-distinct sibling attestation profiles](../docs/governance.md#byte-distinct-sibling-attestation-profiles).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
interpreted as described in BCP 14 only when they appear in all capitals.

## 1. Identity and purpose

A content assertion binds exact external content to an issuer, audience, subject
lineage, semantic profile, time window, and predecessor. The profile identity is
`bap-content-assertion-es256/1`. It uses the ES256 signature primitives of
[BAP v3 § 3](bap-v3.md#3-the-es256-signature-suite) and fixes protected
`alg: "ES256"` (`REQ-CAE1-CORE-identity`).

The separately named API is `BoundedAuthorityProtocol.ContentAssertion.ES256.V1`.
Callers MUST select it explicitly before reading the compact. This profile and
every other profile, including [CA1](bap-content-assertion-v1.md), MUST reject one
another's bytes (`REQ-CAE1-CORE-separation`). The protected type and algorithm
are checked only against the selected profile. Runtime dispatch, negotiation,
schema lookup, and fallback are forbidden (`REQ-CAE1-CORE-no-dispatch`).

## 2. Wire contract

The compact is the standard three-segment JWS. Each segment uses canonical
unpadded base64url. The decoded signature segment is exactly 64 bytes. Its protected header contains
exactly `alg: "ES256"`, `typ: "ba+content-assertion-es256"`, and `kid`. The `kid`
is a nonempty ASCII identifier under the BAP1 `[A-Za-z0-9._~-]` and `kid_bytes` rules.
`kid` is a lookup hint, never a trust selector. Every header byte is signed
(`REQ-CAE1-HEADER-closed`).

The payload follows [CA1 § 2](bap-content-assertion-v1.md#2-wire-contract) exactly
and retains its version and bounds. The payload contains exactly thirteen
required members:

| Member | Type and rule |
|---|---|
| `v` | Integer exactly 1. |
| `jti` | Nonempty StringOrUri artifact identifier. |
| `iss` | Nonempty StringOrUri asserted issuer identifier. |
| `aud` | One nonempty StringOrUri audience; never an array. |
| `sub` | Nonempty StringOrUri stable assertion-lineage identifier. |
| `profile` | Nonempty StringOrUri semantic-profile identifier, compared as data. |
| `profile_digest` | Canonical unpadded base64url of exactly 32 bytes. |
| `content_digest` | Canonical unpadded base64url of exactly 32 bytes. |
| `gen` | Integer from 1 through caller `integer_magnitude`. |
| `prev` | Canonical unpadded base64url of exactly 32 bytes. |
| `iat` | Integer NumericDate within both signs of caller `integer_magnitude`. |
| `nbf` | Integer NumericDate within both signs of caller `integer_magnitude`. |
| `exp` | Integer NumericDate within both signs of caller `integer_magnitude`. |

All identifier strings obey the BAP1 StringOrUri rules and `identifier_bytes`.
Every listed member is required; additional members, duplicate members, wrong
types, and float lexemes for integers are invalid (`REQ-CAE1-CLAIM-closed`). Digest
widths are fixed; no algorithm tag or alternate encoding is accepted
(`REQ-CAE1-CLAIM-digests`).

Producer, parser, assembler, and verifier MUST enforce `iat <= nbf < exp`
(`REQ-CAE1-CLAIM-time`). `gen == 1` if and only if `prev` is 32 zero bytes;
other pairings are invalid (`REQ-CAE1-CLAIM-genesis`). Both decoded header and payload
bytes MUST equal their RFC 8785 canonical re-encoding (`REQ-CAE1-CLAIM-canonical`).

The compact MUST fit `anchor_bytes` and applicable compact/segment/decoded-segment,
JSON/JCS, structural, identifier, and numeric bounds. Callers may tighten ceilings,
never widen them or change fixed widths. Producer-emitted bytes and projected
compact length MUST satisfy the same caller bounds as consumption
(`REQ-CAE1-BOUND-symmetry`).

## 3. Digest contract

`content_digest(bytes, bounds)` accepts exactly 1 through `content_bytes` bytes.
The shared `content_bytes` maximum is 65,536 and may be tightened.

| Bound | Maximum |
|---|---:|
| `content_bytes` | 65,536 |

The result is raw 32-byte SHA-256 of the following concatenation:

```text
UTF8("BAP1-CONTENT") || 0x00 || exact_content_bytes
```

This domain is shared with CA1. The same content bytes yield the same digest in
both suites. BAP MUST NOT parse, normalize, re-encode, or fetch that content
(`REQ-CAE1-DIGEST-content`). Content authors own serialization and schema validation.
A caller MUST retain and compare the exact hashed bytes when interpreting content.
`profile_digest` is an opaque caller-pinned 32-byte identity; BAP only compares it
(`REQ-CAE1-DIGEST-profile`).

`assertion_digest(compact, bounds)` first validates the compact as this profile,
including closed shape, canonical encoding, time/genesis structure, and bounds,
then returns unprefixed SHA-256 of its exact received bytes. It does not verify the
signature or trust. The verified facts `digest` and successor `prev` use this same
hash domain (`REQ-CAE1-DIGEST-assertion`). Hashing a structurally valid compact does
not turn it into verified facts.

## 4. Verification

`verify_assertion(compact, %ExpectedContentAssertion{})` requires all these members:

| Expected member | Required value |
|---|---|
| `attestor` | `V1.HistoricalPublicKey` with exact key ID, raw 65-byte uncompressed SEC1 P-256 key, integral `valid_from`, and integral `valid_before` or `:unbounded`. |
| `issuer`, `audience`, `subject`, `profile` | Expected nonempty bounded StringOrUri values. |
| `profile_digest`, `content_digest` | Expected raw 32-byte values. |
| `now` | Explicit integral NumericDate within the caller's signed magnitude ceiling. |
| `bounds` | Valid bounds under the common tightenable-ceiling contract. |

Malformed expected values MUST return the closed error before unsafe dereference;
finite key-window endpoints obey integer magnitude and `valid_from < valid_before`
(`REQ-CAE1-VERIFY-context`). Verification MUST check:

1. Profile parsing and canonical bytes from section 2.
2. Header `kid` equals `attestor.key_id` (`REQ-CAE1-VERIFY-key`).
3. `iss`, `aud`, `sub`, and `profile` exactly equal their expected strings
   (`REQ-CAE1-VERIFY-identities`).
4. Both profile and content digests equal their expected raw bytes
   (`REQ-CAE1-VERIFY-digests`). Content-digest comparison has no opt-out.
5. `iat >= valid_from`, `nbf >= valid_from`, and `exp <= valid_before` when
   bounded. Equality at the finite expiry ceiling is valid
   (`REQ-CAE1-VERIFY-containment`).
6. `nbf <= now < exp` (`REQ-CAE1-VERIFY-now`). No implicit clock or skew is used.
7. The ES256 signature over the original JWS signing input verifies against the
   supplied public key (`REQ-CAE1-VERIFY-signature`).

[BAP v3 § 3.1](bap-v3.md#31-keys-and-the-proof-jwk) supplies the exact raw key
format, coordinate range, on-curve rules, and P-256 JWK thumbprint construction.
[BAP v3 § 3.2](bap-v3.md#signatures) supplies the exact signature rules. The raw
64-byte `r || s` signature MUST pass range validation and then the low-S check
before the backend verifies ECDSA with SHA-256 over the exact JWS signing input.
DER signatures and compressed keys are refused. Backend rejection and exceptions
return the closed error (`REQ-CAE1-VERIFY-v3-primitives`).

Structural `iat <= nbf` and the current-window check imply `iat <= now`.
No key selection, trust walk, revocation query, content schema evaluation, replay
reservation, or host decision is performed (`REQ-CAE1-VERIFY-pure`).

Success returns `%ContentAssertionFacts{}` with exactly these value fields:
`version: 1`, `attestor_key_id`, `attestor_key_fingerprint`, `jti`, `iss`, `aud`,
`sub`, `profile`, `profile_digest`, `content_digest`, `gen`, `prev`, `iat`, `nbf`,
`exp`, `digest`, `verification: :signature_and_window`, and `trust:
:not_evaluated`. The fingerprint uses the v3 RFC 7638 P-256 JWK thumbprint.
Digests and fingerprint are raw 32-byte values. The ES256 namespace supplies
a distinct facts type carrying suite provenance. Diagnostic inspection MUST
use the fully redacted form of the [diagnostic rendering contract](diagnostic-rendering.md),
with the ES256-qualified `BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts` name
(`REQ-CAE1-VERIFY-facts`).

## 5. Successor verification

`verify_successor(predecessor_facts, successor_facts, bounds)` accepts only complete
`ContentAssertionFacts` structs with version 1, `verification:
:signature_and_window`, and `trust: :not_evaluated`. It MUST validate their scalar
shapes, identifier/numeric bounds, fixed byte widths, structural time/genesis rules,
and markers. Decoded artifacts and malformed or partially populated facts MUST
fail closed (`REQ-CAE1-SUCCESSOR-input`).

Both inputs MUST carry provenance as facts of this ES256 profile. Any pair
containing facts from different suites MUST fail closed, even if every field and
digest comparison would otherwise pass. A suite change starts a new lineage with
`gen == 1` and an all-zero `prev` under the newly selected suite
(`REQ-CAE1-SUCCESSOR-suite`).

It then requires:

- Equal `iss`, `aud`, `sub`, `profile`, and `profile_digest`
  (`REQ-CAE1-SUCCESSOR-context`).
- `successor.gen == predecessor.gen + 1`, without overflowing permitted magnitude
  (`REQ-CAE1-SUCCESSOR-generation`).
- `successor.prev` equals `predecessor.digest` byte-for-byte
  (`REQ-CAE1-SUCCESSOR-predecessor`).
- `successor.iat >= predecessor.iat` (`REQ-CAE1-SUCCESSOR-time`).
- `successor.jti != predecessor.jti` (`REQ-CAE1-SUCCESSOR-identity`).

It does not compare signing key ID/fingerprint, validity windows, or content digest;
those may change in a successor. It does not require the predecessor to remain
unexpired and receives no present-time input. Each new assertion must separately
pass verification using its caller-admitted key and expected content. Reconstructed
facts are caller-provenanced values, not opaque capabilities; this comparison
cannot establish their original signature verification or persistence history
(`REQ-CAE1-SUCCESSOR-provenance`).

`sub` remains stable within a lineage. A consumer-selected transfer or re-enrollment
within the suite uses a new subject and genesis. When migrating suites the host
explicitly admits the new genesis in its new suite context. Bootstrap,
missing-history admission, global latest generation, idempotency, fork
resolution, and durable replay state remain host policy.

## 6. Public API and assembly

The profile namespace provides:

| Surface | Successful result |
|---|---|
| `assertion_signing_input/2` | `{:ok, V1.SigningInput.t()}` with kind `:content_assertion_es256`. |
| `assemble_compact/2`, `assemble_compact/3` | `{:ok, compact_bytes}` from an external raw 64-byte signature; `/2` uses default bounds. |
| `decode_assertion/2` | `{:ok, DecodedContentAssertion.t()}`; no signature or trust claim. |
| `verify_assertion/2` | `{:ok, ContentAssertionFacts.t()}`. |
| `content_digest/2`, `assertion_digest/2` | `{:ok, raw_32_byte_digest}`. |
| `verify_successor/3` | `:ok`. |

Every failure is exactly `{:error, :invalid}`; no values leak in errors
(`REQ-CAE1-API-complete`). All runtime functions are pure. No private key or signing
callback enters this package (`REQ-CAE1-API-no-signer`).

The producer `%ContentAssertion{}` in the ES256 namespace carries
`attestor_key_id`, `jti`, `iss`, `aud`, `sub`, `profile`, `profile_digest`,
`content_digest`, `gen`, `prev`, `iat`, `nbf`, and `exp`. The profile fixes `v`.
The decoded struct carries `version: 1`,
`attestor_key_id`, the payload values corresponding to those producer members,
and `verification: :not_evaluated`. Diagnostic inspection MUST use the fully
redacted form with the ES256-qualified
`BoundedAuthorityProtocol.ContentAssertion.ES256.V1.DecodedContentAssertion` name
(`REQ-CAE1-API-decoded`).

Assembly MUST admit only this profile's signing-input kind and revalidate all
header and payload structure and bounds. It MUST apply the raw width, range,
and low-S checks of [BAP v3 § 3.2](bap-v3.md#signatures) before returning bytes.
Assembly emits accepted signature bytes unchanged. It performs no equation
check. Decode and assertion digest check signature framing and width only.
Assembly MUST NOT infer the profile from another assembler's failure
(`REQ-CAE1-API-assembly`). Signature input is standard ASCII
`base64url(protected) || "." || base64url(payload)`.

## 7. Trust, knowledge, and operational limits

One successful verification proves equality and signature/window checks against
explicit inputs. It does not prove content truth, semantic-profile validity, issuer
trust, subject key possession, revocation freshness, latest generation, complete
history, or permission to execute (`REQ-CAE1-SECURITY-not-authority`).

Key rotation may use separately verified historical transitions, but all key trust
and windows remain caller-supplied. This profile MUST NOT synthesize validity windows
from transition times or implicitly admit a successor key. Existing transition
verification's effective instant must lie inside both supplied key windows
(`REQ-CAE1-SECURITY-trust`).

An offline verifier cannot discover unseen revocations or successors. A restored
snapshot can restore earlier clock/high-water/history state. Authentic bytes do not
establish administrator-resistant restore continuity or distinguish copied content
and keys. Such guarantees require separately qualified host mechanisms
(`REQ-CAE1-SECURITY-knowledge`).

## 8. Conformance and release

The candidate corpus location is
`priv/conformance/attestation-profiles/content-assertion-es256/v1`. Every consumer
MUST pin the frozen index and verify the indexed file hashes. Index SHA-256
(hex) at freeze is `TBD-by-reference-implementation`
(`REQ-CAE1-CONFORMANCE-pin`).

Required cases cover every header and payload rule, canonical encodings, digests,
bounds and numeric edges, issuer and key-window mismatches, invalid SEC1 points,
signature widths, scalar ranges, high-S alternatives, bad signature equations,
and all successor rules. Include mixed-suite successor refusal and bidirectional
rejection with every other profile, including CA1, as well as ES256 and EdDSA
algorithm-confusion cases. Preserve existing corpus verdicts. Independently
compare the content digest across both content assertion profiles and prove
signing-input and assembly agreement with exact bytes. Compare whole compacts in
pinned deterministic fixtures. For randomized signers, compare the signing input
and assemble the same accepted signature across implementations. Named safety
checks require red-capable mutation evidence (`REQ-CAE1-CONFORMANCE-cases`).

All maintained SDKs, including the graduated TypeScript verifier, MUST implement
and certify the surface before the first package release bearing it. A real
companion signer and an independent non-Elixir verifier MUST retain issuance and
consumption evidence, including content-digest equality, against the same
immutable candidate (`REQ-CAE1-CONFORMANCE-sdks`,
`REQ-CAE1-CONFORMANCE-receipts`).

The first publication uses a new package minor, with immutable source, package
and corpus identities, completed package gates, and authorization for the exact
release under the [governance policy](../docs/governance.md)
(`REQ-CAE1-RELEASE-immutable`).

## 9. IANA considerations

The RFC 6838 LIMITED USE registration template for
`application/ba-content-assertion-es256+jwt` has a
[JSON source](../docs/design/iana/media-types.json) and a
[rendered form](../docs/design/iana/media-types.md). The wire `typ` remains
`ba+content-assertion-es256`. Submission is gated on the protocol's first
external submission (`REQ-CAE1-IANA-template`).
