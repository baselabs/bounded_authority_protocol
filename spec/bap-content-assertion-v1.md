---
title: BAP Content Assertion Profile 1
docname: bap-content-assertion-v1
---

# BAP Content Assertion Profile 1

Document status: normative contract for `bap-content-assertion/1`, revision 1;
first released in package 0.7.0; the companion signer supports it from
`bounded_authority_report_adapter` 0.9.0. Governing decision:
[ADR 0037](../docs/adr/0037-content-assertion-profile.md).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
interpreted as described in BCP 14 only when they appear in all capitals.

## 1. Identity and purpose

A content assertion binds exact external content to an issuer, audience, subject
lineage, semantic profile, time window, and predecessor. The profile identity is
`bap-content-assertion/1`; its suite is `BAP1-Ed25519-SHA256`, using Ed25519 and
protected `alg: "EdDSA"` (`REQ-CA1-CORE-identity`).

The separately named API is `BoundedAuthorityProtocol.ContentAssertion.V1`.
Selection MUST be explicit, never inferred from bytes or retried after another
profile fails. This profile and every existing contract-major, loopback proof,
and role-attestation profile MUST reject one another's bytes
(`REQ-CA1-CORE-separation`). No runtime registry, schema dispatch, negotiation, or
fallback is introduced (`REQ-CA1-CORE-no-dispatch`). Verification is not authority.

## 2. Wire contract

The compact is the standard three-segment JWS. Its protected header contains
exactly `alg: "EdDSA"`, `typ: "ba+content-assertion"`, and `kid`, a nonempty ASCII
identifier under the existing BAP1 `[A-Za-z0-9._~-]` and `kid_bytes` rules.
`kid` is a lookup hint, never a trust selector. Every header byte is signed
(`REQ-CA1-HEADER-closed`).

The payload contains exactly thirteen required members:

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
types, and float lexemes for integers are invalid (`REQ-CA1-CLAIM-closed`). Digest
widths are fixed; no algorithm tag or alternate encoding is accepted
(`REQ-CA1-CLAIM-digests`).

Producer, parser, assembler, and verifier MUST enforce `iat <= nbf < exp`
(`REQ-CA1-CLAIM-time`). `gen == 1` if and only if `prev` is 32 zero bytes;
other pairings are invalid (`REQ-CA1-CLAIM-genesis`). Both decoded header and payload
bytes MUST equal their RFC 8785 canonical re-encoding (`REQ-CA1-CLAIM-canonical`).

The compact MUST fit `anchor_bytes` and applicable compact/segment/decoded-segment,
JSON/JCS, structural, identifier, and numeric bounds. Callers may tighten ceilings,
never widen them or change fixed widths. Producer-emitted bytes and projected
compact length MUST satisfy the same caller bounds as consumption
(`REQ-CA1-BOUND-symmetry`).

## 3. Digest contract

`content_digest(bytes, bounds)` accepts exactly 1 through `content_bytes` bytes.
The new `content_bytes` maximum is 65,536 and may be tightened.

| Bound | Maximum |
|---|---:|
| `content_bytes` | 65,536 |
 The result is raw
32-byte SHA-256 of the following concatenation:

```text
UTF8("BAP1-CONTENT") || 0x00 || exact_content_bytes
```

BAP MUST NOT parse, normalize, re-encode, or fetch that content
(`REQ-CA1-DIGEST-content`). Content authors own serialization and schema validation.
A caller MUST retain and compare the exact hashed bytes when interpreting content.
`profile_digest` is an opaque caller-pinned 32-byte identity; BAP only compares it
(`REQ-CA1-DIGEST-profile`).

`assertion_digest(compact, bounds)` first validates the compact as this profile,
including closed shape, canonical encoding, time/genesis structure, and bounds,
then returns unprefixed SHA-256 of its exact received bytes. It does not verify the
signature or trust. The verified facts `digest` and successor `prev` use this same
hash domain (`REQ-CA1-DIGEST-assertion`). Hashing a structurally valid compact does
not turn it into verified facts.

## 4. Verification

`verify_assertion(compact, %ExpectedContentAssertion{})` requires all these members:

| Expected member | Required value |
|---|---|
| `attestor` | `V1.HistoricalPublicKey` with exact key ID, raw 32-byte public key, integral `valid_from`, and integral `valid_before` or `:unbounded`. |
| `issuer`, `audience`, `subject`, `profile` | Expected nonempty bounded StringOrUri values. |
| `profile_digest`, `content_digest` | Expected raw 32-byte values. |
| `now` | Explicit integral NumericDate within the caller's signed magnitude ceiling. |
| `bounds` | Valid bounds under the common tightenable-ceiling contract. |

Malformed expected values MUST return the closed error before unsafe dereference;
finite key-window endpoints obey integer magnitude and `valid_from < valid_before`
(`REQ-CA1-VERIFY-context`). Verification MUST check:

1. Profile parsing and canonical bytes from section 2.
2. Header `kid` equals `attestor.key_id` (`REQ-CA1-VERIFY-key`).
3. `iss`, `aud`, `sub`, and `profile` exactly equal their expected strings
   (`REQ-CA1-VERIFY-identities`).
4. Both profile and content digests equal their expected raw bytes
   (`REQ-CA1-VERIFY-digests`). Content-digest comparison has no opt-out.
5. `iat >= valid_from`, `nbf >= valid_from`, and `exp <= valid_before` when
   bounded. Equality at the finite expiry ceiling is valid
   (`REQ-CA1-VERIFY-containment`).
6. `nbf <= now < exp` (`REQ-CA1-VERIFY-now`). No implicit clock or skew is used.
7. The exact JWS signing input's Ed25519 signature verifies against the supplied
   public key (`REQ-CA1-VERIFY-signature`).

Structural `iat <= nbf` and the current-window check imply `iat <= now`.
No key selection, trust walk, revocation query, content schema evaluation, replay
reservation, or host decision is performed (`REQ-CA1-VERIFY-pure`).

Success returns `%ContentAssertionFacts{}` with exactly these value fields:
`version: 1`, `attestor_key_id`, `attestor_key_fingerprint`, `jti`, `iss`, `aud`,
`sub`, `profile`, `profile_digest`, `content_digest`, `gen`, `prev`, `iat`, `nbf`,
`exp`, `digest`, `verification: :signature_and_window`, and `trust:
:not_evaluated`. The fingerprint uses RFC 7638 Ed25519 JWK thumbprint bytes.
Digests and fingerprint are raw 32-byte values. Inspection MUST redact values;
facts contain no raw key, signature, decision, or authorization marker
(`REQ-CA1-VERIFY-facts`).

## 5. Successor verification

`verify_successor(predecessor_facts, successor_facts, bounds)` accepts only complete
`ContentAssertionFacts` structs with version 1, `verification:
:signature_and_window`, and `trust: :not_evaluated`. It MUST validate their scalar
shapes, identifier/numeric bounds, fixed byte widths, structural time/genesis rules,
and markers. Decoded artifacts and malformed or partially populated facts MUST
fail closed (`REQ-CA1-SUCCESSOR-input`).

It then requires:

- Equal `iss`, `aud`, `sub`, `profile`, and `profile_digest`
  (`REQ-CA1-SUCCESSOR-context`).
- `successor.gen == predecessor.gen + 1`, without overflowing permitted magnitude
  (`REQ-CA1-SUCCESSOR-generation`).
- `successor.prev` equals `predecessor.digest` byte-for-byte
  (`REQ-CA1-SUCCESSOR-predecessor`).
- `successor.iat >= predecessor.iat` (`REQ-CA1-SUCCESSOR-time`).
- `successor.jti != predecessor.jti` (`REQ-CA1-SUCCESSOR-identity`).

It does not compare signing key ID/fingerprint, validity windows, or content digest;
those may change in a successor. It does not require the predecessor to remain
unexpired and receives no present-time input. Each new assertion must separately
pass verification using its caller-admitted key and expected content. Reconstructed
facts are caller-provenanced values, not opaque capabilities; this comparison
cannot establish their original signature verification or persistence history
(`REQ-CA1-SUCCESSOR-provenance`).

`sub` remains stable within a lineage. A consumer-selected transfer or re-enrollment
that starts a new lineage uses a new subject and genesis; its business meaning is
outside BAP. Bootstrap, missing-history admission, global latest generation,
idempotency, fork resolution, and durable replay state remain host policy.

## 6. Public API and assembly

The profile namespace provides:

| Surface | Successful result |
|---|---|
| `assertion_signing_input/2` | `{:ok, V1.SigningInput.t()}` with the profile's distinct kind. |
| `assemble_compact/2`, `assemble_compact/3` | `{:ok, compact_bytes}` from an external raw 64-byte signature; `/2` uses default bounds. |
| `decode_assertion/2` | `{:ok, DecodedContentAssertion.t()}`; no signature or trust claim. |
| `verify_assertion/2` | `{:ok, ContentAssertionFacts.t()}`. |
| `content_digest/2`, `assertion_digest/2` | `{:ok, raw_32_byte_digest}`. |
| `verify_successor/3` | `:ok`. |

Every failure is exactly `{:error, :invalid}`; no values leak in errors
(`REQ-CA1-API-complete`). All runtime functions are pure. No private key or signing
callback enters this package (`REQ-CA1-API-no-signer`).

The producer `%ContentAssertion{}` carries `attestor_key_id`, `jti`, `iss`, `aud`,
`sub`, `profile`, `profile_digest`, `content_digest`, `gen`, `prev`, `iat`, `nbf`,
and `exp`; `v` is fixed by the profile. The decoded struct carries `version: 1`,
`attestor_key_id`, the payload values corresponding to those producer members,
and `verification: :not_evaluated`. It MUST NOT masquerade as verified facts
(`REQ-CA1-API-decoded`).

Assembly MUST admit only this profile's signing-input kind and revalidate all
header/payload structure and bounds before returning bytes. It MUST NOT infer the
profile from a failed generic assembler (`REQ-CA1-API-assembly`). Signature input
is standard ASCII `base64url(protected) || "." || base64url(payload)`.

## 7. Trust, knowledge, and operational limits

One successful verification proves equality and signature/window checks against
explicit inputs. It does not prove content truth, semantic-profile validity, issuer
trust, subject key possession, revocation freshness, latest generation, complete
history, or permission to execute (`REQ-CA1-SECURITY-not-authority`).

Key rotation may use separately verified historical transitions, but all key trust
and windows remain caller-supplied. This profile MUST NOT synthesize validity windows
from transition times or implicitly admit a successor key. Existing transition
verification's effective instant must lie inside both supplied key windows
(`REQ-CA1-SECURITY-trust`).

An offline verifier cannot discover unseen revocations or successors. A restored
snapshot can restore earlier clock/high-water/history state. Authentic bytes do not
establish administrator-resistant restore continuity or distinguish copied content
and keys. Such guarantees require separately qualified host mechanisms
(`REQ-CA1-SECURITY-knowledge`).

## 8. Conformance and release

The profile corpus location is
`priv/conformance/attestation-profiles/content-assertion/v1`. Revision 1 contains
131 assertion cases, 9 content-digest cases, and 14 successor cases. The frozen
index SHA-256 is `14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876`.
Every consumer MUST pin this exact index and verify its indexed file hashes
(`REQ-CA1-CONFORMANCE-pin`). Corpus agreement is local source qualification;
package publication and connected companion receipts remain separate requirements.

Required cases cover every missing/unknown member; wrong type/algorithm/version;
duplicate and noncanonical encodings; every digest width/encoding; genesis pairings
both ways; structural time and both key-window edges; expected-field mismatches;
meaningful signature tampering; every successor rule and malformed facts; changed
signing key with an otherwise valid successor; both sides of all relevant size and
numeric limits; ES256 confusion; and bidirectional rejection with every existing
profile. Producer/assembly bytes and digest output MUST agree independently.
Named safety checks require red-capable mutation evidence
(`REQ-CA1-CONFORMANCE-cases`).

All maintained independent SDKs, including the graduated TypeScript verifier, MUST
implement and certify the surface before the first package release bearing it
(`REQ-CA1-CONFORMANCE-sdks`). A real companion signer and an independent non-Elixir
verifier MUST retain issuance/consumption receipts, including content-digest equality,
against the exact immutable candidate (`REQ-CA1-CONFORMANCE-receipts`).

The first publication requires a new pre-1.0 minor, immutable source/package/corpus
identities, completed package gates, and owner authorization for the exact release.
Companion dependency admission follows its own existing policy
(`REQ-CA1-RELEASE-immutable`).

## 9. IANA considerations

IANA is asked to register `application/ba-content-assertion+jwt` using the RFC 6838
field template under LIMITED USE. The ready-to-file source and rendered form live
in `docs/design/iana/media-types.json` and `docs/design/iana/media-types.md`.
Filing remains gated on the protocol's first external submission; this profile and
its protected `ba+content-assertion` wire `typ` do not claim an existing registration
(`REQ-CA1-IANA-template`).
