# ADR 0037: The content-assertion sibling profile (`bap-content-assertion/1`)

- Status: accepted; released in 0.7.0; companion-signer dependency admission and
  consumer acceptance remain with their owners
- Date: September 27, 2026
- Track: T2
- Governing class: [ADR 0036](0036-role-attestation-profile.md), sibling attestation profiles
- Amends: [ADR 0018](0018-sdk-bounds-contract.md), adding the tightenable `content_bytes` ceiling
- Normative contract: [BAP Content Assertion Profile 1](../../spec/bap-content-assertion-v1.md)
- Traceability: [requirement map](../design/content-assertion-requirement-map.md)

## Context

A consumer needs a signed assertion that binds exact external content to an issuer,
audience, stable subject lineage, semantic profile, validity window, and predecessor.
The consumer owns the document's vocabulary and interpretation. The public protocol
must authenticate those bindings without interpreting content or selecting trust.

Existing profiles have different signed purposes. A boundary anchor binds a chain
checkpoint and an instant, without issuer, audience, or a bounded assertion window.
A role attestation binds one subject key to a member of a closed role set. Reusing
an identifier or chain hash to convey this new assertion would reinterpret existing
bytes. A grant remains a grant even when its verification returns non-authorizing
facts. An external agreement or action receipt does not become this assertion by
adding opaque optional data. A separately selected sibling preserves these meanings.

The design underwent an independent adversarial pass and independent judgment.
Their adopted correction is a digest-bound envelope rather than a domain-specific
content grammar. Acceptance of this design is not an execution or release receipt.

## Decision

### Identity and scope

Reserve `bap-content-assertion/1`, protected type `ba+content-assertion`, public module
`BoundedAuthorityProtocol.ContentAssertion.V1`, and requirement prefix `REQ-CA1-`.
The media-type identity is `application/ba-content-assertion+jwt`; reservation in
project registries does not claim IANA registration.

This is a standalone, grant-unbound attestation under the existing
`BAP1-Ed25519-SHA256` suite. It is not an extension to grants, anchors, role
attestations, or a generic claim/plugin registry. The payload's `profile` is an
exactly compared identifier; it never selects executable code or fetches a schema.

The closed thirteen-member payload is `v`, `jti`, `iss`, `aud`, `sub`, `profile`,
`profile_digest`, `content_digest`, `gen`, `prev`, `iat`, `nbf`, and `exp`. The
specification defines exact types, canonical bytes, and comparisons. `sub` names
one assertion lineage, not a public key or a live process. Content meaning remains
outside BAP; a consumer must independently validate its content contract.

### Digest ownership and bounds

Content is exact bytes, not BAP's tagged JSON algebra. Compute SHA-256 over UTF-8
`BAP1-CONTENT`, one zero byte, and the unmodified content bytes. The caller must
retain those exact bytes. BAP neither normalizes text nor parses the content.
`profile_digest` is a caller-pinned opaque 32-byte identity; BAP does not compute it.
The assertion's own digest and its predecessor link use unprefixed SHA-256 over
exact compact bytes. All digest values are raw 32-byte values at the Elixir API and
canonical unpadded base64url on the wire.

**ADR 0018 amendment:** add tightenable `content_bytes`, maximum 65,536 bytes,
for this digest API. Empty content is invalid. Retain every existing bound and
fixed cryptographic width. This addition must be represented consistently in
all SDK bounds contracts; it does not change any existing profile's wire meaning.
The assertion compact remains subject to `anchor_bytes` as well as applicable
compact, segment, JSON, canonicalization, identifier, and integer bounds.

### Verification and lineage

Verification requires the expected content digest along with issuer, audience,
subject, profile, profile digest, public attestor key/window, time, and bounds.
A signature alone cannot discharge content equality. Structural time is
`iat <= nbf < exp`; the assertion and issuance instant must fit the supplied key
window, and the caller's current time must lie in `[nbf, exp)`.

Generation one has exactly the all-zero predecessor digest; every other generation
has a nonzero predecessor digest. Pairwise successor verification checks complete
facts shapes, stable context, an increment of exactly one, the predecessor's exact
compact digest, nondecreasing issuance time, and a different artifact ID. It does
not recheck the predecessor against current time. Current expiry, replay/fork
policy, missing-history bootstrap, durable high-water marks, and latest-known
state remain consumer responsibilities.

Facts carry the exact compact digest, redacted inspection, and `trust:
:not_evaluated`, with no authorization marker. A facts struct is a value, not an
unforgeable credential: callers are responsible for the provenance of reconstructed
facts. The pairwise function does not rediscover or reverify their signatures.

### Trust and signing boundaries

Each verification receives exactly one caller-selected key and validity window.
Unknown key IDs fail equality; verification never discovers keys, walks rotations,
checks revocation, or fetches a trust document. Existing historical key transitions
may be verified separately, but this profile does not derive key windows from
transition instants. Existing transition verification requires its effective instant
to lie inside both supplied windows; making that instant the retiring key's exclusive
upper bound would fail that contract. Trust admission and window selection remain
explicit caller policy.

The companion signer adds a typed, role-agnostic entry point using its atomic
`key_identity/1` snapshot and wrong-key guard. It obtains signing bytes from this
profile and assembles with this profile's assembler. No role-attestation gate or
grant issuance semantics are imported. BAP accepts an external signature, never
private keys or signing callbacks. Companion dependency qualification remains
subject to that repository's existing release and authority-validation policy;
this ADR does not waive it.

### Fit against all nine ADR 0036 conditions

| Condition | Decision |
|---|---|
| Distinct protected type | `ba+content-assertion` is signed and closed. |
| Separate contract identity | Namespace, specification, `REQ-CA1-*`, corpus, and registry rows are required. |
| Cross-rejection | Both directions against every contract-major, loopback proof, and role attestation; retain old corpus verdicts. |
| No reinterpretation | Existing profile bytes and claims keep their meanings. |
| Standalone API | Explicit profile selection; no grant binding or fallback. |
| Shared primitives | Reuse V1 bounded JSON/JCS/base64url/compact/Ed25519 primitives; only the distinct signing-input kind and header admission are added to shared framing. |
| Independent SDKs | Every maintained SDK, including graduated TypeScript, implements and certifies the surface before release. |
| Breaking first release | First publication uses a new pre-1.0 minor with immutable source/package/corpus identities. |
| No dynamic machinery | No runtime registry, negotiation, inference, retry, schema fetch, or plugin. |

The field added to the common bounds contract is the explicit ADR 0018 amendment
above, not an unrecorded exception to primitive reuse.

## Alternatives and consequences

Reusing anchor or role bytes saves a profile but changes their purpose and leaves
context/window rules outside their contract. A general JWT claims API allows
arbitrary schemas and dispatch choices that this bounded requirement does not need.
Embedding content JSON centralizes the wrong semantics and forces content through
unrelated numeric/structural limits. Online state can supply newer knowledge but
cannot replace a deterministic offline verifier.

The chosen design adds one closed envelope and one byte-digest API. It preserves
clear ownership and leaves content serialization/profile evolution with consumers.
Its cost is independent specification, corpus, SDK, mutation, signer, and release
qualification. Digests authenticate equality; they do not prove content truth,
current trust, key possession by the subject, complete history, or current state.

## Release acceptance

No corpus index digest or execution success is asserted here. Certification is
PENDING. Before publication, freeze the corpus; pin its identity in the normative
specification, requirement map, reference tests, and all SDKs; execute independent
conformance and named mutation checks; retain the project's full final gate receipt.
The graduated TypeScript repository participates at corpus freeze under ADR 0015.

Retain a real companion-signer issuance receipt and an independent non-Elixir
consumption receipt, including exact content-digest equality, against the same
immutable candidate. Complete registry, changelog, roadmap, documentation, and
package-identity work. An exact package/release authorization is still required.
Neither this decision nor source qualification publishes any package.

Release status (September 28, 2026): the revision-1 corpus is frozen and its index is
pinned in the specification and requirement map. Reference and SDK conformance and the
full package gate passed; the requirement map records the mutation evidence and its one
static-type exception. A real companion-signer issuance and an independent Python
consumption, including content-digest equality, were run against the built 0.7.0 package
before publication; the registry checksum read back afterward
(`777c606660727781ba03b742e7a7785f2655814048fe365f415b3a0c7253e0a8`) equals that build. The owner authorized the exact 0.7.0 release, published to Hex.
Companion-signer dependency admission and consumer acceptance remain with their owners.
