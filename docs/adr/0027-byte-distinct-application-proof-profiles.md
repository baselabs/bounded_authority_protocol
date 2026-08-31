# ADR 0027: Byte-distinct application proof profiles

- Status: accepted
- Date: 2026-08-30

## Context

The contract-major 1 holder-proof profile uses protected `typ: "dpop+jwt"` and requires a
normalized hierarchical HTTPS `htu`. HTTP is invalid. Governance currently sends every wire or
verification-behavior change to a complete parallel contract-major.

A local application integration needs honest HTTP target binding on literal loopback without
weakening the HTTPS proof profile, resolving hostnames, trusting proxy metadata, duplicating the
verifier, or adopting mutable source. Three designs were evaluated:

1. add a transport argument to the existing V1 APIs;
2. expose a separate API that accepts the same `dpop+jwt` bytes under caller context;
3. use the complete successor contract-major.

The first two fail the byte-level self-declaration property: identical self-declared proof bytes
would be valid in one verifier and invalid in another. The third conforms to the previous governance
but couples one proof-transport profile to the successor charter's delegation, offline, suite,
freshness, and selector scope.

The owner approved a fourth design after independent adversarial review: a signed, byte-distinct
sibling proof profile that reuses the current grant-major and shared mechanics while every existing
proof surface continues to reject it.

## Decision

### 1. Add a narrowly governed sibling-proof-profile evolution class

An application proof profile MAY reuse an existing grant-major and shared claim mechanics only when
all of the following are true:

- its artifact is mechanically distinguishable by a new signed protected `typ`;
- it has a separate public namespace, normative specification, stable requirement namespace,
  conformance corpus identity, and registry entry;
- every existing profile rejects its bytes and retains every existing corpus verdict;
- it adds no claim to and reinterprets no byte accepted by an existing profile;
- it has independent conformance implementations and every shipped SDK implements its relevant
  verification surface before release;
- its first publication is a breaking pre-1.0 package release (`0.x.0`) with immutable source,
  package, corpus, and real-substrate evidence;
- it introduces no runtime registry, negotiation, inference, fallback, or plugin mechanism.

This is a second evolution axis, not an erratum and not an artifact contract-major. Changing an
existing profile's verdicts, shared claims, algorithms, bounds, or suite still requires a complete
parallel contract-major.

### 2. Define the literal-loopback HTTP proof profile

The profile identity is `bap-application-proof/local-loopback-http/1`. Its protected `typ` is
`ba+loopback-proof`; its associated media type is `application/ba-loopback-proof+jwt`.

The profile binds a contract-major 1 grant and reuses the current proof claims and cryptographic
mechanics. It requires a nonce and admits only canonical HTTP targets whose host spelling is exactly
`127.0.0.1` or `[::1]`. It rejects HTTPS, hostnames, other loopback spellings, non-loopback
addresses, proxy-derived authority, and every unknown value.

Its normative contract is [the local loopback HTTP proof profile](../../spec/bap-local-loopback-http-v1.md).

### 3. Keep one implementation mechanism

The new public facade and every existing proof facade delegate to one private bounded URI, proof,
assembly, decode, and envelope pipeline with a closed internal policy. No public data selects that
policy. The existing `BoundedAuthorityProtocol.V1` API remains unchanged.

The profile-specific facade owns URI normalization, proof signing input, compact assembly, proof
decoding, and envelope checking. Assembly is part of the boundary: a signing input that cannot be
revalidated under the same profile cannot become a compact artifact.

### 4. Require real transport evidence without adding I/O to the library

The package stays pure and signer-free. A release-only executable outside `lib/` and package contents
performs real IPv4 and IPv6 loopback client/server exchanges with ephemeral in-memory keys. Corpus
agreement proves deterministic semantics; the socket drill proves transport composition. Neither
substitutes for the other.

The public verifier does not own nonce reservation, replay state, listener policy, or business
effects. A stateful adopter separately proves those properties on its real substrate.

## Security consequences

Literal loopback HTTP has no TLS confidentiality or server authentication. Loopback is not process
isolation. The profile therefore requires a nonce, direct listener/request target derivation,
environment-specific trust configuration, and host-side replay reservation before effect. It must
never be described as equivalent to HTTPS or as safe for non-loopback transport.

The separate signed `typ` prevents an artifact from ambiguously self-declaring as the existing
`dpop+jwt` profile. It does not prevent application code from dynamically choosing or chaining
verifiers; public guidance and adopter architecture gates prohibit inference and try-both fallback.

## Alternatives rejected

- **A boolean or public profile argument on V1.** Rejected: it widens the apparent V1 surface and
  makes policy selection an ordinary data value.
- **A separate same-byte facade.** Rejected: two verifiers would disagree on identical
  self-declared proof bytes.
- **`localhost`, all `127/8`, semantic IPv6 equivalence, or DNS resolution.** Rejected:
  cross-language parsers disagree on historical numeric forms and resolution is runtime state.
- **A transport-only v2.** Rejected under current authority: the accepted successor charter
  consolidates five mechanism families and activates reserved names as one complete major.
- **A proxy or local TLS shim.** Rejected: it would make the signed target differ from the direct
  transport requirement and would not define portable proof semantics.

## Consequences

- The existing BAP1 HTTPS proof profile, APIs, corpus bytes, corpus identity, and verdicts remain
  unchanged.
- The public protocol gains one independently versioned sibling proof profile and the governance
  precedent described above.
- The Elixir reference and TypeScript, Python, Rust, and Go SDKs must implement the relevant profile
  surface before release.
- Publication, tagging, and downstream adoption remain separate immutable-delivery decisions.
