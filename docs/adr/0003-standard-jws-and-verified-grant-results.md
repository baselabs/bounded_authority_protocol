# ADR 0003: Standard JWS signing and verified grant facts

- Status: accepted
- Date: 2026-07-27
- Track: T2
- Supersedes: the grant/proof separator rows in
  [`docs/protocol-v1.md`](../protocol-v1.md) and the `EnvelopeFacts`-only result wording in
  [ADR 0001](0001-public-protocol-verifier-boundary.md)

## Context

The original unpublished v1 profile prefixed grant and proof signing inputs with
`BAP1-GRANT\0` and `BAP1-PROOF\0`. RFC 7515 defines a JWS signing input as the ASCII bytes
`base64url(protected) <> "." <> base64url(payload)`. RFC 9449 requires a DPoP proof to be a JWT
secured as a JWS. Adding bytes outside that signing input would produce a private signature format,
not a standard compact JWS.

The original authority wording also named only the combined `EnvelopeFacts` result. A caller needs
to verify a raw grant against an already-trusted issuer before it can safely perform private
runtime work, but a decoded or caller-constructed intermediate must never become an execution
credential.

The package is still unpublished at `0.1.0`. This correction is therefore frozen before external
consumption rather than hidden behind a permissive parser.

## Decision

1. Grant and proof signatures use the exact RFC 7515 JWS signing input:
   `base64url(protected) <> "." <> base64url(payload)`. No domain prefix is prepended.
2. `BAP1-REQUEST\0` remains the request-digest prefix. Its JCS body is
   `[operation, typed(cast_arguments)]`, where every tagged JSON variant projects to a closed
   JSON array beginning with its type name and object/array children project recursively. This
   preserves integer versus integral-float identity across RFC 8785 canonicalization.
   `BAP1-CHAIN\0` and `BAP1-ARCHIVE\0` remain reserved for BAP-04. The grant/proof separator rows
   are retired.
3. Deterministic producer functions canonicalize protected headers and payloads, return the exact
   JWS signing input, and never accept a private key, signer, or signing callback.
4. Verification signs and verifies the exact received protected and payload segments. Closed JSON
   member order is semantically insignificant; a correctly signed received object need not use
   producer order.
5. `verify_grant/3` accepts only raw compact bytes, an exact `TrustedIssuer`, and an exact
   `ExpectedGrant`. It returns a closed `GrantFacts` value with
   `authorization: :not_evaluated`, or `{:error, :invalid}`.
6. `check_envelope/2` accepts only raw grant/proof credentials and an exact `ExpectedRequest`. It
   re-verifies the raw grant through the same pure primitive and never accepts `GrantFacts`,
   decoded values, or another caller-constructible intermediate as credentials.
7. `GrantFacts` and `EnvelopeFacts` are value-bearing and redacted. Their fields remain directly
   readable, but fixed `Inspect` output and the absence of generic encoders prevent accidental
   display. They contain only the identifiers, timestamps, and fixed-size fingerprints/hashes
   named in the public contract; they exclude request argument values, selector values, raw
   credentials, signatures, JWK containers, and nonces.
8. Both result types are evidence of cryptographic and contextual verification only. They never
   select trust, check current revocation, reserve replay, grant execution, or override host
   policy.

## Consequences

- Standard JWS and DPoP implementations can reproduce the signed bytes without a private BAP
  convention.
- Closed `typ` and claim schemas, rather than a non-JWS prefix, separate grant and proof objects.
- A private runtime can perform standalone grant verification without accepting a forgeable facts
  value as authority.
- Any implementation that retains the retired grant/proof prefixes, accepts facts as credentials,
  or describes the result as value-free is nonconforming to v1.
- This ADR does not add trust discovery, signing, live state, replay, revocation, or business
  authorization to the public package.
