# 1. Public protocol verifier and private authority runtime

Date: 2026-07-26

## Status

Accepted.

## Context

Hosted and on-prem consumers need identical bounded-authority wire behavior and the ability to
verify grants and evidence independently. A written specification alone is not executable and
cannot prove that two implementations agree on canonical bytes, duplicate handling, normalization,
limits, signature inputs, or malformed-input rejection.

Publishing the stateful authority implementation would expose BaseLabs' operational machinery:
trusted-key selection, key custody, issuance, revocation ordering, replay reservation, execution
claims, PostgreSQL persistence, evidence writes, archive privileges, witnesses, recovery, and
operations. Those responsibilities are reusable but remain a private differentiator.

## Decision

1. Create the public repository and package `bounded_authority_protocol` /
   `:bounded_authority_protocol` / `BoundedAuthorityProtocol` under Apache License 2.0. The flat
   namespace prevents two packages from owning modules under the private runtime's
   `BoundedAuthority` namespace.
2. Put canonical protocol types, limits, JCS/request-digest rules, grant/DPoP byte verification,
   chain/archive verification, conformance vectors, and a verifier CLI in the public package.
3. Make all verifier context explicit. The caller supplies an already-trusted public key, expected
   audience/instance, server-derived request context, evaluation time, and limits.
   Provide a separate bounded `untrusted_key_locator/2` preparse that returns only the closed
   protected-header `kid` as an explicitly untrusted hint. It neither parses authorization claims
   nor selects trust; the private runtime combines it with expected issuer context, resolves a
   candidate-key snapshot, verifies the full envelope outside a database transaction, then
   re-resolves and locks current key/revocation state and requires the same fingerprint and current
   eligibility before any replay reservation or execution claim.
4. A public verifier result never selects trust, checks live state, reserves replay, grants
   execution, or overrides host policy. It is named `EnvelopeFacts`, explicitly carries
   `authorization: :not_evaluated`, has redacted inspection and no generic JSON encoder, and is
   never accepted as an execution credential by the private runtime.
5. Keep `bounded_authority` private. It consumes the public package and owns issuance, key custody
   and resolution, revocation state and ordering, replay reservation, invocation/execution claims,
   PostgreSQL persistence, outcome/consumption writes, archive removal, witnesses, recovery,
   telemetry, health, and operator workflows.
6. Keep `beamline_ash` dependent on the private runtime. It must not convert a direct public
   verification result into operational authority or bypass the private runtime.
7. Keep Beamline core and QorPay independent of both packages.
8. Version public formats and APIs under SemVer and contract-major discipline. Unknown versions
   and extensions fail closed.

## License decision

The initial option was a fully private implementation plus a public written protocol. The
adversarial pass rejected it because independent users could not execute the normative verifier or
prove exact-byte interoperability. MIT was considered for the library, but Apache-2.0 is selected
because its explicit patent grant and termination terms better fit a cryptographic protocol and
remain compatible with private commercial consumers.

## Consequences

- Hosted, on-prem, and third-party auditors can reproduce protocol verification without receiving
  the private stateful runtime.
- The public package is useful independently without exposing BaseLabs' authority operations.
- The private runtime has one canonical parser/verifier rather than a competing implementation.
- The private runtime accepts raw credentials at its public boundary and re-resolves current trust,
  revocation, replay, and execution state before minting its private decision/claim.
- Dependency direction remains one-way: private and product packages may depend on public
  protocol code; public protocol code never depends on them.
- QorPay remains unchanged; its private authority schemas and wire formats are not compatibility
  targets.
