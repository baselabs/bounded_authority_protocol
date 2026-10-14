# bounded_authority_protocol — AI Agent and Contributor Guide

## Read first

Before work, read this file, [`README.md`](README.md), [`docs/ROADMAP.md`](docs/ROADMAP.md), the accepted ADRs under
[`docs/adr/`](docs/adr/), and the stable contracts under [`docs/design/`](docs/design/).

When local process artifacts exist, they are implementation aids, not the remote cold-start
authority. The tracked roadmap, ADR, protocol charter, threat model, and conformance contract
must always be sufficient to regenerate a reviewed implementation plan.

## What this is

`bounded_authority_protocol` is the public, provider-neutral, deterministic protocol and
verification library for bounded proof-of-possession authority. Its package and namespace are
`:bounded_authority_protocol` and `BoundedAuthorityProtocol`.

It defines canonical grant, DPoP, request-binding, consumption-chain, and archive formats;
pure verification functions; independent conformance vectors; and a verifier CLI. It does not
grant operational authority by itself.

## Current state

Closed: `BAP-00` through `BAP-11`, `BAP-13` through `BAP-19`, and `BAP-21` through `BAP-24`
(`BAP-17` is design-only; `BAP-24`, the strict Ed25519 soundness erratum, closed with the 0.8.0
release). Open: `BAP-12` (IANA filing, gated on the BAP-08 external submission preconditions) and
`BAP-25` (producer-surface signature canonicality, erratum 3, landing for 0.9.0).
Consult [`docs/ROADMAP.md`](docs/ROADMAP.md); its closeout-evidence
blocks are the status authority.

Unreleased source (version 0.9.0, a clarifying minor, erratum 3): compact assembly and
anchored-export encoding refuse a signature no conforming signer emits and never rewrite accepted
bytes (`REQ1/REQ2-SIGNING-ed25519-producer-canonical`, `REQ3-SIGNING-producer-canonical`), with the
additive certified `bap-producer-canonicality/1` corpus (`priv/conformance/producer-canonicality`,
75 cases) and the new public `BoundedAuthorityProtocol.Es256` owner of the ES256 rules
(`canonical_signature?/1`, `acceptable_public_key?/1`, `verify_strict/3`, `normalize_low_s/1`,
`der_to_raw/1`). The Python, Go, Rust, and TypeScript units of erratum 3 are open.

Release 0.8.0 is the strict Ed25519 verification soundness repair
([ADR 0040](docs/adr/0040-strict-ed25519-soundness-erratum.md), erratum 2): rule S1 (canonical
point encodings, no small-order key or `R`, `S < L`, the cofactorless equation) on every Ed25519
surface, owned by the public `BoundedAuthorityProtocol.Ed25519` (`verify_strict/3`,
`acceptable_public_key?/1`, `torsion_free?/1`), with the additive certified strict-Ed25519 corpus
(`priv/conformance/strict-ed25519`, `bap-strict-ed25519/1`, 2,410 cases) and the
soundness-repair governance class. The latest Hex release is 0.8.0, tagged `v0.8.0` (published
October 13, 2026 with its security advisory and read back from the registry; releases 0.1.0
through 0.7.0 are retired), over the 0.7.0 content-assertion release, the 0.6.2 cross-Elixir
repair patch, the 0.6.0 role-attestation release, and the 0.5.0 ES256 contract-major 3
activation. The graduated TypeScript packages are at npm verifier 0.7.0 (browser-safe) and
signer 0.5.0. The
package retains zero production
dependencies, no application callback, and no supervision tree. Contract-major 1 remains frozen;
contract-major 2 is active under `BoundedAuthorityProtocol.V2` with the `lte` and `gte` selector
kinds, its own normative profile, certified 268-case corpus, `REQ2-*` traceability, and
cross-major rejection; contract-major 3 is active under `BoundedAuthorityProtocol.V3` — the
`BAP3-ES256-SHA256` suite (ECDSA P-256/SHA-256, RFC 7518 §3.4 raw `r || s` signatures with
low-S canonicality, EC JWK holder keys, `BAP3-*` separators) with its own normative profile,
certified 292-case corpus, `REQ3-*` traceability, and cross-major rejection of v1 and v2 bytes.
The v1 corpus remains 283 cases across 28 surfaces. The protocol also carries three byte-distinct
sibling profiles parsed by no contract-major: the loopback proof profile
(`bap-application-proof/local-loopback-http/1`, ADR 0027) and the role-attestation profile
(`bap-role-attestation/1`, ADR 0036 — a standalone, grant-unbound BA-signed role binding with
`BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2`, its certified 40-case corpus,
`REQ-RA1-*` ids, and the sibling-attestation governance class; the BARA RA11 prerequisite,
released in 0.6.0 with both consumption receipts recorded), and the content-assertion profile
(`bap-content-assertion/1`, ADR 0037, released in 0.7.0: a standalone, grant-unbound signed
binding of an exact content digest to issuer, audience, lineage subject, semantic profile,
window, and predecessor, with `BoundedAuthorityProtocol.ContentAssertion.V1`, its certified
131/9/14-case corpus, and `REQ-CA1-*` ids). See
[ADR 0030](docs/adr/0030-v2-contract-major-activation.md),
[ADR 0035](docs/adr/0035-es256-contract-major-activation.md),
[ADR 0036](docs/adr/0036-role-attestation-profile.md),
[ADR 0037](docs/adr/0037-content-assertion-profile.md), [`spec/bap-v1.md`](spec/bap-v1.md),
[`spec/bap-v2.md`](spec/bap-v2.md), [`spec/bap-v3.md`](spec/bap-v3.md),
[`spec/bap-role-attestation-v1.md`](spec/bap-role-attestation-v1.md), and
[`spec/bap-content-assertion-v1.md`](spec/bap-content-assertion-v1.md).

Unpublished cross-language verifier SDKs are authored under [`sdks/`](sdks/)
([ADR 0014](docs/adr/0014-cross-language-verifier-sdks.md)): Python
(`bounded-authority-verifier`), Rust
(`bounded-authority-protocol`, BAP-15), and Go (`bounded_authority_protocol_go`, BAP-16) — each
reimplements the frozen profiles from the specs and corpora alone, passes the certified v1, v2,
and v3 vectors plus the loopback, role-attestation, and content-assertion profile corpora with
every corpus index
SHA-256 asserted at load, and ships a red-capable per-language
permissiveness mutation gate. None of these three is published to a registry. Per
[ADR 0015](docs/adr/0015-sdk-graduation-and-publish-topology.md), each graduates to its own per-SDK
repository on first publication, and the `sdk-publish-guard` pre-commit hook and CI job reject
registry-publish infrastructure in this monorepo. The TypeScript SDK was the first to graduate
(2026-09-14): it is published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
from its own repository,
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript)
(vendored corpora, self-contained CI, and two-stage npm publishing). Its source no longer lives in
this monorepo; a corpus rotation is a snapshot-bump commit in that repository.

Design-carrying slices (all zero wire-behavior change on the closed v1 profile): BAP-11
(cryptographic-suite succession and cross-suite evidence longevity,
[ADR 0009](docs/adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md)),
BAP-14 (delegation with attenuation,
[ADR 0010](docs/adr/0010-delegation-with-attenuation.md)), BAP-08 (the MCP capability-authorization
extension drafts under `docs/extensions/`,
[ADR 0013](docs/adr/0013-capability-authorization-extension.md)), BAP-13 (published governance,
[docs/governance.md](docs/governance.md)), and BAP-17 (the reserved `ba_offline` floor-limit claim
and its activating-major mechanism,
[ADR 0016](docs/adr/0016-offline-eligible-grant-claims.md)). The BAP-15 hardening-arc contracts are
recorded in ADR 0017 (the inter-SDK behavioral contract), ADR 0018 (the SDK bounds contract), and
ADR 0019 (corpus-artifact distribution), ADR 0020 (bounds-aware assembly and issuer-mediated
reauthorization posture), ADR 0021 (the v1 `all` selector recognized-shapes erratum), ADR 0022
(durable contract identities), and ADR 0027 (byte-distinct application-proof profiles). Accepted
ADRs are 0001–0037 and 0040 (ADR 0040 is the strict Ed25519 soundness erratum; 0038 and 0039
are reserved for designs not yet accepted; ADR 0035 activates the ES256 contract-major 3 suite; ADR 0036 adds the
role-attestation sibling profile; ADR 0037 adds the content-assertion sibling profile; ADR 0029 records the cumulative-budget posture and explicitly defers the
`ba+budget-window` attestation-shape design; ADR 0034 decides the UCP riding point as
transport-composed) under [`docs/adr/`](docs/adr/). BAP-19's source identity is fixed by
`v0.3.0`; the registry publication and checksum read-back closed 2026-08-31, and downstream
immutable-package adoption is tracked in the private runtime.

The companion signer `bounded_authority_report_adapter` 0.10.0 signs this profile over BAP 0.8.0
(`sign_content_assertion/3`). Each consumer's acceptance is tracked by that consumer.

## Critical rules

1. **Verification is not authority.** A successful pure verification result proves only that
   caller-supplied bytes satisfy caller-supplied trusted inputs and expected context. It never
   selects trusted keys, reserves replay, checks live revocation, grants execution, or overrides a
   host policy. Public verified results are `GrantFacts`, `EnvelopeFacts`, `ChainFacts`,
   `AnchorFacts`, `KeyTransitionFacts`, `AnchoredExportFacts`, `AttestationFacts`, and
   `ContentAssertionFacts`. Only
   `GrantFacts`, `EnvelopeFacts`, and `AnchoredExportFacts` carry `authorization: :not_evaluated`;
   the diagnostic chain, anchor, transition, and attestation facts carry only
   `trust: :not_evaluated`. There is no `allowed?`,
   `authorized?`, `decision`, or receipt. Facts are value-bearing and redacted, never execution
   credentials.
2. **Pure and deterministic.** Runtime code has no database, filesystem, network, environment,
   process dictionary, clock, random-number generator, supervisor, or application callback.
   Time, expected audience, already-trusted public keys, request context, and limits are explicit
   inputs.
3. **Fail closed.** Unknown versions, algorithms, headers, claims, selectors, holder modes,
   duplicate keys, invalid encodings, and over-limit structures return closed, value-free errors.
4. **No private-runtime responsibilities.** Key custody, trusted-key discovery, issuance,
   revocation state, replay reservation, invocation claims, outcomes, consumption writes, archive
   removal, witnesses, recovery, and operational health belong to the private
   `bounded_authority` runtime.
5. **No product vocabulary.** Runtime and wire surfaces contain no host-product, Ash, AshAI, QorPay,
   ScopeAxis, tenant, merchant, asset, partition, or provider-specific semantics.
6. **No secret material.** The verifier accepts public keys only. Private keys, signing callbacks,
   KMS/HSM clients, credentials, and secrets cannot enter the package or conformance fixtures.
7. **Canonical bytes are the contract.** Grant and proof signatures use the exact standard JWS
   signing input. Request digests, chain links, archives, duplicate handling, normalization,
   limits, and errors are versioned and independently tested.
8. **Public compatibility is deliberate.** Once released, wire formats and public APIs follow
   SemVer and the contract-major discipline. No permissive compatibility parser is added.
9. **QorPay is out of bounds.** Do not access its repository. Never edit, import, decode, issue, or
   promise compatibility with private QorPay credentials, schemas, or wire formats.
10. **Apache-2.0 is the stable release license.** Do not introduce proprietary source, private
    package dependencies, or a timed license conversion.

## Repository relationships

- Public protocol: [`baselabs/bounded_authority_protocol`](https://github.com/baselabs/bounded_authority_protocol)
- Holder-side signer companion:
  [`baselabs/bounded_authority_report_adapter`](https://github.com/baselabs/bounded_authority_report_adapter)
  (public Hex package `bounded_authority_report_adapter`; one-directional — it depends on this
  package, which never depends on it)
- Private runtime consumer: `baselabs/bounded_authority` (a private commercial application; it
  must never be published as a public Hex package, and any private-Hex release requires
  a paid subscription plus fresh owner approval
  for that exact release)
- Product consumers: private; their repository identities and deployment topology are not part of
  this public protocol's documentation or history
- QorPay: unchanged and not a dependency

```text
private authority runtime  -> bounded_authority_protocol + runtime dependencies
private product consumers  -> private authority runtime
holder report adapter      -> bounded_authority_protocol (holder-side signing; never the reverse)
bounded_authority_protocol -> pure protocol/crypto dependencies only
qorpay                     -> no authority dependency
```

A production consumer obtains an operational decision from a stateful authority runtime. It does
not treat a direct public-verifier result as execution authority or call this package directly.
The runtime accepts raw credentials at its public boundary, not a caller-provided `EnvelopeFacts`.

## Workflow

- Stay on `main`; do not create ad-hoc branches or worktrees.
- Never use stash, history rewrites, blanket staging, or destructive cleanup.
- Use Kimosabe for every change. Wire formats, cryptography, verification, canonicalization,
  conformance, and verifier SDK surfaces are T2.
- Write the failing test first. Every security gate requires allow, deny, malformed-input, and
  mutation-red evidence as applicable.
- Run `mix quality` before landing. It is the complete local package, purity, documentation,
  advisory, license, SBOM, and unpacked-consumer gate.
- Update the changelog, roadmap, ADR/design contracts, vectors, and consumer documentation in the
  same landing as a changed public contract.
- Do not claim interoperability from self-round-trips. Normative vectors require an independent
  implementation and exact-byte comparison.
