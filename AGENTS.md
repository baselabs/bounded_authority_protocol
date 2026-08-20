# bounded_authority_protocol — AI Agent and Contributor Guide

## Read first

Before work, read this file, [`README.md`](README.md), [`docs/ROADMAP.md`](docs/ROADMAP.md), the accepted ADRs under
[`docs/adr/`](docs/adr/), and the stable contracts under [`docs/design/`](docs/design/).

When local Forge artifacts exist, they are implementation aids, not the remote cold-start
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

Closed: `BAP-00` through `BAP-11`, `BAP-13` through `BAP-15`,
`BAP-17` (design-only), and `BAP-18` — including `BAP-07` (connected verification and first public
release, executed 2026-08-20 by owner decision: the exact candidate passed the private runtime's
PostgreSQL 18 gate and the consumer connected gates, the fresh review set closed, and the archive
published to Hex; consumption uses the Hex release). Open: `BAP-12` (IANA templates, gated on the
BAP-08 external submission preconditions) and `BAP-16` (the Go verifier SDK — authored, not
started). Consult
[`docs/ROADMAP.md`](docs/ROADMAP.md); its closeout-evidence blocks are the status authority.

The published 0.1.0 package retains zero production dependencies, no application callback, and no
supervision tree. The v1 surface is complete: the normative tables and bounds, raw-number preflight,
the bounded ordered JSON decoder with recursive duplicate rejection, strict base64url decoding,
Draft 2020-12 structural schemas, architecture mutation gates, public compatibility CI, exact-package
consumer proof, CycloneDX output, and trusted-main provenance verification are closed. BAP-03 added
standard RFC 7515 JWS signing-input production, deterministic grant/proof producers, bounded raw
decode, standalone raw-grant and combined raw-envelope verification, value-bearing redacted facts,
public-only independently verified vectors, and portable resource bounds. BAP-04 added canonical
consumption rows and range verification, signed boundary anchors and historical-key transitions,
authenticated rollover, and atomic raw archived-export verification. BAP-10 added the RFC 2119/8174
normative rewrite with stable `REQ1-*` requirement identifiers and the MUST-to-conformance-cell
traceability map; BAP-06 froze the 0.1.0 release candidate (the locked public API surface enforced
by the architecture gate, [ADR 0008](docs/adr/0008-release-candidate-contract.md), plus the
two-build `release.candidate` reproducibility check); BAP-05 shipped the portable conformance corpus
(283 cases across 28 surfaces, dual-verified by the independent Node runner) and the deterministic
verifier CLI, with the 55/55 conformance mutation battery and `conformance.verify` (agreed=283)
wired into `mix quality` alongside the full suite (295 tests + 13 properties).

Cross-language verifier SDKs live under [`sdks/`](sdks/)
([ADR 0014](docs/adr/0014-cross-language-verifier-sdks.md)): TypeScript
(`@bounded-authority/verifier`), Python (`bounded-authority-verifier`), and Rust
(`bounded-authority-protocol`, BAP-15) — each reimplements the frozen v1 profile from the spec and
corpus alone, passes all 283 vectors with the certified corpus index SHA-256 asserted at load (the
Rust SDK vendors a self-contained snapshot; the TypeScript and Python runners consume the monorepo
corpus in place), and ships a red-capable per-language permissiveness mutation-gate. None is
published to a registry: per
[ADR 0015](docs/adr/0015-sdk-graduation-and-publish-topology.md), each graduates to its own per-SDK
repository on first publication, and the `sdk-publish-guard` pre-commit hook and CI job reject
registry-publish infrastructure in this monorepo.

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
ADR 0019 (corpus-artifact distribution), and ADR 0020 (bounds-aware assembly and issuer-mediated
reauthorization posture). Accepted ADRs run 0001–0020 under
[`docs/adr/`](docs/adr/). Commercial release readiness remains open.

## Critical rules

1. **Verification is not authority.** A successful pure verification result proves only that
   caller-supplied bytes satisfy caller-supplied trusted inputs and expected context. It never
   selects trusted keys, reserves replay, checks live revocation, grants execution, or overrides a
   host policy. Public verified results are `GrantFacts`, `EnvelopeFacts`, `ChainFacts`,
   `AnchorFacts`, `KeyTransitionFacts`, and `AnchoredExportFacts`. Only `GrantFacts`,
   `EnvelopeFacts`, and `AnchoredExportFacts` carry `authorization: :not_evaluated`; the diagnostic
   chain, anchor, and transition facts carry only `trust: :not_evaluated`. There is no `allowed?`,
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
5. **No product vocabulary.** Runtime and wire surfaces contain no Beamline, Ash, AshAI, QorPay,
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
- Private runtime consumer: `baselabs/bounded_authority` (private)
- Product consumer: `baselabs/navyler_cdc` (private; the successor product — `beamline_ash` is
  deprecated and not a current consumer)
- QorPay: unchanged and not a dependency

```text
bounded_authority          -> bounded_authority_protocol + ecto_sql + postgrex + runtime deps
navyler_cdc                -> bounded_authority + CDC transport libraries (capstan, replicant)
bounded_authority_protocol -> pure protocol/crypto dependencies only
qorpay                     -> no authority dependency
```

A production consumer obtains an operational decision from a stateful authority runtime. It does
not treat a direct public-verifier result as execution authority or call this package directly.
The runtime accepts raw credentials at its public boundary, not a caller-provided `EnvelopeFacts`.

## Workflow

- Stay on `main`; do not create ad-hoc branches or worktrees outside sanctioned Forge lanes.
- Never use stash, history rewrites, blanket staging, or destructive cleanup.
- Use Forge for every slice. Wire formats, cryptography, verification, canonicalization, and
  conformance are T2.
- Write the failing test first. Every security gate requires allow, deny, malformed-input, and
  mutation-red evidence as applicable.
- Run `mix quality` before landing. It is the complete local package, purity, documentation,
  advisory, license, SBOM, and unpacked-consumer gate.
- Update the changelog, roadmap, ADR/design contracts, vectors, and consumer documentation in the
  same landing as a changed public contract.
- Do not claim interoperability from self-round-trips. Normative vectors require an independent
  implementation and exact-byte comparison.
