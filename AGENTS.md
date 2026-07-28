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

`BAP-00` through `BAP-04` are implemented. The unpublished 0.1.0 package retains zero production
dependencies, no application callback, and no supervision tree. The normative v1 tables and
bounds, raw-number preflight, bounded ordered JSON decoder with recursive duplicate rejection,
strict base64url decoder, Draft 2020-12 structural schemas, architecture mutation gates, public
compatibility CI, exact-package consumer proof, CycloneDX output, and trusted-main provenance
verification are closed. BAP-03 adds standard RFC 7515 JWS signing, deterministic grant/proof
producers, bounded raw decode, standalone raw-grant verification, combined raw-envelope
verification, value-bearing redacted facts, public-only independently verified vectors, and
portable resource bounds. BAP-04 adds canonical consumption rows and range verification, signed
boundary anchors and historical-key transitions, authenticated rollover, and atomic raw archived
export verification. Consult [`docs/ROADMAP.md`](docs/ROADMAP.md),
[`ADR 0003`](docs/adr/0003-standard-jws-and-verified-grant-results.md), and
[`ADR 0004`](docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md).
Commercial release readiness and BAP-05 remain open.

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
- First product consumer: `baselabs/beamline` package `integrations/retired_private_consumer` (private)
- QorPay: unchanged and not a dependency

```text
bounded_authority          -> bounded_authority_protocol + ecto_sql + postgrex + runtime deps
retired_private_consumer               -> beamline + bounded_authority + ash + ash_ai
bounded_authority_protocol -> pure protocol/crypto dependencies only
beamline                   -> no authority dependency
qorpay                     -> no authority dependency
```

`retired_private_consumer` obtains an operational decision from the private runtime. It does not treat a
direct public-verifier result as execution authority or call this package directly. The private
runtime accepts raw credentials at its public boundary, not a caller-provided `EnvelopeFacts`.

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
