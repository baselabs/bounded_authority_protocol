# Contributor guide for bounded_authority_protocol

## Where to read, by area

- Status: [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`CHANGELOG.md`](CHANGELOG.md).
- Wire formats and verification: the normative specs under [`spec/`](spec/), the protocol
  charter, threat model and conformance contract under [`docs/design/`](docs/design/), and
  the published [governance policy](docs/governance.md).
- Verifier SDKs and their publication boundary: [`sdks/README.md`](sdks/README.md).

## What this is

`bounded_authority_protocol` is the public, provider-neutral, deterministic protocol and
verification library for bounded proof-of-possession authority. Its package and namespace are
`:bounded_authority_protocol` and `BoundedAuthorityProtocol`.

It defines canonical grant, DPoP, request-binding, consumption-chain, and archive formats;
pure verification functions; independent conformance vectors; and a verifier CLI. It does not
grant operational authority by itself.

## Publication

- Cross-language verifier SDKs under `sdks/` are unpublished. Each graduates to its own
  repository on first publication; the `sdk-publish-guard` pre-commit hook and CI job
  reject registry-publish infrastructure in this repository. The TypeScript verifier graduated to
  [`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript);
  a corpus rotation is a snapshot-bump commit there.

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
5. **No product vocabulary.** Runtime and wire surfaces contain no host-product, Ash, AshAI,
   ScopeAxis, tenant, merchant, asset, partition, or provider-specific semantics.
6. **No secret material.** The verifier accepts public keys only. Private keys, signing callbacks,
   KMS/HSM clients, credentials, and secrets cannot enter the package or conformance fixtures.
7. **Canonical bytes are the contract.** Grant and proof signatures use the exact standard JWS
   signing input. Request digests, chain links, archives, duplicate handling, normalization,
   limits, and errors are versioned and independently tested.
8. **Public compatibility is deliberate.** Once released, wire formats and public APIs follow
   SemVer and the contract-major discipline. No permissive compatibility parser is added.
9. **Apache-2.0 is the stable release license.** Do not introduce proprietary source, private
   package dependencies, or a timed license conversion.

## Repository relationships

- Public protocol: [`baselabs/bounded_authority_protocol`](https://github.com/baselabs/bounded_authority_protocol)
- Holder-side signer companion:
  [`baselabs/bounded_authority_report_adapter`](https://github.com/baselabs/bounded_authority_report_adapter)
  (public Hex package `bounded_authority_report_adapter`; its dependency is one-directional: it depends on this
  package, which never depends on it)
- Stateful runtime consumers own operational authorization and live state; this package
  supplies only pure verification.
- Product consumers: private; their repository identities and deployment topology are not part of
  this public protocol's documentation or history

```text
private authority runtime  -> bounded_authority_protocol + runtime dependencies
private product consumers  -> private authority runtime
holder report adapter      -> bounded_authority_protocol (holder-side signing; never the reverse)
bounded_authority_protocol -> pure protocol/crypto dependencies only
```

A production consumer obtains an operational decision from a stateful authority runtime. It does
not treat a direct public-verifier result as execution authority or call this package directly.
The runtime accepts raw credentials at its public boundary, not a caller-provided `EnvelopeFacts`.

## Workflow

Make the change and commit it with named paths. A maintainer lands it through the
qualification run: CI starts only on a push to a `kci/<sha>` branch, and `main` moves to that
exact commit only when the run's last job, `qualified`, is green. Pull requests get no CI run of
their own; the landing run qualifies them.

- CI runs `mix quality` (package, purity, documentation, advisory, license, SBOM and
  unpacked-consumer checks). Run the parts that cover your change.
- Contributors and agents never publish, tag a version, deploy or dispatch a workflow.
  `publish.yml` publishes the Hex package and `pages.yml` deploys the site; the maintainers'
  release operator dispatches both from `main`.
- A test that fails on every run is a defect: fix it, or quarantine it with a reason, in the
  change that finds it.
- Update the CHANGELOG when behavior, a dependency or a contract changes; other docs only when
  a contract changes.
- A changed public contract updates its vectors, spec or ADR and consumer documentation in the
  same commit.
- Do not claim interoperability from self-round-trips. Normative vectors require an independent
  implementation and exact-byte comparison.
