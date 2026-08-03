# bounded_authority_protocol

Public Apache-2.0 protocol, deterministic verifier, and conformance suite for cryptographically
bounded proof-of-possession authority.

## Status

The public/private boundary is complete under
[`BAP-00`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/ROADMAP.md). The source tree now
contains the unpublished `:bounded_authority_protocol` 0.1.0 Mix package scaffold and its enforced
release boundary. `BAP-01` through `BAP-04` are complete. BAP-04's package-bearing closeout head
`c4d7716de6499f29524e60638207b1c36e9484b3` passed the supported CI matrix and exact unpublished
package, checksum, provenance, and SBOM gates. The package implements deterministic standard
compact-JWS grant and RFC 9449 holder-proof production, bounded decoding, standalone raw-grant
verification, and combined raw-envelope verification. Its public-only vectors are independently
verified and cover exact key census, meaningful byte tampering, duplicate members, holder binding,
request digests, selectors, time boundaries, and URI normalization. Portable timing/allocation
bounds and the unpacked external-consumer gate exercise the same public API. BAP-04 adds canonical
consumption chains, signed boundary anchors, authenticated historical-key rollover, deterministic
anchored archives, and atomic raw-archive verification against mandatory caller boundaries,
digest, and object version. Its public-only corpus and resource limits are independently verified.
Nothing in this repository has been published to Hex.

The scaffold has zero production dependencies, no application callback, and no supervision tree.
Source AST, compiled BEAM imports, generated application metadata, dependency declarations, and
the unpacked Hex archive are all checked to preserve that boundary.

## Public contract

The v1 profile now provides:

- immutable protected-header, claim, selector, separator, URI, encoding, and resource-limit tables;
- `BoundedAuthorityProtocol.V1.Json.decode/2`, returning the closed tagged JSON algebra with
  recursive duplicate rejection and no input-name atomization;
- raw numeric-lexeme and exact-decimal magnitude enforcement before numeric conversion;
- `BoundedAuthorityProtocol.V1.Base64Url.decode/2`, providing strict canonical unpadded
  base64url decoding;
- a protected-header-only `untrusted_key_locator/2` that returns `trust: :not_evaluated`;
- deterministic grant and proof signing-input production with external signature assembly;
- exact public Ed25519 JWK encoding, decoding, and RFC 7638 thumbprints;
- bounded HTTPS target-URI normalization and type-preserving request digests;
- bounded grant/proof decoding with `verification: :not_evaluated`;
- `verify_grant/3`, returning redacted, non-authorizing `GrantFacts`;
- `check_envelope/2`, re-verifying the raw grant and binding the holder signature, request,
  nonce, time, digest, operation, and selectors before returning redacted, non-authorizing
  `EnvelopeFacts`.
- canonical consumption-row production and raw range checking against exact predecessor/head
  boundaries;
- deterministic boundary-anchor and historical-key-transition standard-JWS signing inputs with
  external signature assembly;
- deterministic anchored-export framing and `verify_anchored_export/3`, which scans raw chunks to
  exact EOF, verifies the complete digest and out-of-band object version, authenticates the
  positional key path and both boundaries, and checks every row;
- fixed-redacted, non-authorizing chain, anchor, transition, and anchored-export facts.

The two decoder functions live in named public submodules under the explicit
`BoundedAuthorityProtocol.V1` namespace. There is no duplicate decoder façade and no implicit
latest profile. Resource limits are tightening-only positive integers; the Ed25519 key/signature
and SHA-256 digest widths are immutable protocol constants. Unknown, non-integer, zero/negative,
widening, or fixed-width-changing values fail with the fixed value-free `{:error, :invalid}`. The
structural Draft 2020-12 schemas accompany the decoders but do not replace duplicate-name,
raw-number, UTF-8 byte, depth, node-count, or canonical-encoding enforcement.

Later rows will provide:

- the portable conformance corpus and verifier CLI;
- release-candidate and connected-release gates.

All verification inputs are explicit: already-trusted public key, expected audience and instance,
server-derived method, normalized URI, invocation ID, operation, cast arguments, evaluation time,
and limits. A successful result means only that the supplied bytes satisfy those supplied inputs.

The public package exposes a bounded `untrusted_key_locator/2` preparse that returns only the
closed protected-header `kid` as an explicitly untrusted lookup hint. It does not decode payload
or signature segments and never selects or marks a key trusted.

## Deliberate exclusions

This package does not discover trust, issue grants, hold keys, read a database, reserve replay,
check live revocation state, claim an execution, authorize a business effect, append outcomes or
consumptions, remove archived evidence, submit witnesses, or run an OTP service.

Those stateful responsibilities belong to the private
[`bounded_authority`](https://github.com/baselabs/bounded_authority) runtime. Product integration
belongs to the consuming host. QorPay is unchanged; its private authority schemas and wire formats
are not protocol compatibility targets.

## Dependency direction

```text
bounded_authority          -> bounded_authority_protocol
retired_private_consumer               -> beamline + bounded_authority + ash + ash_ai
bounded_authority_protocol -> no private or product package
```

See the [normative v1 profile](docs/protocol-v1.md),
[protocol charter](docs/design/protocol-charter.md), [threat model](docs/design/threat-model.md),
[conformance contract](docs/design/conformance-contract.md), and
[ADR 0001](docs/adr/0001-public-protocol-verifier-boundary.md) plus
[ADR 0002](docs/adr/0002-normative-v1-parsing-profile.md) and
[ADR 0003](docs/adr/0003-standard-jws-and-verified-grant-results.md), plus
[ADR 0004](docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md), plus
[ADR 0005](docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md).

## Conformance

The package ships a language-neutral v1 conformance corpus and a deterministic offline verifier
CLI. The corpus (`priv/conformance/v1/corpus`) is the normative evidence: 68 cases across 28
surfaces with a total surface × class applicability matrix, re-derived from the official
implementation and independently re-verified by a second Node implementation
(`conformance/corpus_independent.mjs`) that recomputes every verdict from scratch. A value that
only round-trips the official implementation is not normative until the independent runner agrees.

Build the verifier and run it against the shipped corpus:

```bash
mix escript.build
./bounded_authority_conformance --corpus priv/conformance/v1/corpus
```

`--corpus DIR` is required (no default — a wrong-corpus run that exits 0 is a quiet
misverification path in the tool built to eliminate quiet misverification). It exits `0` only on
complete agreement, `1` on any integrity/verdict failure, `2` on usage error. From a consumer
dependency, point `--corpus` at the packaged path under `deps/bounded_authority_protocol/`. The
report is deterministic JCS bytes binding the corpus index SHA-256. See
[`docs/design/conformance-contract.md`](docs/design/conformance-contract.md) and
[ADR 0005](docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md).

## Development

The supported CI matrix is Elixir 1.18/OTP 27, Elixir 1.19/OTP 28, and Elixir 1.20/OTP 29.
After installing a supported pair:

```bash
mix deps.get
mix quality
```

`mix quality` runs formatting, warnings-as-errors compilation, the purity architecture gate,
Credo, tests with coverage, Dialyzer, documentation, unused/retired/vulnerable dependency checks,
closed dependency-license and CycloneDX checks, and an exact packed/unpacked consumer test.

Useful focused gates are:

```bash
mix architecture
mix audit
mix bap03.performance
mix bap04.performance
mix conformance.verify
mix chain_archive.mutations
mix conformance.mutations
mix package.check
mix sbom.generate
```

`mix.exs` is the executable authority for the supported Elixir floor, and
`.github/workflows/ci.yml` is the executable authority for tested Elixir/OTP pairs. Each
trusted-main workflow run, checksum, and attestation identifies its own source revision and
artifact. These executable facts deliberately have no duplicate lifecycle ADR.

Main-branch CI builds an unpublished package archive, records its SHA-256 checksum, produces
release and tooling CycloneDX documents, and creates separate GitHub build-provenance and SBOM
attestations. That CI artifact is not a release candidate and is never published by BAP-01.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
