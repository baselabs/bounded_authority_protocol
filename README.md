# bounded_authority_protocol

Public Apache-2.0 protocol, deterministic verifier, and conformance suite for cryptographically
bounded proof-of-possession authority.

## Status

The public/private boundary is complete under
[`BAP-00`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/ROADMAP.md). The source tree now
contains the unpublished `:bounded_authority_protocol` 0.1.0 Mix package scaffold and its enforced
release boundary. BAP-01 remains in progress until public CI and trusted-main attestations pass.
No protocol profile or verifier behavior is implemented yet; `BAP-02` starts only after that
closeout. Nothing in this repository has been published to Hex.

The scaffold has zero production dependencies, no application callback, and no supervision tree.
Source AST, compiled BEAM imports, generated application metadata, dependency declarations, and
the unpacked Hex archive are all checked to preserve that boundary.

## Public contract

The planned library will provide:

- closed, versioned capability-grant and RFC 9449 DPoP data types;
- RFC 8785 JCS request digests and exact signing inputs;
- compact EdDSA grant and holder-proof decoding and verification;
- consumption-chain and archive verification;
- normative fixtures, independent conformance vectors, and a verifier CLI;
- fixed, value-free errors and explicit resource limits.

All verification inputs are explicit: already-trusted public key, expected audience and instance,
server-derived method, normalized URI, invocation ID, operation, cast arguments, evaluation time,
and limits. A successful result means only that the supplied bytes satisfy those supplied inputs.

The public package also exposes a bounded `untrusted_key_locator/2` preparse that returns only the
closed protected-header `kid` as an explicitly untrusted lookup hint. It never selects or marks a
key trusted. The stateful runtime combines that hint with its expected issuer context, resolves a
candidate-key snapshot, and verifies the complete envelope outside a database transaction. It then
opens the state transaction, re-resolves and locks the current key/revocation rows, requires the
same key fingerprint and current eligibility, and only then reserves replay or claims execution.

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
beamline_ash               -> beamline + bounded_authority + ash + ash_ai
bounded_authority_protocol -> no private or product package
```

See the [protocol charter](docs/design/protocol-charter.md), [threat model](docs/design/threat-model.md),
[conformance contract](docs/design/conformance-contract.md), and
[ADR 0001](docs/adr/0001-public-protocol-verifier-boundary.md).

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
mix package.check
mix sbom.generate
```

Main-branch CI builds an unpublished package archive, records its SHA-256 checksum, produces
release and tooling CycloneDX documents, and creates separate GitHub build-provenance and SBOM
attestations. That CI artifact is not a release candidate and is never published by BAP-01.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
