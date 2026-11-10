# API stability and versioning

This page lists exactly what the Hex package promises across a release line, and what it does
not. The repository's test suite checks the module lists below against the architecture gate
that pins the package's public exports and struct fields, so the page and the code cannot drift
apart.

## Two version numbers

- **Package versions** (`0.9.1`, `1.0.0`, `1.1.0`) are Hex releases of this library, following
  [Semantic Versioning](https://semver.org). "Package 1.x" means every release from 1.0.0 before
  2.0.0.
- **Contract-majors** (1, 2, 3) are closed wire profiles, each with its own namespace
  (`BoundedAuthorityProtocol.V1`, `V2`, `V3`), suite (`BAP1-Ed25519-SHA256`,
  `BAP2-Ed25519-SHA256`, `BAP3-ES256-SHA256`), specification, and corpus.

The numbers are independent. One package release carries several contract-majors, a new
contract-major arrives in a package minor release, and a package major release changes no wire
profile.

## What a release may change

From package 1.0.0 ([governance § Package versions](../governance.md#package-versions) is the
normative text):

| Release | May contain |
|---|---|
| Patch (1.0.x) | An editorial erratum, or a fix that changes no documented behavior or verdict. |
| Minor (1.x.0) | A new contract-major or sibling profile; a new public function, optional argument, or struct field with a default; a soundness repair that meets every governance condition; a raised Elixir or Erlang/OTP floor, announced in the changelog. |
| Major (2.0.0) | Removing a namespace, or changing a struct field, a function arity, a return shape, an enforced key, or a documented error. |

A soundness repair is the one way a verdict changes inside a contract-major: it changes verdicts
only from accept to reject, only on inputs no conforming producer emits, and it is recorded in
the [errata registry](../errata.md). Pin the minor-bounded requirement (`~> 1.0` admits every 1.x
release) and run the packaged corpora after each upgrade
([Recipes](recipes.md#run-every-packaged-corpus)).

Within a contract-major, the accepted bytes and verdicts never change except through such a
repair. Every function keeps returning `{:ok, value}` or exactly `{:error, :invalid}`, and the
facts structs keep their not-evaluated markers.

## Stable surface

Within package 1.x, these modules keep their public functions (name, arity, argument and return
shapes), their struct fields, and their documented errors. New functions and new defaulted
fields may be added.

Contract-major 1 facade and structs:

- `BoundedAuthorityProtocol.V1`
- `BoundedAuthorityProtocol.V1.AnchorFacts`
- `BoundedAuthorityProtocol.V1.AnchoredExportFacts`
- `BoundedAuthorityProtocol.V1.AnchoredExportInput`
- `BoundedAuthorityProtocol.V1.ArchivedObject`
- `BoundedAuthorityProtocol.V1.BoundaryAnchor`
- `BoundedAuthorityProtocol.V1.ChainFacts`
- `BoundedAuthorityProtocol.V1.ChainInput`
- `BoundedAuthorityProtocol.V1.ConsumptionEntry`
- `BoundedAuthorityProtocol.V1.Credentials`
- `BoundedAuthorityProtocol.V1.DecodedGrant`
- `BoundedAuthorityProtocol.V1.DecodedProof`
- `BoundedAuthorityProtocol.V1.EncodedAnchoredExport`
- `BoundedAuthorityProtocol.V1.EncodedConsumptionEntry`
- `BoundedAuthorityProtocol.V1.EnvelopeFacts`
- `BoundedAuthorityProtocol.V1.ExpectedAnchor`
- `BoundedAuthorityProtocol.V1.ExpectedAnchoredExport`
- `BoundedAuthorityProtocol.V1.ExpectedChain`
- `BoundedAuthorityProtocol.V1.ExpectedExport`
- `BoundedAuthorityProtocol.V1.ExpectedGrant`
- `BoundedAuthorityProtocol.V1.ExpectedKeyTransition`
- `BoundedAuthorityProtocol.V1.ExpectedRequest`
- `BoundedAuthorityProtocol.V1.Grant`
- `BoundedAuthorityProtocol.V1.GrantFacts`
- `BoundedAuthorityProtocol.V1.HistoricalKeyChain`
- `BoundedAuthorityProtocol.V1.HistoricalPublicKey`
- `BoundedAuthorityProtocol.V1.KeyLocator`
- `BoundedAuthorityProtocol.V1.KeyTransition`
- `BoundedAuthorityProtocol.V1.KeyTransitionFacts`
- `BoundedAuthorityProtocol.V1.Operation`
- `BoundedAuthorityProtocol.V1.Proof`
- `BoundedAuthorityProtocol.V1.Selector`
- `BoundedAuthorityProtocol.V1.SigningInput`
- `BoundedAuthorityProtocol.V1.TrustedIssuer`

Shared building blocks:

- `BoundedAuthorityProtocol.V1.Base64Url`
- `BoundedAuthorityProtocol.V1.Bounds`
- `BoundedAuthorityProtocol.V1.Jcs`
- `BoundedAuthorityProtocol.V1.Json`
- `BoundedAuthorityProtocol.V1.Jwk`
- `BoundedAuthorityProtocol.V1.Uri`

Contract-major 2 facade and structs:

- `BoundedAuthorityProtocol.V2`
- `BoundedAuthorityProtocol.V2.AnchorFacts`
- `BoundedAuthorityProtocol.V2.AnchoredExportFacts`
- `BoundedAuthorityProtocol.V2.ChainFacts`
- `BoundedAuthorityProtocol.V2.DecodedGrant`
- `BoundedAuthorityProtocol.V2.DecodedProof`
- `BoundedAuthorityProtocol.V2.EnvelopeFacts`
- `BoundedAuthorityProtocol.V2.Grant`
- `BoundedAuthorityProtocol.V2.GrantFacts`
- `BoundedAuthorityProtocol.V2.KeyTransitionFacts`
- `BoundedAuthorityProtocol.V2.Operation`
- `BoundedAuthorityProtocol.V2.Proof`
- `BoundedAuthorityProtocol.V2.Selector`

Contract-major 3 facade and structs:

- `BoundedAuthorityProtocol.V3`
- `BoundedAuthorityProtocol.V3.AnchorFacts`
- `BoundedAuthorityProtocol.V3.AnchoredExportFacts`
- `BoundedAuthorityProtocol.V3.ChainFacts`
- `BoundedAuthorityProtocol.V3.DecodedGrant`
- `BoundedAuthorityProtocol.V3.DecodedProof`
- `BoundedAuthorityProtocol.V3.EcJwk`
- `BoundedAuthorityProtocol.V3.EnvelopeFacts`
- `BoundedAuthorityProtocol.V3.Grant`
- `BoundedAuthorityProtocol.V3.GrantFacts`
- `BoundedAuthorityProtocol.V3.KeyTransitionFacts`
- `BoundedAuthorityProtocol.V3.Operation`
- `BoundedAuthorityProtocol.V3.Proof`
- `BoundedAuthorityProtocol.V3.Selector`

Signature suites:

- `BoundedAuthorityProtocol.Ed25519`
- `BoundedAuthorityProtocol.Es256`

Sibling profiles:

- `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1`
- `BoundedAuthorityProtocol.RoleAttestation.V1`
- `BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts`
- `BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation`
- `BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation`
- `BoundedAuthorityProtocol.RoleAttestation.V1.RoleAttestation`
- `BoundedAuthorityProtocol.ContentAssertion.V1`
- `BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertion`
- `BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts`
- `BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion`
- `BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion`

Conformance:

- `BoundedAuthorityProtocol.Conformance.Cli`: `run/1` and the `bounded_authority_conformance`
  command. Its flags (`--corpus DIR`, required; `--report PATH`; `--help`; `--version`), its exit statuses
  (`0` complete agreement, `1` any disagreement, integrity, completeness, or I/O failure, `2` a
  usage error), and its report's JSON fields (`format`, `agreement`, `exit_status`, `total`,
  `agreed`, `disagreed`, `index_sha256_base64url`) are part of the contract.

## Not covered

These are public only because Elixir has no private modules, are hidden from these docs, and may
change in any release:

- `BoundedAuthorityProtocol.V1.Runtime`, `BoundedAuthorityProtocol.V2.Runtime`,
  `BoundedAuthorityProtocol.V3.Runtime`, and every other `Runtime` module;
- `BoundedAuthorityProtocol.Conformance.Corpus`, `BoundedAuthorityProtocol.Conformance.Runner`,
  and `BoundedAuthorityProtocol.Conformance.Report`, the CLI's internals;
- `BoundedAuthorityProtocol.Conformance.Cli.Main`, the escript entry point;
- `BoundedAuthorityProtocol.V1.Jwk.thumbprint_digest_unchecked/1`;
- the signature gate helpers `BoundedAuthorityProtocol.Ed25519.signature_gate?/1` and
  `BoundedAuthorityProtocol.Ed25519.strict_gate?/2`;
- the selector helpers that verification and the producers share, in each of `BoundedAuthorityProtocol.V1.Selector`, `BoundedAuthorityProtocol.V2.Selector`, and `BoundedAuthorityProtocol.V3.Selector`:
  - `BoundedAuthorityProtocol.V1.Selector.float_zero_free?/1`, `BoundedAuthorityProtocol.V1.Selector.integral_float_free?/1`,
    `BoundedAuthorityProtocol.V1.Selector.match_all/3`, `BoundedAuthorityProtocol.V1.Selector.semantic_equal?/2`;
  - `BoundedAuthorityProtocol.V2.Selector.float_zero_free?/1`, `BoundedAuthorityProtocol.V2.Selector.integral_float_free?/1`,
    `BoundedAuthorityProtocol.V2.Selector.match_all/3`, `BoundedAuthorityProtocol.V2.Selector.semantic_equal?/2`;
  - `BoundedAuthorityProtocol.V3.Selector.float_zero_free?/1`, `BoundedAuthorityProtocol.V3.Selector.integral_float_free?/1`,
    `BoundedAuthorityProtocol.V3.Selector.match_all/3`, `BoundedAuthorityProtocol.V3.Selector.semantic_equal?/2`;
- every function or module marked `@doc false` or `@moduledoc false`.

Also not covered: the text of `inspect/2` output (it redacts credentials, arguments, and nonces,
and its exact form may change), the order of keys in maps you did not build, and the wording of
any message the CLI writes to standard error.

## What never changes

Whatever the package version:

- every verification and production function returns `{:ok, value}` or exactly
  `{:error, :invalid}`, and signals every failure with that one value;
- the facts are redacted and never authorize (`authorization: :not_evaluated`,
  `trust: :not_evaluated`);
- the package performs no I/O, reads no clock, and holds no keys, outside the conformance CLI's
  documented file reads.
