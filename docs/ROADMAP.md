# Roadmap

The public roadmap of `bounded_authority_protocol`. Release history is in the
[changelog](../CHANGELOG.md); decisions are published through [governance](governance.md), the
specifications under [`spec/`](../spec/), and the [errata registry](errata.md).

## Where things stand

- **Shipped:** contract-majors 1, 2, and 3; the local-loopback HTTP, role-attestation, and
  content-assertion sibling profiles; strict Ed25519 verification (erratum 2); producer
  signature canonicality (erratum 3); and their certified corpora. The current Hex release is
  0.9.1.
- **On `main`, unreleased:** the selector float-zero soundness repair (erratum 6) on every
  contract-major, with its additive corpus; the package 1.x stability contract and version
  rules; a hardened conformance CLI that verifies every packaged corpus; and the documentation
  and Livebook refresh.
- **Verifiers in other languages:** TypeScript is published on npm. Python, Rust, and Go live
  under [`sdks/`](../sdks/) and pass every corpus; each moves to its own repository when it is
  first published.

## Next: package 1.0.0

Package 1.0.0 freezes the public API under the 1.x stability contract
([API stability and versioning](guides/api-stability.md)) and ships erratum 6. Before it
publishes:

1. the documentation, recipes, and Livebooks are complete and run in the test suite;
2. one independent review covers the combined code and documentation changes;
3. the release commit passes the full quality gate and CI;
4. the release archive's checksum matches the supply-chain attestation before publication, and
   the registry checksum, HexDocs, a fresh consumer, every packaged corpus, and each Livebook
   are read back after it.

The TypeScript verifier and signer release their erratum-6 repair in the same window, and the
holder-side companion `bounded_authority_report_adapter` moves to the 1.x line after the
protocol publishes.

## Later

Candidates, not commitments; each lands as its own minor release under the governance rules:

- `Json.from_term/2`, converting already-parsed Elixir terms into the tagged JSON form;
- an HTTP transport binding that names the headers carrying a grant and a proof;
- first publication of the Python, Rust, and Go verifiers;
- the standards submissions prepared under [`standards/`](standards/) and
  [`extensions/`](extensions/), when a venue accepts the work.

A new wire capability arrives as a new contract-major or sibling profile beside the existing
ones; the existing profiles never change their accepted bytes.
