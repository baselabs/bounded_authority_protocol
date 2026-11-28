# Roadmap

The public roadmap of `bounded_authority_protocol`. Release history is in the
[changelog](../CHANGELOG.md); decisions are published through [governance](governance.md), the
specifications under [`spec/`](../spec/), and the [errata registry](errata.md).

## Where things stand

- **Shipped:** package 1.1.0 with contract-majors 1, 2, and 3; the local-loopback HTTP,
  role-attestation, and content-assertion sibling profiles; strict Ed25519 verification
  (erratum 2); producer signature canonicality (erratum 3); the selector float-zero soundness
  repair (erratum 6); and their certified corpora. The public API follows the 1.x stability
  contract ([API stability and versioning](guides/api-stability.md)).
- **Verifiers in other languages:** TypeScript is published on npm. Python, Rust, and Go live
  under [`sdks/`](../sdks/) and pass every corpus. They are not published yet; install them
  from a pinned commit of this repository.
- **Transport design:** the [A2A capability-binding profile](design/a2a-capability-binding-profile.md#5-carriage)
  defines `BA-Grant` and `BA-Proof` HTTP carriage and the corresponding gRPC metadata. Reuse
  that carriage rather than introducing a separate BAP-over-HTTP binding. The profile is
  design-only; it does not establish runtime interoperability.

## Unreleased

- Source-candidate profiles: action approval records, ES256 content assertions, and holder
  custody attestations, with their corpora, in the Elixir reference and, for action approval
  and ES256 content assertions, the Python, Rust, and Go verifiers.
- Erratum 7: a bracketed StringOrURI host must be an IPv6 literal, in every verifier.
- `Json.from_term/2` converts already-parsed, cast Elixir terms into the bounded tagged JSON
  form shared by all contract-majors. See the [recipe](guides/recipes.md#turn-already-parsed-params-into-tagged-arguments).

## Later

Candidates, not commitments; each lands as its own minor release under the governance rules:

- first publication of the Python, Rust, and Go verifiers, and of a Python signer;
- the standards submissions prepared under [`standards/`](standards/) and
  [`extensions/`](extensions/), when a venue accepts the work.

A new wire capability arrives as a new contract-major or sibling profile beside the existing
ones; the existing profiles never change their accepted bytes.
