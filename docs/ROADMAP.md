# Roadmap

The public roadmap of `bounded_authority_protocol`. Release history is in the
[changelog](../CHANGELOG.md); decisions are published through [governance](governance.md), the
specifications under [`spec/`](../spec/), and the [errata registry](errata.md).

## Where things stand

- **Shipped:** package 1.0.0 with contract-majors 1, 2, and 3; the local-loopback HTTP,
  role-attestation, and content-assertion sibling profiles; strict Ed25519 verification
  (erratum 2); producer signature canonicality (erratum 3); the selector float-zero soundness
  repair (erratum 6); and their certified corpora. The public API follows the 1.x stability
  contract ([API stability and versioning](guides/api-stability.md)).
- **Verifiers in other languages:** TypeScript is published on npm. Python, Rust, and Go live
  under [`sdks/`](../sdks/) and pass every corpus; each moves to its own repository when it is
  first published.

## Later

Candidates, not commitments; each lands as its own minor release under the governance rules:

- `Json.from_term/2`, converting already-parsed Elixir terms into the tagged JSON form;
- an HTTP transport binding that names the headers carrying a grant and a proof;
- first publication of the Python, Rust, and Go verifiers;
- the standards submissions prepared under [`standards/`](standards/) and
  [`extensions/`](extensions/), when a venue accepts the work.

A new wire capability arrives as a new contract-major or sibling profile beside the existing
ones; the existing profiles never change their accepted bytes.
