# Roadmap

The public roadmap of `bounded_authority_protocol`. Release history is in the
[changelog](../CHANGELOG.md); decisions are published through [governance](governance.md), the
specifications under [`spec/`](../spec/), and the [errata registry](errata.md).

## Where things stand

- **Shipped:** package 1.5.0 carries contract-majors 1, 2, and 3; local-loopback HTTP
  proofs; role and holder custody attestations; EdDSA and ES256 content assertions;
  action approval; and thirteen certified corpora. The StringOrURI corpus verifies the
  IPv6 literal rule in erratum 7. The [1.x stability contract](guides/api-stability.md)
  covers the new public modules.
- **Verifiers in other languages:** TypeScript is published on npm. Python, Rust, and Go live
  under [`sdks/`](../sdks/), install from pinned source, and run ten standalone corpora.
  They also verify ES256 content assertions and action approval in source-checkout jobs.
- **Transport design:** the [A2A capability-binding profile](design/a2a-capability-binding-profile.md#5-carriage)
  defines `BA-Grant` and `BA-Proof` HTTP carriage and the corresponding gRPC metadata. Reuse
  that carriage rather than introducing a separate BAP-over-HTTP binding. The profile is
  design-only; it does not establish runtime interoperability.

## Later

Candidates, not commitments; each lands as its own minor release under the governance rules:

- first publication of the Python, Rust, and Go verifiers, and of a Python signer;
- the standards submissions prepared under [`standards/`](standards/) and
  [`extensions/`](extensions/), when a venue accepts the work.

A new wire capability arrives as a new contract-major or sibling profile beside the existing
ones; the existing profiles never change their accepted bytes.
