# Other languages

The protocol is defined by its specifications and certified corpora, not by this package's
code, so a verifier in any language can conform. Four verifiers besides this Elixir reference
implement contract-majors 1, 2, and 3 and the local-loopback, role-attestation, and
content-assertion sibling profiles, with strict Ed25519 verification and producer canonicality.
Each one recomputes every verdict of every certified corpus and asserts each corpus index digest
when it loads; the [interoperability report](../design/interoperability-report.md) records the
latest results.

Like this package, each is a pure verification library: no I/O, clock, randomness, or network,
and no authorization decision. Each returns redacted facts or one value-free rejection.

| Language | Package | Status | Runtime | Notes |
|---|---|---|---|---|
| TypeScript | [`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier) | Published on npm | Node.js 22 or later, browsers, Deno, Bun, workers | [Repository](https://github.com/baselabs/bounded_authority_protocol_typescript) and [deployment notes](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/typescript-sdk.md) |
| Python | `bounded-authority-verifier` | Not yet published; install from a pinned commit | Python 3.10 or later, `cryptography` | [README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/python/README.md) and [deployment notes](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/python-sdk.md) |
| Rust | `bounded-authority-protocol` | Not yet published; use a path or Git dependency | Rust 1.81 or later | [README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/rust/README.md) and [deployment notes](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/rust-sdk.md) |
| Go | `github.com/baselabs/bounded_authority_protocol_go` | Not yet published; use a `replace` to a checkout | Go 1.25 or later, standard library only | [README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/go/README.md) and [deployment notes](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/go-sdk.md) |

The Python, Rust, and Go verifiers live under
[`sdks/`](https://github.com/baselabs/bounded_authority_protocol/tree/main/sdks) in this
package's repository. Each moves to its own repository when it is first published, as the
TypeScript verifier did; until then, the commit you install from is the identity of what you
deployed. A package with one of the planned names on a public registry is not this project's
until that SDK's README says it is published.

## Signing in other languages

The verifiers never sign. For holder-side signing:

- Elixir:
  [`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter)
  signs grants, proofs, anchors, transitions, attestations, and assertions through a key handle
  you supply (an HSM, a KMS, or a local key), using this package's signing inputs.
- TypeScript:
  [`@bounded-authority-protocol/signer`](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
  ([repository](https://github.com/baselabs/bounded_authority_signer_typescript)) signs grants,
  proofs, anchors, and key transitions on all three contract-majors through a key handle that
  reaches your KMS, HSM, WebCrypto key, or test key.

## Mixing languages

A deployment can verify with one language and sign with another, or run two verifiers side by
side. Conforming implementations return the same verdict for the same bytes and the same
expectations; that is what the shared corpora certify. When a verdict differs, it is a defect in
one implementation or in the specification: report it as the
[security policy](https://github.com/baselabs/bounded_authority_protocol/blob/main/SECURITY.md)
describes, because a disagreement between conforming verifiers is a soundness failure.

To build a verifier in a new language, start with the [implementer's guide](implementers-guide.md).
