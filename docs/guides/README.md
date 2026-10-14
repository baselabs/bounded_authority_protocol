# Guides

Reading order for the published documentation set:

1. [Getting started](getting-started.md): from zero to a verified request, then rejection
   handling, issuer-key rotation, and testing your integration. Every Elixir block runs in the
   repository's test suite.
2. [Livebook walkthrough](../livebooks/bap-walkthrough.livemd): produce, assemble, verify, and
   reject standard HTTPS and literal-loopback HTTP proofs, role attestations, content assertions,
   strict Ed25519 forgeries, and contract-major 3 (ES256) credentials with ephemeral keys.
3. [Usage rules](../../usage-rules.md): what a consuming host must do around verification.
4. [Upgrading](upgrading.md): what each release changes and the compatibility contract.
5. [The implementer's guide](implementers-guide.md): building a conforming verifier in another
   language from the specifications, the corpora, and the runner contract.

The specifications are the normative authorities: [contract-major 1](../../spec/bap-v1.md),
[contract-major 2](../../spec/bap-v2.md), [contract-major 3](../../spec/bap-v3.md), the
[local-loopback application profile](../../spec/bap-local-loopback-http-v1.md), the
[role-attestation profile](../../spec/bap-role-attestation-v1.md), and the
[content-assertion profile](../../spec/bap-content-assertion-v1.md). The guides are operational
reading around them (`docs/protocol-v1.md` is the generated view of contract-major 1).

Deployment notes for the verifier SDKs: [TypeScript](../deployment/typescript-sdk.md) (published
to npm), and [Python](../deployment/python-sdk.md), [Rust](../deployment/rust-sdk.md), and
[Go](../deployment/go-sdk.md) (not yet published; install from a checkout by local path).
