# Guides

Reading order for the published documentation set:

1. [Getting started](getting-started.md): from zero to a verified request, then rejection
   handling, issuer-key rotation, and testing your integration.
2. The Livebooks: the [protocol walkthrough](../livebooks/bap-walkthrough.livemd),
   [service integration](../livebooks/service-integration.livemd), and
   [chains and archives](../livebooks/chains-and-archives.livemd).
3. [Choosing a profile](choosing-a-profile.md): which contract-major or sibling profile to use.
4. [Recipes](recipes.md): Plug and Phoenix integration, selectors per contract-major, ES256 keys
   in a KMS or HSM, issuer key rotation, nonce modes, and running every packaged corpus.
5. [Evidence](evidence.md): consumption chains, boundary anchors, key transitions, and anchored
   exports.
6. [Troubleshooting `{:error, :invalid}`](troubleshooting.md): the checklist for a rejection.
7. [Usage rules](../../usage-rules.md): what a consuming host must do around verification.
8. [Upgrading to 1.0](upgrading.md) and [API stability and versioning](api-stability.md).
9. [Other languages](other-languages.md) and the [implementer's guide](implementers-guide.md):
   the TypeScript, Python, Rust, and Go verifiers, and building a new one.

Reference: the [cheatsheet](cheatsheet.cheatmd), the [glossary](glossary.md), and the
[FAQ](faq.md). Every Elixir block in these guides runs in the repository's test suite.

The specifications are the normative authorities: [contract-major 1](../../spec/bap-v1.md),
[contract-major 2](../../spec/bap-v2.md), [contract-major 3](../../spec/bap-v3.md), the
[local-loopback application profile](../../spec/bap-local-loopback-http-v1.md), the
[role-attestation profile](../../spec/bap-role-attestation-v1.md), and the
[content-assertion profile](../../spec/bap-content-assertion-v1.md). The guides are operational
reading around them.
