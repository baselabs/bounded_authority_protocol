# Guides

Curated reading order for the published documentation set:

1. [Getting started](getting-started.md) — zero to a verified envelope, and the three rules
   that surprise newcomers.
2. [The implementer's guide](implementers-guide.md) — building a conforming verifier in any
   language from the specification, the corpus, and the runner contract.
3. [Upgrading](upgrading.md) — the published compatibility contract and what a consumer may
   rely on across releases.
4. [Runnable Livebook walkthrough](../livebooks/bap-walkthrough.livemd) — produce, assemble,
   verify, and reject standard HTTPS and literal-loopback HTTP proofs with ephemeral keys.

The [standard v1 specification](../../spec/bap-v1.md) and the
[local-loopback application-profile specification](../../spec/bap-local-loopback-http-v1.md) are
the normative authorities; the guides are operational reading around them
(`docs/protocol-v1.md` is the standard profile's generated view).

Deployment notes for the independently versioned verifier SDKs:
[TypeScript](../deployment/typescript-sdk.md), [Python](../deployment/python-sdk.md),
[Rust](../deployment/rust-sdk.md), and [Go](../deployment/go-sdk.md).
