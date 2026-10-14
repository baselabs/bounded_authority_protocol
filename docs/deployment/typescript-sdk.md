# TypeScript verifier SDK: deployment notes

The TypeScript verifier is **published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)**
and developed in its own repository,
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript).
SDKs are authored in this repository while unpublished and move to their own repository on first
publication ([ADR 0015](../adr/0015-sdk-graduation-and-publish-topology.md)); these notes stay
here because this package remains the normative entry point. That repository's README is the
reference for its API.

The SDK is a pure, deterministic implementation of contract-majors 1, 2, and 3, the
local-loopback HTTP proof profile, and the role-attestation and content-assertion sibling
profiles, with strict Ed25519 verification. It is a **verifier**: it returns redacted facts or a
single `Invalid` outcome, never an authorization decision. The normative authorities are
`spec/bap-v1.md`, `spec/bap-v2.md`, `spec/bap-v3.md`, and the profile specifications;
[ADR 0014](../adr/0014-cross-language-verifier-sdks.md) records the packaging decisions.

## Install

```bash
npm install @bounded-authority-protocol/verifier
```

## Runtime posture

- Node.js 22 or later, current browsers, Deno, Bun, and workers, with identical verdicts.
- Two crypto backends, chosen by the package's `"imports"` conditions: on Node.js, Ed25519,
  ES256, and SHA-256 run on `node:crypto`; elsewhere a portable pure-JavaScript backend runs
  them over three exact-pinned, MIT-licensed runtime dependencies (`@noble/ed25519`,
  `@noble/curves`, and `@noble/hashes`).
- ESM only, with no side effects on import. The published package carries the compiled
  library (`dist`); the conformance corpora and runners stay in the repository.
- Pure functions only: no clock, network, filesystem, or randomness in the verify path. Time,
  trusted keys, and expected context are explicit inputs.

## Releases

The repository's release workflow stages each version to npm with provenance (GitHub Actions
OIDC trusted publishing, no long-lived tokens), and a maintainer approves the staged version on
npmjs.com under the organization's two-factor requirement. CI cannot make a version live on
its own.

## Corpus updates

The SDK vendors certified snapshots of the v1, v2, and v3 corpora and the local-loopback,
role-attestation, content-assertion, and strict-Ed25519 corpora, runs them in CI, and asserts
each `index.json` SHA-256 at load. When this repository rotates a corpus, the SDK repository
takes a snapshot-bump commit, and the load-time check fails on any drift.

Erratum 3 (producer canonicality) is not implemented in release 0.7.0: its compact assembly
does not yet refuse a non-canonical signature, and it does not yet run the
`bap-producer-canonicality/1` corpus. Verification is unaffected.
