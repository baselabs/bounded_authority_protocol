# TypeScript verifier SDK — deployment guide

The TypeScript verifier SDK is **published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)**
and developed in its own graduated repository,
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript)
(per [ADR 0015](../adr/0015-sdk-graduation-and-publish-topology.md): SDKs are authored in this
monorepo while unpublished and graduate to a per-SDK repository on first publication — this guide
stays here because the protocol package remains the normative entry point).

The SDK is a pure, deterministic, fail-closed reimplementation of the wire profiles
(contract-majors 1, 2, and 3, plus the role-attestation sibling profile). It is a **verifier**:
it returns redacted, value-bearing facts or a single `Invalid` outcome, never an authorization
decision. See `spec/bap-v1.md` / `spec/bap-v2.md` / `spec/bap-v3.md` /
`spec/bap-role-attestation-v1.md` (the normative authorities) and
[ADR 0014](../adr/0014-cross-language-verifier-sdks.md) for the packaging and
derivation-hygiene decisions.

## Runtime posture

- Node >= 22; `node:crypto` for the suite primitives — Ed25519 (majors 1–2) and ECDSA P-256
  (major 3) — with zero non-stdlib dependencies.
- Pure functions only: no clock, network, filesystem, or randomness in the verify path. Time,
  trusted keys, and expected context are explicit inputs.
- Bundle shape: the published package carries the compiled verifier only (`dist/src`); the
  conformance corpora and runners live in the repository, not the tarball. Tree-shaking keeps
  serverless bundles small (the verifier core is a single module closure).

## Install and releases

```bash
npm install @bounded-authority-protocol/verifier
```

Releases are two-stage by owner decision: the graduated repository's release workflow stages
each version to npm with provenance (GitHub Actions OIDC trusted publishing — no tokens), and a
human approves the staged version on npmjs.com under the org's 2FA requirement. CI cannot make
a version live alone.

## Corpus updates

The SDK vendors certified snapshots of the v1, v2, and v3 conformance corpora plus the
role-attestation profile corpus, runs them in CI (`pnpm conformance`, `conformance:v2`,
`conformance:v3`, `conformance:role-attestation`), and asserts each `index.json` SHA-256 at
load. When this monorepo rotates a corpus, the SDK repository takes a snapshot-bump commit —
the startup assertion fails loudly on any drift.
