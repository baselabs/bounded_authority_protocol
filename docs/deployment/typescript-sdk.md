# TypeScript verifier SDK — deployment guide

The TypeScript verifier SDK (`sdks/typescript/`, package `@bounded-authority/verifier`) is a
pure, deterministic, fail-closed reimplementation of the BAP v1 profile. It is a **verifier**:
it returns redacted, value-bearing facts or a single `Invalid` outcome, never an authorization
decision.

See `spec/bap-v1.md` (the normative authority; `docs/protocol-v1.md` is its generated view)
and [ADR 0014](../adr/0014-cross-language-verifier-sdks.md) for the packaging and
derivation-hygiene decisions.

## Runtime posture

- Node >= 22; `node:crypto` for Ed25519 (zero non-stdlib dependencies by default).
- Pure functions only: no clock, network, filesystem, or randomness in the verify path. Time,
  trusted keys, and expected context are explicit inputs.
- Bundle shape: the published package carries the compiled verifier plus the conformance
  runner; tree-shaking keeps serverless bundles small (the verifier core is a single module
  closure).

## Deployment targets

| Target | Notes |
|---|---|
| AWS Lambda (nodejs22.x) | Cold-start friendly: no dynamic requires, no wasm; pin the runtime and pin the package version in the lockfile |
| Node service (Express/Fastify middleware) | Verify at the boundary; pass RAW credential bytes to the verifier, never pre-decoded structs |
| Edge runtimes supporting node:crypto | The verifier core is synchronous and allocation-bounded; check the runtime's `crypto.verify` (Ed25519) availability |

## Local-loopback application profile

Local development listeners select `localLoopbackHttpUriNormalize`,
`localLoopbackHttpProofSigningInput`, `assembleLocalLoopbackHttpCompact`,
`decodeLocalLoopbackHttpProof`, and `checkLocalLoopbackHttpEnvelope` explicitly. Admit only direct
literal `127.0.0.1`/`[::1]` HTTP targets and require the server nonce. Never derive the target from
`Forwarded`/`X-Forwarded-*`, accept `localhost`, or retry standard `dpop+jwt` after rejection.

## Supply-chain posture

Zero non-stdlib runtime dependencies by default; the development toolchain (tests, the
conformance runner) is devDependency-only. Consumers SHOULD pin the exact version and verify
the package integrity digest from the registry at install time.

## Verification is not authority

A green verification proves byte-level properties against the inputs the CALLER supplied.
Trust selection, replay reservation, and revocation belong to a stateful authority runtime;
see the specification's verification-contract section for the boundary in normative terms.
