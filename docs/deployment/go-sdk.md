# Go verifier SDK — deployment guide

The Go verifier SDK (`sdks/go/`, module `github.com/baselabs/bounded_authority_protocol_go`)
is a pure, deterministic, fail-closed reimplementation of the BAP v1 profile. It is a
**verifier**: it returns redacted, value-bearing facts or a single rejection, never an
authorization decision.

See `spec/bap-v1.md` (the normative authority; `docs/protocol-v1.md` is its generated view)
and [ADR 0014](../adr/0014-cross-language-verifier-sdks.md) for the packaging and
derivation-hygiene decisions.

## Runtime posture

- Go 1.25 floor; ZERO runtime dependencies — the standard library's `crypto/ed25519` and
  `crypto/sha256` are the entire cryptographic closure.
- Pure functions only: no clock, network, filesystem, or randomness in the verify path. Time,
  trusted keys, and expected context are explicit inputs.
- `go vet` clean, `gofmt` clean, and a purity vet backed by a test that rejects forbidden
  import additions.

## Deployment targets

| Target | Notes |
|---|---|
| Any Go service | `go get` the module; the standard 17-function façade, five local-profile functions, and versioned primitives are the whole surface |
| Static binaries / distroless containers | Zero-dependency closure means `CGO_ENABLED=0` builds with no tag set |
| AWS Lambda (provided.al2023 custom runtime) | Build the bootstrap binary statically; cold start is the binary load |

## Local-loopback application profile

Local development listeners select `LocalLoopbackHTTPUriNormalize`,
`LocalLoopbackHTTPProofSigningInput`, `AssembleLocalLoopbackHTTPCompact`,
`DecodeLocalLoopbackHTTPProof`, and `CheckLocalLoopbackHTTPEnvelope` explicitly. Admit only direct
literal `127.0.0.1`/`[::1]` HTTP targets and require the server nonce. Never derive the target from
`Forwarded`/`X-Forwarded-*`, accept `localhost`, or retry standard `dpop+jwt` after rejection.

## Supply-chain posture

Zero runtime dependencies; `go mod graph` shows the module alone. Consumers SHOULD pin the
exact version (`go get module@vX.Y.Z`) and enable `go mod verify`. The SDK's conformance runner
and mutation battery live under `go test` and add nothing to the consumer closure.

## Verification is not authority

A green verification proves byte-level properties against the inputs the CALLER supplied.
Trust selection, replay reservation, and revocation belong to a stateful authority runtime;
see the specification's verification-contract section for the boundary in normative terms.
