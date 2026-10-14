# Go verifier SDK: deployment notes

The Go verifier SDK (`sdks/go/`, module path `github.com/baselabs/bounded_authority_protocol_go`)
is a pure, deterministic implementation of the BAP verification profiles: contract-majors 1, 2,
and 3 plus the local-loopback, role-attestation, and content-assertion sibling profiles. It is a
**verifier**: it returns redacted facts or the single error `ErrInvalid`, never an authorization
decision. The [SDK README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/go/README.md)
has the quickstart and the full API list.

## Not published yet

The module has no tagged version and the Go module proxy does not serve it, so `go get` fails.
It moves to its own repository when it is first published
([ADR 0015](../adr/0015-sdk-graduation-and-publish-topology.md)). Until then, build against a
checkout of this repository. From an empty directory:

```bash
git clone https://github.com/baselabs/bounded_authority_protocol.git
mkdir myapp && cd myapp
go mod init example.com/myapp
go mod edit \
  -require=github.com/baselabs/bounded_authority_protocol_go@v0.0.0 \
  -replace=github.com/baselabs/bounded_authority_protocol_go=../bounded_authority_protocol/sdks/go
```

Record the commit you build from: without a published version, the commit is the identity of
what you deployed.

Erratum 3 (producer canonicality) is not implemented in this SDK yet: `AssembleCompact`,
`EncodeAnchoredExport` (and their `Profile` and `EcdsaProfile` methods),
`AssembleLocalLoopbackHTTPCompact`, `AssembleAttestationCompact`, and
`AssembleContentAssertionCompact` do not refuse a non-canonical signature. Verification is
unaffected. See the SDK README.

## Runtime posture

- Go 1.25 or later. No third-party dependencies: the standard library's `crypto/ed25519`,
  `crypto/ecdsa`, `crypto/elliptic` (P-256 for contract-major 3), `crypto/sha256`,
  `crypto/subtle`, and `math/big` are the whole cryptographic closure.
- Pure functions only: no clock, network, filesystem, or randomness in the library. Time,
  trusted keys, and expected context are explicit inputs.
- `gofmt` and `go vet` clean. `tools/purity_check.sh` scans every non-test source file for
  forbidden APIs and allowlists its imports; it is a shell check, not a Go test.
- 64-bit platforms only.

## Deployment targets

| Target | Notes |
|---|---|
| Any Go service | Verify at the request boundary and pass the raw compact strings, never pre-decoded values |
| Static binaries and distroless containers | With no dependencies, `CGO_ENABLED=0` builds need no build tags |
| AWS Lambda (`provided.al2023` custom runtime) | Build the `bootstrap` binary statically; cold start is the binary load |

## Local-loopback application profile

Local development listeners select `LocalLoopbackHTTPUriNormalize`,
`LocalLoopbackHTTPProofSigningInput`, `AssembleLocalLoopbackHTTPCompact`,
`DecodeLocalLoopbackHTTPProof`, and `CheckLocalLoopbackHTTPEnvelope` explicitly. Admit only direct
literal `127.0.0.1`/`[::1]` HTTP targets and require the server nonce. Never derive the target from
`Forwarded`/`X-Forwarded-*`, accept `localhost`, or retry standard `dpop+jwt` after rejection.

## Strict Ed25519 verification

Every Ed25519 verification in the SDK applies rule S1 of
[ADR 0040](../adr/0040-strict-ed25519-soundness-erratum.md) at its single Ed25519 verification
point: canonical point encodings, no small-order key or `R`, a scalar below the group order, and
the cofactorless equation. Key import, JWK encode and decode, and thumbprint functions refuse a
key that fails key acceptance. Call `TorsionFree` at key enrollment, at trust install, and before
any deny-list or revocation comparison. A vendored snapshot of the strict-Ed25519 corpus under
`conformance/corpus-strict/` runs in `conformance/strict_test.go` with its index SHA-256 pinned.

## Supply chain

No third-party modules: `go list -m all` prints only this module, and `tools/license_check.sh`
fails if any other module appears. The conformance runners and the permissiveness battery run
under `go test` and add nothing to a consumer's build.

## Verification is not authority

A successful verification proves byte-level properties against the inputs the caller supplied.
Trust selection, replay reservation, and revocation belong to your service or a stateful
authority runtime; the specification's verification-contract section states the boundary in
normative terms.
