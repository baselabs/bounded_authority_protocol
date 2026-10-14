# Bounded Authority Protocol verifier for Go

A pure, deterministic Go implementation of the Bounded Authority Protocol (BAP) verification
profiles: contract-majors 1 and 2 (Ed25519) and 3 (ES256), the local-loopback HTTP proof
profile, and the role-attestation and content-assertion profiles, with strict Ed25519
verification on every Ed25519 surface.

It checks the exact bytes of a grant, a holder proof, or an evidence object against public keys
and expected context that you supply, and returns redacted facts or the single error
`ErrInvalid`. It is a **verifier, not an authority**: it never selects trusted keys, reserves
replay, checks revocation, or decides whether a request may run. Those stay in your service.

Its behavior is defined by the specifications ([v1](../../spec/bap-v1.md),
[v2](../../spec/bap-v2.md), [v3](../../spec/bap-v3.md), and the sibling profiles under
[`spec/`](../../spec/)) and the certified conformance corpora; source comments cross-reference
the Elixir reference implementation for traceability.

## Status

**Not published.** There is no tagged module version and the Go module proxy does not serve
this module, so `go get github.com/baselabs/bounded_authority_protocol_go` fails. The module
moves to its own repository when it is first published
([ADR 0015](../../docs/adr/0015-sdk-graduation-and-publish-topology.md)). Until then, use it
from a checkout of this repository.

- Go **1.25** or later (`go.mod`). CI installs Go with `actions/setup-go` and
  `go-version: "1.25"`, which selects a 1.25.x release (the runner's cached one when present).
  Development here uses Go 1.25.14.
- **No third-party dependencies**: only the standard library (`crypto/ed25519`, `crypto/ecdsa`,
  `crypto/elliptic`, `crypto/sha256`, `crypto/subtle`, `math/big`, and pure parsing and
  formatting packages). `tools/license_check.sh` asserts the module graph stays empty.
- **64-bit platforms only**: the bounds hold 9,007,199,254,740,991 in an `int`.
- **Erratum 3 (producer canonicality) is not yet implemented.** The producers that frame a
  signature check its width but not its value: `AssembleCompact` and `EncodeAnchoredExport`
  (and their `Profile` and `EcdsaProfile` methods), `AssembleLocalLoopbackHTTPCompact`,
  `AssembleAttestationCompact`, and `AssembleContentAssertionCompact`. So they can assemble an
  Ed25519 signature with `S >= L` or a non-canonical or small-order `R`, or an ES256 signature
  that is out of range or high-S.
  Every verifier, this one included, rejects such a credential. Until this SDK implements
  erratum 3, check a signature from an external signer before assembly (for ES256, normalize
  to low S).

## Install from a checkout

From an empty directory, clone this repository, create your module next to it, point the
module at the SDK directory, and run the quickstart below as a test:

```bash
git clone https://github.com/baselabs/bounded_authority_protocol.git
mkdir myapp && cd myapp
go mod init example.com/myapp
go mod edit \
  -require=github.com/baselabs/bounded_authority_protocol_go@v0.0.0 \
  -replace=github.com/baselabs/bounded_authority_protocol_go=../bounded_authority_protocol/sdks/go
cp ../bounded_authority_protocol/sdks/go/example_test.go .
go test -run Example .
```

In your own code, import it as `verifier "github.com/baselabs/bounded_authority_protocol_go"`.

## Quickstart

This is [`example_test.go`](example_test.go): `go test` runs it and checks its output, and a
test keeps this copy identical to the file.

```go
package verifier_test

import (
	"crypto/ed25519"
	"fmt"

	verifier "github.com/baselabs/bounded_authority_protocol_go"
)

// Example issues a grant, signs a holder proof for one request, and verifies both, then shows
// that the same proof fails for other arguments. The keys come from fixed seeds so the output is
// stable; in production the private keys stay with the issuer and the holder, and the verifier
// receives only public keys.
func Example() {
	issuerKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	holderSeed := make([]byte, ed25519.SeedSize)
	holderSeed[0] = 1
	holderKey := ed25519.NewKeyFromSeed(holderSeed)
	issuerPublic := issuerKey.Public().(ed25519.PublicKey)
	holderPublic := holderKey.Public().(ed25519.PublicKey)

	// The bytes to sign: ASCII(base64url(protected) || "." || base64url(payload)).
	message := func(si verifier.SigningInput) []byte {
		return []byte(verifier.Base64urlEncode(si.Protected) + "." + verifier.Base64urlEncode(si.Payload))
	}
	mustJSON := func(text string) verifier.Value {
		value, err := verifier.JsonDecode([]byte(text), nil)
		if err != nil {
			panic(err)
		}
		return value
	}

	// The issuer grants one operation, restricted to one argument value.
	holderThumbprint, err := verifier.PublicKeyThumbprintRaw(holderPublic, nil)
	if err != nil {
		panic(err)
	}
	grantInput, err := verifier.GrantSigningInput(verifier.Grant{
		KeyID:            "issuer-1",
		Issuer:           "https://issuer.example",
		GrantID:          "grant-001",
		Audiences:        []string{"https://docs.example"},
		IssuedAt:         1800000000,
		NotBefore:        1800000000,
		ExpiresAt:        1800003600,
		HolderThumbprint: verifier.Base64urlEncode(holderThumbprint[:]),
		Operations: []verifier.OperationDef{{
			Name:      "publish_article",
			Selectors: []verifier.Value{mustJSON(`{"kind":"equals","path":["section"],"value":"science"}`)},
		}},
	}, nil)
	if err != nil {
		panic(err)
	}
	grant, err := verifier.AssembleCompact(grantInput, ed25519.Sign(issuerKey, message(grantInput)), nil)
	if err != nil {
		panic(err)
	}

	// The holder binds one request to the grant.
	arguments := mustJSON(`{"section":"science","title":"Tides"}`)
	proofInput, err := verifier.ProofSigningInput(verifier.Proof{
		ProofID:         "proof-001",
		HolderPublicKey: holderPublic,
		InvocationID:    "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
		Operation:       "publish_article",
		Method:          "POST",
		TargetURI:       "https://docs.example/articles",
		IssuedAt:        1800000100,
		GrantCompact:    grant,
		CastArguments:   arguments,
	}, nil)
	if err != nil {
		panic(err)
	}
	proof, err := verifier.AssembleCompact(proofInput, ed25519.Sign(holderKey, message(proofInput)), nil)
	if err != nil {
		panic(err)
	}

	// The service verifies the raw bytes against what it derived from the request.
	expected := verifier.ExpectedRequest{
		TrustedIssuer:  verifier.TrustedIssuer{KeyID: "issuer-1", PublicKey: issuerPublic},
		Issuer:         "https://issuer.example",
		Audience:       "https://docs.example",
		EvaluationTime: 1800000100,
		ClockSkew:      60,
		Method:         "POST",
		TargetURI:      "https://docs.example/articles",
		InvocationID:   "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
		Operation:      "publish_article",
		CastArguments:  arguments,
		ProofMaxAge:    300,
		Nonce:          verifier.NonceNotRequired(),
	}
	credentials := verifier.Credentials{Grant: grant, Proof: proof}

	facts, err := verifier.CheckEnvelope(credentials, expected)
	fmt.Println(facts.Operation, facts.GrantID, facts.Authorization == verifier.AuthorizationNotEvaluated, err)

	// The same proof against other arguments fails closed, with no detail.
	expected.CastArguments = mustJSON(`{"section":"sports","title":"Tides"}`)
	_, err = verifier.CheckEnvelope(credentials, expected)
	fmt.Println(err == verifier.ErrInvalid)

	// Output:
	// publish_article grant-001 true <nil>
	// true
}
```

The bytes to sign are always `base64url(protected) + "." + base64url(payload)` of the
`SigningInput` a producer returns. The SDK never sees a private key.

## API

Contract-major 1 functions are package-level. Contract-major 2 and 3 are stateless namespace
types whose methods have the same names and shapes: `verifier.Profile{}` (v2, adds the `lte`
and `gte` range selectors) and `verifier.EcdsaProfile{}` (v3, ES256 with 65-byte uncompressed
SEC1 keys and 64-byte raw `r || s` signatures). Each major rejects the others' bytes.

| Group | Functions |
|---|---|
| Producers | `GrantSigningInput`, `ProofSigningInput`, `BoundaryAnchorSigningInput`, `KeyTransitionSigningInput`, `AssembleCompact`, `EncodeConsumptionEntry`, `EncodeAnchoredExport`, `RequestDigest` |
| Decoders (no signature check) | `DecodeGrant`, `DecodeProof`, `UntrustedKeyLocator` |
| Verifiers | `VerifyGrant`, `CheckEnvelope`, `CheckChain`, `VerifyHistoricalAnchor`, `VerifyKeyTransition`, `VerifyAnchoredExport` |
| Local-loopback HTTP proofs | `LocalLoopbackHTTPUriNormalize`, `LocalLoopbackHTTPProofSigningInput`, `AssembleLocalLoopbackHTTPCompact`, `DecodeLocalLoopbackHTTPProof`, `CheckLocalLoopbackHTTPEnvelope` |
| Role attestations | `AttestationSigningInput`, `AssembleAttestationCompact`, `DecodeAttestation`, `VerifyAttestation` |
| Content assertions | `AssertionSigningInput`, `AssembleContentAssertionCompact`, `DecodeContentAssertion`, `VerifyContentAssertion`, `ContentDigest`, `AssertionDigest`, `VerifyContentAssertionSuccessor` |
| Strict Ed25519 | `VerifyStrict`, `AcceptablePublicKey`, `TorsionFree` |
| Primitives | `JsonDecode`, `JcsEncode`, `Base64urlDecode`, `Base64urlEncode`, `UriNormalize`, `JwkDecodePublic`, `JwkEncodePublic`, `JwkThumbprintPreimage`, `JwkThumbprint`, `JwkThumbprintRaw`, `PublicKeyThumbprintRaw`, `BoundsMaximum`, `BoundsNew`, `NonceNotRequired`, `NonceRequired` |

`EcdsaProfile` also carries its own EC JWK and thumbprint methods. The loopback, attestation,
and content-assertion functions exist only at package level (they are Ed25519 profiles).

**Errors.** Every fallible function returns `(T, error)`, and the error is `nil` or exactly
`ErrInvalid`; it carries no reason, and no function panics on bad input.
`VerifyContentAssertionSuccessor` returns only an `error` (`nil` when the successor step holds).
`VerifyStrict`,
`AcceptablePublicKey`, and `TorsionFree` return `bool`; `Base64urlEncode` and `BoundsMaximum`
cannot fail. A `nil` `*Bounds` means the profile maxima; build tighter limits with `BoundsNew`.

**Facts.** `GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`,
`AnchoredExportFacts`, `AttestationFacts`, and `ContentAssertionFacts` hold identifiers,
digests, times, and counts, never raw signatures, keys, nonces, or arguments. `GrantFacts`,
`EnvelopeFacts`, and `AnchoredExportFacts` carry `Authorization: AuthorizationNotEvaluated`; the
chain, anchor, transition, export, attestation, and content-assertion facts carry
`Trust: TrustNotEvaluated`. There is no `Authorized` or decision field. The facts types have no
redacted `String` method yet, so `fmt` prints their fields; log the fields you need by name.

## Strict Ed25519

Every Ed25519 signature check goes through one function (`verifyEd25519` in `ed25519.go`) that
applies rule S1 of [ADR 0040](../../docs/adr/0040-strict-ed25519-soundness-erratum.md) before
the standard-library backend: exact widths, canonical `A` and `R`, neither of small order,
`S < L`, then the cofactorless equation. `AcceptablePublicKey` is the key-entry check (canonical,
not small order, on the curve), and every JWK and thumbprint function returns `ErrInvalid` for a
key that fails it. `TorsionFree` adds `[L]A = O` in pure `math/big` arithmetic; call it at key
enrollment, at trust install, and before any deny-list or revocation comparison, never on the
verification path.

## Conformance

`go test ./...` runs everything:

- the root package: unit tests, the quickstart example, the local-loopback (36 URI and 8 proof
  cases), role-attestation (40), and content-assertion (131 assertion, 9 digest, 14 successor)
  corpora read from `priv/conformance/`, and the strict-Ed25519 unit and fuzz-seed tests;
- `conformance/`: the vendored v1 (283 cases), v2 (268), v3 (292), and strict-Ed25519 (2,410)
  snapshots, each with its `index.json` SHA-256 asserted at load, every case file checked
  against the index, and a key census comparing the keys the runner imported with the index's
  `public_key_fingerprints`;
- `tests/`: the permissiveness battery, which builds each defect a parser closure exists to
  reject and proves the closure catches it.

```bash
go test ./...
go test -v ./conformance/ | grep agreed
# agreed=283 disagreed=0 census=11
# strict corpus: agreed=2410/2410
# agreed=268 disagreed=0 census=22 declared=17
# agreed=292 disagreed=0 census=8 declared=11
```

The producer-canonicality corpus (erratum 3) is not run yet; see Status.

## What this SDK does not do

No I/O, filesystem, clock, randomness, network, environment, or process access in the library
(`tools/purity_check.sh` scans every non-test file and allowlists its imports). No trust
discovery, key custody, signing, replay reservation, revocation state, issuance, or
authorization decisions. No registry-publish setup: a pre-commit hook and a CI job reject it
here (ADR 0015).

## Development

```bash
test -z "$(gofmt -l .)" && go vet ./...
go test ./...
sh tools/purity_check.sh && sh tools/license_check.sh
```

Deployment notes: [`docs/deployment/go-sdk.md`](../../docs/deployment/go-sdk.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
