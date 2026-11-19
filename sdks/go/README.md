# Bounded Authority Protocol verifier for Go

A pure, deterministic Go implementation of the Bounded Authority Protocol (BAP) verification
profiles: contract-majors 1 and 2 (Ed25519) and 3 (ES256), the local-loopback HTTP proof
profile, and the role-attestation and content-assertion profiles, with strict Ed25519
verification on every Ed25519 surface.

It checks the exact bytes of a grant, a holder proof, or an evidence object against public keys
and expected context that you supply, and returns facts or the single error
`ErrInvalid`. It is a **verifier, not an authority**: it never selects trusted keys, reserves
replay, checks revocation, or decides whether a request may run. Those stay in your service.
Facts exclude raw credentials and secrets; the logging notes below describe their display limitations.

Already-trusted public keys, expected context, and time are explicit inputs. The SDK has no
private-key access or custody and reads no clock.

Its behavior is defined by the specifications ([v1](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md),
[v2](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v2.md), [v3](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md), and the sibling profiles under
[`spec/`](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/)) and the certified conformance corpora; source comments cite
the tracked normative specifications and independent conformance corpora.

## Status

**Not published.** There is no tagged module version and the Go module proxy does not serve
this module, so `go get github.com/baselabs/bounded_authority_protocol_go` fails. The module
moves to its own repository when it is first published
with its self-contained tests and corpus inputs. Until then, use it
from a checkout of this repository.

- Go **1.25** or later (`go.mod`). CI installs exactly Go **1.25.0** for the declared floor.
  The module advisory scan separately uses patched Go 1.27.4 and checks the complete module
  set, including the standard library, with `govulncheck` 1.1.4.
- **No third-party dependencies**: only the standard library (`crypto/ed25519`, `crypto/ecdsa`,
  `crypto/elliptic`, `crypto/sha256`, `crypto/subtle`, `math/big`, and pure parsing and
  formatting packages). `tools/license_check.sh` asserts the module graph stays empty.
- **64-bit platforms only**: the bounds hold 9,007,199,254,740,991 in an `int`.
- **Erratum 3 (producer canonicality) is implemented.** Compact assembly and anchored-export encoding for every profile refuse a signature no
  conforming signer emits under spec/bap-v1.md §16 and spec/bap-v3.md §3.2. The certified
  `bap-producer-canonicality/1` corpus (75 cases) runs with this SDK's conformance suite.
- **Erratum 6 (selector float-zero) is implemented.** Grant decode for contract-majors 1, 2,
  and 3 rejects an `equals` value or `one_of` member holding a float-tagged zero at any depth
  (any sign or spelling; range bounds and inert `all` members are unchanged), and the grant
  signing-input producer refuses any float-tagged integral selector value, range bounds
  included. The certified `bap-selector-float-zero/1` corpus (161 cases) runs with this SDK's
  conformance suite.

## Install from a checkout

From an empty directory, fetch this selected commit and declare a local module replacement.
The full source commit is the identity of this unpublished SDK.

<!-- sdk-install:go -->

```bash
git init upstream
git -C upstream remote add origin https://github.com/baselabs/bounded_authority_protocol.git
git -C upstream fetch --depth 1 origin c8b3bab8e4caf0b7f93e6f240570673534c331e2
git -C upstream checkout --detach FETCH_HEAD
test "$(git -C upstream rev-parse HEAD)" = "c8b3bab8e4caf0b7f93e6f240570673534c331e2"
go mod init example.com/bap-consumer
go mod edit -require=github.com/baselabs/bounded_authority_protocol_go@v0.0.0
go mod edit -replace=github.com/baselabs/bounded_authority_protocol_go=./upstream/sdks/go
```

Save the quickstart below as `quickstart_test.go`, then run `go test -v .`.
CI executes these commands and that example in an empty project. The SDK root includes its
complete tests and conformance inputs.

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
	fmt.Println(facts.Operation(), facts.GrantID(), facts.Authorization() == verifier.AuthorizationNotEvaluated, err)

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
`EnvelopeFacts`, and `AnchoredExportFacts` carry `Authorization() == AuthorizationNotEvaluated`; the
chain, anchor, transition, export, attestation, and content-assertion facts carry
`Trust() == TrustNotEvaluated`. There is no `Authorized` or decision field. The facts types implement `String`, `GoString`, and
`Format`: values and pointers match the specified diagnostic rendering (for example,
`#BoundedAuthorityProtocol.V1.GrantFacts<redacted>`), including `%v`, `%+v`, and `%#v`.
Contract-majors retain their `V1`, `V2`, or `V3` namespace; sibling facts use
`RoleAttestation.V1` and `ContentAssertion.V1`. `MarshalJSON`, `MarshalText`, and `GobEncode`
return `ErrInvalid` without encoded field values. Read individual values through named accessor
methods, for example `facts.GrantID()` and `facts.Operation()`. Anchor facts expose the
authenticated `ChainHash()` and `KeyFingerprint()` digests as 32-byte values. Facts store their values behind
an unexported closure; slice accessors return copies. A zero value has zero-valued accessors.

All formatting verbs, flags, pointer forms, and nested containers preserve redaction. Go's
`fmt` can skip methods for an unexported containing field or a bad verb, but its fallback
sees only the private closure, never the stored values. It may print pointer or type
metadata instead of the fixed rendering. Facts are no longer comparable with `==`;
compare the named values that matter to the caller.

**Decoded diagnostics.** Grants and role attestations use the specified inspection
notation. Proofs expose named accessors and redact their nonce; content assertions expose
named accessors and render fully redacted. Both refuse JSON, text, and gob encoding.
Decoded proofs now include `GrantHash()`, `RequestHash()`, `HolderPublicKey()`, and
`HolderThumbprint()`; the returned public-key slice is a copy.

## Strict Ed25519

Every Ed25519 signature check goes through one function (`verifyEd25519` in `ed25519.go`) that
applies rule S1 of [erratum 2](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md) before
the standard-library backend: exact widths, canonical `A` and `R`, neither of small order,
`S < L`, then the cofactorless equation. `AcceptablePublicKey` is the key-entry check (canonical,
not small order, on the curve), and every JWK and thumbprint function returns `ErrInvalid` for a
key that fails it. `TorsionFree` adds `[L]A = O` in pure `math/big` arithmetic; call it at key
enrollment, at trust install, and before any deny-list or revocation comparison, never on the
verification path.

## Conformance

`conformance/priv/conformance/` is a complete, byte-identical snapshot of the Hex package built
from this commit's `priv/conformance/` tree. It includes all nine certified corpora, schemas, focused vectors,
and `verdict-digests.json`. Every test input is inside this SDK root; copying this directory
alone is sufficient to run the suite.
The manifest was introduced in 1.1.0.

| Corpus | Cases |
|---|---:|
| v1 / v2 / v3 | 283 / 268 / 292 |
| Local-loopback HTTP | 44 (36 URI, 8 proof) |
| Role attestation | 40 |
| Content assertion | 154 (131 assertion, 9 digest, 14 successor) |
| Producer canonicality | 75 |
| Selector float zero | 161 |
| Strict Ed25519 | 2,410 |

Each runner pins its index, hashes every indexed file, including `.raw` inputs, and rejects
extra or missing files, duplicate IDs, and skipped cases. It records computed outcomes,
orders them by the index's file and case order, and checks their JCS/SHA-256 verdict digest
against the vendored manifest. Expected-value comparison cannot substitute for this check.
Outcome projections and index ordering are specified in the
[verdict digest contract](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/corpus-verdict-digests.md).
The contract-major runners also retain their public-key import censuses.

Run from this SDK directory:

```bash
go test ./...
```

The module zip includes the complete `conformance/` tree. CI checks it with the official
module zip tooling and runs the suite from an SDK directory copied alone.

The monorepo's distribution job copies only this SDK root into a temporary directory,
runs its full suite, checks its package, and removes the temporary artifacts afterward.
A corpus update replaces the entire snapshot from the verified Hex unpack in one change;
individual case edits are not a supported update path. These checks do not publish the SDK.

## What this SDK does not do

No I/O, filesystem, clock, randomness, network, environment, or process access in the library
(`tools/purity_check.sh` scans every non-test file and allowlists its imports). No trust
discovery, key custody, signing, replay reservation, revocation state, issuance, or
authorization decisions. No registry-publish setup: a pre-commit hook and a CI job reject it
here.

## Development

```bash
unformatted=$(gofmt -l .) && test -z "$unformatted" && go vet ./...
go test ./...
bash tools/purity_check.sh && bash tools/license_check.sh
```

Deployment notes: [`docs/deployment/go-sdk.md`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/go-sdk.md).

## Migration from earlier source snapshots

These SDKs are unpublished at version 0.1.0; there is no earlier supported registry major.
When moving from an older source commit, apply these changes recorded in the monorepo
[CHANGELOG](https://github.com/baselabs/bounded_authority_protocol/blob/main/CHANGELOG.md). The quickstart uses the current forms.

| Earlier usage | Current usage |
|---|---|
| `facts.GrantID` and direct facts literals/assignments | Obtain facts from verification and read `facts.GrantID()`. Every value uses read-only accessors; slices are copies. |
| `a == b` for facts | Compare the specific accessor results needed by the application; closure-backed values are not comparable. |
| Generic JSON, text or gob serialization | Read named accessors into an explicit application projection. Generic exports return `ErrInvalid`. |
| Omit diagnostic major or match `#GrantFacts<redacted>` | Read `facts.Version()` and expect full namespaces such as `#BoundedAuthorityProtocol.V1.GrantFacts<redacted>`. |
| Read a subset of decoded proof fields | Use the hash, holder-key and thumbprint accessors; every formatting fallback still redacts the nonce. |

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
