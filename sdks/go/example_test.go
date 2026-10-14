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
