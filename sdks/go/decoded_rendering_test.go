package verifier

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDecodedRenderingMatchesReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoded-rendering.json")
	if err != nil {
		t.Fatal(err)
	}
	var gold map[string]string
	if err = json.Unmarshal(raw, &gold); err != nil {
		t.Fatal(err)
	}
	for major := 1; major <= 3; major++ {
		grant := GrantDecoded{Version: major, KeyID: "kid", Issuer: "issuer", GrantID: "grant", Audiences: []string{"aud"}, IssuedAt: 1, NotBefore: 2, ExpiresAt: 3, Operations: []OperationDef{{Name: "read", Selectors: []Value{Obj{{Key: "kind", Val: Str("all")}}}}}}
		proof := ProofDecoded{data: privateValue(&proofDecodedData{Version: major, ProofID: "proof", Method: "POST", TargetURI: "https://example.test/", IssuedAt: 1, Nonce: "hidden-nonce", HasNonce: true, InvocationID: "invocation", Operation: "read", HolderPublicKey: make([]byte, 32)})}
		attestation := AttestationDecoded{Version: 1, AttestorKeyID: "attestor", Jti: "jti", KeyID: "subject", Role: "issuer", Nbf: 1, Exp: 2}
		content := DecodedContentAssertion{data: privateValue(&decodedContentAssertionData{Jti: "hidden-content"})}
		for key, value := range map[string]any{fmt.Sprintf("grant%d", major): grant, fmt.Sprintf("proof%d", major): proof, "attestation": attestation, "content": content} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				if got := fmt.Sprintf(verb, value); got != gold[key] {
					t.Errorf("%s %s got %s want %s", key, verb, got, gold[key])
				}
			}
		}
		for _, value := range []any{proof, &proof, content, &content} {
			for _, nested := range []any{value, struct{ value any }{value}, []any{value}} {
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p", "%T", "%b", "%c", "%o", "%O", "%U", "%t", "%e", "%E", "%f", "%F", "%g", "%G", "%w", "%%", "%Z"} {
					if got := fmt.Sprintf(verb, nested); strings.Contains(got, "hidden-") {
						t.Fatalf("%s leaks %s", verb, got)
					}
				}
				if _, err := json.Marshal(struct{ Value any }{value}); err == nil {
					t.Fatal("redacted decoded values must refuse JSON")
				}
			}
			var buffer bytes.Buffer
			if err := gob.NewEncoder(&buffer).Encode(value); err == nil {
				t.Fatal("redacted decoded values must refuse gob")
			}
			if b, e := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); e != ErrInvalid || len(b) != 0 {
				t.Fatal("redacted decoded values must refuse text")
			}
		}
	}
}

func TestDecodedWireRenderingMatchesReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoded-wire-rendering.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Major                   int
		Kind, Compact, Expected string
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		var value any
		if row.Kind == "grant" {
			switch row.Major {
			case 1:
				value, err = DecodeGrant(row.Compact, nil)
			case 2:
				value, err = (Profile{}).DecodeGrant(row.Compact, nil)
			case 3:
				value, err = (EcdsaProfile{}).DecodeGrant(row.Compact, nil)
			}
		} else {
			switch row.Major {
			case 1:
				value, err = DecodeProof(row.Compact, nil)
			case 2:
				value, err = (Profile{}).DecodeProof(row.Compact, nil)
			case 3:
				value, err = (EcdsaProfile{}).DecodeProof(row.Compact, nil)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(value); got != row.Expected {
			t.Errorf("major %d %s got %s want %s", row.Major, row.Kind, got, row.Expected)
		}
	}
}

func TestDecodedBinaryNotationMatchesReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoded-binary-rendering.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Hex, Expected string }
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		raw, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		if got := inspectBinary(raw); got != row.Expected {
			t.Errorf("binary notation mismatch: got %s want %s", got, row.Expected)
		}
	}
}
