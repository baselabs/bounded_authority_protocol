package verifier

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
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
		Major                       int
		ID, Kind, Compact, Expected string
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
			t.Errorf("%s major %d %s got %s want %s", row.ID, row.Major, row.Kind, got, row.Expected)
		}
	}
}

func TestDecodedBinaryNotationMatchesReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoded-binary-rendering.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ ID, Hex, Expected string }
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		raw, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		if got := inspectBinary(raw); got != row.Expected {
			t.Errorf("%s binary notation mismatch: got %s want %s", row.ID, got, row.Expected)
		}
	}
}

func TestFloatNotationMatchesSpecifiedFixtureBytes(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoded-rendering.json")
	if err != nil {
		t.Fatal(err)
	}
	var gold map[string]string
	if err = json.Unmarshal(raw, &gold); err != nil {
		t.Fatal(err)
	}
	for key, expected := range gold {
		if !strings.HasPrefix(key, "float:") {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimPrefix(key, "float:"), 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := inspectRender(inspectTagged(Float(value))); got != "{:float, "+expected+"}" {
			t.Errorf("%s got %s want %s", key, got, expected)
		}
	}
}

func TestHandBuiltDecodedValuesAreTotal(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoded-rendering.json")
	if err != nil {
		t.Fatal(err)
	}
	var gold map[string]string
	if err := json.Unmarshal(raw, &gold); err != nil {
		t.Fatal(err)
	}
	operation := inspectStruct("BoundedAuthorityProtocol.V1.Operation", inspectField("name", inspectTerm{kind: "unrenderable"}), inspectField("selectors", inspectInt(1)))
	if got := inspectRender(inspectListing([]inspectTerm{operation})); got != gold["handbuilt:operation"] {
		t.Fatal(got)
	}

	for _, kind := range []string{"x\ny", "\xff", "", "Upper", "a-b", "a?b", "é"} {
		selector := Obj{{Key: "kind", Val: Str(kind)}, {Key: "path", Val: Arr{}}, {Key: "value", Val: Int(1)}}
		if got := inspectRender(inspectSelector(selector)); got != "{#unrenderable, [], {:integer, 1}}" {
			t.Fatalf("%q: %s", kind, got)
		}
	}
	malformed := []Value{nil, (*Int)(nil), Int(1), Obj{}, Obj{{Key: "kind", Val: Int(1)}}, Obj{{Key: "kind", Val: Str("eq")}},
		Obj{{Key: "kind", Val: Str("eq")}, {Key: "path", Val: Int(1)}, {Key: "value", Val: Int(1)}},
		Obj{{Key: "kind", Val: Str("eq")}, {Key: "path", Val: Arr{Int(1)}}, {Key: "value", Val: Int(1)}},
		Obj{{Key: "kind", Val: Str("eq")}, {Key: "path", Val: Arr{}}},
		Obj{{Key: "kind", Val: Str("one_of")}, {Key: "path", Val: Arr{}}, {Key: "values", Val: Int(1)}}}
	for _, value := range malformed {
		if got := inspectRender(inspectSelector(value)); got != "#unrenderable" {
			t.Fatal(got)
		}
	}
	for _, kind := range []string{"_", "ready?", "run!", "aB_9"} {
		if got := inspectRender(inspectAtom(kind)); got != ":"+kind {
			t.Fatal(got)
		}
	}
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if got := inspectRender(inspectTagged(Arr{Float(value)})); got != "{:array, [float: #unrenderable]}" {
			t.Fatal(got)
		}
	}
	for _, value := range []Value{nil, (*Int)(nil), (*Obj)(nil)} {
		if got := inspectRender(inspectTagged(value)); got != "#unrenderable" {
			t.Fatal(got)
		}
	}
	cycle := make(Arr, 1)
	cycle[0] = cycle
	if got := inspectRender(inspectTagged(cycle)); !strings.Contains(got, "...") {
		t.Fatal(got)
	}
	bad := "x\ny\xff"
	for major := 1; major <= 3; major++ {
		grant := GrantDecoded{Version: major, KeyID: bad, Issuer: bad, GrantID: bad, Audiences: []string{bad}, Verification: DecodeStatus(123), Operations: []OperationDef{{Name: bad, Selectors: malformed}}}
		proof := ProofDecoded{data: privateValue(&proofDecodedData{Version: major, ProofID: bad, Method: bad, TargetURI: bad, InvocationID: bad, Operation: bad, Nonce: "hidden", HasNonce: true, HolderPublicKey: []byte{255}})}
		attestation := AttestationDecoded{AttestorKeyID: bad, Jti: bad, KeyID: bad, Role: bad, Verification: DecodeStatus(123)}
		for _, value := range []any{grant, proof, attestation, GrantDecoded{}, ProofDecoded{}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
				got := fmt.Sprintf(verb, value)
				if !utf8.ValidString(got) || strings.ContainsAny(got, "\n\r\x00") || strings.Contains(got, "hidden") {
					t.Fatalf("%s: %q", verb, got)
				}
			}
		}
		if !strings.Contains(grant.String(), "verification: #unrenderable") || !strings.Contains(attestation.String(), "verification: #unrenderable") {
			t.Fatal("off-domain status")
		}
	}
}

func TestLargeDiagnosticConversionIsBounded(t *testing.T) {
	value := append([]byte{255}, make([]byte, 4*1024*1024)...)
	expected := "<<255, " + strings.TrimSuffix(strings.Repeat("0, ", 199), ", ") + ", ...>>"
	if got := inspectBinary(value); got != expected || got != inspectBinary(value[:201]) {
		t.Fatal(got)
	}
	text := strings.Repeat("😀", 1024*1024)
	if got := inspectText(text); len(got.raw) > 16384 {
		t.Fatal(len(got.raw))
	}
	if got := inspectString(strings.Repeat("😀", 4096)); got != "\""+strings.Repeat("😀", 4096)+"\"" {
		t.Fatal("scalar boundary")
	}
}
