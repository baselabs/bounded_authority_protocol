package conformance_test

// The selector float-zero runner (profile bap-selector-float-zero/1, erratum 6): it executes the
// vendored additive corpus (corpus-selector-float-zero, a byte-identical snapshot of
// priv/conformance/selector-float-zero/) against grant decode, the grant signing-input producer,
// and envelope checking for contract-majors 1, 2 and 3. It SHA-binds the vendored index.json
// before any case runs, verifies every listed file against the index's per-file SHA-256 and case
// counts, and requires every case to agree: an invalid case is ErrInvalid; an accepted decode
// carries the certified key id; an accepted signing input is byte-equal to the certified segments.
//
// Typed values travel as JSON text (operations_json, cast_arguments_json): encoding/json would
// collapse the integer/float tag, so this runner decodes them with the SDK's own tag-preserving
// v.JsonDecode.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

// sfzCertifiedIndexSHA256 is the SHA-256 (base64url) of the certified selector float-zero corpus
// index.json (hex 97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003). A vendored
// corpus that hashes to anything else fails closed here.
const sfzCertifiedIndexSHA256 = "l_16mc2_OswKePW6HGVW4jpj4K1m9TPjH9afgtxfMAM"

const (
	sfzCorpusDir  = "corpus-selector-float-zero"
	sfzProfile    = "bap-selector-float-zero/1"
	sfzRevision   = 1
	sfzTotalCases = 161
)

type sfzIndex struct {
	Profile    string         `json:"profile"`
	Revision   int            `json:"revision"`
	TotalCases int            `json:"total_cases"`
	Families   map[string]int `json:"families"`
	Files      []struct {
		Cases  int    `json:"cases"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

type sfzCase struct {
	ID           string `json:"id"`
	Rule         string `json:"rule"`
	Major        int    `json:"major"`
	Surface      string `json:"surface"`
	Class        string `json:"class"`
	Construction string `json:"construction"`
	Input        struct {
		// decode_grant
		Compact string `json:"compact"`
		// grant_signing_input
		Audiences        []string `json:"audiences"`
		ExpiresAt        int64    `json:"expires_at"`
		GrantID          string   `json:"grant_id"`
		HolderThumbprint string   `json:"holder_thumbprint"`
		IssuedAt         int64    `json:"issued_at"`
		Issuer           string   `json:"issuer"`
		KeyID            string   `json:"key_id"`
		NotBefore        int64    `json:"not_before"`
		OperationsJSON   string   `json:"operations_json"`
		// check_envelope
		Grant    string `json:"grant"`
		Proof    string `json:"proof"`
		Expected struct {
			Audience          string `json:"audience"`
			CastArgumentsJSON string `json:"cast_arguments_json"`
			ClockSkew         int64  `json:"clock_skew"`
			EvaluationTime    int64  `json:"evaluation_time"`
			InvocationID      string `json:"invocation_id"`
			Issuer            string `json:"issuer"`
			Method            string `json:"method"`
			Operation         string `json:"operation"`
			ProofMaxAge       int64  `json:"proof_max_age"`
			TargetURI         string `json:"target_uri"`
			TrustedIssuer     struct {
				KeyID     string `json:"key_id"`
				PublicKey string `json:"public_key"`
			} `json:"trusted_issuer"`
		} `json:"expected"`
	} `json:"input"`
	Expected struct {
		Verdict          string `json:"verdict"`
		KeyID            string `json:"key_id"`
		Message          string `json:"message"`
		ProtectedSegment string `json:"protected_segment"`
		PayloadSegment   string `json:"payload_segment"`
	} `json:"expected"`
}

func loadSelectorFloatZero(t *testing.T) []sfzCase {
	t.Helper()
	indexBytes, err := os.ReadFile(filepath.Join(sfzCorpusDir, "index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	sum := sha256.Sum256(indexBytes)
	if v.Base64urlEncode(sum[:]) != sfzCertifiedIndexSHA256 {
		t.Fatalf("index.json SHA-256 mismatch: %s", v.Base64urlEncode(sum[:]))
	}
	var index sfzIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	if index.Profile != sfzProfile || index.Revision != sfzRevision || index.TotalCases != sfzTotalCases {
		t.Fatalf("corpus identity: %s rev %d total %d", index.Profile, index.Revision, index.TotalCases)
	}
	var cases []sfzCase
	counted := 0
	for _, file := range index.Files {
		raw, err := os.ReadFile(filepath.Join(sfzCorpusDir, file.Path))
		if err != nil {
			t.Fatalf("read %s: %v", file.Path, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			t.Fatalf("%s SHA-256 mismatch", file.Path)
		}
		if file.Cases == 0 {
			continue // profile.json, revision.json
		}
		var doc struct {
			Family string    `json:"family"`
			Cases  []sfzCase `json:"cases"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", file.Path, err)
		}
		if len(doc.Cases) != file.Cases {
			t.Fatalf("%s holds %d cases, index declares %d", file.Path, len(doc.Cases), file.Cases)
		}
		cases = append(cases, doc.Cases...)
		counted += len(doc.Cases)
	}
	if counted != sfzTotalCases {
		t.Fatalf("case census %d != %d", counted, sfzTotalCases)
	}
	return cases
}

// sfzTyped decodes JSON text with the SDK's tag-preserving decoder.
func sfzTyped(t *testing.T, id, text string) v.Value {
	t.Helper()
	val, err := v.JsonDecode([]byte(text), nil)
	if err != nil {
		t.Fatalf("%s: typed JSON text not decodable: %s", id, text)
	}
	return val
}

func sfzMember(obj v.Obj, key string) (v.Value, bool) {
	for _, m := range obj {
		if m.Key == key {
			return m.Val, true
		}
	}
	return nil, false
}

// sfzOperations turns the decoded operations_json array into producer operation definitions.
func sfzOperations(t *testing.T, c sfzCase) []v.OperationDef {
	t.Helper()
	arr, ok := sfzTyped(t, c.ID, c.Input.OperationsJSON).(v.Arr)
	if !ok {
		t.Fatalf("%s: operations_json is not an array", c.ID)
	}
	ops := make([]v.OperationDef, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(v.Obj)
		if !ok {
			t.Fatalf("%s: operation is not an object", c.ID)
		}
		name, ok := sfzMember(obj, "name")
		if !ok {
			t.Fatalf("%s: operation has no name", c.ID)
		}
		nameStr, ok := name.(v.Str)
		if !ok {
			t.Fatalf("%s: operation name is not a string", c.ID)
		}
		selectors, ok := sfzMember(obj, "selectors")
		if !ok {
			t.Fatalf("%s: operation has no selectors", c.ID)
		}
		selArr, ok := selectors.(v.Arr)
		if !ok {
			t.Fatalf("%s: selectors is not an array", c.ID)
		}
		ops = append(ops, v.OperationDef{Name: string(nameStr), Selectors: []v.Value(selArr)})
	}
	return ops
}

func sfzGrant(t *testing.T, c sfzCase) v.Grant {
	t.Helper()
	return v.Grant{
		KeyID:            c.Input.KeyID,
		Issuer:           c.Input.Issuer,
		GrantID:          c.Input.GrantID,
		Audiences:        c.Input.Audiences,
		IssuedAt:         c.Input.IssuedAt,
		NotBefore:        c.Input.NotBefore,
		ExpiresAt:        c.Input.ExpiresAt,
		HolderThumbprint: c.Input.HolderThumbprint,
		Operations:       sfzOperations(t, c),
	}
}

func sfzRequest(t *testing.T, c sfzCase) (v.Credentials, v.ExpectedRequest) {
	t.Helper()
	e := c.Input.Expected
	pk, err := v.Base64urlDecode(e.TrustedIssuer.PublicKey)
	if err != nil {
		t.Fatalf("%s: trusted issuer key: %v", c.ID, err)
	}
	return v.Credentials{Grant: c.Input.Grant, Proof: c.Input.Proof}, v.ExpectedRequest{
		TrustedIssuer:  v.TrustedIssuer{KeyID: e.TrustedIssuer.KeyID, PublicKey: pk},
		Issuer:         e.Issuer,
		Audience:       e.Audience,
		EvaluationTime: e.EvaluationTime,
		ClockSkew:      e.ClockSkew,
		Method:         e.Method,
		TargetURI:      e.TargetURI,
		InvocationID:   e.InvocationID,
		Operation:      e.Operation,
		CastArguments:  sfzTyped(t, c.ID, e.CastArgumentsJSON),
		ProofMaxAge:    e.ProofMaxAge,
		Nonce:          v.NonceNotRequired(),
	}
}

// sfzRun runs one case and reports whether it agrees with the certified verdict (and, for an
// accepted case, the certified key id or signing-input bytes).
func sfzRun(t *testing.T, c sfzCase) (bool, string) {
	t.Helper()
	wantValid := c.Expected.Verdict == "valid"
	switch c.Surface {
	case "decode_grant":
		var kid string
		var err error
		switch c.Major {
		case 1:
			var d v.GrantDecoded
			d, err = v.DecodeGrant(c.Input.Compact, nil)
			kid = d.KeyID
		case 2:
			var d v.GrantDecoded
			d, err = profile.DecodeGrant(c.Input.Compact, nil)
			kid = d.KeyID
		case 3:
			var d v.GrantDecoded
			d, err = es256Profile.DecodeGrant(c.Input.Compact, nil)
			kid = d.KeyID
		default:
			t.Fatalf("%s: major %d", c.ID, c.Major)
		}
		if (err == nil) != wantValid {
			return false, "verdict"
		}
		if wantValid && kid != c.Expected.KeyID {
			return false, "key id " + kid
		}
	case "grant_signing_input":
		g := sfzGrant(t, c)
		var si v.SigningInput
		var err error
		switch c.Major {
		case 1:
			si, err = v.GrantSigningInput(g, nil)
		case 2:
			si, err = profile.GrantSigningInput(g, nil)
		case 3:
			si, err = es256Profile.GrantSigningInput(g, nil)
		default:
			t.Fatalf("%s: major %d", c.ID, c.Major)
		}
		if (err == nil) != wantValid {
			return false, "verdict"
		}
		if wantValid {
			protected := v.Base64urlEncode(si.Protected)
			payload := v.Base64urlEncode(si.Payload)
			if protected != c.Expected.ProtectedSegment || payload != c.Expected.PayloadSegment ||
				protected+"."+payload != c.Expected.Message {
				return false, "signing-input bytes"
			}
		}
	case "check_envelope":
		creds, expected := sfzRequest(t, c)
		var err error
		switch c.Major {
		case 1:
			_, err = v.CheckEnvelope(creds, expected)
		case 2:
			_, err = profile.CheckEnvelope(creds, expected)
		case 3:
			_, err = es256Profile.CheckEnvelope(creds, expected)
		default:
			t.Fatalf("%s: major %d", c.ID, c.Major)
		}
		if (err == nil) != wantValid {
			return false, "verdict"
		}
	default:
		t.Fatalf("%s: unknown surface %s", c.ID, c.Surface)
	}
	return true, ""
}

func TestSelectorFloatZeroCorpus(t *testing.T) {
	cases := loadSelectorFloatZero(t)
	seen := map[string]bool{}
	agreed, rejected, accepted := 0, 0, 0
	var disagreed []string
	for _, c := range cases {
		if seen[c.ID] {
			t.Fatalf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
		if c.Expected.Verdict != "valid" && c.Expected.Verdict != "invalid" {
			t.Fatalf("%s: verdict %q", c.ID, c.Expected.Verdict)
		}
		ok, why := sfzRun(t, c)
		if !ok {
			disagreed = append(disagreed, c.ID+" ("+c.Construction+"; "+why+")")
			continue
		}
		agreed++
		if c.Expected.Verdict == "valid" {
			accepted++
		} else {
			rejected++
		}
	}
	if len(seen) != sfzTotalCases {
		t.Fatalf("case census %d != %d", len(seen), sfzTotalCases)
	}
	if len(disagreed) != 0 {
		for _, d := range disagreed {
			t.Errorf("disagree: %s", d)
		}
		t.Fatalf("selector float-zero: agreed=%d disagreed=%d", agreed, len(disagreed))
	}
	t.Logf("selector float-zero: agreed=%d/%d disagreed=0 (%d rejected, %d accepted)",
		agreed, sfzTotalCases, rejected, accepted)
}
