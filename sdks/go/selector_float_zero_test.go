package verifier_test

// Selector float-zero soundness repair (erratum 6): the certified matrix lives in the vendored
// bap-selector-float-zero/1 corpus (the conformance package's runner, 161 cases). This file
// observes the two rules directly at the public surfaces of every contract-major:
//
//   - grant decode rejects an equals value or one_of member holding a float-tagged zero at any
//     depth, whatever its sign or spelling, and leaves range bounds and inert all members alone;
//   - the grant signing-input producer refuses any float-tagged integral selector value (RFC
//     8785 writes it as integer text, which decodes integer-tagged), range bounds included.

import (
	"math"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

type sfzSuite struct {
	name    string
	alg     string
	major   int
	decode  func(string, *v.Bounds) (v.GrantDecoded, error)
	produce func(v.Grant, *v.Bounds) (v.SigningInput, error)
	ranges  bool
}

var sfzSuites = []sfzSuite{
	{"v1", "EdDSA", 1, v.DecodeGrant, v.GrantSigningInput, false},
	{"v2", "EdDSA", 2, v.Profile{}.DecodeGrant, v.Profile{}.GrantSigningInput, true},
	{"v3", "ES256", 3, v.EcdsaProfile{}.DecodeGrant, v.EcdsaProfile{}.GrantSigningInput, true},
}

// sfzCompact frames a grant whose single selector is the given JSON text. Decode verifies no
// signature, so a fixed 64-byte signature suffices.
func sfzCompact(s sfzSuite, selector string) string {
	header := `{"alg":"` + s.alg + `","kid":"issuer","typ":"ba+cap"}`
	payload := `{"aud":["https://resource.example.test"],"cnf":{"jkt":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"},` +
		`"exp":2000,"iat":1000,"iss":"https://issuer.example.test","jti":"urn:example:grant:float-zero","nbf":1000,` +
		`"operations":[{"name":"transfer","selectors":[` + selector + `]}],"v":` + string(rune('0'+s.major)) + `}`
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = 0x11
	}
	return v.Base64urlEncode([]byte(header)) + "." + v.Base64urlEncode([]byte(payload)) + "." + v.Base64urlEncode(sig)
}

func TestDecodeGrantRejectsFloatZeroSelectorValues(t *testing.T) {
	rejected := []string{
		`{"kind":"equals","path":["x"],"value":0.0}`,
		`{"kind":"equals","path":["x"],"value":-0.0}`,
		`{"kind":"equals","path":["x"],"value":0e0}`,
		`{"kind":"equals","path":["x"],"value":-0E0}`,
		`{"kind":"equals","path":["x"],"value":-0e-5}`,
		`{"kind":"equals","path":["x"],"value":0.000}`,
		`{"kind":"equals","path":["x"],"value":1e-400}`,
		`{"kind":"equals","path":["x"],"value":-1e-400}`,
		`{"kind":"equals","path":["x"],"value":[1,-0.0]}`,
		`{"kind":"equals","path":["x"],"value":{"a":{"b":0.0}}}`,
		`{"kind":"one_of","path":["x"],"values":[1,-0.0]}`,
		`{"kind":"one_of","path":["x"],"values":[[0e0]]}`,
		`{"kind":"one_of","path":["x"],"values":[{"a":-0e-5}]}`,
	}
	accepted := []string{
		`{"kind":"equals","path":["x"],"value":0}`,
		`{"kind":"equals","path":["x"],"value":-0}`,
		`{"kind":"equals","path":["x"],"value":0.5}`,
		`{"kind":"equals","path":["x"],"value":10.0}`,
		`{"kind":"equals","path":["x"],"value":1e1}`,
		`{"kind":"equals","path":["x"],"value":[0,1.5]}`,
		`{"kind":"one_of","path":["x"],"values":[0,10.0,-2.25]}`,
		`{"kind":"all","path":["x"],"value":-0.0}`,
		`{"kind":"all","path":["x"],"values":[0.0]}`,
	}
	ranges := []string{
		`{"kind":"lte","path":["x"],"value":0.0}`,
		`{"kind":"lte","path":["x"],"value":-0.0}`,
		`{"kind":"gte","path":["x"],"value":-0e0}`,
		`{"kind":"gte","path":["x"],"value":0.0}`,
	}
	for _, s := range sfzSuites {
		for _, sel := range rejected {
			if _, err := s.decode(sfzCompact(s, sel), nil); err != v.ErrInvalid {
				t.Errorf("%s: decode accepted float-zero selector %s (err %v)", s.name, sel, err)
			}
		}
		for _, sel := range accepted {
			if _, err := s.decode(sfzCompact(s, sel), nil); err != nil {
				t.Errorf("%s: decode rejected %s: %v", s.name, sel, err)
			}
		}
		if s.ranges {
			for _, sel := range ranges {
				if _, err := s.decode(sfzCompact(s, sel), nil); err != nil {
					t.Errorf("%s: decode rejected range bound %s: %v", s.name, sel, err)
				}
			}
		}
	}
}

func sfzSelector(kind string, member string, value v.Value) v.Value {
	return v.Obj{
		{Key: "kind", Val: v.Str(kind)},
		{Key: "path", Val: v.Arr{v.Str("x")}},
		{Key: member, Val: value},
	}
}

func sfzGrant(selector v.Value) v.Grant {
	return v.Grant{
		KeyID:            "issuer",
		Issuer:           "https://issuer.example.test",
		GrantID:          "urn:example:grant:float-zero",
		Audiences:        []string{"https://resource.example.test"},
		IssuedAt:         1000,
		NotBefore:        1000,
		ExpiresAt:        2000,
		HolderThumbprint: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
		Operations:       []v.OperationDef{{Name: "transfer", Selectors: []v.Value{selector}}},
	}
}

func TestGrantSigningInputRefusesIntegralFloatSelectorValues(t *testing.T) {
	negZero := v.Float(math.Copysign(0, -1))
	integral := []v.Value{
		v.Float(0), negZero, v.Float(10), v.Float(-3), v.Float(4503599627370496),
		v.Arr{v.Int(1), v.Float(0)},
		v.Obj{{Key: "a", Val: v.Float(10)}},
		v.Obj{{Key: "a", Val: v.Arr{v.Obj{{Key: "b", Val: negZero}}}}},
	}
	fine := []v.Value{
		v.Float(0.5), v.Float(-2.25), v.Int(0), v.Int(10),
		v.Arr{v.Int(1), v.Float(1.5)},
		v.Obj{{Key: "a", Val: v.Float(0.25)}},
	}
	for _, s := range sfzSuites {
		for _, value := range integral {
			if _, err := s.produce(sfzGrant(sfzSelector("equals", "value", value)), nil); err != v.ErrInvalid {
				t.Errorf("%s: producer signed equals value %#v (err %v)", s.name, value, err)
			}
			if _, err := s.produce(sfzGrant(sfzSelector("one_of", "values", v.Arr{v.Int(1), value})), nil); err != v.ErrInvalid {
				t.Errorf("%s: producer signed one_of member %#v (err %v)", s.name, value, err)
			}
		}
		for _, value := range fine {
			if _, err := s.produce(sfzGrant(sfzSelector("equals", "value", value)), nil); err != nil {
				t.Errorf("%s: producer refused equals value %#v: %v", s.name, value, err)
			}
			if _, err := s.produce(sfzGrant(sfzSelector("one_of", "values", v.Arr{v.Int(10), value})), nil); err != nil {
				t.Errorf("%s: producer refused one_of member %#v: %v", s.name, value, err)
			}
		}
		if !s.ranges {
			continue
		}
		for _, kind := range []string{"lte", "gte"} {
			for _, bound := range []v.Value{v.Float(0), negZero, v.Float(10), v.Float(-3)} {
				if _, err := s.produce(sfzGrant(sfzSelector(kind, "value", bound)), nil); err != v.ErrInvalid {
					t.Errorf("%s: producer signed %s bound %#v (err %v)", s.name, kind, bound, err)
				}
			}
			for _, bound := range []v.Value{v.Float(0.5), v.Float(-2.25), v.Int(0), v.Int(-3)} {
				if _, err := s.produce(sfzGrant(sfzSelector(kind, "value", bound)), nil); err != nil {
					t.Errorf("%s: producer refused %s bound %#v: %v", s.name, kind, bound, err)
				}
			}
		}
	}
}
