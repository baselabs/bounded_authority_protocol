package verifier

import "testing"

// Selector algebra (spec/bap-v1.md § Selector algebra) + typed request
// digest (§ Signing and digest inputs). Formula values pinned numerically at
// authoring against the corpus fixtures.
func mustDecode(t *testing.T, s string) Value {
	t.Helper()
	v, err := JsonDecode([]byte(s), nil)
	if err != nil {
		t.Fatalf("fixture decode %s: %v", s, err)
	}
	return v
}

func TestSelectorValidateAndApply(t *testing.T) {
	args := mustDecode(t, `{"record":{"id":"rec-1"},"limit":10}`)
	sel := func(s string) Value { return mustDecode(t, s) }

	// all matches any root (scalar included)
	if err := validateSelector(sel(`{"kind":"all"}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := applySelectors([]Value{sel(`{"kind":"all"}`)}, Int(7)); err != nil {
		t.Fatal(err)
	}
	// equals with existing path
	if err := validateSelector(sel(`{"kind":"equals","path":["record","id"],"value":"rec-1"}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["record","id"],"value":"rec-1"}`)}, args); err != nil {
		t.Fatal(err)
	}
	// mismatch rejects
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["record","id"],"value":"rec-2"}`)}, args); err == nil {
		t.Fatal("non-matching equals must reject")
	}
	// missing path rejects (REQ1-SELECTOR-path-required)
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["missing"],"value":1}`)}, args); err == nil {
		t.Fatal("missing path must reject")
	}
	// int/float tag distinction: equals 10 (integer) does NOT match 10.0
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["limit"],"value":10}`)}, args); err != nil {
		t.Fatalf("integer 10 must match integer 10: %v", err)
	}
	floatArgs := mustDecode(t, `{"limit":10.0}`)
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["limit"],"value":10}`)}, floatArgs); err == nil {
		t.Fatal("integer tag must not match float 10.0 (no tag collapse)")
	}
	// one_of
	if err := applySelectors([]Value{sel(`{"kind":"one_of","path":["record","id"],"values":["rec-1","rec-9"]}`)}, args); err != nil {
		t.Fatal(err)
	}
	if err := applySelectors([]Value{sel(`{"kind":"one_of","path":["record","id"],"values":["rec-2","rec-9"]}`)}, args); err == nil {
		t.Fatal("one_of with no match must reject")
	}
	// conjunctive application: every selector must match
	if err := applySelectors([]Value{
		sel(`{"kind":"equals","path":["limit"],"value":10}`),
		sel(`{"kind":"equals","path":["record","id"],"value":"rec-1"}`),
	}, args); err != nil {
		t.Fatal(err)
	}
	if err := applySelectors([]Value{
		sel(`{"kind":"equals","path":["limit"],"value":10}`),
		sel(`{"kind":"equals","path":["record","id"],"value":"rec-2"}`),
	}, args); err == nil {
		t.Fatal("conjunctive failure must reject")
	}
	// object identity is unordered-recursive
	unordered := mustDecode(t, `{"b":{"y":2,"x":1},"a":0}`)
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["b"],"value":{"x":1,"y":2}}`)}, unordered); err != nil {
		t.Fatalf("object member order must not affect identity: %v", err)
	}
	// arrays compare positionally
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["arr"],"value":[1,2]}`)}, mustDecode(t, `{"arr":[1,2]}`)); err != nil {
		t.Fatal(err)
	}
	if err := applySelectors([]Value{sel(`{"kind":"equals","path":["arr"],"value":[2,1]}`)}, mustDecode(t, `{"arr":[1,2]}`)); err == nil {
		t.Fatal("array order is positional")
	}

	// validation rejections
	bad := []string{
		`{"kind":"contains"}`,                   // unknown kind
		`{}`,                                    // missing kind
		`{"kind":"equals","value":1}`,           // missing path
		`{"kind":"equals","path":[],"value":1}`, // empty path
		`{"kind":"equals","path":["a"],"value":1,"extra":true}`,   // unlisted member
		`{"kind":"one_of","path":["a"]}`,                          // missing values
		`{"kind":"one_of","path":["a"],"values":[]}`,              // empty values
		`{"kind":"one_of","path":["a"],"values":{"not":"array"}}`, // non-array values
		`{"kind":"equals","path":[1],"value":1}`,                  // non-string path segment
		`{"kind":"equals","path":[""],"value":1}`,                 // empty segment
		`["kind"]`, // not an object
	}
	for _, in := range bad {
		v := mustDecode(t, in)
		if err := validateSelector(v, nil); err == nil {
			t.Fatalf("validateSelector(%s) must reject", in)
		}
	}
}

func TestRequestDigest(t *testing.T) {
	// corpus request-digest-float-cast-arguments: operation "read", args 1e-7
	d, err := RequestDigest("read", Float(1e-7), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d != "-fTRu1NZroD6L_Q_IDSrPoqfCItKMpV1GDM3FV5ol0Y" {
		t.Fatalf("float digest = %s", d)
	}
	// corpus object case: {"limit":10,"record":{"id":"rec-1"}}
	args := mustDecode(t, `{"limit":10,"record":{"id":"rec-1"}}`)
	d, err = RequestDigest("read", args, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d != "uv20PiC8tRQoOy9-eRlBFPQngtiDXkw_SCbbgzxjC2g" {
		t.Fatalf("object digest = %s", d)
	}
	// int/float distinction changes the digest
	di, _ := RequestDigest("read", Int(10), nil)
	df, _ := RequestDigest("read", Float(10), nil)
	if di == df {
		t.Fatal("integer and integral-float digests must differ (typed projection)")
	}
	// operation is validated
	for _, bad := range []string{"", "bad op", "op\x01"} {
		if _, err := RequestDigest(bad, Null{}, nil); err == nil {
			t.Fatalf("RequestDigest(%q) must reject", bad)
		}
	}
}
