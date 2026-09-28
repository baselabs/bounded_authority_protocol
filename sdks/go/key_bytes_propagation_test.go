package verifier

import "testing"

func TestKeyBytesTighteningReachesEverySharedConsumer(t *testing.T) {
	bounds, err := BoundsNew(map[string]int{"key_bytes": 3})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("json member name", func(t *testing.T) {
		if _, err := JsonDecode([]byte(`{"four":0}`), &bounds); err != ErrInvalid {
			t.Fatalf("JsonDecode error = %v, want ErrInvalid", err)
		}
	})
	t.Run("jcs member name", func(t *testing.T) {
		if _, err := JcsEncode(Obj{{Key: "four", Val: Int(0)}}, &bounds); err != ErrInvalid {
			t.Fatalf("JcsEncode error = %v, want ErrInvalid", err)
		}
	})

	selector := Obj{
		{Key: "kind", Val: Str("equals")},
		{Key: "path", Val: Arr{Str("four")}},
		{Key: "value", Val: Int(0)},
	}
	for name, validate := range map[string]func(Value, *Bounds) error{
		"v1 selector": validateSelector,
		"v2 selector": (Profile{}).validateSelector,
		"v3 selector": (EcdsaProfile{}).validateSelector,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(selector, &bounds); err != ErrInvalid {
				t.Fatalf("selector error = %v, want ErrInvalid", err)
			}
		})
	}
}
