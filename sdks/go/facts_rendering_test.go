package verifier

import (
	"bytes"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestFactsRenderingIsFixedAndValueFree(t *testing.T) {
	for _, facts := range []any{
		GrantFacts{},
		EnvelopeFacts{},
		ChainFacts{},
		AnchorFacts{},
		KeyTransitionFacts{},
		AnchoredExportFacts{},
		AttestationFacts{},
		ContentAssertionFacts{},
	} {
		typ := reflect.TypeOf(facts)
		t.Run(typ.Name(), func(t *testing.T) {
			value := reflect.New(typ)
			storage := populateFacts(t, value, 1, "caller-text-7f3a")

			profile := "V1"
			if typ.Name() == "AttestationFacts" {
				profile = "RoleAttestation.V1"
			}
			if typ.Name() == "ContentAssertionFacts" {
				profile = "ContentAssertion.V1"
			}
			version := storage.FieldByName("Version")
			if version.IsValid() {
				version.SetInt(1)
			}
			expected := "#BoundedAuthorityProtocol." + profile + "." + typ.Name() + "<redacted>"
			for _, input := range []any{value.Elem().Interface(), value.Interface()} {

				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%80v", "%.3v"} {
					rendered := fmt.Sprintf(verb, input)
					if rendered != expected {
						t.Fatalf("%s: got %q, want %q", verb, rendered, expected)
					}
					for _, fieldValue := range []string{"caller-text-7f3a", "caller-check-7f3a", "987654321", "173"} {
						if strings.Contains(rendered, fieldValue) {
							t.Fatalf("%s leaks a field value", verb)
						}
					}
				}
				if got := fmt.Sprint(input); got != expected {
					t.Fatalf("Sprint: %q", got)
				}
				stringer, ok := input.(fmt.Stringer)
				if !ok || stringer.String() != expected {
					t.Fatal("String is not redacted")
				}
				goStringer, ok := input.(fmt.GoStringer)
				if !ok || goStringer.GoString() != expected {
					t.Fatal("GoString is not redacted")
				}
				if encoded, err := json.Marshal(input); err == nil || bytes.Contains(encoded, []byte("caller-")) {
					t.Fatal("facts must refuse JSON encoding")
				}
				text, ok := input.(encoding.TextMarshaler)
				if !ok {
					t.Fatal("missing text refusal")
				}
				if encoded, err := text.MarshalText(); err == nil || len(encoded) != 0 {
					t.Fatal("facts must refuse text encoding")
				}
				var buffer bytes.Buffer
				if err := gob.NewEncoder(&buffer).Encode(input); err == nil {
					t.Fatal("facts must refuse gob encoding")
				}

			}
		})
	}
}

func TestFactsMajorsRenderDistinctly(t *testing.T) {
	for _, facts := range []any{GrantFacts{}, EnvelopeFacts{}, ChainFacts{}, AnchorFacts{}, KeyTransitionFacts{}, AnchoredExportFacts{}} {
		value := reflect.New(reflect.TypeOf(facts)).Elem()
		for major := 1; major <= 3; major++ {
			populateFacts(t, value.Addr(), major, "caller-text-7f3a")
			expected := fmt.Sprintf("#BoundedAuthorityProtocol.V%d.%s<redacted>", major, value.Type().Name())
			for _, verb := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(verb, value.Interface()); got != expected {
					t.Fatalf("got %q want %q", got, expected)
				}
			}
		}
	}
}

func TestEveryFmtFallbackKeepsFactsOpaque(t *testing.T) {
	for _, facts := range []any{GrantFacts{}, EnvelopeFacts{}, ChainFacts{}, AnchorFacts{}, KeyTransitionFacts{}, AnchoredExportFacts{}, AttestationFacts{}, ContentAssertionFacts{}} {
		typ := reflect.TypeOf(facts)
		for major := 1; major <= 3; major++ {
			value := reflect.New(typ)
			populateFacts(t, value, major, "hidden-value-7f3a")
			for _, input := range []any{value.Elem().Interface(), value.Interface(),
				struct{ Value any }{value.Elem().Interface()}, struct{ value any }{value.Elem().Interface()},
				&struct{ Value any }{value.Interface()}, []any{value.Elem().Interface()},
				map[string]any{"facts": value.Interface()}} {
				for _, verb := range []string{"v", "s", "q", "x", "X", "d", "p", "T", "b", "c", "o", "O", "U", "t", "e", "E", "f", "F", "g", "G", "w", "%", "Z"} {
					for _, flags := range []string{"", "+", "#", " ", "0", "-", "+#020.3"} {
						format := "%" + flags + verb
						got := fmt.Sprintf(format, input)
						for _, secret := range []string{"hidden-value-7f3a", "987654321", "173 173", "adadadad"} {
							if strings.Contains(got, secret) {
								t.Errorf("%s major %d %s leaks: %s", typ.Name(), major, format, got)
							}
						}
					}
				}
			}
		}
	}
}

func TestFactsRefuseEachGenericEncoder(t *testing.T) {
	for _, facts := range []any{GrantFacts{}, EnvelopeFacts{}, ChainFacts{}, AnchorFacts{}, KeyTransitionFacts{}, AnchoredExportFacts{}, AttestationFacts{}, ContentAssertionFacts{}} {
		typ := reflect.TypeOf(facts)
		pointer := reflect.New(typ)
		for _, input := range []any{facts, pointer.Interface()} {
			encoders := map[string]func(*testing.T) ([]byte, error){
				"MarshalJSON": func(t *testing.T) ([]byte, error) {
					encoder, ok := input.(json.Marshaler)
					if !ok {
						t.Fatal("missing MarshalJSON refusal")
					}
					return encoder.MarshalJSON()
				},
				"MarshalText": func(t *testing.T) ([]byte, error) {
					encoder, ok := input.(encoding.TextMarshaler)
					if !ok {
						t.Fatal("missing MarshalText refusal")
					}
					return encoder.MarshalText()
				},
				"GobEncode": func(t *testing.T) ([]byte, error) {
					encoder, ok := input.(gob.GobEncoder)
					if !ok {
						t.Fatal("missing GobEncode refusal")
					}
					return encoder.GobEncode()
				},
			}
			for name, encode := range encoders {
				t.Run(typ.Name()+"/"+name, func(t *testing.T) {
					encoded, err := encode(t)
					if err != ErrInvalid || len(encoded) != 0 {
						t.Fatalf("got bytes=%d err=%v; want no bytes and ErrInvalid", len(encoded), err)
					}
				})
			}
			for name, container := range map[string]any{
				"slice": []any{input}, "map": map[string]any{"facts": input},
				"struct": struct{ Facts any }{Facts: input},
			} {
				t.Run(typ.Name()+"/JSON/"+name, func(t *testing.T) {
					encoded, err := json.Marshal(container)
					if err == nil || len(encoded) != 0 {
						t.Fatal("nested facts must refuse JSON encoding")
					}
				})
			}
		}
	}
}

// Private storage is populated explicitly; reflection touches exported members of that storage only.
func populateFacts(t *testing.T, pointer reflect.Value, major int, text string) reflect.Value {
	var data any
	switch pointer.Interface().(type) {
	case *GrantFacts:
		d := &grantFactsData{}
		pointer.Elem().Set(reflect.ValueOf(GrantFacts{data: privateValue(d)}))
		data = d
	case *EnvelopeFacts:
		d := &envelopeFactsData{}
		pointer.Elem().Set(reflect.ValueOf(EnvelopeFacts{data: privateValue(d)}))
		data = d
	case *ChainFacts:
		d := &chainFactsData{}
		pointer.Elem().Set(reflect.ValueOf(ChainFacts{data: privateValue(d)}))
		data = d
	case *AnchorFacts:
		d := &anchorFactsData{}
		pointer.Elem().Set(reflect.ValueOf(AnchorFacts{data: privateValue(d)}))
		data = d
	case *KeyTransitionFacts:
		d := &keyTransitionFactsData{}
		pointer.Elem().Set(reflect.ValueOf(KeyTransitionFacts{data: privateValue(d)}))
		data = d
	case *AnchoredExportFacts:
		d := &anchoredExportFactsData{}
		pointer.Elem().Set(reflect.ValueOf(AnchoredExportFacts{data: privateValue(d)}))
		data = d
	case *AttestationFacts:
		d := &attestationFactsData{}
		pointer.Elem().Set(reflect.ValueOf(AttestationFacts{data: privateValue(d)}))
		data = d
	case *ContentAssertionFacts:
		d := &contentAssertionFactsData{}
		pointer.Elem().Set(reflect.ValueOf(ContentAssertionFacts{data: privateValue(d)}))
		data = d
	default:
		t.Fatal("uncovered opaque type")
	}
	storage := reflect.ValueOf(data).Elem()
	for i := 0; i < storage.NumField(); i++ {
		field := storage.Field(i)
		switch field.Kind() {
		case reflect.String:
			field.SetString(text)
		case reflect.Int, reflect.Int64:
			field.SetInt(987654321)
		case reflect.Array:
			for j := 0; j < field.Len(); j++ {
				field.Index(j).SetUint(173)
			}
		case reflect.Slice:
			field.Set(reflect.ValueOf([]string{text}))
		default:
			t.Fatal("uncovered storage field")
		}
	}
	if version := storage.FieldByName("Version"); version.IsValid() {
		version.SetInt(int64(major))
	}
	return storage
}

func TestOpaqueAccessorsReturnCopies(t *testing.T) {
	chain := ChainFacts{data: privateValue(&chainFactsData{Checks: []string{"original"}})}
	checks := chain.Checks()
	checks[0] = "changed"
	if chain.Checks()[0] != "original" {
		t.Fatal("checks accessor exposes mutable storage")
	}
	proof := ProofDecoded{data: privateValue(&proofDecodedData{HolderPublicKey: []byte{7, 8}})}
	key := proof.HolderPublicKey()
	key[0] = 99
	if proof.HolderPublicKey()[0] != 7 {
		t.Fatal("public-key accessor exposes mutable storage")
	}
	for _, facts := range []any{GrantFacts{}, EnvelopeFacts{}, ChainFacts{}, AnchorFacts{}, KeyTransitionFacts{}, AnchoredExportFacts{}, AttestationFacts{}, ContentAssertionFacts{}, ProofDecoded{}, DecodedContentAssertion{}} {
		value := reflect.ValueOf(facts)
		typ := value.Type()
		for i := 0; i < typ.NumMethod(); i++ {
			method := typ.Method(i)
			if method.Type.NumIn() == 1 && method.Type.NumOut() == 1 && method.Type.Out(0).Kind() != reflect.String {
				value.Method(i).Call(nil)
			}
		}
	}
}
