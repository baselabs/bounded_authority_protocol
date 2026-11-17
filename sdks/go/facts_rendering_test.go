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
			for i := 0; i < typ.NumField(); i++ {
				field := value.Elem().Field(i)
				switch field.Kind() {
				case reflect.String:
					field.SetString("caller-text-7f3a")
				case reflect.Int, reflect.Int64:
					field.SetInt(987654321)
				case reflect.Array:
					for j := 0; j < field.Len(); j++ {
						field.Index(j).SetUint(173)
					}
				case reflect.Slice:
					field.Set(reflect.ValueOf([]string{"caller-check-7f3a"}))
				default:
					t.Fatalf("uncovered facts field: %s", typ.Field(i).Name)
				}
			}
			profile := "V1"
			if typ.Name() == "AttestationFacts" {
				profile = "RoleAttestation.V1"
			}
			if typ.Name() == "ContentAssertionFacts" {
				profile = "ContentAssertion.V1"
			}
			version := value.Elem().FieldByName("Version")
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
			value.FieldByName("Version").SetInt(int64(major))
			expected := fmt.Sprintf("#BoundedAuthorityProtocol.V%d.%s<redacted>", major, value.Type().Name())
			for _, verb := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(verb, value.Interface()); got != expected {
					t.Fatalf("got %q want %q", got, expected)
				}
			}
		}
	}
}

func TestUnexportedContainingFieldsAreFmtLanguageLimit(t *testing.T) {
	value := struct{ facts GrantFacts }{GrantFacts{Issuer: "caller-text-7f3a", Version: 1}}
	if got := fmt.Sprintf("%+v", value); !strings.Contains(got, "caller-text-7f3a") {
		t.Fatal("update the documented fmt limitation if the runtime changes this behavior")
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
