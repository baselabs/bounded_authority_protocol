package verifier

import (
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
			expected := "#" + typ.Name() + "<redacted>"
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
			}
		})
	}
}
