package verifier

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

type inspectTerm struct {
	kind, text string
	raw        []byte
	more       bool
	values     []Value
	members    Obj
	texts      []string
	operations []OperationDef
	version    int
	children   []inspectTerm
}

func inspectIdentifier(v string) bool {
	if len(v) == 0 || !(v[0] >= 'a' && v[0] <= 'z' || v[0] == '_') {
		return false
	}
	tail := v[1:]
	if len(tail) > 0 && (tail[len(tail)-1] == '?' || tail[len(tail)-1] == '!') {
		tail = tail[:len(tail)-1]
	}
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func inspectAtom(v string) inspectTerm {
	if !inspectIdentifier(v) {
		return inspectTerm{kind: "unrenderable"}
	}
	return inspectTerm{kind: "atom", text: v}
}
func inspectInt(v int64) inspectTerm {
	return inspectTerm{kind: "scalar", text: strconv.FormatInt(v, 10)}
}
func inspectRaw(v []byte) inspectTerm { return inspectTerm{kind: "binary", raw: v} }
func inspectText(v string) inspectTerm {
	return inspectTerm{kind: "binary", raw: []byte(v[:min(len(v), 16384)]), more: len(v) > 16384}
}
func inspectTuple(v ...inspectTerm) inspectTerm        { return inspectTerm{kind: "tuple", children: v} }
func inspectListing(v []inspectTerm) inspectTerm       { return inspectTerm{kind: "list", children: v} }
func inspectField(k string, v inspectTerm) inspectTerm { return inspectTuple(inspectAtom(k), v) }
func inspectStruct(name string, fields ...inspectTerm) inspectTerm {
	return inspectTerm{kind: "struct", text: name, children: fields}
}
func inspectQuoted(raw []byte) (string, bool) {
	scan := raw
	for count := 0; count < 4096 && len(scan) > 0; count++ {
		r, width := utf8.DecodeRune(scan)
		if r == utf8.RuneError && width == 1 {
			return "", false
		}
		if !(r >= 32 && r <= 127 || r >= 160 && r <= 55295 || r >= 57344 && r <= 65533 || r >= 65536 && r <= 1114111 || strings.ContainsRune("\a\b\t\n\v\f\r\x1b", r)) {
			return "", false
		}
		scan = scan[width:]
	}
	var b strings.Builder
	b.WriteByte('"')
	i := 0
	for count := 0; count < 4096 && i < len(raw); count++ {
		r, width := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && width == 1 {
			fmt.Fprintf(&b, `\x%02X`, raw[i])
			i++
			continue
		}
		i += width
		switch r {
		case 0:
			b.WriteString(`\0`)
		case 127:
			b.WriteString(`\d`)
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\v':
			b.WriteString(`\v`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '\x1b':
			b.WriteString(`\e`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '#':
			if i < len(raw) && raw[i] == '{' {
				b.WriteString(`\#{`)
				i++
			} else {
				b.WriteRune(r)
			}
		default:
			if r == 0xFEFF || r == 0x061C || r == 0x200E || r == 0x200F || r == 0x200C || r == 0x200D || r == 0x034F || r == 0x00A0 || r == 0x200B || r == 0x2060 || r == 0x2028 || r == 0x2029 || r == 0x205F || r >= 0x2061 && r <= 0x2064 || r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r >= 0xFFF9 && r <= 0xFFFC || r >= 0x2000 && r <= 0x200A {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else if r < 32 || r >= 128 && r < 160 {
				fmt.Fprintf(&b, `\x%02X`, r)
			} else if r == 0xFFFE || r == 0xFFFF {
				fmt.Fprintf(&b, `\x{%04X}`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	if i < len(raw) {
		b.WriteString(" <> ...")
	}
	return b.String(), true
}
func inspectRender(term inspectTerm) string { remaining := 200; return inspectWalk(term, &remaining) }
func inspectContainer(values []inspectTerm, left, right string, keyword bool, remaining *int) string {
	parts := make([]string, 0, min(len(values), *remaining)+1)
	for _, value := range values {
		if *remaining <= 0 {
			parts = append(parts, "...")
			break
		}
		*remaining--
		if keyword {
			parts = append(parts, value.children[0].text+": "+inspectWalk(value.children[1], remaining))
		} else {
			parts = append(parts, inspectWalk(value, remaining))
		}
	}
	return left + strings.Join(parts, ", ") + right
}
func inspectSequence(length int, get func(int) inspectTerm, left, right string, keyword bool, remaining *int) string {
	parts := make([]string, 0, min(length, *remaining)+1)
	for i := 0; i < length; i++ {
		if *remaining == 0 {
			parts = append(parts, "...")
			break
		}
		*remaining--
		v := get(i)
		if keyword {
			parts = append(parts, v.children[0].text+": "+inspectWalk(v.children[1], remaining))
		} else {
			parts = append(parts, inspectWalk(v, remaining))
		}
	}
	return left + strings.Join(parts, ", ") + right
}
func inspectWalk(term inspectTerm, remaining *int) string {
	switch term.kind {
	case "unrenderable":
		return "#unrenderable"
	case "atom":
		if term.text == "true" || term.text == "false" || term.text == "nil" {
			return term.text
		}
		return ":" + term.text
	case "scalar":
		return term.text
	case "binary":
		if quoted, ok := inspectQuoted(term.raw); ok {
			if term.more && !strings.HasSuffix(quoted, " <> ...") {
				quoted += " <> ..."
			}
			return quoted
		}
		count := len(term.raw)
		if count > *remaining {
			count = *remaining
		}
		parts := make([]string, count)
		for i, v := range term.raw[:count] {
			parts[i] = strconv.Itoa(int(v))
		}
		if term.more || count < len(term.raw) {
			parts = append(parts, "...")
		}
		*remaining -= len(term.raw)
		if *remaining < 0 {
			*remaining = 0
		}
		return "<<" + strings.Join(parts, ", ") + ">>"
	case "array":
		keyword := len(term.values) > 0
		for _, v := range term.values {
			switch v.(type) {
			case Bool, Int, Float, Str, Arr, Obj:
			default:
				keyword = false
			}
		}
		return inspectSequence(len(term.values), func(i int) inspectTerm { return inspectTagged(term.values[i]) }, "[", "]", keyword, remaining)
	case "object":
		return inspectSequence(len(term.members), func(i int) inspectTerm {
			m := term.members[i]
			return inspectTuple(inspectText(m.Key), inspectTagged(m.Val))
		}, "[", "]", false, remaining)
	case "path":
		return inspectSequence(len(term.values), func(i int) inspectTerm { return inspectOrdinary(term.values[i]) }, "[", "]", false, remaining)
	case "selectors":
		return inspectSequence(len(term.values), func(i int) inspectTerm { return inspectSelector(term.values[i]) }, "[", "]", false, remaining)
	case "texts":
		return inspectSequence(len(term.texts), func(i int) inspectTerm { return inspectText(term.texts[i]) }, "[", "]", false, remaining)
	case "operations":
		return inspectSequence(len(term.operations), func(i int) inspectTerm {
			op := term.operations[i]
			return inspectStruct(fmt.Sprintf("BoundedAuthorityProtocol.V%d.Operation", term.version), inspectField("name", inspectText(op.Name)), inspectField("selectors", inspectTerm{kind: "selectors", values: op.Selectors}))
		}, "[", "]", false, remaining)
	case "struct":
		return inspectContainer(term.children, "%"+term.text+"{", "}", true, remaining)
	case "tuple":
		return inspectContainer(term.children, "{", "}", false, remaining)
	default:
		keyword := len(term.children) > 0
		for _, v := range term.children {
			if v.kind != "tuple" || len(v.children) != 2 || v.children[0].kind != "atom" {
				keyword = false
				break
			}
		}
		return inspectContainer(term.children, "[", "]", keyword, remaining)
	}
}
func inspectBinary(raw []byte) string { return inspectRender(inspectRaw(raw)) }
func inspectString(v string) string   { return inspectRender(inspectText(v)) }
func inspectTagged(value Value) inspectTerm {
	var tag string
	var val inspectTerm
	switch v := value.(type) {
	case Null:
		return inspectAtom("null")
	case Bool:
		tag = "boolean"
		val = inspectAtom(strconv.FormatBool(bool(v)))
	case Int:
		tag = "integer"
		val = inspectInt(int64(v))
	case Float:
		tag = "float"
		val = inspectTerm{kind: "scalar", text: inspectFloat(float64(v))}
	case Str:
		tag = "string"
		val = inspectText(string(v))
	case Arr:
		tag = "array"
		val = inspectTerm{kind: "array", values: v}
	case Obj:
		tag = "object"
		val = inspectTerm{kind: "object", members: v}
	default:
		return inspectTerm{kind: "unrenderable"}
	}

	return inspectTuple(inspectAtom(tag), val)
}

// Scalar rendering chooses notation after obtaining the shortest round-trip digits.
func inspectFloat(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "#unrenderable"
	}
	if value == 0 {
		return strconv.FormatFloat(value, 'f', 1, 64)
	}
	shortest := strconv.FormatFloat(value, 'e', -1, 64)
	sign := ""
	if shortest[0] == '-' {
		sign, shortest = "-", shortest[1:]
	}
	parts := strings.Split(shortest, "e")
	exponent, _ := strconv.Atoi(parts[1])
	digits := strings.ReplaceAll(parts[0], ".", "")
	fraction := digits[1:]
	if fraction == "" {
		fraction = "0"
	}
	scientific := digits[:1] + "." + fraction + "e" + strconv.Itoa(exponent)
	point := exponent + 1
	var fixed string
	switch {
	case point <= 0:
		fixed = "0." + strings.Repeat("0", -point) + digits
	case point >= len(digits):
		fixed = digits + strings.Repeat("0", point-len(digits)) + ".0"
	default:
		fixed = digits[:point] + "." + digits[point:]
	}
	if value > -9007199254740992 && value < 9007199254740992 && len(fixed) <= len(scientific) {
		return sign + fixed
	}
	return sign + scientific
}
func inspectMember(value Value, key string) Value {
	if obj, ok := value.(Obj); ok {
		for _, m := range obj {
			if m.Key == key {
				return m.Val
			}
		}
	}
	return nil
}
func inspectOrdinary(value Value) inspectTerm {
	switch v := value.(type) {
	case Null:
		return inspectAtom("nil")
	case Bool:
		return inspectAtom(strconv.FormatBool(bool(v)))
	case Int:
		return inspectInt(int64(v))
	case Float:
		return inspectTerm{kind: "scalar", text: inspectFloat(float64(v))}
	case Str:
		return inspectText(string(v))
	case Arr:
		return inspectTerm{kind: "path", values: v}
	default:
		return inspectTerm{kind: "unrenderable"}
	}
}
func inspectSelector(value Value) inspectTerm {
	kind, ok := inspectMember(value, "kind").(Str)
	if !ok {
		return inspectTerm{kind: "unrenderable"}
	}
	if kind == "all" {
		return inspectAtom("all")
	}
	path, ok := inspectMember(value, "path").(Arr)
	if !ok {
		return inspectTerm{kind: "unrenderable"}
	}
	for _, v := range path {
		if _, ok := v.(Str); !ok {
			return inspectTerm{kind: "unrenderable"}
		}
	}
	var operand inspectTerm
	if kind == "one_of" {
		members, ok := inspectMember(value, "values").(Arr)
		if !ok {
			return inspectTerm{kind: "unrenderable"}
		}
		operand = inspectTerm{kind: "array", values: members}
	} else {
		member := inspectMember(value, "value")
		if member == nil {
			return inspectTerm{kind: "unrenderable"}
		}
		operand = inspectTagged(member)
	}
	return inspectTuple(inspectAtom(string(kind)), inspectTerm{kind: "path", values: path}, operand)
}

func inspectDecodeStatus(v DecodeStatus) inspectTerm {
	if v != DecodeVerificationNotEvaluated {
		return inspectTerm{kind: "unrenderable"}
	}
	return inspectAtom("not_evaluated")
}

// String matches the structural decoded-grant diagnostic notation.
func (d GrantDecoded) String() string {
	if d.Version < 1 || d.Version > 3 {
		return "#unrenderable"
	}
	audiences := inspectTerm{kind: "texts", texts: d.Audiences}
	operations := inspectTerm{kind: "operations", operations: d.Operations, version: d.Version}
	return inspectRender(inspectStruct(fmt.Sprintf("BoundedAuthorityProtocol.V%d.DecodedGrant", d.Version),
		inspectField("version", inspectInt(int64(d.Version))), inspectField("key_id", inspectText(d.KeyID)), inspectField("issuer", inspectText(d.Issuer)), inspectField("grant_id", inspectText(d.GrantID)),
		inspectField("audiences", audiences), inspectField("issued_at", inspectInt(d.IssuedAt)), inspectField("not_before", inspectInt(d.NotBefore)), inspectField("expires_at", inspectInt(d.ExpiresAt)),
		inspectField("holder_thumbprint", inspectRaw(d.HolderThumbprint[:])), inspectField("operations", operations), inspectField("verification", inspectDecodeStatus(d.Verification))))
}
func (d GrantDecoded) GoString() string           { return d.String() }
func (d GrantDecoded) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(d.String())) }

// String redacts only the optional nonce, matching decoded proof inspection.
func (d ProofDecoded) String() string {
	if d.Version() < 1 || d.Version() > 3 {
		return "#unrenderable"
	}
	nonce := "nil"
	if d.HasNonce() {
		nonce = ":redacted"
	}
	gh, rh, hp := d.GrantHash(), d.RequestHash(), d.HolderThumbprint()
	return fmt.Sprintf("#BoundedAuthorityProtocol.V%d.DecodedProof<version: %d, proof_id: %s, method: %s, target_uri: %s, issued_at: %d, nonce: %s, invocation_id: %s, operation: %s, grant_hash: %s, request_hash: %s, holder_public_key: %s, holder_thumbprint: %s, verification: %s>", d.Version(), d.Version(), inspectString(d.ProofID()), inspectString(d.Method()), inspectString(d.TargetURI()), d.IssuedAt(), nonce, inspectString(d.InvocationID()), inspectString(d.Operation()), inspectBinary(gh[:]), inspectBinary(rh[:]), inspectBinary(d.data().HolderPublicKey), inspectBinary(hp[:]), inspectRender(inspectDecodeStatus(d.Verification())))
}
func (d ProofDecoded) GoString() string           { return d.String() }
func (d ProofDecoded) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(d.String())) }
func (ProofDecoded) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (ProofDecoded) MarshalText() ([]byte, error) { return nil, ErrInvalid }
func (ProofDecoded) GobEncode() ([]byte, error)   { return nil, ErrInvalid }

func (d AttestationDecoded) String() string {
	return inspectRender(inspectStruct("BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation",
		inspectField("version", inspectInt(int64(d.Version))), inspectField("attestor_key_id", inspectText(d.AttestorKeyID)), inspectField("jti", inspectText(d.Jti)), inspectField("key_id", inspectText(d.KeyID)),
		inspectField("public_key", inspectRaw(d.PublicKey[:])), inspectField("role", inspectText(d.Role)), inspectField("nbf", inspectInt(d.Nbf)), inspectField("exp", inspectInt(d.Exp)), inspectField("verification", inspectDecodeStatus(d.Verification))))
}
func (d AttestationDecoded) GoString() string           { return d.String() }
func (d AttestationDecoded) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(d.String())) }

func (DecodedContentAssertion) String() string {
	return "#BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion<redacted>"
}
func (d DecodedContentAssertion) GoString() string           { return d.String() }
func (d DecodedContentAssertion) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(d.String())) }
func (DecodedContentAssertion) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DecodedContentAssertion) MarshalText() ([]byte, error) { return nil, ErrInvalid }
func (DecodedContentAssertion) GobEncode() ([]byte, error)   { return nil, ErrInvalid }
