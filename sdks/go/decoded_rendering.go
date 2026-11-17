package verifier

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type inspectTerm struct {
	kind, text string
	raw        []byte
	children   []inspectTerm
}

func inspectAtom(v string) inspectTerm { return inspectTerm{kind: "atom", text: v} }
func inspectInt(v int64) inspectTerm {
	return inspectTerm{kind: "scalar", text: strconv.FormatInt(v, 10)}
}
func inspectRaw(v []byte) inspectTerm                  { return inspectTerm{kind: "binary", raw: v} }
func inspectText(v string) inspectTerm                 { return inspectRaw([]byte(v)) }
func inspectTuple(v ...inspectTerm) inspectTerm        { return inspectTerm{kind: "tuple", children: v} }
func inspectListing(v []inspectTerm) inspectTerm       { return inspectTerm{kind: "list", children: v} }
func inspectField(k string, v inspectTerm) inspectTerm { return inspectTuple(inspectAtom(k), v) }
func inspectStruct(name string, fields ...inspectTerm) inspectTerm {
	return inspectTerm{kind: "struct", text: name, children: fields}
}
func inspectQuoted(raw []byte) (string, bool) {
	if !utf8.Valid(raw) {
		return "", false
	}
	chars := []rune(string(raw))
	for i, r := range chars {
		if i == 4096 {
			break
		}
		if !(r >= 32 && r <= 126 || r >= 160 && r <= 55295 || r >= 57344 && r <= 65533 || r >= 65536 && r <= 1114111 || strings.ContainsRune("\a\b\t\n\v\f\r\x1b", r)) {
			return "", false
		}
	}
	var b strings.Builder
	b.WriteByte('"')
	i := 0
	for count := 0; count < 4096 && i < len(chars); count++ {
		r := chars[i]
		i++
		switch r {
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
			if i < len(chars) && chars[i] == '{' {
				b.WriteString(`\#{`)
				i++
			} else {
				b.WriteRune(r)
			}
		default:
			if r == 0xFEFF || r == 0x061C || r == 0x200E || r == 0x200F || r == 0x200C || r == 0x200D || r == 0x034F || r == 0x00A0 || r == 0x200B || r == 0x2060 || r == 0x2028 || r == 0x2029 || r == 0x205F || r >= 0x2061 && r <= 0x2064 || r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r >= 0xFFF9 && r <= 0xFFFC || r >= 0x2000 && r <= 0x200A {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	if i < len(chars) {
		b.WriteString(" <> ...")
	}
	return b.String(), true
}
func inspectRender(term inspectTerm) string { remaining := 200; return inspectWalk(term, &remaining) }
func inspectContainer(values []inspectTerm, left, right string, keyword bool, remaining *int) string {
	parts := make([]string, 0, len(values))
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
func inspectWalk(term inspectTerm, remaining *int) string {
	switch term.kind {
	case "atom":
		if term.text == "true" || term.text == "false" || term.text == "nil" {
			return term.text
		}
		return ":" + term.text
	case "scalar":
		return term.text
	case "binary":
		if quoted, ok := inspectQuoted(term.raw); ok {
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
		if count < len(term.raw) {
			parts = append(parts, "...")
		}
		*remaining -= len(term.raw)
		if *remaining < 0 {
			*remaining = 0
		}
		return "<<" + strings.Join(parts, ", ") + ">>"
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
		s := strconv.FormatFloat(float64(v), 'g', -1, 64)
		if a := strings.Split(s, "e"); len(a) == 2 {
			if !strings.Contains(a[0], ".") {
				a[0] += ".0"
			}
			e, _ := strconv.Atoi(a[1])
			s = a[0] + "e" + strconv.Itoa(e)
		} else if !strings.Contains(s, ".") {
			s += ".0"
		}
		if v >= 1 && v < 1e16 && float64(int64(v)) == float64(v) || v <= -1 && v > -1e16 && float64(int64(v)) == float64(v) {
			s = strconv.FormatFloat(float64(v), 'f', 1, 64)
		}
		val = inspectTerm{kind: "scalar", text: s}
	case Str:
		tag = "string"
		val = inspectText(string(v))
	case Arr:
		tag = "array"
		members := make([]inspectTerm, len(v))
		for i, c := range v {
			members[i] = inspectTagged(c)
		}
		val = inspectListing(members)
	case Obj:
		tag = "object"
		members := make([]inspectTerm, len(v))
		for i, c := range v {
			members[i] = inspectTuple(inspectText(c.Key), inspectTagged(c.Val))
		}
		val = inspectListing(members)
	default:
		return inspectAtom("nil")
	}
	return inspectTuple(inspectAtom(tag), val)
}
func inspectMember(value Value, key string) Value {
	if obj, ok := value.(Obj); ok {
		for _, m := range obj {
			if m.Key == key {
				return m.Val
			}
		}
	}
	return Null{}
}
func inspectSelector(value Value) inspectTerm {
	kind, _ := inspectMember(value, "kind").(Str)
	if kind == "all" {
		return inspectAtom("all")
	}
	path, _ := inspectMember(value, "path").(Arr)
	names := make([]inspectTerm, len(path))
	for i, v := range path {
		s, _ := v.(Str)
		names[i] = inspectText(string(s))
	}
	operand := inspectTagged(inspectMember(value, "value"))
	if kind == "one_of" {
		members, _ := inspectMember(value, "values").(Arr)
		parts := make([]inspectTerm, len(members))
		for i, v := range members {
			parts[i] = inspectTagged(v)
		}
		operand = inspectListing(parts)
	}
	return inspectTuple(inspectAtom(string(kind)), inspectListing(names), operand)
}

// String matches the structural decoded-grant diagnostic notation.
func (d GrantDecoded) String() string {
	audiences := make([]inspectTerm, len(d.Audiences))
	for i, a := range d.Audiences {
		audiences[i] = inspectText(a)
	}
	operations := make([]inspectTerm, len(d.Operations))
	for i, op := range d.Operations {
		selectors := make([]inspectTerm, len(op.Selectors))
		for j, s := range op.Selectors {
			selectors[j] = inspectSelector(s)
		}
		operations[i] = inspectStruct(fmt.Sprintf("BoundedAuthorityProtocol.V%d.Operation", d.Version), inspectField("name", inspectText(op.Name)), inspectField("selectors", inspectListing(selectors)))
	}
	return inspectRender(inspectStruct(fmt.Sprintf("BoundedAuthorityProtocol.V%d.DecodedGrant", d.Version),
		inspectField("version", inspectInt(int64(d.Version))), inspectField("key_id", inspectText(d.KeyID)), inspectField("issuer", inspectText(d.Issuer)), inspectField("grant_id", inspectText(d.GrantID)),
		inspectField("audiences", inspectListing(audiences)), inspectField("issued_at", inspectInt(d.IssuedAt)), inspectField("not_before", inspectInt(d.NotBefore)), inspectField("expires_at", inspectInt(d.ExpiresAt)),
		inspectField("holder_thumbprint", inspectRaw(d.HolderThumbprint[:])), inspectField("operations", inspectListing(operations)), inspectField("verification", inspectAtom("not_evaluated"))))
}
func (d GrantDecoded) GoString() string           { return d.String() }
func (d GrantDecoded) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(d.String())) }

// String redacts only the optional nonce, matching decoded proof inspection.
func (d ProofDecoded) String() string {
	nonce := "nil"
	if d.HasNonce() {
		nonce = ":redacted"
	}
	gh, rh, hp := d.GrantHash(), d.RequestHash(), d.HolderThumbprint()
	return fmt.Sprintf("#BoundedAuthorityProtocol.V%d.DecodedProof<version: %d, proof_id: %s, method: %s, target_uri: %s, issued_at: %d, nonce: %s, invocation_id: %s, operation: %s, grant_hash: %s, request_hash: %s, holder_public_key: %s, holder_thumbprint: %s, verification: :not_evaluated>", d.Version(), d.Version(), inspectString(d.ProofID()), inspectString(d.Method()), inspectString(d.TargetURI()), d.IssuedAt(), nonce, inspectString(d.InvocationID()), inspectString(d.Operation()), inspectBinary(gh[:]), inspectBinary(rh[:]), inspectBinary(d.HolderPublicKey()), inspectBinary(hp[:]))
}
func (d ProofDecoded) GoString() string           { return d.String() }
func (d ProofDecoded) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(d.String())) }
func (ProofDecoded) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (ProofDecoded) MarshalText() ([]byte, error) { return nil, ErrInvalid }
func (ProofDecoded) GobEncode() ([]byte, error)   { return nil, ErrInvalid }

func (d AttestationDecoded) String() string {
	return inspectRender(inspectStruct("BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation",
		inspectField("version", inspectInt(1)), inspectField("attestor_key_id", inspectText(d.AttestorKeyID)), inspectField("jti", inspectText(d.Jti)), inspectField("key_id", inspectText(d.KeyID)),
		inspectField("public_key", inspectRaw(d.PublicKey[:])), inspectField("role", inspectText(d.Role)), inspectField("nbf", inspectInt(d.Nbf)), inspectField("exp", inspectInt(d.Exp)), inspectField("verification", inspectAtom("not_evaluated"))))
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
