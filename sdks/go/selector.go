package verifier

import "crypto/sha256"

// Selector algebra (docs/protocol-v1.md § Selector algebra): closed ordered
// objects of kind all | equals | one_of over object-member paths. Selectors
// are applied conjunctively to the server-derived tagged arguments. Semantic
// identity preserves tagged scalar distinctions (integer and integral float
// are NOT equal), compares arrays positionally, and compares objects as
// unordered recursive key/value sets. No selector grants authorization
// (REQ1-SELECTOR-not-authorization).

// validateSelector closed-set-validates one selector value (an Obj decoded
// from grant payload bytes or caller-built).
func validateSelector(v Value, bounds *Bounds) error {
	b, err := resolveBounds(bounds)
	if err != nil {
		return ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok {
		return ErrInvalid // REQ1-SELECTOR-closed-set
	}
	var kind *Str
	var path Arr
	var hasPath bool
	var value Value
	var hasValue bool
	var values Arr
	var hasValues bool
	for _, m := range obj {
		switch m.Key {
		case "kind":
			if s, ok := m.Val.(Str); ok {
				kind = &s
			}
		case "path":
			if p, ok := m.Val.(Arr); ok {
				path, hasPath = p, true
			}
		case "value":
			value, hasValue = m.Val, true
		case "values":
			if vs, ok := m.Val.(Arr); ok {
				values, hasValues = vs, true
			}
		default:
			return ErrInvalid // unlisted member
		}
	}
	if kind == nil {
		return ErrInvalid
	}
	switch *kind {
	case "all":
		// open pattern (corpus: check-envelope-valid-selector-all-with-extra-members):
		// all matches any root and tolerates extra members — only the kind
		// member is interpreted.
		return nil
	case "equals":
		if len(obj) != 3 || !hasPath || !hasValue {
			return ErrInvalid
		}
	case "one_of":
		if len(obj) != 3 || !hasPath || !hasValues {
			return ErrInvalid
		}
		if len(values) == 0 || len(values) > b.OneOfValues {
			return ErrInvalid // REQ1-SELECTOR-one-of-size
		}
	default:
		return ErrInvalid // unknown kind
	}
	if len(path) == 0 || len(path) > b.PathSegments {
		return ErrInvalid // REQ1-SELECTOR-path-shape
	}
	for _, seg := range path {
		s, ok := seg.(Str)
		if !ok || len(s) == 0 || len(s) > objectNameBytes {
			return ErrInvalid
		}
	}
	// selector values live inside the same JSON bounds as arguments and must
	// be prototype-safe: no object anywhere in the value tree may carry a
	// "__proto__" member (corpus: check-envelope-invalid-selector-value-proto-member)
	if hasValue {
		if _, err := JcsEncode(value, &b); err != nil {
			return ErrInvalid
		}
		if hasProtoMember(value) {
			return ErrInvalid
		}
	}
	if hasValues {
		for _, item := range values {
			if _, err := JcsEncode(item, &b); err != nil {
				return ErrInvalid
			}
			if hasProtoMember(item) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// hasProtoMember reports whether any object in the value tree carries a
// "__proto__" member.
func hasProtoMember(v Value) bool {
	switch val := v.(type) {
	case Arr:
		for _, item := range val {
			if hasProtoMember(item) {
				return true
			}
		}
	case Obj:
		for _, m := range val {
			if m.Key == "__proto__" || hasProtoMember(m.Val) {
				return true
			}
		}
	}
	return false
}

// applySelectors applies every selector conjunctively; nil means every
// selector matched, ErrInvalid means one did not (or the input is invalid).
func applySelectors(selectors []Value, args Value) error {
	for _, sel := range selectors {
		obj, ok := sel.(Obj)
		if !ok {
			return ErrInvalid
		}
		var kind Str
		var path []string
		var target Value
		var candidates Arr
		for _, m := range obj {
			switch m.Key {
			case "kind":
				if k, ok := m.Val.(Str); ok {
					kind = k
				}
			case "path":
				if p, ok := m.Val.(Arr); ok {
					for _, seg := range p {
						if s, ok := seg.(Str); ok {
							path = append(path, string(s))
						}
					}
				}
			case "value":
				target = m.Val
			case "values":
				if vs, ok := m.Val.(Arr); ok {
					candidates = vs
				}
			}
		}
		switch kind {
		case "all":
			continue
		case "equals":
			found, ok := walkPath(args, path)
			if !ok || !semanticEqual(found, target) {
				return ErrInvalid // REQ1-SELECTOR-path-required
			}
		case "one_of":
			found, ok := walkPath(args, path)
			if !ok {
				return ErrInvalid
			}
			matched := false
			for _, cand := range candidates {
				if semanticEqual(found, cand) {
					matched = true
					break
				}
			}
			if !matched {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}

// walkPath traverses object members only — never indexes arrays
// (REQ1-SELECTOR-path-shape).
func walkPath(root Value, path []string) (Value, bool) {
	cur := root
	for _, seg := range path {
		obj, ok := cur.(Obj)
		if !ok {
			return nil, false
		}
		found := false
		for _, m := range obj {
			if m.Key == seg {
				cur = m.Val
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return cur, true
}

// semanticEqual is the tagged semantic identity (REQ1-SELECTOR-semantic-identity,
// REQ1-SELECTOR-no-tag-collapse): integer and integral float are distinct,
// arrays positional, duplicate-free objects unordered-recursive.
func semanticEqual(a, b Value) bool {
	switch av := a.(type) {
	case Null:
		_, ok := b.(Null)
		return ok
	case Bool:
		bv, ok := b.(Bool)
		return ok && av == bv
	case Int:
		bv, ok := b.(Int)
		return ok && av == bv
	case Float:
		bv, ok := b.(Float)
		return ok && av == bv
	case Str:
		bv, ok := b.(Str)
		return ok && av == bv
	case Arr:
		bv, ok := b.(Arr)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !semanticEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case Obj:
		bv, ok := b.(Obj)
		if !ok || len(av) != len(bv) {
			return false
		}
		index := make(map[string]Value, len(bv))
		for _, m := range bv {
			index[m.Key] = m.Val
		}
		for _, m := range av {
			other, present := index[m.Key]
			if !present || !semanticEqual(m.Val, other) {
				return false
			}
		}
		return true
	}
	return false
}

// requestDigestPrefix is the exact ASCII domain separator including its final
// zero byte (REQ1-SIGNING-digest-prefix).
var requestDigestPrefix = []byte("BAP1-REQUEST\x00")

// RequestDigest computes the request digest:
//
//	base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
//
// where typed/1 projects the tagged algebra to the closed tagged JSON form
// before JCS, preserving the integer/float distinction
// (REQ1-DIGEST-typed-projection).
func RequestDigest(operation string, castArguments Value, bounds *Bounds) (string, error) {
	raw, err := requestDigestRaw(operation, castArguments, bounds)
	if err != nil {
		return "", ErrInvalid
	}
	return Base64urlEncode(raw[:]), nil
}

func requestDigestRaw(operation string, castArguments Value, bounds *Bounds) ([32]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	if !validOperationName(operation, b.OperationBytes) {
		return [32]byte{}, ErrInvalid
	}
	projected := typedProjection(castArguments)
	body, err := JcsEncode(Arr{Str(operation), projected}, &b)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	h := sha256.New()
	h.Write(requestDigestPrefix)
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// typedProjection projects the tagged algebra to the closed tagged JSON form.
func typedProjection(v Value) Value {
	switch val := v.(type) {
	case Null:
		return Arr{Str("null")}
	case Bool:
		return Arr{Str("boolean"), val}
	case Int:
		return Arr{Str("integer"), val}
	case Float:
		return Arr{Str("float"), val}
	case Str:
		return Arr{Str("string"), val}
	case Arr:
		out := make(Arr, 0, len(val))
		for _, item := range val {
			out = append(out, typedProjection(item))
		}
		return Arr{Str("array"), out}
	case Obj:
		out := make(Obj, 0, len(val))
		for _, m := range val {
			out = append(out, Member{Key: m.Key, Val: typedProjection(m.Val)})
		}
		return Arr{Str("object"), out}
	}
	return nil // unreachable for the closed algebra; fail closed by JCS
}

// validOperationName: 1..bound bytes of printable ASCII
// (REQ1-CLAIM-operation-shape for names; the same class for the request).
func validOperationName(name string, byteCeiling int) bool {
	if len(name) == 0 || len(name) > byteCeiling {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] > 0x7e {
			return false
		}
	}
	return true
}
