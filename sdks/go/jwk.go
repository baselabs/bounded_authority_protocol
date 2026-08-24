package verifier

import "crypto/sha256"

// The public OKP JWK surface (docs/protocol-v1.md § Protected headers):
// exactly {crv:"Ed25519", kty:"OKP", x:canonical_base64url_32_bytes} in any
// member order; every additional member — private `d` included — is invalid
// (REQ1-HEADER-proof-jwk, REQ1-HEADER-no-private-jwk). The RFC 7638
// thumbprint preimage is the JCS form {"crv":"Ed25519","kty":"OKP","x":...}
// and the thumbprint is unpadded base64url SHA-256 of it; verified facts and
// APIs here carry the RAW 32-byte digest (REQ1-HEADER-digest-width).
// Issuer-key fingerprinting uses the same construction over the caller's raw
// 32-byte public key (REQ1-HEADER-issuer-fingerprint).

// JwkDecodePublic decodes a public Ed25519 OKP JWK (JSON bytes) under the
// closed member set and returns the raw 32-byte public key.
func JwkDecodePublic(data []byte, bounds *Bounds) ([]byte, error) {
	x, err := decodePublicJwk(data, bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	return x, nil
}

// JwkEncodePublic emits the canonical JCS bytes of the public JWK for a raw
// 32-byte Ed25519 public key.
func JwkEncodePublic(key []byte, bounds *Bounds) ([]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(key) != b.PublicKeyBytes {
		return nil, ErrInvalid
	}
	out := []byte(`{"crv":"Ed25519","kty":"OKP","x":"`)
	out = append(out, Base64urlEncode(key)...)
	out = append(out, '"', '}')
	return out, nil
}

// JwkThumbprintPreimage returns the exact RFC 7638 preimage bytes for a
// public Ed25519 OKP JWK.
func JwkThumbprintPreimage(data []byte, bounds *Bounds) ([]byte, error) {
	x, err := decodePublicJwk(data, bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	return []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + Base64urlEncode(x) + `"}`), nil
}

// JwkThumbprint returns the unpadded base64url SHA-256 RFC 7638 thumbprint
// of a public Ed25519 OKP JWK.
func JwkThumbprint(data []byte, bounds *Bounds) (string, error) {
	raw, err := JwkThumbprintRaw(data, bounds)
	if err != nil {
		return "", ErrInvalid
	}
	return Base64urlEncode(raw[:]), nil
}

// JwkThumbprintRaw returns the raw 32-byte SHA-256 RFC 7638 thumbprint of a
// public Ed25519 OKP JWK.
func JwkThumbprintRaw(data []byte, bounds *Bounds) ([32]byte, error) {
	pre, err := JwkThumbprintPreimage(data, bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(pre), nil
}

// PublicKeyThumbprintRaw is the issuer-key fingerprint: the RFC 7638
// thumbprint construction applied to the caller's raw 32-byte public key.
func PublicKeyThumbprintRaw(key []byte, bounds *Bounds) ([32]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	if len(key) != b.PublicKeyBytes {
		return [32]byte{}, ErrInvalid
	}
	pre := []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + Base64urlEncode(key) + `"}`)
	return sha256.Sum256(pre), nil
}

// decodePublicJwk parses and closed-set-validates a public Ed25519 OKP JWK,
// returning the raw key bytes.
func decodePublicJwk(data []byte, bounds *Bounds) ([]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(data) > b.JSONBytes {
		return nil, ErrInvalid
	}
	v, err := JsonDecode(data, &b)
	if err != nil {
		return nil, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return nil, ErrInvalid // exact three-member set
	}
	var crv, kty, x *Str
	for _, m := range obj {
		switch m.Key {
		case "crv":
			if s, ok := m.Val.(Str); ok {
				crv = &s
			}
		case "kty":
			if s, ok := m.Val.(Str); ok {
				kty = &s
			}
		case "x":
			if s, ok := m.Val.(Str); ok {
				x = &s
			}
		default:
			return nil, ErrInvalid // unlisted member (REQ1-HEADER-closed-set)
		}
	}
	if crv == nil || kty == nil || x == nil {
		return nil, ErrInvalid
	}
	if *crv != "Ed25519" || *kty != "OKP" {
		return nil, ErrInvalid
	}
	raw, err := Base64urlDecode(string(*x))
	if err != nil || len(raw) != b.PublicKeyBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
