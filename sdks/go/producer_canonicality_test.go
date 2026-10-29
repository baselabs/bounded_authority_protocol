package verifier_test

// Producer-canonicality refusals (erratum 3): the certified rule matrix lives in the vendored
// bap-producer-canonicality/1 corpus (the conformance package's runner, 75 cases — every refusal
// clause on every producer surface, the exact-bound accepts with byte-equality). This file adds
// what the corpus cannot carry: honest-signature positive controls per suite, proving the gates
// do not over-refuse what a conforming signer emits, and the same signature's refusal legs
// observed directly at the public surface.
//
// Defect-injection record (at authoring): removing each gate's call line disagreed the corpus
// runner at its first case for that suite; each was restored and re-run green.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

var pcL = new(big.Int).SetBytes([]byte{
	0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed})

func pcLEBytes(x *big.Int) []byte {
	out := make([]byte, 32)
	x.FillBytes(out)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func pcWithS(sig []byte, s *big.Int) []byte {
	out := append([]byte{}, sig...)
	copy(out[32:], pcLEBytes(s))
	return out
}

func pcMustJSON(text string) v.Value {
	value, err := v.JsonDecode([]byte(text), nil)
	if err != nil {
		panic(err)
	}
	return value
}

// An honest Ed25519 signature assembles unchanged; the same signature with S = L refuses, on the
// v1 and v2 assemblers and the three sibling profiles (the corpus pins the full matrix).
func TestProducerEd25519HonestControlAndSLRefusal(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := v.PublicKeyThumbprintRaw(pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	si, err := v.GrantSigningInput(v.Grant{
		KeyID: "issuer", Issuer: "https://issuer.example.test", GrantID: "urn:example:grant:pc-1",
		Audiences: []string{"https://resource.example.test"}, IssuedAt: 1000, NotBefore: 1000, ExpiresAt: 2000,
		HolderThumbprint: v.Base64urlEncode(fp[:]),
		Operations: []v.OperationDef{{
			Name:      "read",
			Selectors: []v.Value{pcMustJSON(`{"kind":"all"}`)},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(v.Base64urlEncode(si.Protected) + "." + v.Base64urlEncode(si.Payload))
	honest := ed25519.Sign(priv, msg)
	frame := v.Base64urlEncode(si.Protected) + "." + v.Base64urlEncode(si.Payload) + "." + v.Base64urlEncode(honest)

	if compact, err := v.AssembleCompact(si, honest, nil); err != nil || compact != frame {
		t.Error("v1: an honest signature must assemble unchanged")
	}
	if _, err := v.AssembleCompact(si, pcWithS(honest, pcL), nil); err == nil {
		t.Error("v1: S = L must refuse")
	}
	v2SI, err := (v.Profile{}).GrantSigningInput(v.Grant{
		KeyID: "issuer", Issuer: "https://issuer.example.test", GrantID: "urn:example:grant:pc-2",
		Audiences: []string{"https://resource.example.test"}, IssuedAt: 1000, NotBefore: 1000, ExpiresAt: 2000,
		HolderThumbprint: v.Base64urlEncode(fp[:]),
		Operations: []v.OperationDef{{
			Name:      "read",
			Selectors: []v.Value{pcMustJSON(`{"kind":"all"}`)},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v2Honest := ed25519.Sign(priv, []byte(v.Base64urlEncode(v2SI.Protected)+"."+v.Base64urlEncode(v2SI.Payload)))
	if _, err := (v.Profile{}).AssembleCompact(v2SI, v2Honest, nil); err != nil {
		t.Error("v2 honest control")
	}
	if _, err := (v.Profile{}).AssembleCompact(v2SI, pcWithS(v2Honest, pcL), nil); err == nil {
		t.Error("v2: S = L must refuse")
	}
}

// An honest low-S ES256 signature assembles unchanged on v3; its high-S twin — which verifies
// under raw ECDSA — refuses.
func TestProducerES256HonestControlAndTwinRefusal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 65)
	raw[0] = 4
	key.X.FillBytes(raw[1:33])
	key.Y.FillBytes(raw[33:65])
	fp, err := (v.EcdsaProfile{}).PublicKeyThumbprintRaw(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	si, err := (v.EcdsaProfile{}).GrantSigningInput(v.Grant{
		KeyID: "issuer", Issuer: "https://issuer.example.test", GrantID: "urn:example:grant:pc-3",
		Audiences: []string{"https://resource.example.test"}, IssuedAt: 1000, NotBefore: 1000, ExpiresAt: 2000,
		HolderThumbprint: v.Base64urlEncode(fp[:]),
		Operations: []v.OperationDef{{
			Name:      "transfer",
			Selectors: []v.Value{pcMustJSON(`{"kind":"lte","path":["amount"],"value":50}`)},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(v.Base64urlEncode(si.Protected) + "." + v.Base64urlEncode(si.Payload))
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	if s.Cmp(half) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	honest := make([]byte, 64)
	r.FillBytes(honest[:32])
	s.FillBytes(honest[32:])
	if _, err := (v.EcdsaProfile{}).AssembleCompact(si, honest, nil); err != nil {
		t.Error("an honest low-S signature must assemble")
	}
	high := append([]byte{}, honest...)
	sHigh := new(big.Int).Sub(elliptic.P256().Params().N, s)
	sHigh.FillBytes(high[32:])
	if _, err := (v.EcdsaProfile{}).AssembleCompact(si, high, nil); err == nil {
		t.Error("the high-S twin must refuse")
	}
}
