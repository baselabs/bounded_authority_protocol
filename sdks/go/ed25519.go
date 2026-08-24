package verifier

import "crypto/ed25519"

// Ed25519 verification over the exact received signing input. Width gates are
// the immutable suite constants; a backend rejection or exception is exactly
// ErrInvalid (REQ1-SIGNING-backend-reject). Public keys are caller-supplied
// trusted inputs — never discovered here.
func verifyEd25519(publicKey []byte, message, signature []byte) error {
	if len(publicKey) != 32 || len(signature) != 64 {
		return ErrInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return ErrInvalid
	}
	return nil
}
