package verifier

// Read-only accessors copy variable-length values; fmt fallbacks cannot traverse a closure's captured storage.

// Version returns the decoded or verified Version value.
func (facts GrantFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// Issuer returns the decoded or verified Issuer value.
func (facts GrantFacts) Issuer() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Issuer
}

// GrantID returns the decoded or verified GrantID value.
func (facts GrantFacts) GrantID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().GrantID
}

// IssuerKeyFingerprint returns the decoded or verified IssuerKeyFingerprint value.
func (facts GrantFacts) IssuerKeyFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().IssuerKeyFingerprint
}

// HolderThumbprint returns the decoded or verified HolderThumbprint value.
func (facts GrantFacts) HolderThumbprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().HolderThumbprint
}

// MatchedAudience returns the decoded or verified MatchedAudience value.
func (facts GrantFacts) MatchedAudience() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().MatchedAudience
}

// IssuedAt returns the decoded or verified IssuedAt value.
func (facts GrantFacts) IssuedAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().IssuedAt
}

// NotBefore returns the decoded or verified NotBefore value.
func (facts GrantFacts) NotBefore() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().NotBefore
}

// ExpiresAt returns the decoded or verified ExpiresAt value.
func (facts GrantFacts) ExpiresAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().ExpiresAt
}

// Authorization returns the decoded or verified Authorization value.
func (facts GrantFacts) Authorization() Authorization {
	if facts.data == nil {
		var zero Authorization
		return zero
	}
	return facts.data().Authorization
}

// Version returns the decoded or verified Version value.
func (facts EnvelopeFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// Issuer returns the decoded or verified Issuer value.
func (facts EnvelopeFacts) Issuer() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Issuer
}

// GrantID returns the decoded or verified GrantID value.
func (facts EnvelopeFacts) GrantID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().GrantID
}

// IssuerKeyFingerprint returns the decoded or verified IssuerKeyFingerprint value.
func (facts EnvelopeFacts) IssuerKeyFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().IssuerKeyFingerprint
}

// HolderThumbprint returns the decoded or verified HolderThumbprint value.
func (facts EnvelopeFacts) HolderThumbprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().HolderThumbprint
}

// MatchedAudience returns the decoded or verified MatchedAudience value.
func (facts EnvelopeFacts) MatchedAudience() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().MatchedAudience
}

// IssuedAt returns the decoded or verified IssuedAt value.
func (facts EnvelopeFacts) IssuedAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().IssuedAt
}

// NotBefore returns the decoded or verified NotBefore value.
func (facts EnvelopeFacts) NotBefore() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().NotBefore
}

// ExpiresAt returns the decoded or verified ExpiresAt value.
func (facts EnvelopeFacts) ExpiresAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().ExpiresAt
}

// ProofID returns the decoded or verified ProofID value.
func (facts EnvelopeFacts) ProofID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ProofID
}

// InvocationID returns the decoded or verified InvocationID value.
func (facts EnvelopeFacts) InvocationID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().InvocationID
}

// Operation returns the decoded or verified Operation value.
func (facts EnvelopeFacts) Operation() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Operation
}

// TargetURI returns the decoded or verified TargetURI value.
func (facts EnvelopeFacts) TargetURI() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().TargetURI
}

// GrantHash returns the decoded or verified GrantHash value.
func (facts EnvelopeFacts) GrantHash() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().GrantHash
}

// RequestHash returns the decoded or verified RequestHash value.
func (facts EnvelopeFacts) RequestHash() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().RequestHash
}

// ProofIssuedAt returns the decoded or verified ProofIssuedAt value.
func (facts EnvelopeFacts) ProofIssuedAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().ProofIssuedAt
}

// Authorization returns the decoded or verified Authorization value.
func (facts EnvelopeFacts) Authorization() Authorization {
	if facts.data == nil {
		var zero Authorization
		return zero
	}
	return facts.data().Authorization
}

// Version returns the decoded or verified Version value.
func (facts ChainFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// ChainID returns the decoded or verified ChainID value.
func (facts ChainFacts) ChainID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ChainID
}

// FirstSequence returns the decoded or verified FirstSequence value.
func (facts ChainFacts) FirstSequence() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().FirstSequence
}

// LastSequence returns the decoded or verified LastSequence value.
func (facts ChainFacts) LastSequence() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().LastSequence
}

// RowCount returns the decoded or verified RowCount value.
func (facts ChainFacts) RowCount() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().RowCount
}

// LastHash returns the decoded or verified LastHash value.
func (facts ChainFacts) LastHash() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().LastHash
}

// Checks returns the decoded or verified Checks value.
func (facts ChainFacts) Checks() []string {
	if facts.data == nil {
		var zero []string
		return zero
	}
	return append([]string(nil), facts.data().Checks...)
}

// Trust returns the decoded or verified Trust value.
func (facts ChainFacts) Trust() Trust {
	if facts.data == nil {
		var zero Trust
		return zero
	}
	return facts.data().Trust
}

// Version returns the decoded or verified Version value.
func (facts AnchorFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// AnchorID returns the decoded or verified AnchorID value.
func (facts AnchorFacts) AnchorID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().AnchorID
}

// ChainID returns the decoded or verified ChainID value.
func (facts AnchorFacts) ChainID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ChainID
}

// KeyID returns the decoded or verified KeyID value.
func (facts AnchorFacts) KeyID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().KeyID
}

// Sequence returns the decoded or verified Sequence value.
func (facts AnchorFacts) Sequence() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Sequence
}

// AnchoredAt returns the decoded or verified AnchoredAt value.
func (facts AnchorFacts) AnchoredAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().AnchoredAt
}

// Trust returns the decoded or verified Trust value.
func (facts AnchorFacts) Trust() Trust {
	if facts.data == nil {
		var zero Trust
		return zero
	}
	return facts.data().Trust
}

// Version returns the decoded or verified Version value.
func (facts KeyTransitionFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// TransitionID returns the decoded or verified TransitionID value.
func (facts KeyTransitionFacts) TransitionID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().TransitionID
}

// ChainID returns the decoded or verified ChainID value.
func (facts KeyTransitionFacts) ChainID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ChainID
}

// EffectiveAt returns the decoded or verified EffectiveAt value.
func (facts KeyTransitionFacts) EffectiveAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().EffectiveAt
}

// FromFingerprint returns the decoded or verified FromFingerprint value.
func (facts KeyTransitionFacts) FromFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().FromFingerprint
}

// ToFingerprint returns the decoded or verified ToFingerprint value.
func (facts KeyTransitionFacts) ToFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().ToFingerprint
}

// ToKeyID returns the decoded or verified ToKeyID value.
func (facts KeyTransitionFacts) ToKeyID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ToKeyID
}

// Trust returns the decoded or verified Trust value.
func (facts KeyTransitionFacts) Trust() Trust {
	if facts.data == nil {
		var zero Trust
		return zero
	}
	return facts.data().Trust
}

// Version returns the decoded or verified Version value.
func (facts AnchoredExportFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// ChainID returns the decoded or verified ChainID value.
func (facts AnchoredExportFacts) ChainID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ChainID
}

// FirstSequence returns the decoded or verified FirstSequence value.
func (facts AnchoredExportFacts) FirstSequence() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().FirstSequence
}

// LastSequence returns the decoded or verified LastSequence value.
func (facts AnchoredExportFacts) LastSequence() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().LastSequence
}

// RowCount returns the decoded or verified RowCount value.
func (facts AnchoredExportFacts) RowCount() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().RowCount
}

// TransitionCount returns the decoded or verified TransitionCount value.
func (facts AnchoredExportFacts) TransitionCount() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().TransitionCount
}

// ChunkCount returns the decoded or verified ChunkCount value.
func (facts AnchoredExportFacts) ChunkCount() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().ChunkCount
}

// ByteCount returns the decoded or verified ByteCount value.
func (facts AnchoredExportFacts) ByteCount() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().ByteCount
}

// Digest returns the decoded or verified Digest value.
func (facts AnchoredExportFacts) Digest() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().Digest
}

// Checks returns the decoded or verified Checks value.
func (facts AnchoredExportFacts) Checks() []string {
	if facts.data == nil {
		var zero []string
		return zero
	}
	return append([]string(nil), facts.data().Checks...)
}

// Trust returns the decoded or verified Trust value.
func (facts AnchoredExportFacts) Trust() Trust {
	if facts.data == nil {
		var zero Trust
		return zero
	}
	return facts.data().Trust
}

// Authorization returns the decoded or verified Authorization value.
func (facts AnchoredExportFacts) Authorization() Authorization {
	if facts.data == nil {
		var zero Authorization
		return zero
	}
	return facts.data().Authorization
}

// AttestorKeyID returns the decoded or verified AttestorKeyID value.
func (facts AttestationFacts) AttestorKeyID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().AttestorKeyID
}

// AttestorKeyFingerprint returns the decoded or verified AttestorKeyFingerprint value.
func (facts AttestationFacts) AttestorKeyFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().AttestorKeyFingerprint
}

// SubjectKeyID returns the decoded or verified SubjectKeyID value.
func (facts AttestationFacts) SubjectKeyID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().SubjectKeyID
}

// SubjectKeyFingerprint returns the decoded or verified SubjectKeyFingerprint value.
func (facts AttestationFacts) SubjectKeyFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().SubjectKeyFingerprint
}

// Role returns the decoded or verified Role value.
func (facts AttestationFacts) Role() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Role
}

// Jti returns the decoded or verified Jti value.
func (facts AttestationFacts) Jti() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Jti
}

// Nbf returns the decoded or verified Nbf value.
func (facts AttestationFacts) Nbf() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Nbf
}

// Exp returns the decoded or verified Exp value.
func (facts AttestationFacts) Exp() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Exp
}

// Verification returns the decoded or verified Verification value.
func (facts AttestationFacts) Verification() AttestationVerification {
	if facts.data == nil {
		var zero AttestationVerification
		return zero
	}
	return facts.data().Verification
}

// Trust returns the decoded or verified Trust value.
func (facts AttestationFacts) Trust() Trust {
	if facts.data == nil {
		var zero Trust
		return zero
	}
	return facts.data().Trust
}

// Version returns the decoded or verified Version value.
func (facts ContentAssertionFacts) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// AttestorKeyID returns the decoded or verified AttestorKeyID value.
func (facts ContentAssertionFacts) AttestorKeyID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().AttestorKeyID
}

// AttestorKeyFingerprint returns the decoded or verified AttestorKeyFingerprint value.
func (facts ContentAssertionFacts) AttestorKeyFingerprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().AttestorKeyFingerprint
}

// Jti returns the decoded or verified Jti value.
func (facts ContentAssertionFacts) Jti() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Jti
}

// Iss returns the decoded or verified Iss value.
func (facts ContentAssertionFacts) Iss() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Iss
}

// Aud returns the decoded or verified Aud value.
func (facts ContentAssertionFacts) Aud() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Aud
}

// Sub returns the decoded or verified Sub value.
func (facts ContentAssertionFacts) Sub() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Sub
}

// Profile returns the decoded or verified Profile value.
func (facts ContentAssertionFacts) Profile() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Profile
}

// ProfileDigest returns the decoded or verified ProfileDigest value.
func (facts ContentAssertionFacts) ProfileDigest() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().ProfileDigest
}

// ContentDigest returns the decoded or verified ContentDigest value.
func (facts ContentAssertionFacts) ContentDigest() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().ContentDigest
}

// Gen returns the decoded or verified Gen value.
func (facts ContentAssertionFacts) Gen() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Gen
}

// Prev returns the decoded or verified Prev value.
func (facts ContentAssertionFacts) Prev() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().Prev
}

// Iat returns the decoded or verified Iat value.
func (facts ContentAssertionFacts) Iat() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Iat
}

// Nbf returns the decoded or verified Nbf value.
func (facts ContentAssertionFacts) Nbf() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Nbf
}

// Exp returns the decoded or verified Exp value.
func (facts ContentAssertionFacts) Exp() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Exp
}

// Digest returns the decoded or verified Digest value.
func (facts ContentAssertionFacts) Digest() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().Digest
}

// Verification returns the decoded or verified Verification value.
func (facts ContentAssertionFacts) Verification() AttestationVerification {
	if facts.data == nil {
		var zero AttestationVerification
		return zero
	}
	return facts.data().Verification
}

// Trust returns the decoded or verified Trust value.
func (facts ContentAssertionFacts) Trust() Trust {
	if facts.data == nil {
		var zero Trust
		return zero
	}
	return facts.data().Trust
}

// Version returns the decoded or verified Version value.
func (facts DecodedContentAssertion) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// AttestorKeyID returns the decoded or verified AttestorKeyID value.
func (facts DecodedContentAssertion) AttestorKeyID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().AttestorKeyID
}

// Jti returns the decoded or verified Jti value.
func (facts DecodedContentAssertion) Jti() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Jti
}

// Iss returns the decoded or verified Iss value.
func (facts DecodedContentAssertion) Iss() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Iss
}

// Aud returns the decoded or verified Aud value.
func (facts DecodedContentAssertion) Aud() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Aud
}

// Sub returns the decoded or verified Sub value.
func (facts DecodedContentAssertion) Sub() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Sub
}

// Profile returns the decoded or verified Profile value.
func (facts DecodedContentAssertion) Profile() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Profile
}

// ProfileDigest returns the decoded or verified ProfileDigest value.
func (facts DecodedContentAssertion) ProfileDigest() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().ProfileDigest
}

// ContentDigest returns the decoded or verified ContentDigest value.
func (facts DecodedContentAssertion) ContentDigest() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().ContentDigest
}

// Gen returns the decoded or verified Gen value.
func (facts DecodedContentAssertion) Gen() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Gen
}

// Prev returns the decoded or verified Prev value.
func (facts DecodedContentAssertion) Prev() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().Prev
}

// Iat returns the decoded or verified Iat value.
func (facts DecodedContentAssertion) Iat() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Iat
}

// Nbf returns the decoded or verified Nbf value.
func (facts DecodedContentAssertion) Nbf() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Nbf
}

// Exp returns the decoded or verified Exp value.
func (facts DecodedContentAssertion) Exp() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().Exp
}

// Verification returns the decoded or verified Verification value.
func (facts DecodedContentAssertion) Verification() DecodeStatus {
	if facts.data == nil {
		var zero DecodeStatus
		return zero
	}
	return facts.data().Verification
}

// ProofID returns the decoded or verified ProofID value.
func (facts ProofDecoded) ProofID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().ProofID
}

// Version returns the decoded or verified Version value.
func (facts ProofDecoded) Version() int {
	if facts.data == nil {
		var zero int
		return zero
	}
	return facts.data().Version
}

// Method returns the decoded or verified Method value.
func (facts ProofDecoded) Method() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Method
}

// TargetURI returns the decoded or verified TargetURI value.
func (facts ProofDecoded) TargetURI() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().TargetURI
}

// IssuedAt returns the decoded or verified IssuedAt value.
func (facts ProofDecoded) IssuedAt() int64 {
	if facts.data == nil {
		var zero int64
		return zero
	}
	return facts.data().IssuedAt
}

// InvocationID returns the decoded or verified InvocationID value.
func (facts ProofDecoded) InvocationID() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().InvocationID
}

// Operation returns the decoded or verified Operation value.
func (facts ProofDecoded) Operation() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Operation
}

// Nonce returns the decoded or verified Nonce value.
func (facts ProofDecoded) Nonce() string {
	if facts.data == nil {
		var zero string
		return zero
	}
	return facts.data().Nonce
}

// HasNonce returns the decoded or verified HasNonce value.
func (facts ProofDecoded) HasNonce() bool {
	if facts.data == nil {
		var zero bool
		return zero
	}
	return facts.data().HasNonce
}

// Verification returns the decoded or verified Verification value.
func (facts ProofDecoded) Verification() DecodeStatus {
	if facts.data == nil {
		var zero DecodeStatus
		return zero
	}
	return facts.data().Verification
}

// GrantHash returns the decoded GrantHash.
func (facts ProofDecoded) GrantHash() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().GrantHash
}

// RequestHash returns the decoded RequestHash.
func (facts ProofDecoded) RequestHash() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().RequestHash
}

// HolderPublicKey returns the decoded HolderPublicKey.
func (facts ProofDecoded) HolderPublicKey() []byte {
	if facts.data == nil {
		var zero []byte
		return zero
	}
	return append([]byte(nil), facts.data().HolderPublicKey...)
}

// HolderThumbprint returns the decoded HolderThumbprint.
func (facts ProofDecoded) HolderThumbprint() [32]byte {
	if facts.data == nil {
		var zero [32]byte
		return zero
	}
	return facts.data().HolderThumbprint
}

// privateValue keeps captured storage opaque even when fmt skips every formatting method.
// A pointer field is insufficient: fmt's bad-verb path dereferences it at a fresh depth.
func privateValue[T any](value *T) func() *T {
	return func() *T { return value }
}
