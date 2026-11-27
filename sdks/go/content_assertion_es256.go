package verifier

import "fmt"

// ContentAssertionES256 is the caller-selected ES256 content assertion profile.
type ContentAssertionES256 struct{}

type assertionFacts = ContentAssertionFacts
type decodedAssertion = DecodedContentAssertion

// ES256ContentAssertionFacts is redacted evidence from the ES256 assertion profile.
type ES256ContentAssertionFacts struct{ assertionFacts }

// ES256DecodedContentAssertion contains redacted, unverified ES256 assertion claims.
type ES256DecodedContentAssertion struct{ decodedAssertion }

// String returns the ES256 profile’s fixed redacted rendering.
func (ES256ContentAssertionFacts) String() string {
	return "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts<redacted>"
}

// GoString uses the same redacted rendering for Go-syntax formatting.
func (f ES256ContentAssertionFacts) GoString() string { return f.String() }

// Format uses the redacted rendering for every formatting verb.
func (f ES256ContentAssertionFacts) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte(f.String()))
}

// String returns the ES256 profile’s fixed redacted rendering.
func (ES256DecodedContentAssertion) String() string {
	return "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.DecodedContentAssertion<redacted>"
}

// GoString uses the same redacted rendering for Go-syntax formatting.
func (d ES256DecodedContentAssertion) GoString() string { return d.String() }

// Format uses the redacted rendering for every formatting verb.
func (d ES256DecodedContentAssertion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte(d.String()))
}

// ContentDigest hashes nonempty bounded content in the shared assertion domain.
func (ContentAssertionES256) ContentDigest(content []byte, bounds *Bounds) ([32]byte, error) {
	return ContentDigest(content, bounds)
}

// AssertionSigningInput returns the canonical signing input tagged for this profile.
func (ContentAssertionES256) AssertionSigningInput(a ContentAssertion, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	return contentAssertionES256.signingInput(a, bounds)
}

// AssembleCompact frames a supplied raw low-S signature with canonical signing bytes.
func (ContentAssertionES256) AssembleCompact(si SigningInput, signature []byte, bounds *Bounds) (compact string, err error) {
	defer closedResult(&err)
	return contentAssertionES256.assembleCompact(si, signature, bounds)
}

// DecodeAssertion decodes canonical claims without signature verification.
func (ContentAssertionES256) DecodeAssertion(compact string, bounds *Bounds) (decoded ES256DecodedContentAssertion, err error) {
	defer closedResult(&err)
	value, err := contentAssertionES256.decode(compact, bounds)
	return ES256DecodedContentAssertion{value}, err
}

// AssertionDigest hashes exact, structurally valid compact bytes under this profile.
func (ContentAssertionES256) AssertionDigest(compact string, bounds *Bounds) (digest [32]byte, err error) {
	defer closedResult(&err)
	return contentAssertionES256.digest(compact, bounds)
}

// VerifyAssertion checks the signature, time and exact caller-trusted context.
func (ContentAssertionES256) VerifyAssertion(compact string, expected ExpectedContentAssertion) (facts ES256ContentAssertionFacts, err error) {
	defer closedResult(&err)
	value, err := contentAssertionES256.verify(compact, expected)
	return ES256ContentAssertionFacts{value}, err
}

// VerifySuccessor checks consecutive verified ES256 generations and their exact digest link.
func (ContentAssertionES256) VerifySuccessor(predecessor, successor ES256ContentAssertionFacts, bounds *Bounds) (err error) {
	defer closedResult(&err)
	return contentAssertionES256.verifySuccessor(predecessor.assertionFacts, successor.assertionFacts, bounds)
}
