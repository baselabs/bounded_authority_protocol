package verifier

import "fmt"

// Verified facts (spec/bap-v1.md § Public verification contract). Facts
// are value-bearing and redacted: they contain only their exact documented
// fields, no raw credentials, signatures, JWK containers, nonces, request
// argument values, or selector values. They carry no JSON or generic
// encoder and are not credentials (REQ1-VERIFY-facts-redacted,
// REQ1-VERIFY-facts-not-credentials). String, GoString, and Format always
// emit the fixed #Type<redacted> rendering, including flags and precision.

// Authorization is the fixed non-authorizing marker on GrantFacts,
// EnvelopeFacts, and AnchoredExportFacts. Only NotEvaluated exists.
type Authorization int

const (
	AuthorizationNotEvaluated Authorization = iota
)

// Trust is the fixed not-a-trust-decision marker on the diagnostic chain,
// anchor, transition, and export facts. Only NotEvaluated exists.
type Trust int

const (
	TrustNotEvaluated Trust = iota
)

// GrantFacts is the standalone raw-grant verification result.
type GrantFacts struct {
	Version              int
	Issuer               string
	GrantID              string
	IssuerKeyFingerprint [32]byte
	HolderThumbprint     [32]byte
	MatchedAudience      string
	IssuedAt             int64
	NotBefore            int64
	ExpiresAt            int64
	Authorization        Authorization
}

// EnvelopeFacts is the combined grant+proof verification result.
type EnvelopeFacts struct {
	Version              int
	Issuer               string
	GrantID              string
	IssuerKeyFingerprint [32]byte
	HolderThumbprint     [32]byte
	MatchedAudience      string
	IssuedAt             int64
	NotBefore            int64
	ExpiresAt            int64
	ProofID              string
	InvocationID         string
	Operation            string
	TargetURI            string
	GrantHash            [32]byte
	RequestHash          [32]byte
	ProofIssuedAt        int64
	Authorization        Authorization
}

// ChainFacts is the consumption-chain range verification result: bounded
// identifiers, times, counts, hashes, and performed-verification labels only
// (REQ1-CHAIN-facts-shape).
type ChainFacts struct {
	ChainID       string
	FirstSequence int64
	LastSequence  int64
	RowCount      int64
	LastHash      [32]byte
	Checks        []string
	Trust         Trust
}

// AnchorFacts is the historical boundary-anchor verification result.
type AnchorFacts struct {
	AnchorID   string
	ChainID    string
	KeyID      string
	Sequence   int64
	AnchoredAt int64
	Trust      Trust
}

// KeyTransitionFacts is the historical key-transition verification result.
type KeyTransitionFacts struct {
	TransitionID    string
	ChainID         string
	EffectiveAt     int64
	FromFingerprint [32]byte
	ToFingerprint   [32]byte
	ToKeyID         string
	Trust           Trust
}

// AnchoredExportFacts is the complete archive verification result. It states
// the performed cryptographic checks and never carries rows, commitments,
// compacts, archive bytes, or the object-store version.
type AnchoredExportFacts struct {
	ChainID         string
	FirstSequence   int64
	LastSequence    int64
	RowCount        int64
	TransitionCount int
	ChunkCount      int
	ByteCount       int64
	Digest          [32]byte
	Checks          []string
	Trust           Trust
	Authorization   Authorization
}

// KeyLocator is the untrusted-key-locator result: a closed kid hint with
// trust not evaluated (REQ1-LOCATOR-not-authority).
type KeyLocator struct {
	KeyID string
	Trust Trust
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (GrantFacts) String() string { return "#GrantFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (GrantFacts) GoString() string { return "#GrantFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (GrantFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#GrantFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (EnvelopeFacts) String() string { return "#EnvelopeFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (EnvelopeFacts) GoString() string { return "#EnvelopeFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (EnvelopeFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#EnvelopeFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (ChainFacts) String() string { return "#ChainFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (ChainFacts) GoString() string { return "#ChainFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (ChainFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#ChainFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (AnchorFacts) String() string { return "#AnchorFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (AnchorFacts) GoString() string { return "#AnchorFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (AnchorFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#AnchorFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (KeyTransitionFacts) String() string { return "#KeyTransitionFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (KeyTransitionFacts) GoString() string { return "#KeyTransitionFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (KeyTransitionFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#KeyTransitionFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (AnchoredExportFacts) String() string { return "#AnchoredExportFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (AnchoredExportFacts) GoString() string { return "#AnchoredExportFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (AnchoredExportFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#AnchoredExportFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (AttestationFacts) String() string { return "#AttestationFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (AttestationFacts) GoString() string { return "#AttestationFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (AttestationFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#AttestationFacts<redacted>"))
}

// String returns the fixed redacted rendering (REQ1-VERIFY-facts-redacted).
func (ContentAssertionFacts) String() string { return "#ContentAssertionFacts<redacted>" }

// GoString returns the same fixed rendering for Go syntax formatting.
func (ContentAssertionFacts) GoString() string { return "#ContentAssertionFacts<redacted>" }

// Format keeps every formatting verb, flag, width, and precision value-free.
func (ContentAssertionFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("#ContentAssertionFacts<redacted>"))
}
