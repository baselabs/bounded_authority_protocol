package verifier

// Verified facts (docs/protocol-v1.md § Public verification contract). Facts
// are value-bearing and redacted: they contain only their exact documented
// fields, no raw credentials, signatures, JWK containers, nonces, request
// argument values, or selector values. They carry no JSON, string, or generic
// encoder and are not credentials (REQ1-VERIFY-facts-redacted,
// REQ1-VERIFY-facts-not-credentials). Go cannot seal %+v formatting the way
// the Elixir seals Inspect; the redaction contract is the closed field set
// itself.

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
