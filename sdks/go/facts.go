package verifier

import "fmt"

// Verified facts (spec/bap-v1.md § Public verification contract). Facts
// are value-bearing and redacted: they contain only their exact documented
// fields, no raw credentials, signatures, JWK containers, nonces, request
// argument values, or selector values. They carry no JSON or generic
// encoder and are not credentials (REQ1-VERIFY-facts-redacted,
// REQ1-VERIFY-facts-not-credentials). String, GoString, and Format always
// emit the exact full Elixir module rendering, including flags and precision.
// JSON, text, and gob encoders return ErrInvalid without field values.

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
	Version       int
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
	Version    int
	AnchorID   string
	ChainID    string
	KeyID      string
	Sequence   int64
	AnchoredAt int64
	Trust      Trust
}

// KeyTransitionFacts is the historical key-transition verification result.
type KeyTransitionFacts struct {
	Version         int
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
	Version         int
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

// String returns the exact fixed rendering for the verified profile.
func (facts GrantFacts) String() string {
	switch facts.Version {
	case 2:
		return "#BoundedAuthorityProtocol.V2.GrantFacts<redacted>"
	case 3:
		return "#BoundedAuthorityProtocol.V3.GrantFacts<redacted>"
	default:
		return "#BoundedAuthorityProtocol.V1.GrantFacts<redacted>"
	}
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts GrantFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts GrantFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (GrantFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (GrantFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (GrantFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts EnvelopeFacts) String() string {
	switch facts.Version {
	case 2:
		return "#BoundedAuthorityProtocol.V2.EnvelopeFacts<redacted>"
	case 3:
		return "#BoundedAuthorityProtocol.V3.EnvelopeFacts<redacted>"
	default:
		return "#BoundedAuthorityProtocol.V1.EnvelopeFacts<redacted>"
	}
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts EnvelopeFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts EnvelopeFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (EnvelopeFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (EnvelopeFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (EnvelopeFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts ChainFacts) String() string {
	switch facts.Version {
	case 2:
		return "#BoundedAuthorityProtocol.V2.ChainFacts<redacted>"
	case 3:
		return "#BoundedAuthorityProtocol.V3.ChainFacts<redacted>"
	default:
		return "#BoundedAuthorityProtocol.V1.ChainFacts<redacted>"
	}
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts ChainFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts ChainFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (ChainFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (ChainFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (ChainFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts AnchorFacts) String() string {
	switch facts.Version {
	case 2:
		return "#BoundedAuthorityProtocol.V2.AnchorFacts<redacted>"
	case 3:
		return "#BoundedAuthorityProtocol.V3.AnchorFacts<redacted>"
	default:
		return "#BoundedAuthorityProtocol.V1.AnchorFacts<redacted>"
	}
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts AnchorFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts AnchorFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (AnchorFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (AnchorFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (AnchorFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts KeyTransitionFacts) String() string {
	switch facts.Version {
	case 2:
		return "#BoundedAuthorityProtocol.V2.KeyTransitionFacts<redacted>"
	case 3:
		return "#BoundedAuthorityProtocol.V3.KeyTransitionFacts<redacted>"
	default:
		return "#BoundedAuthorityProtocol.V1.KeyTransitionFacts<redacted>"
	}
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts KeyTransitionFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts KeyTransitionFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (KeyTransitionFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (KeyTransitionFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (KeyTransitionFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts AnchoredExportFacts) String() string {
	switch facts.Version {
	case 2:
		return "#BoundedAuthorityProtocol.V2.AnchoredExportFacts<redacted>"
	case 3:
		return "#BoundedAuthorityProtocol.V3.AnchoredExportFacts<redacted>"
	default:
		return "#BoundedAuthorityProtocol.V1.AnchoredExportFacts<redacted>"
	}
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts AnchoredExportFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts AnchoredExportFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (AnchoredExportFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (AnchoredExportFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (AnchoredExportFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts AttestationFacts) String() string {
	return "#BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts<redacted>"
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts AttestationFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts AttestationFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (AttestationFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (AttestationFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (AttestationFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// String returns the exact fixed rendering for the verified profile.
func (facts ContentAssertionFacts) String() string {
	return "#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts<redacted>"
}

// GoString returns the fixed rendering for Go syntax formatting.
func (facts ContentAssertionFacts) GoString() string { return facts.String() }

// Format refuses field rendering for every verb, flag, width, and precision.
func (facts ContentAssertionFacts) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(facts.String()))
}

// MarshalJSON refuses generic serialization of verified facts.
func (ContentAssertionFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic serialization of verified facts.
func (ContentAssertionFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic serialization of verified facts.
func (ContentAssertionFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }
