package verifier

// Caller-supplied context structs (spec/bap-v1.md § Public verification
// contract). Every public entry revalidates every field
// (REQ1-VERIFY-revalidate); structs are exact — no extra members exist.

// Kind names the four current-v1 signing kinds.
type Kind string

const (
	KindGrant          Kind = "grant"
	KindProof          Kind = "proof"
	KindBoundaryAnchor Kind = "boundary_anchor"
	KindKeyTransition  Kind = "key_transition"
)

// SigningInput is a canonical JWS signing-input pair: the exact canonical
// JSON bytes of the protected header and payload. The JWS signing input is
// ASCII(BASE64URL(protected) || '.' || BASE64URL(payload)) — no domain
// prefix, no extra bytes (REQ1-SIGNING-exact-input, ADR 0003).
type SigningInput struct {
	Kind      Kind
	Protected []byte
	Payload   []byte
}

// OperationDef is one grant operation: a printable-ASCII name and its ordered
// selector list (closed selector values).
type OperationDef struct {
	Name      string
	Selectors []Value
}

// Grant is the producer-side grant structure for GrantSigningInput.
type Grant struct {
	KeyID            string
	Issuer           string
	GrantID          string
	Audiences        []string
	IssuedAt         int64
	NotBefore        int64
	ExpiresAt        int64
	HolderThumbprint string // cnf.jkt (unpadded base64url SHA-256)
	Operations       []OperationDef
}

// Proof is the producer-side holder-proof structure for ProofSigningInput.
// GrantCompact feeds the ath binding; HolderPublicKey is the raw 32-byte key.
type Proof struct {
	ProofID         string
	HolderPublicKey []byte
	InvocationID    string
	Operation       string
	Method          string
	TargetURI       string
	IssuedAt        int64
	GrantCompact    string
	CastArguments   Value
	HasNonce        bool
	Nonce           string
}

// BoundaryAnchor is the producer-side anchor structure.
type BoundaryAnchor struct {
	AnchorID   string
	ChainID    string
	KeyID      string
	AnchoredAt int64
	Sequence   int64
	ChainHash  string // unpadded base64url SHA-256 (all-zero for genesis)
	PublicKey  []byte // raw 32 bytes; fingerprinted per REQ1-HEADER-issuer-fingerprint
}

// KeyTransition is the producer-side transition structure.
type KeyTransition struct {
	TransitionID     string
	ChainID          string
	CurrentKeyID     string
	NextKeyID        string
	EffectiveAt      int64
	CurrentPublicKey []byte
	NextPublicKey    []byte
}

// ConsumptionEntry is one canonical consumption row input (ADR 0004).
type ConsumptionEntry struct {
	ChainID      string
	Commitment   string
	PreviousHash string
	Sequence     int64
}

// ChainInput carries raw canonical row bytes (REQ1-CHAIN-raw-rows-bounds).
type ChainInput struct {
	Rows [][]byte
}

// HistoricalPublicKey is one exact caller-trusted historical key with its
// validity window. ValidBeforeUnbounded is the only open upper interval
// (ADR 0004).
type HistoricalPublicKey struct {
	KeyID                string
	PublicKey            []byte
	ValidFrom            int64
	ValidBefore          int64
	ValidBeforeUnbounded bool
}

// HistoricalKeyChain is the ordered positional rollover path.
type HistoricalKeyChain []HistoricalPublicKey

// ExpectedChain is the mandatory caller boundary for a consumption range.
type ExpectedChain struct {
	ChainID       string
	FirstSequence int64
	LastSequence  int64
	PreviousHash  string // caller predecessor (all-zero for a genesis range)
	LastHash      string // caller head
	RowCount      int64
	Bounds        *Bounds
}

// ExpectedAnchor is the exact expected signed anchor tuple.
type ExpectedAnchor struct {
	AnchorID       string
	ChainID        string
	KeyID          string
	Sequence       int64
	AnchoredAt     int64
	ChainHash      string
	KeyFingerprint string // unpadded base64url SHA-256
	Bounds         *Bounds
}

// ExpectedKeyTransition is the exact expected signed transition tuple.
type ExpectedKeyTransition struct {
	TransitionID          string
	ChainID               string
	CurrentKeyID          string
	NextKeyID             string
	EffectiveAt           int64
	CurrentKeyFingerprint string
	NextKeyFingerprint    string
	Bounds                *Bounds
}

// ExpectedAnchoredExport is the complete expected chain/anchor/transition/
// digest/object-version context (REQ1-EXPORT-input-shape). A present nested
// Bounds must equal the outer resolved bounds; absent nested bounds are valid
// only under an effectively-untightened outer (ADR 0018 D2 identity
// semantics).
type ExpectedAnchoredExport struct {
	Chain         ExpectedChain
	StartAnchor   ExpectedAnchor
	EndAnchor     ExpectedAnchor
	Transitions   []ExpectedKeyTransition
	Digest        string // expected archive digest (unpadded base64url SHA-256)
	ObjectVersion string
	Bounds        *Bounds
}

// AnchoredExportInput is the producer-side archive composition (ADR 0004):
// canonical rows plus the start/end anchor compacts and ordered transition
// compacts.
type AnchoredExportInput struct {
	Rows        [][]byte
	StartAnchor string
	EndAnchor   string
	Transitions []string
}

// ArchivedObject is the verify-side raw archive: bounded nonempty proper flat
// chunks (chunk zero is the 20-byte magic) plus the out-of-band object-store
// version, which is exact expected context (REQ1-EXPORT-version-exact).
type ArchivedObject struct {
	Chunks  [][]byte
	Version string
}

// TrustedIssuer contains the exact key ID and raw 32-byte public key.
type TrustedIssuer struct {
	KeyID     string
	PublicKey []byte
}

// ExpectedGrant contains issuer, audience, integral evaluation time,
// nonnegative skew, and tightening bounds.
type ExpectedGrant struct {
	Issuer         string
	Audience       string
	EvaluationTime int64
	ClockSkew      int64
	Bounds         *Bounds
}

// NonceMode is `:not_required | {:required, nonce}`
// (REQ1-VERIFY-nonce-mode). Construct only via NonceNotRequired /
// NonceRequired.
type NonceMode struct {
	required bool
	nonce    string
}

// NonceNotRequired: the proof MUST NOT carry a nonce.
func NonceNotRequired() NonceMode { return NonceMode{} }

// NonceRequired: the proof MUST carry exactly this nonce.
func NonceRequired(nonce string) NonceMode { return NonceMode{required: true, nonce: nonce} }

// ExpectedRequest is the complete combined-verification context: the
// ExpectedGrant fields plus method, normalized HTTPS target, invocation UUID,
// operation, tagged cast arguments, positive proof maximum age, and the nonce
// mode.
type ExpectedRequest struct {
	TrustedIssuer  TrustedIssuer
	Issuer         string
	Audience       string
	EvaluationTime int64
	ClockSkew      int64
	Method         string
	TargetURI      string
	InvocationID   string
	Operation      string
	CastArguments  Value
	ProofMaxAge    int64
	Nonce          NonceMode
	Bounds         *Bounds
}

// Credentials are the raw compact grant and proof bytes.
type Credentials struct {
	Grant string
	Proof string
}
