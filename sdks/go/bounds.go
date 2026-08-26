package verifier

import "sort"

// Bounds carries the profile's caller-tightenable resource ceilings
// (spec/bap-v1.md § Hard maxima). Only two constructors produce a valid
// Bounds: BoundsMaximum (the immutable profile maxima) and BoundsNew (a
// tightening-only override map). A zero-value Bounds is invalid and fails
// closed at every boundary that revalidates it.
//
// The 32-byte public-key and digest widths and the 64-byte signature width
// are the immutable cryptographic constants of the suite BAP1-Ed25519-SHA256:
// they appear here so every bound-sensitive site resolves through one struct,
// but they cannot be tightened or widened (REQ1-BOUNDS-fixed-widths).
type Bounds struct {
	CompactBytes        int
	EncodedSegmentBytes int
	DecodedSegmentBytes int
	JSONBytes           int
	JCSBytes            int
	Depth               int
	ObjectMembers       int
	ArrayItems          int
	TotalNodes          int
	StringBytes         int
	NumberLexemeBytes   int
	IntegerMagnitude    int
	FloatMagnitude      int
	KidBytes            int
	KeyBytes            int
	URIBYtes            int
	IdentifierBytes     int
	NonceBytes          int
	MethodBytes         int
	OperationBytes      int
	Audiences           int
	Operations          int
	Selectors           int
	PathSegments        int
	OneOfValues         int
	PublicKeyBytes      int
	SignatureBytes      int
	DigestBytes         int
	ClockSkew           int
	ProofMaxAge         int
	ChainRowBytes       int
	ChainRows           int
	AnchorBytes         int
	ArchiveHeaderBytes  int
	KeyTransitions      int
	ArchiveChunks       int
	ArchiveBytes        int
	ObjectVersionBytes  int
}

// BoundsMaximum returns the immutable profile maxima.
func BoundsMaximum() Bounds {
	return Bounds{
		CompactBytes:        65536,
		EncodedSegmentBytes: 32768,
		DecodedSegmentBytes: 24576,
		JSONBytes:           65536,
		JCSBytes:            65536,
		Depth:               32,
		ObjectMembers:       64,
		ArrayItems:          256,
		TotalNodes:          4096,
		StringBytes:         8192,
		NumberLexemeBytes:   64,
		IntegerMagnitude:    9007199254740991,
		FloatMagnitude:      9007199254740991,
		KidBytes:            128,
		KeyBytes:            128,
		URIBYtes:            8192,
		IdentifierBytes:     512,
		NonceBytes:          512,
		MethodBytes:         32,
		OperationBytes:      128,
		Audiences:           64,
		Operations:          64,
		Selectors:           64,
		PathSegments:        32,
		OneOfValues:         256,
		PublicKeyBytes:      32,
		SignatureBytes:      64,
		DigestBytes:         32,
		ClockSkew:           60,
		ProofMaxAge:         300,
		ChainRowBytes:       4096,
		ChainRows:           65536,
		AnchorBytes:         8192,
		ArchiveHeaderBytes:  8192,
		KeyTransitions:      256,
		ArchiveChunks:       65796,
		ArchiveBytes:        270820384,
		ObjectVersionBytes:  512,
	}
}

// fixedWidthFields cannot be tightened or widened: their value must equal the
// profile maximum exactly (REQ1-BOUNDS-fixed-widths).
var fixedWidthFields = map[string]bool{
	"digest_bytes":     true,
	"public_key_bytes": true,
	"signature_bytes":  true,
}

// BoundsNew constructs tightening-only bounds from snake_case override keys.
// Unknown, non-positive, widening, or fixed-width-changing limits are invalid
// (REQ1-BOUNDS-reject-list); absent keys keep the profile maximum.
func BoundsNew(overrides map[string]int) (Bounds, error) {
	b := BoundsMaximum()
	names := make([]string, 0, len(overrides))
	for k := range overrides {
		names = append(names, k)
	}
	sort.Strings(names) // deterministic iteration for validation order
	for _, k := range names {
		v := overrides[k]
		if v <= 0 {
			return Bounds{}, ErrInvalid
		}
		cur, max, ok := boundsField(&b, k)
		if !ok {
			return Bounds{}, ErrInvalid // unknown key
		}
		if fixedWidthFields[k] && v != max {
			return Bounds{}, ErrInvalid // immutable widths: exact value only
		}
		if v > max {
			return Bounds{}, ErrInvalid // widening
		}
		*cur = v
	}
	if err := validateBounds(&b); err != nil {
		return Bounds{}, err
	}
	return b, nil
}

// boundsField resolves a snake_case bounds key to a live field pointer, its
// profile maximum, and presence.
func boundsField(b *Bounds, key string) (*int, int, bool) {
	max := BoundsMaximum()
	switch key {
	case "compact_bytes":
		return &b.CompactBytes, max.CompactBytes, true
	case "encoded_segment_bytes":
		return &b.EncodedSegmentBytes, max.EncodedSegmentBytes, true
	case "decoded_segment_bytes":
		return &b.DecodedSegmentBytes, max.DecodedSegmentBytes, true
	case "json_bytes":
		return &b.JSONBytes, max.JSONBytes, true
	case "jcs_bytes":
		return &b.JCSBytes, max.JCSBytes, true
	case "depth":
		return &b.Depth, max.Depth, true
	case "object_members":
		return &b.ObjectMembers, max.ObjectMembers, true
	case "array_items":
		return &b.ArrayItems, max.ArrayItems, true
	case "total_nodes":
		return &b.TotalNodes, max.TotalNodes, true
	case "string_bytes":
		return &b.StringBytes, max.StringBytes, true
	case "number_lexeme_bytes":
		return &b.NumberLexemeBytes, max.NumberLexemeBytes, true
	case "integer_magnitude":
		return &b.IntegerMagnitude, max.IntegerMagnitude, true
	case "float_magnitude":
		return &b.FloatMagnitude, max.FloatMagnitude, true
	case "kid_bytes":
		return &b.KidBytes, max.KidBytes, true
	case "key_bytes":
		return &b.KeyBytes, max.KeyBytes, true
	case "uri_bytes":
		return &b.URIBYtes, max.URIBYtes, true
	case "identifier_bytes":
		return &b.IdentifierBytes, max.IdentifierBytes, true
	case "nonce_bytes":
		return &b.NonceBytes, max.NonceBytes, true
	case "method_bytes":
		return &b.MethodBytes, max.MethodBytes, true
	case "operation_bytes":
		return &b.OperationBytes, max.OperationBytes, true
	case "audiences":
		return &b.Audiences, max.Audiences, true
	case "operations":
		return &b.Operations, max.Operations, true
	case "selectors":
		return &b.Selectors, max.Selectors, true
	case "path_segments":
		return &b.PathSegments, max.PathSegments, true
	case "one_of_values":
		return &b.OneOfValues, max.OneOfValues, true
	case "public_key_bytes":
		return &b.PublicKeyBytes, max.PublicKeyBytes, true
	case "signature_bytes":
		return &b.SignatureBytes, max.SignatureBytes, true
	case "digest_bytes":
		return &b.DigestBytes, max.DigestBytes, true
	case "clock_skew":
		return &b.ClockSkew, max.ClockSkew, true
	case "proof_max_age":
		return &b.ProofMaxAge, max.ProofMaxAge, true
	case "chain_row_bytes":
		return &b.ChainRowBytes, max.ChainRowBytes, true
	case "chain_rows":
		return &b.ChainRows, max.ChainRows, true
	case "anchor_bytes":
		return &b.AnchorBytes, max.AnchorBytes, true
	case "archive_header_bytes":
		return &b.ArchiveHeaderBytes, max.ArchiveHeaderBytes, true
	case "key_transitions":
		return &b.KeyTransitions, max.KeyTransitions, true
	case "archive_chunks":
		return &b.ArchiveChunks, max.ArchiveChunks, true
	case "archive_bytes":
		return &b.ArchiveBytes, max.ArchiveBytes, true
	case "object_version_bytes":
		return &b.ObjectVersionBytes, max.ObjectVersionBytes, true
	}
	return nil, 0, false
}

// validateBounds revalidates a resolved Bounds: every field strictly positive,
// none above the profile maximum, and the three fixed-width fields exactly at
// their immutable values. Every limits-taking public boundary calls it
// (REQ1-VERIFY-revalidate).
func validateBounds(b *Bounds) error {
	if b == nil {
		return ErrInvalid
	}
	max := BoundsMaximum()
	for _, key := range boundsKeys() {
		cur, maxV, ok := boundsField(b, key)
		if !ok || *cur <= 0 || *cur > maxV {
			return ErrInvalid
		}
	}
	if b.DigestBytes != max.DigestBytes || b.PublicKeyBytes != max.PublicKeyBytes || b.SignatureBytes != max.SignatureBytes {
		return ErrInvalid
	}
	return nil
}

// resolveBounds is the boundary normalization: nil means the profile maximum;
// a present value is revalidated before use.
func resolveBounds(b *Bounds) (Bounds, error) {
	if b == nil {
		return BoundsMaximum(), nil
	}
	if err := validateBounds(b); err != nil {
		return Bounds{}, err
	}
	return *b, nil
}

// boundsKeys returns every bounds key in a deterministic order.
func boundsKeys() []string {
	return []string{
		"compact_bytes", "encoded_segment_bytes", "decoded_segment_bytes",
		"json_bytes", "jcs_bytes", "depth", "object_members", "array_items",
		"total_nodes", "string_bytes", "number_lexeme_bytes",
		"integer_magnitude", "float_magnitude", "kid_bytes", "key_bytes",
		"uri_bytes", "identifier_bytes", "nonce_bytes", "method_bytes",
		"operation_bytes", "audiences", "operations", "selectors",
		"path_segments", "one_of_values", "public_key_bytes",
		"signature_bytes", "digest_bytes", "clock_skew", "proof_max_age",
		"chain_row_bytes", "chain_rows", "anchor_bytes",
		"archive_header_bytes", "key_transitions", "archive_chunks",
		"archive_bytes", "object_version_bytes",
	}
}
