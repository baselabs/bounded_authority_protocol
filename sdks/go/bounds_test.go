package verifier

import "testing"

// Bounds (spec § Hard maxima; REQ1-BOUNDS-tighten-only / -reject-list /
// -fixed-widths). Maxima data-verified against the corpus bounds/new exact_bound cases.
func TestBoundsMaximum(t *testing.T) {
	m := BoundsMaximum()
	checks := []struct {
		got  int
		want int
	}{
		{m.CompactBytes, 65536},
		{m.EncodedSegmentBytes, 32768},
		{m.DecodedSegmentBytes, 24576},
		{m.JSONBytes, 65536},
		{m.JCSBytes, 65536},
		{m.Depth, 32},
		{m.ObjectMembers, 64},
		{m.ArrayItems, 256},
		{m.TotalNodes, 4096},
		{m.StringBytes, 8192},
		{m.NumberLexemeBytes, 64},
		{m.IntegerMagnitude, 9007199254740991},
		{m.FloatMagnitude, 9007199254740991},
		{m.KidBytes, 128},
		{m.KeyBytes, 128},
		{m.URIBYtes, 8192},
		{m.IdentifierBytes, 512},
		{m.NonceBytes, 512},
		{m.MethodBytes, 32},
		{m.OperationBytes, 128},
		{m.Audiences, 64},
		{m.Operations, 64},
		{m.Selectors, 64},
		{m.PathSegments, 32},
		{m.OneOfValues, 256},
		{m.PublicKeyBytes, 32},
		{m.SignatureBytes, 64},
		{m.DigestBytes, 32},
		{m.ClockSkew, 60},
		{m.ProofMaxAge, 300},
		{m.ChainRowBytes, 4096},
		{m.ChainRows, 65536},
		{m.AnchorBytes, 8192},
		{m.ArchiveHeaderBytes, 8192},
		{m.KeyTransitions, 256},
		{m.ArchiveChunks, 65796},
		{m.ArchiveBytes, 270820384},
		{m.ObjectVersionBytes, 512},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Fatalf("BoundsMaximum field = %d, want %d", c.got, c.want)
		}
	}
	if err := validateBounds(&m); err != nil {
		t.Fatalf("maximum bounds must validate: %v", err)
	}
}

func TestBoundsNew(t *testing.T) {
	// valid: empty overrides = maximum
	b, err := BoundsNew(map[string]int{})
	if err != nil || b != BoundsMaximum() {
		t.Fatalf("empty overrides must produce the maximum: %v %v", b, err)
	}
	// valid: exact maximum (== max is not widening)
	if _, err := BoundsNew(map[string]int{"anchor_bytes": 8192}); err != nil {
		t.Fatalf("exact-maximum override must be valid: %v", err)
	}
	// valid: simultaneous tightenings (corpus bounds-new-valid-tightened)
	if _, err := BoundsNew(map[string]int{"compact_bytes": 1000, "string_bytes": 4096}); err != nil {
		t.Fatalf("simultaneous tightenings must be valid: %v", err)
	}
	b, err = BoundsNew(map[string]int{"string_bytes": 100})
	if err != nil || b.StringBytes != 100 || b.Depth != 32 {
		t.Fatalf("tightening resolution wrong: %+v %v", b, err)
	}
	// reject list: unknown, zero, negative, widening, fixed-width changes
	bad := []map[string]int{
		{"nonexistent": 1},                           // unknown
		{"string_bytes": 0},                          // zero
		{"string_bytes": -1},                         // negative
		{"string_bytes": 8193},                       // widening
		{"anchor_bytes": 8193},                       // maximum_plus_one (corpus class)
		{"archive_bytes": 270820385},                 // maximum_plus_one
		{"digest_bytes": 31},                         // fixed width
		{"digest_bytes": 33},                         // fixed width
		{"public_key_bytes": 31},                     // fixed width
		{"signature_bytes": 63},                      // fixed width
		{"signature_bytes": 65},                      // fixed width
		{"clock_skew": 61},                           // ceiling (REQ1-VERIFY-time-bounds)
		{"proof_max_age": 301},                       // ceiling
		{"compact_bytes": 100, "string_bytes": 8193}, // one bad among good
	}
	for _, o := range bad {
		if b, err := BoundsNew(o); err == nil {
			t.Fatalf("BoundsNew(%v) = %+v, want ErrInvalid", o, b)
		}
	}
	// A zero-value Bounds is NOT the maximum — only BoundsMaximum/BoundsNew
	// produce valid bounds; everything else fails closed at revalidation.
	var zero Bounds
	if err := validateBounds(&zero); err == nil {
		t.Fatal("zero-value Bounds must fail validation (fail-closed)")
	}
}
