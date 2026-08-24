package verifier

import "crypto/sha256"

// The consumption chain (ADR 0004): one row is the closed JCS object
// {"chain_id","commitment","previous","sequence","v"} and its raw hash is
// SHA-256("BAP1-CHAIN\0" || canonical_row_bytes). Sequence one requires the
// all-zero predecessor; verification accepts raw canonical row bytes plus
// mandatory caller boundaries (REQ1-CHAIN-raw-rows-bounds).

var chainDomainPrefix = []byte("BAP1-CHAIN\x00")

// ConsumedEntry is the EncodeConsumptionEntry result: the canonical row bytes
// and their domain hash. Producer results are not credentials and not
// accepted as stored objects.
type ConsumedEntry struct {
	Row  []byte
	Hash [32]byte
}

// EncodeConsumptionEntry produces the canonical row bytes and domain hash
// (ADR 0004). Sequence one requires the all-zero predecessor.
func EncodeConsumptionEntry(e ConsumptionEntry, bounds *Bounds) (out ConsumedEntry, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return ConsumedEntry{}, ErrInvalid
	}
	if !validStringOrURI(e.ChainID, b.IdentifierBytes) {
		return ConsumedEntry{}, ErrInvalid
	}
	if _, ok := canonicalDigestString(e.Commitment); !ok {
		return ConsumedEntry{}, ErrInvalid
	}
	if _, ok := canonicalDigestString(e.PreviousHash); !ok {
		return ConsumedEntry{}, ErrInvalid
	}
	if e.Sequence < 1 {
		return ConsumedEntry{}, ErrInvalid // sequence zero is invalid on rows
	}
	if e.Sequence == 1 && e.PreviousHash != allZeroHashB64 {
		return ConsumedEntry{}, ErrInvalid // genesis row binds the zero predecessor
	}
	row, err := JcsEncode(Obj{
		{Key: "chain_id", Val: Str(e.ChainID)},
		{Key: "commitment", Val: Str(e.Commitment)},
		{Key: "previous", Val: Str(e.PreviousHash)},
		{Key: "sequence", Val: Int(e.Sequence)},
		{Key: "v", Val: Int(1)},
	}, &b)
	if err != nil {
		return ConsumedEntry{}, ErrInvalid
	}
	if len(row) > b.ChainRowBytes {
		return ConsumedEntry{}, ErrInvalid
	}
	h := chainHash(row)
	return ConsumedEntry{Row: row, Hash: h}, nil
}

func chainHash(row []byte) [32]byte {
	hh := sha256.New()
	hh.Write(chainDomainPrefix)
	hh.Write(row)
	var out [32]byte
	copy(out[:], hh.Sum(nil))
	return out
}

// chainRowData is a parsed canonical row.
type chainRowData struct {
	ChainID    string
	Commitment [32]byte
	Previous   [32]byte
	Sequence   int64
}

// parseCanonicalRow requires exact canonical bytes (a re-encoded row must
// equal the received bytes byte-for-byte), the closed member set, and every
// field bound.
func parseCanonicalRow(raw []byte, b Bounds) (chainRowData, error) {
	var out chainRowData
	if len(raw) == 0 || len(raw) > b.ChainRowBytes {
		return out, ErrInvalid
	}
	v, err := JsonDecode(raw, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 5 {
		return out, ErrInvalid
	}
	commitment, previous := "", ""
	for _, m := range obj {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 1 {
				return out, ErrInvalid
			}
		case "chain_id":
			if s, ok := m.Val.(Str); ok {
				out.ChainID = string(s)
			}
		case "commitment":
			if s, ok := m.Val.(Str); ok {
				commitment = string(s)
			}
		case "previous":
			if s, ok := m.Val.(Str); ok {
				previous = string(s)
			}
		case "sequence":
			if t, ok := integralTime(m.Val, b); ok {
				out.Sequence = t
			} else {
				return out, ErrInvalid
			}
		default:
			return out, ErrInvalid
		}
	}
	if !validStringOrURI(out.ChainID, b.IdentifierBytes) {
		return out, ErrInvalid
	}
	c, ok := canonicalDigestString(commitment)
	if !ok {
		return out, ErrInvalid
	}
	out.Commitment = c
	p, ok := canonicalDigestString(previous)
	if !ok {
		return out, ErrInvalid
	}
	out.Previous = p
	// canonical re-encode equality: the received bytes must be the JCS form
	reenc, err := JcsEncode(obj, &b)
	if err != nil || string(reenc) != string(raw) {
		return out, ErrInvalid
	}
	return out, nil
}

// CheckChain verifies a consumption range: raw canonical rows against
// mandatory caller boundaries. Requires chain identity, consecutive
// sequence, predecessor links, row count, first/last sequence, caller
// predecessor, and caller head (ADR 0004).
func CheckChain(input ChainInput, expected ExpectedChain) (f ChainFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return ChainFacts{}, ErrInvalid
	}
	// caller-boundary validation before any row work
	if !validStringOrURI(expected.ChainID, b.IdentifierBytes) {
		return ChainFacts{}, ErrInvalid
	}
	if expected.FirstSequence < 1 || expected.LastSequence < expected.FirstSequence ||
		expected.RowCount < 1 || expected.RowCount > int64(b.ChainRows) {
		return ChainFacts{}, ErrInvalid
	}
	if expected.LastSequence-expected.FirstSequence+1 != expected.RowCount {
		return ChainFacts{}, ErrInvalid // range/count coherence
	}
	wantPrev, ok := canonicalDigestString(expected.PreviousHash)
	if !ok {
		return ChainFacts{}, ErrInvalid
	}
	wantHead, ok := canonicalDigestString(expected.LastHash)
	if !ok {
		return ChainFacts{}, ErrInvalid
	}
	if len(input.Rows) == 0 || int64(len(input.Rows)) > int64(b.ChainRows) {
		return ChainFacts{}, ErrInvalid
	}
	if int64(len(input.Rows)) != expected.RowCount {
		return ChainFacts{}, ErrInvalid
	}
	var lastHash [32]byte
	for i, raw := range input.Rows {
		row, err := parseCanonicalRow(raw, b)
		if err != nil {
			return ChainFacts{}, ErrInvalid
		}
		if row.ChainID != expected.ChainID {
			return ChainFacts{}, ErrInvalid
		}
		if row.Sequence != expected.FirstSequence+int64(i) {
			return ChainFacts{}, ErrInvalid // consecutive sequence
		}
		if i == 0 {
			if row.Sequence == 1 {
				// genesis row: predecessor must be all-zero AND match caller
				if row.Previous != [32]byte{} {
					return ChainFacts{}, ErrInvalid
				}
			}
			if row.Previous != wantPrev {
				return ChainFacts{}, ErrInvalid // caller predecessor binding
			}
		} else {
			if row.Previous != lastHash {
				return ChainFacts{}, ErrInvalid // predecessor link
			}
		}
		lastHash = chainHash(raw)
	}
	if lastHash != wantHead {
		return ChainFacts{}, ErrInvalid // caller head binding
	}
	return ChainFacts{
		ChainID:       expected.ChainID,
		FirstSequence: expected.FirstSequence,
		LastSequence:  expected.LastSequence,
		RowCount:      expected.RowCount,
		LastHash:      lastHash,
		Checks: []string{
			"canonical_rows", "chain_identity", "consecutive_sequence",
			"predecessor_links", "row_count", "caller_boundaries",
		},
		Trust: TrustNotEvaluated,
	}, nil
}
