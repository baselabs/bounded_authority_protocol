package verifier

import (
	"fmt"
	"slices"
	"unicode/utf8"
)

// ApprovalProfile identifies the action approval record contract.
const ApprovalProfile = "bap-action-approval/1"

const approvalRecordScaffold = `{"action":,"approver_role":,"request_id":,"resources":[],"revision_digest":,"subject":,"v":1}`

// ApprovalProfileDigest returns the SHA-256 pin of the frozen profile descriptor.
func ApprovalProfileDigest() [32]byte {
	return [32]byte{
		0x7e, 0x44, 0xf7, 0x32, 0x17, 0xcd, 0x25, 0x03,
		0x78, 0x39, 0xec, 0xc2, 0x58, 0x37, 0xde, 0x84,
		0xaa, 0xd3, 0x67, 0x36, 0x26, 0xb9, 0xb1, 0x25,
		0xc9, 0x4c, 0x97, 0xe9, 0x96, 0x7f, 0xa1, 0xeb,
	}
}

// ApprovalRecordBounds contains the positive, independently tightenable record ceilings.
type ApprovalRecordBounds struct {
	StringBytes   int
	ResourceCount int
	RecordBytes   int
}

// ApprovalRecordBoundsMaximum returns the profile's largest supported ceilings.
func ApprovalRecordBoundsMaximum() ApprovalRecordBounds {
	return ApprovalRecordBounds{StringBytes: 1024, ResourceCount: 4096, RecordBytes: 65536}
}

func approvalRecordLimits(ca Bounds, limits *ApprovalRecordBounds) (ApprovalRecordBounds, error) {
	maximum := ApprovalRecordBoundsMaximum()
	b := maximum
	if limits != nil {
		b = *limits
	}
	if b.StringBytes < 1 || b.StringBytes > maximum.StringBytes ||
		b.ResourceCount < 1 || b.ResourceCount > maximum.ResourceCount ||
		b.RecordBytes < 1 || b.RecordBytes > maximum.RecordBytes {
		return ApprovalRecordBounds{}, ErrInvalid
	}
	b.RecordBytes = min(b.RecordBytes, ca.ContentBytes)
	return b, nil
}

// ApprovalRecord is the subject, action, request, revision and approver role for an exact resource set.
type ApprovalRecord struct {
	data func() *approvalRecordData
}

type approvalRecordData struct {
	subject, action, requestID, approverRole string
	resources                                []string
	revisionDigest                           [32]byte
}

// NewApprovalRecord copies authoring input for the bounded codec. Encoding validates
// the fields. An input resource count above the hard ceiling yields an invalid record.
func NewApprovalRecord(subject, action, requestID, approverRole string, resources []string, revisionDigest [32]byte) ApprovalRecord {
	if len(resources) > ApprovalRecordBoundsMaximum().ResourceCount {
		return ApprovalRecord{}
	}
	return makeApprovalRecord(subject, action, requestID, approverRole, slices.Clone(resources), revisionDigest)
}

func makeApprovalRecord(subject, action, requestID, approverRole string, resources []string, revisionDigest [32]byte) ApprovalRecord {
	return ApprovalRecord{data: privateValue(&approvalRecordData{subject, action, requestID, approverRole, resources, revisionDigest})}
}

// Subject returns the subject of the operation.
func (r ApprovalRecord) Subject() string { return r.fields().subject }

// Action returns the action named by the record.
func (r ApprovalRecord) Action() string { return r.fields().action }

// RequestID returns the host request identifier.
func (r ApprovalRecord) RequestID() string { return r.fields().requestID }

// ApproverRole returns the role named by the record.
func (r ApprovalRecord) ApproverRole() string { return r.fields().approverRole }

// Resources returns a copy of the record's resource names.
func (r ApprovalRecord) Resources() []string { return slices.Clone(r.fields().resources) }

// RevisionDigest returns the digest of the host request revision.
func (r ApprovalRecord) RevisionDigest() [32]byte { return r.fields().revisionDigest }

func (r ApprovalRecord) fields() approvalRecordData {
	if r.data == nil {
		return approvalRecordData{}
	}
	return *r.data()
}

// String returns the redacted record rendering.
func (ApprovalRecord) String() string {
	return "#BoundedAuthorityProtocol.ActionApproval.V1.Record<redacted>"
}

// GoString uses the same redacted rendering for Go-syntax formatting.
func (r ApprovalRecord) GoString() string { return r.String() }

// Format uses the redacted rendering for every formatting verb.
func (r ApprovalRecord) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(r.String())) }

// MarshalJSON refuses generic JSON serialization with ErrInvalid.
func (ApprovalRecord) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic text serialization with ErrInvalid.
func (ApprovalRecord) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic gob serialization with ErrInvalid.
func (ApprovalRecord) GobEncode() ([]byte, error) { return nil, ErrInvalid }

func validApprovalText(s string, maximum int) bool {
	return len(s) > 0 && len(s) <= maximum && utf8.ValidString(s)
}

// EncodeApprovalRecord returns canonical JCS bytes. Explicit canonicalization sorts
// and deduplicates the validated input resources without modifying the caller's slice.
func EncodeApprovalRecord(record ApprovalRecord, bounds *Bounds, recordBounds *ApprovalRecordBounds, canonicalize bool) ([]byte, error) {
	ca, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	limits, err := approvalRecordLimits(ca, recordBounds)
	if err != nil {
		return nil, ErrInvalid
	}
	r := record.fields()
	resources := r.resources
	if len(resources) < 1 || len(resources) > limits.ResourceCount ||
		!validContentAssertionIdentifier(r.requestID, ca) {
		return nil, ErrInvalid
	}
	for _, resource := range resources {
		if !validApprovalText(resource, limits.StringBytes) {
			return nil, ErrInvalid
		}
	}
	if canonicalize {
		resources = slices.Clone(resources)
		slices.Sort(resources)
		resources = slices.Compact(resources)
	}

	revision := Base64urlEncode(r.revisionDigest[:])
	size := len(approvalRecordScaffold) + len(resources) - 1 + approvalStringSize(revision)
	for _, value := range [...]string{r.action, r.approverRole, r.requestID, r.subject} {
		if !validApprovalText(value, limits.StringBytes) {
			return nil, ErrInvalid
		}
		size += approvalStringSize(value)
	}
	for i, resource := range resources {
		if i > 0 && resources[i-1] >= resource {
			return nil, ErrInvalid
		}
		size += approvalStringSize(resource)
		if size > limits.RecordBytes {
			return nil, ErrInvalid
		}
	}

	out := make([]byte, 0, size)
	write := func(prefix, value string) {
		out = append(out, prefix...)
		out = appendJcsString(out, value)
	}
	write(`{"action":`, r.action)
	write(`,"approver_role":`, r.approverRole)
	write(`,"request_id":`, r.requestID)
	out = append(out, `,"resources":[`...)
	for i, resource := range resources {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJcsString(out, resource)
	}
	write(`],"revision_digest":`, revision)
	write(`,"subject":`, r.subject)
	return append(out, `,"v":1}`...), nil
}

func approvalStringSize(s string) int {
	size := len(s) + 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case jcsShortEscape(c) != 0:
			size++
		case c < 0x20:
			size += 5
		}
	}
	return size
}

// DecodeApprovalRecord accepts exactly the canonical JCS approval record under
// the effective bounds. Nil bounds select their respective maxima.
func DecodeApprovalRecord(wire []byte, bounds *Bounds, recordBounds *ApprovalRecordBounds) (ApprovalRecord, error) {
	ca, err := resolveBounds(bounds)
	if err != nil {
		return ApprovalRecord{}, ErrInvalid
	}
	limits, err := approvalRecordLimits(ca, recordBounds)
	if err != nil {
		return ApprovalRecord{}, ErrInvalid
	}
	return decodeApprovalRecord(wire, ca, limits)
}

func decodeApprovalRecord(wire []byte, ca Bounds, limits ApprovalRecordBounds) (ApprovalRecord, error) {
	if len(wire) == 0 || len(wire) > limits.RecordBytes {
		return ApprovalRecord{}, ErrInvalid
	}

	// The fixed member order and canonical string tokens reproduce the record's
	// JCS spelling exactly. The grammar has its own bounds for resource arrays.
	d := jsonDecoder{data: wire}
	action, err := readApprovalString(&d, `{"action":`, limits.StringBytes)
	if err != nil {
		return ApprovalRecord{}, ErrInvalid
	}
	role, err := readApprovalString(&d, `,"approver_role":`, limits.StringBytes)
	if err != nil {
		return ApprovalRecord{}, ErrInvalid
	}
	request, err := readApprovalString(&d, `,"request_id":`, min(limits.StringBytes, ca.IdentifierBytes))
	if err != nil || !validContentAssertionIdentifier(request, ca) {
		return ApprovalRecord{}, ErrInvalid
	}
	resource, err := readApprovalString(&d, `,"resources":[`, limits.StringBytes)
	if err != nil {
		return ApprovalRecord{}, ErrInvalid
	}
	resources := []string{resource}
	for d.pos < len(wire) && wire[d.pos] == ',' {
		if len(resources) == limits.ResourceCount {
			return ApprovalRecord{}, ErrInvalid
		}
		next, err := readApprovalString(&d, ",", limits.StringBytes)
		if err != nil || next <= resource {
			return ApprovalRecord{}, ErrInvalid
		}
		resources = append(resources, next)
		resource = next
	}
	digestText, err := readApprovalString(&d, `],"revision_digest":`, 43)
	digest, valid := canonicalDigestString(digestText)
	if err != nil || !valid {
		return ApprovalRecord{}, ErrInvalid
	}
	subject, err := readApprovalString(&d, `,"subject":`, limits.StringBytes)
	if err != nil || d.literal(`,"v":1}`) != nil || d.pos != len(wire) {
		return ApprovalRecord{}, ErrInvalid
	}
	return makeApprovalRecord(subject, action, request, role, resources, digest), nil
}

func readApprovalString(d *jsonDecoder, prefix string, maximum int) (string, error) {
	if d.literal(prefix) != nil || d.pos == len(d.data) || d.data[d.pos] != '"' {
		return "", ErrInvalid
	}
	start := d.pos + 1
	for i := start; i < len(d.data) && i-start <= maximum; i++ {
		switch c := d.data[i]; {
		case c == '"':
			raw := d.data[start:i]
			if len(raw) == 0 || !utf8.Valid(raw) {
				return "", ErrInvalid
			}
			d.pos = i + 1
			return string(raw), nil
		case c == '\\':
			// One decoded byte takes at most six encoded bytes. The isolated
			// decoder cannot scan into an unbounded or unterminated token.
			token := jsonDecoder{data: d.data[d.pos:min(len(d.data), d.pos+6*maximum+2)],
				b: Bounds{StringBytes: maximum}}
			var decoded [128]byte
			value, err := token.parseStringInto(false, decoded[:0])
			if err != nil || len(value) == 0 {
				return "", ErrInvalid
			}
			var encoded [256]byte
			canonical := appendJcsString(encoded[:0], value)
			if string(canonical) != string(token.data[:token.pos]) {
				return "", ErrInvalid
			}
			d.pos += token.pos
			return value, nil
		case c < 0x20:
			return "", ErrInvalid
		}
	}
	return "", ErrInvalid
}
