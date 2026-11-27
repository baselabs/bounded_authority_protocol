package verifier

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestApprovalRecordCanonicalGrammar(t *testing.T) {
	const valid = `{"action":"read","approver_role":"reviewer","request_id":"r","resources":["","𐀀"],"revision_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","subject":"s","v":1}`
	record, err := DecodeApprovalRecord([]byte(valid), nil, nil)
	if err != nil || len(record.Resources()) != 2 {
		t.Fatalf("canonical scalar order: %v", err)
	}
	ipvFuture := strings.Replace(valid, `"request_id":"r"`, `"request_id":"https://[v1.a]/"`, 1)
	if _, err := DecodeApprovalRecord([]byte(ipvFuture), nil, nil); err != ErrInvalid {
		t.Fatal("accepted an IPvFuture request identifier")
	}
	for name, wire := range map[string]string{
		"UTF-16 order":        strings.Replace(valid, `"","𐀀"`, `"𐀀",""`, 1),
		"duplicate item":      strings.Replace(valid, `"","𐀀"`, `"",""`, 1),
		"duplicate field":     strings.Replace(valid, `"action":`, `"action":"read","action":`, 1),
		"space":               valid + " ",
		"surrogate":           strings.Replace(valid, "", `\ud800`, 1),
		"overlong UTF-8":      strings.Replace(valid, "", "\xc0\xaf", 1),
		"unnecessary escape":  strings.Replace(valid, "", `\ue000`, 1),
		"float version":       strings.Replace(valid, `"v":1`, `"v":1.0`, 1),
		"long item":           strings.Replace(valid, "", strings.Repeat("x", 1025), 1),
		"long escaped item":   strings.Replace(valid, "", strings.Repeat(`\n`, 1025), 1),
		"invalid request URI": strings.Replace(valid, `"request_id":"r"`, `"request_id":"bad uri:x"`, 1),
		"noncanonical digest": strings.Replace(valid, `AAA","subject"`, `AAB","subject"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeApprovalRecord([]byte(wire), nil, nil); err != ErrInvalid {
				t.Fatal("accepted invalid approval record")
			}
		})
	}
	for _, change := range []ApprovalRecordBounds{
		{StringBytes: 7, ResourceCount: 2, RecordBytes: len(valid)},
		{StringBytes: 8, ResourceCount: 1, RecordBytes: len(valid)},
		{StringBytes: 8, ResourceCount: 2, RecordBytes: len(valid) - 1},
	} {
		if _, err := DecodeApprovalRecord([]byte(valid), nil, &change); err != ErrInvalid {
			t.Fatal("accepted a record outside its tightened ceiling")
		}
	}
	exact := ApprovalRecordBounds{StringBytes: 8, ResourceCount: 2, RecordBytes: len(valid)}
	got, err := EncodeApprovalRecord(record, nil, &exact, false)
	if err != nil || string(got) != valid {
		t.Fatalf("canonical bytes at exact limits: %v", err)
	}
	ca := BoundsMaximum()
	ca.ContentBytes = len(valid) - 1
	if _, err := DecodeApprovalRecord([]byte(valid), &ca, &exact); err != ErrInvalid {
		t.Fatal("record exceeded the assertion content byte limit")
	}
}

func TestApprovalRecordKeepsStoragePrivate(t *testing.T) {
	const canary = "value-to-redact-é"
	resources := []string{canary}
	record := NewApprovalRecord(canary, "read", "r", "reviewer", resources, [32]byte{})
	resources[0] = "changed by caller"
	record.Resources()[0] = "changed by accessor"
	if record.Resources()[0] != canary {
		t.Fatal("record resources are mutable by the caller")
	}
	wrapper := struct{ hidden ApprovalRecord }{record}
	for _, rendered := range []string{fmt.Sprintf("%q", record), fmt.Sprintf("%#v", &wrapper)} {
		if strings.Contains(rendered, canary) {
			t.Fatal("record rendering revealed a protected value")
		}
	}
	if _, err := json.Marshal(record); !errors.Is(err, ErrInvalid) {
		t.Fatal("record accepted JSON serialization")
	}
	if _, err := record.MarshalText(); err != ErrInvalid {
		t.Fatal("record accepted text serialization")
	}
	if err := gob.NewEncoder(new(bytes.Buffer)).Encode(record); err == nil {
		t.Fatal("record accepted gob serialization")
	}
}
