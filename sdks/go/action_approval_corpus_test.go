package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/baselabs/bounded_authority_protocol_go/internal/corpuscheck"
)

const approvalCorpus = "content-profiles/action-approval/v1"

func TestCandidateActionApprovalCorpus(t *testing.T) {
	root := candidateSource(t, approvalCorpus)
	corpuscheck.Candidate(t, root, "5384b8680fb6757360696c6889c5d6b3b706e8728edccae6dd0c5c468a819a64", candidateApprovalOutcome)
}

func TestApprovalProfileDigest(t *testing.T) {
	candidateSource(t, approvalCorpus)
	descriptor, err := os.ReadFile(filepath.Join(*candidateSourceRoot, "spec", "profiles", "bap-action-approval-v1.descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(append([]byte(ApprovalProfile+"\x00"), descriptor...))
	if want := ApprovalProfileDigest(); got != want {
		t.Fatalf("profile digest mismatch: got %s", hex.EncodeToString(got[:]))
	}
}

type candidateTrustEntry struct {
	Issuer string       `json:"issuer"`
	Key    candidateKey `json:"key"`
	Roles  []string     `json:"roles"`
}

func candidateSnapshot(raw any) *ApprovalTrustSnapshot {
	if raw == nil {
		return nil
	}
	snapshot, err := candidateRead[struct {
		Suite       ApprovalSuite         `json:"suite"`
		TrustDomain string                `json:"trust_domain"`
		Provenance  string                `json:"provenance"`
		AsOf        *int64                `json:"as_of"`
		Entries     []candidateTrustEntry `json:"entries"`
	}](raw)
	if err != nil || snapshot.AsOf == nil || snapshot.Entries == nil {
		return nil
	}
	result := &ApprovalTrustSnapshot{
		Suite: snapshot.Suite, TrustDomain: snapshot.TrustDomain, Provenance: snapshot.Provenance, AsOf: *snapshot.AsOf,
	}
	for _, e := range snapshot.Entries {
		result.Entries = append(result.Entries, ApprovalTrustEntry{e.Issuer, e.Key.historicalKey(), e.Roles})
	}
	return result
}

func candidateRecordBounds(raw any) *ApprovalRecordBounds {
	fields, err := candidateRead[map[string]int](raw)
	if err != nil {
		return &ApprovalRecordBounds{}
	}
	b := ApprovalRecordBoundsMaximum()
	for k, v := range fields {
		switch k {
		case "string_bytes":
			b.StringBytes = v
		case "resource_count":
			b.ResourceCount = v
		case "record_bytes":
			b.RecordBytes = v
		default:
			return &ApprovalRecordBounds{}
		}
	}
	return &b
}

type candidateApprovalRecord struct {
	Subject      string   `json:"subject"`
	Action       string   `json:"action"`
	RequestID    string   `json:"request_id"`
	ApproverRole string   `json:"approver_role"`
	Resources    []string `json:"resources"`
	Revision     string   `json:"revision_digest"`
}

func candidateApprovalContext(raw any) ApprovalContext {
	m := raw.(map[string]any)
	input, err := candidateRead[struct {
		candidateApprovalRecord
		TrustDomain  string   `json:"trust_domain"`
		Audience     string   `json:"audience"`
		Roles        []string `json:"roles"`
		Now          *int64   `json:"now"`
		MaxStaleness *int64   `json:"max_staleness"`
		MaxLifetime  *int64   `json:"max_lifetime"`
		MaxActive    *int64   `json:"max_active"`
	}](raw)
	if err != nil || input.Now == nil || input.MaxStaleness == nil || input.MaxLifetime == nil {
		return ApprovalContext{}
	}
	b, err := candidateBounds(m["bounds"])
	if err != nil {
		return ApprovalContext{}
	}
	return ApprovalContext{
		TrustDomain: input.TrustDomain, Audience: input.Audience, RequestID: input.RequestID,
		RevisionDigest: candidateBytes(input.Revision), Subject: input.Subject, Action: input.Action,
		Resources: input.Resources, Roles: input.Roles, Now: *input.Now, MaxStaleness: *input.MaxStaleness,
		MaxLifetime: *input.MaxLifetime, MaxActive: input.MaxActive, Bounds: &b,
		RecordBounds: candidateRecordBounds(m["record_bounds"]), Snapshot: candidateSnapshot(m["snapshot"]),
	}
}

func candidateApprovalInputs(c map[string]any) (wire []byte, compact string, suite ApprovalSuite, ctx ApprovalContext) {
	return candidateBytes(c["record"].(string)), c["compact"].(string), ApprovalSuite(c["suite"].(string)),
		candidateApprovalContext(c["context"])
}

func candidatePure(c map[string]any) (VerifiedApprovalFacts, ApprovalDiagnostic) {
	wire, compact, suite, ctx := candidateApprovalInputs(c)
	switch suite {
	case ApprovalSuiteEdDSA:
		return VerifyApprovalEdDSA(wire, compact, ctx)
	case ApprovalSuiteES256:
		return VerifyApprovalES256(wire, compact, ctx)
	}
	panic("unknown corpus suite")
}

func candidateApprovalValues(f VerifiedApprovalFacts) map[string]any {
	r := f.Record()
	out := map[string]any{
		"suite": string(f.Suite()), "trust_domain": f.TrustDomain(), "assertion": candidateVerifiedValues(f.Assertion()),
		"record": map[string]any{
			"v": 1, "subject": r.Subject(), "action": r.Action(), "request_id": r.RequestID(), "approver_role": r.ApproverRole(),
			"resources": r.Resources(), "revision_digest": candidateEncoded(r.RevisionDigest()),
		},
	}
	if f.Trust() == TrustNotEvaluated {
		out["trust"] = "not_evaluated"
	}
	return out
}

func candidateTrustValues(entry ApprovalTrustEntry) map[string]any {
	var before any = entry.Key.ValidBefore
	if entry.Key.ValidBeforeUnbounded {
		before = "unbounded"
	}
	return map[string]any{
		"issuer": entry.Issuer, "roles": entry.Roles,
		"key": map[string]any{
			"key_id": entry.Key.KeyID, "public_key": Base64urlEncode(entry.Key.PublicKey),
			"valid_from": entry.Key.ValidFrom, "valid_before": before,
		},
	}
}

func candidateObservation(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		if v == "exception" {
			panic("test predicate failure")
		}
		// The typed predicate represents cancellation and unavailable or malformed observations as errors.
		return false, errors.New(v)
	}
	panic("unexpected predicate call")
}

func candidateApprovalOutcome(t *testing.T, entry corpuscheck.Case, _ map[string]any, byID map[string]any) any {
	c := entry.Value
	switch entry.File {
	case "approval-cases.json", "multi-fault-cases.json":
		facts, code := candidatePure(c)
		if code == ApprovalNoDiagnostic {
			return candidateApprovalValues(facts)
		}
		return code.Code()
	case "record-cases.json":
		b, err := candidateBounds(c["ca_bounds"])
		if err != nil {
			return "invalid"
		}
		limits := candidateRecordBounds(c["bounds"])
		var record ApprovalRecord
		if wire, ok := c["wire"]; ok {
			record, err = DecodeApprovalRecord(candidateBytes(wire.(string)), &b, limits)
			if err != nil {
				return "invalid"
			}
		} else {
			a := candidateRequire[candidateApprovalRecord](t, c["author"])
			revision := candidateBytes(a.Revision)
			if len(revision) != 32 {
				return "invalid"
			}
			record = NewApprovalRecord(a.Subject, a.Action, a.RequestID, a.ApproverRole, a.Resources, [32]byte(revision))
		}
		encoded, err := EncodeApprovalRecord(record, &b, limits, c["canonicalize"].(bool))
		if err != nil {
			return "invalid"
		}
		digest, err := ContentDigest(encoded, &b)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"wire": Base64urlEncode(encoded), "content_digest": candidateEncoded(digest)}
	case "helper-cases.json":
		wire, compact, suite, ctx := candidateApprovalInputs(byID[c["pure_case"].(string)].(map[string]any))
		observations := c["observations"].(map[string]any)
		calls := []any{}
		isRevoked := func(entry ApprovalTrustEntry, fingerprint [32]byte) (bool, error) {
			calls = append(calls, map[string]any{"predicate": "is_revoked", "arguments": []any{
				candidateTrustValues(entry), candidateEncoded(fingerprint),
			}})
			return candidateObservation(observations["is_revoked"])
		}
		isReplayed := func(domain, issuer, jti string) (bool, error) {
			calls = append(calls, map[string]any{"predicate": "is_replayed", "arguments": []any{domain, issuer, jti}})
			return candidateObservation(observations["is_replayed"])
		}
		result := CheckApproval(wire, compact, suite, ctx, isReplayed, isRevoked)
		presenter := result.PresenterResult()
		helper := presenter
		if code := result.Diagnostic(); code != ApprovalNoDiagnostic {
			helper = code.Code()
		}
		return map[string]any{"calls": calls, "helper": helper, "presenter": presenter, "rendering": result.RenderPresenterResult()}
	case "rendering-cases.json":
		pure := byID[c["pure_case"].(string)].(map[string]any)
		return candidateApprovalRendering(t, c, pure)
	}
	t.Fatal("unknown candidate approval case file")
	return nil
}

func candidateApprovalRendering(t *testing.T, c, pure map[string]any) any {
	var out, inspected any
	facts, code := candidatePure(pure)
	switch c["id"].(string) {
	case "host-local-error":
		inspected, out = code, RenderApprovalVerification(facts, code)
	case "presenter-error":
		wire, compact, suite, ctx := candidateApprovalInputs(pure)
		result := CheckApproval(wire, compact, suite, ctx, nil, nil)
		inspected, out = result, result.RenderPresenterResult()
	case "verified-facts":
		inspected, out = facts, RenderApprovalVerification(facts, code)
	case "nested-record":
		inspected, out = facts.Record(), facts.Record().String()
	case "nested-assertion":
		inspected, out = facts.Assertion(), facts.Assertion().String()
	case "helper-exception":
		wire, compact, suite, ctx := candidateApprovalInputs(pure)
		inputs := c["inputs"].(map[string]any)
		replayCalls := 0
		result := CheckApproval(wire, compact, suite, ctx, func(string, string, string) (bool, error) {
			replayCalls++
			return false, nil
		}, func(ApprovalTrustEntry, [32]byte) (bool, error) {
			panic([]any{inputs["chained_context"], inputs["provider_cause"], inputs["traceback"]})
		})
		if replayCalls != 0 {
			t.Fatal("replay ran after revocation predicate failed")
		}
		inspected = result
		out = map[string]any{"local": result.String(), "presenter": result.RenderPresenterResult()}
	default:
		t.Fatal("unknown candidate rendering case")
	}
	if keys, ok := c["forbidden"].(map[string]any); ok {
		var logs strings.Builder
		fmt.Fprintf(&logs, "%v %+v %#v %s %+v", inspected, inspected, inspected, inspected, out)
		for _, variants := range keys {
			spellings := candidateRequire[[]string](t, variants)
			if slices.ContainsFunc(spellings, func(s string) bool { return strings.Contains(logs.String(), s) }) {
				t.Fatal("approval diagnostic revealed a protected value")
			}
		}
	}
	return out
}
