package verifier

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

var approvalP99 = flag.Bool("approval-p99", false, "run the approval verification p99 gate")

const (
	approvalWarmup   = 30
	approvalSamples  = 200
	approvalP99Limit = 5 * time.Millisecond
)

type approvalP99Case struct {
	wire    []byte
	compact string
	context ApprovalContext
}

func TestApprovalP99(t *testing.T) {
	if !*approvalP99 {
		t.Skip("pass -approval-p99 to run the performance gate")
	}
	t.Logf("runner=%s/%s go=%s warmup=%d samples=%d quantile=nearest-rank-p99 ceiling_ms=%g",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), approvalWarmup, approvalSamples, approvalP99Limit.Seconds()*1e3)
	for _, selected := range []ApprovalSuite{ApprovalSuiteEdDSA, ApprovalSuiteES256} {
		for _, mode := range []string{"500x64", "encoded-cap"} {
			t.Run(string(selected)+"/"+mode, func(t *testing.T) {
				suite := contentAssertionEdDSA
				if selected == ApprovalSuiteES256 {
					suite = contentAssertionES256
				}
				measureApprovalP99(t, selected, suite, mode == "encoded-cap")
			})
		}
	}
}

func measureApprovalP99(t *testing.T, selected ApprovalSuite, suite contentAssertionSuite, atCap bool) {
	t.Helper()
	cases := make([]approvalP99Case, approvalWarmup+approvalSamples)
	sizeMin, sizeMax := ApprovalRecordBoundsMaximum().RecordBytes, 0
	for i := range cases {
		cases[i] = buildApprovalP99Case(t, selected, i, atCap)
		sizeMin = min(sizeMin, len(cases[i].wire))
		sizeMax = max(sizeMax, len(cases[i].wire))
	}
	var calls, admissions, verification, predicates []time.Duration
	revokedKeys := map[[32]byte]bool{{}: true}
	observedEvents := map[[3]string]bool{{"image-index", "reviewer", "previous-event"}: true}
	for i, c := range cases {
		start := time.Now()
		policy, ok := prepareApproval(c.context)
		if !ok {
			t.Fatal("context preflight failed")
		}
		admissionStart := time.Now()
		entries, ok := admitApprovalSnapshot(c.context.Snapshot, selected, c.context.TrustDomain, policy.assertionBounds, policy.recordBounds)
		if !ok {
			t.Fatal("snapshot admission failed")
		}
		admission := time.Since(admissionStart)
		facts, entry, code := verifyAdmittedApproval(c.wire, c.compact, c.context, selected, suite, policy, entries)
		call := time.Since(start)
		if code != ApprovalNoDiagnostic {
			t.Fatal(code)
		}
		assertion := facts.Assertion()
		fingerprint := assertion.AttestorKeyFingerprint()
		if entry.Key.KeyID != assertion.AttestorKeyID() {
			t.Fatal("verified assertion chose a different entry")
		}
		identity := [3]string{facts.TrustDomain(), assertion.Iss(), assertion.Jti()}
		start = time.Now()
		revoked, replayed := revokedKeys[fingerprint], observedEvents[identity]
		predicate := time.Since(start)
		if revoked || replayed {
			t.Fatal("host predicate refused control")
		}
		if i >= approvalWarmup {
			calls = append(calls, call)
			admissions = append(admissions, admission)
			// Exclude admission from this same verification sample.
			verification = append(verification, call-admission)
			predicates = append(predicates, predicate)
		}
	}
	p99 := func(samples []time.Duration) time.Duration {
		slices.Sort(samples)
		return samples[(99*len(samples)+99)/100-1]
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	result := p99(verification)
	t.Logf("record_bytes_min=%d record_bytes_max=%d verification_p99_ms=%.3f call_with_admission_p99_ms=%.3f snapshot_admission_p99_ms=%.3f host_predicates_p99_ms=%.3f",
		sizeMin, sizeMax, ms(result), ms(p99(calls)), ms(p99(admissions)), ms(p99(predicates)))
	if result > approvalP99Limit {
		t.Fatal("approval verification exceeded the p99 ceiling")
	}
}

func buildApprovalP99Case(t *testing.T, selected ApprovalSuite, ordinal int, atCap bool) approvalP99Case {
	t.Helper()
	width := 64
	if atCap {
		width = 124
	}
	resources := make([]string, 500)
	for i := range resources {
		resources[i] = fmt.Sprintf("%04d/\"\\\n%s", i, strings.Repeat("x", width-8))
		if len(resources[i]) != width {
			t.Fatal("benchmark resource width mismatch")
		}
	}
	request := fmt.Sprintf("request-%d", ordinal)
	var revision [32]byte
	big.NewInt(int64(ordinal)).FillBytes(revision[:])
	encode := func() []byte {
		t.Helper()
		record := NewApprovalRecord("image-indexer", "index", request, "image-review", resources, revision)
		wire, err := EncodeApprovalRecord(record, nil, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := encode()
	if atCap {
		limit := ApprovalRecordBoundsMaximum().RecordBytes
		resources[len(resources)-1] += strings.Repeat("x", limit-len(wire))
		wire = encode()
		if len(wire) != limit {
			t.Fatal("benchmark record did not reach the encoded ceiling")
		}
	}
	digest, err := ContentDigest(wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	kid := fmt.Sprintf("key-%d", ordinal)
	claims := ContentAssertion{
		AttestorKeyID: kid, Jti: fmt.Sprintf("event-%d", ordinal), Iss: "reviewer", Aud: "image-host",
		Sub: request, Profile: ApprovalProfile, ProfileDigest: ApprovalProfileDigest(), ContentDigest: digest,
		Gen: 1, Iat: 10, Nbf: 10, Exp: 60,
	}
	public, compact := signApprovalP99Case(t, selected, claims)
	entry := ApprovalTrustEntry{
		Issuer: "reviewer", Roles: []string{"image-review"},
		Key: HistoricalPublicKey{KeyID: kid, PublicKey: public, ValidFrom: 0, ValidBefore: 60},
	}
	snapshot := ApprovalTrustSnapshot{
		Suite: selected, TrustDomain: "image-index", Provenance: "local configuration", AsOf: 15,
		Entries: []ApprovalTrustEntry{entry},
	}
	ctx := ApprovalContext{
		TrustDomain: "image-index", Audience: "image-host", RequestID: request, RevisionDigest: revision[:],
		Subject: "image-indexer", Action: "index", Resources: resources, Roles: []string{"image-review"},
		Now: 20, MaxStaleness: 5, MaxLifetime: 50, Snapshot: &snapshot,
	}
	return approvalP99Case{wire, compact, ctx}
}

func signApprovalP99Case(t *testing.T, suite ApprovalSuite, claims ContentAssertion) ([]byte, string) {
	t.Helper()
	if suite == ApprovalSuiteEdDSA {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		si, err := AssertionSigningInput(claims, nil)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := AssembleContentAssertionCompact(si, ed25519.Sign(key, signingInputMessage(si)), nil)
		if err != nil {
			t.Fatal(err)
		}
		return public, compact
	}
	es := ContentAssertionES256{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	si, err := es.AssertionSigningInput(claims, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(signingInputMessage(si))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	twin := new(big.Int).Sub(elliptic.P256().Params().N, s)
	if s.Cmp(twin) > 0 {
		s = twin
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	compact, err := es.AssembleCompact(si, signature[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return public, compact
}
