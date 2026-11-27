package verifier

import "testing"

func TestApprovalPreflightAndSuitePrecedence(t *testing.T) {
	ctx := ApprovalContext{
		TrustDomain: "review", Audience: "host", RequestID: "r", RevisionDigest: make([]byte, 32),
		Subject: "s", Action: "read", Resources: []string{"file"}, Roles: []string{"reviewer"},
		Now: 20, MaxStaleness: 5, MaxLifetime: 30,
	}
	old := ApprovalTrustSnapshot{Suite: ApprovalSuiteES256, TrustDomain: "review", Provenance: "local", AsOf: 14}
	ctx.Snapshot = &old
	invalid := ctx
	invalid.Action = ""
	foreign := Base64urlEncode([]byte(`{"alg":"EdDSA","kid":"key","typ":"ba+content-assertion"}`)) +
		"." + Base64urlEncode([]byte(`{}`)) + "."
	for _, tc := range []struct {
		name    string
		ctx     ApprovalContext
		compact string
		want    ApprovalDiagnostic
	}{
		{"bad context before snapshot", invalid, "bad", ApprovalInvalidContext},
		{"stale before framing", ctx, "bad", ApprovalStaleTrust},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := VerifyApprovalES256(nil, tc.compact, tc.ctx); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	old.AsOf = 15
	if _, got := VerifyApprovalES256(nil, foreign+Base64urlEncode(make([]byte, 63)), ctx); got != ApprovalMalformed {
		t.Fatalf("width before suite: %v", got)
	}
	if _, got := VerifyApprovalES256(nil, foreign+Base64urlEncode(make([]byte, 64)), ctx); got != ApprovalUnsupportedAlgorithm {
		t.Fatalf("suite before claims, record and lookup: %v", got)
	}
}
