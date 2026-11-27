package verifier

import (
	"crypto/subtle"
	"fmt"
	"slices"
)

// ApprovalSuite identifies the content assertion suite selected by the relying party.
type ApprovalSuite string

const (
	ApprovalSuiteEdDSA ApprovalSuite = "eddsa"
	ApprovalSuiteES256 ApprovalSuite = "es256"
)

// ApprovalDiagnostic is a closed, value-free code for host-local use.
type ApprovalDiagnostic uint8

const (
	ApprovalNoDiagnostic ApprovalDiagnostic = iota
	ApprovalInvalidContext
	ApprovalTrustUnavailable
	ApprovalStaleTrust
	ApprovalMalformed
	ApprovalUnsupportedAlgorithm
	ApprovalUnknownKey
	ApprovalBadSignature
	ApprovalKeyWindow
	ApprovalRecordMismatch
	ApprovalIssuerMismatch
	ApprovalAudienceMismatch
	ApprovalRequestMismatch
	ApprovalSubjectMismatch
	ApprovalScopeMismatch
	ApprovalNotYetValid
	ApprovalExpired
	ApprovalLifetimeTooLong
	ApprovalActiveTooLong
	ApprovalRoleNotPermitted
	ApprovalRevokedKey
	ApprovalReplayed
	ApprovalPredicateFailed
)

var approvalDiagnosticCodes = [...]string{
	ApprovalInvalidContext:       "invalid_context",
	ApprovalTrustUnavailable:     "trust_unavailable",
	ApprovalStaleTrust:           "stale_trust",
	ApprovalMalformed:            "malformed",
	ApprovalUnsupportedAlgorithm: "unsupported_algorithm",
	ApprovalUnknownKey:           "unknown_key",
	ApprovalBadSignature:         "bad_signature",
	ApprovalKeyWindow:            "key_window",
	ApprovalRecordMismatch:       "record_mismatch",
	ApprovalIssuerMismatch:       "issuer_mismatch",
	ApprovalAudienceMismatch:     "audience_mismatch",
	ApprovalRequestMismatch:      "request_mismatch",
	ApprovalSubjectMismatch:      "subject_mismatch",
	ApprovalScopeMismatch:        "scope_mismatch",
	ApprovalNotYetValid:          "not_yet_valid",
	ApprovalExpired:              "expired",
	ApprovalLifetimeTooLong:      "lifetime_too_long",
	ApprovalActiveTooLong:        "active_too_long",
	ApprovalRoleNotPermitted:     "role_not_permitted",
	ApprovalRevokedKey:           "revoked_key",
	ApprovalReplayed:             "replayed",
	ApprovalPredicateFailed:      "predicate_failed",
}

// Code returns the stable reason code, or the empty string for success.
func (d ApprovalDiagnostic) Code() string {
	if int(d) >= len(approvalDiagnosticCodes) {
		return "invalid"
	}
	return approvalDiagnosticCodes[d]
}

// String renders the diagnostic for host-local logs.
func (d ApprovalDiagnostic) String() string {
	if d == ApprovalNoDiagnostic {
		return ":ok"
	}
	return "{:error, :" + d.Code() + "}"
}

// GoString renders the diagnostic for host-local Go-syntax formatting.
func (d ApprovalDiagnostic) GoString() string { return d.String() }

// ApprovalTrustEntry is a host-enrolled issuer, public key window and current approver roles.
type ApprovalTrustEntry struct {
	Issuer string
	Key    HistoricalPublicKey
	Roles  []string
}

// ApprovalTrustSnapshot is the caller-supplied trust metadata and entries for one domain and suite.
type ApprovalTrustSnapshot struct {
	Suite       ApprovalSuite
	TrustDomain string
	Provenance  string
	AsOf        int64
	Entries     []ApprovalTrustEntry
}

// ApprovalContext is the expected operation, time, policy and trust input.
// Borrowed values must stay stable throughout the call. Nil bounds select their respective maxima.
type ApprovalContext struct {
	TrustDomain    string
	Audience       string
	RequestID      string
	RevisionDigest []byte
	Subject        string
	Action         string
	Resources      []string
	Roles          []string
	Now            int64
	MaxStaleness   int64
	MaxLifetime    int64
	MaxActive      *int64
	Bounds         *Bounds
	RecordBounds   *ApprovalRecordBounds
	Snapshot       *ApprovalTrustSnapshot
}

// VerifiedApprovalFacts is redacted evidence bound to the supplied operation and trust context.
type VerifiedApprovalFacts struct {
	data func() *verifiedApprovalData
}

type verifiedApprovalData struct {
	suite       ApprovalSuite
	trustDomain string
	record      ApprovalRecord
	assertion   ContentAssertionFacts
}

func (f VerifiedApprovalFacts) fields() verifiedApprovalData {
	if f.data == nil {
		return verifiedApprovalData{}
	}
	return *f.data()
}

// Suite returns the suite selected for verification.
func (f VerifiedApprovalFacts) Suite() ApprovalSuite { return f.fields().suite }

// TrustDomain returns the host-supplied domain.
func (f VerifiedApprovalFacts) TrustDomain() string { return f.fields().trustDomain }

// Record returns the canonical record bound to the assertion.
func (f VerifiedApprovalFacts) Record() ApprovalRecord { return f.fields().record }

// Assertion returns the verified content assertion fields for inspection.
// Use AssertionEdDSA or AssertionES256 to obtain suite-specific successor inputs.
func (f VerifiedApprovalFacts) Assertion() ContentAssertionFacts { return f.fields().assertion }

// AssertionEdDSA returns the EdDSA facts for VerifyContentAssertionSuccessor.
// It returns zero facts and false for any other suite or a zero approval.
func (f VerifiedApprovalFacts) AssertionEdDSA() (ContentAssertionFacts, bool) {
	assertion := f.Assertion()
	if assertion.kind != KindContentAssertion {
		return ContentAssertionFacts{}, false
	}
	return assertion, true
}

// AssertionES256 returns the ES256 facts for ContentAssertionES256.VerifySuccessor.
// It returns zero facts and false for any other suite or a zero approval.
func (f VerifiedApprovalFacts) AssertionES256() (ES256ContentAssertionFacts, bool) {
	assertion := f.Assertion()
	if assertion.kind != KindContentAssertionES256 {
		return ES256ContentAssertionFacts{}, false
	}
	return ES256ContentAssertionFacts{assertion}, true
}

// Trust returns the static marker for the verifier trust boundary.
func (VerifiedApprovalFacts) Trust() Trust { return TrustNotEvaluated }

// String returns the redacted approval facts rendering.
func (VerifiedApprovalFacts) String() string {
	return "#BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts<redacted>"
}

// GoString uses the same redacted rendering for Go-syntax formatting.
func (f VerifiedApprovalFacts) GoString() string { return f.String() }

// Format uses the redacted rendering for every formatting verb.
func (f VerifiedApprovalFacts) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(f.String())) }

// MarshalJSON refuses generic JSON serialization with ErrInvalid.
func (VerifiedApprovalFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic text serialization with ErrInvalid.
func (VerifiedApprovalFacts) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic gob serialization with ErrInvalid.
func (VerifiedApprovalFacts) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// VerifyApprovalEdDSA verifies approval under the caller-selected EdDSA suite.
// The returned diagnostic is for host-local use only.
func VerifyApprovalEdDSA(wire []byte, compact string, expected ApprovalContext) (VerifiedApprovalFacts, ApprovalDiagnostic) {
	facts, _, diagnostic := verifyApproval(wire, compact, expected, ApprovalSuiteEdDSA, contentAssertionEdDSA)
	return facts, diagnostic
}

// VerifyApprovalES256 verifies approval under the caller-selected ES256 suite.
// The returned diagnostic is for host-local use only.
func VerifyApprovalES256(wire []byte, compact string, expected ApprovalContext) (VerifiedApprovalFacts, ApprovalDiagnostic) {
	facts, _, diagnostic := verifyApproval(wire, compact, expected, ApprovalSuiteES256, contentAssertionES256)
	return facts, diagnostic
}

type approvalPolicy struct {
	assertionBounds Bounds
	recordBounds    ApprovalRecordBounds
	resources       []string
}

func prepareApproval(c ApprovalContext) (approvalPolicy, bool) {
	b, err := resolveBounds(c.Bounds)
	if err != nil {
		return approvalPolicy{}, false
	}
	limits, err := approvalRecordLimits(b, c.RecordBounds)
	if err != nil {
		return approvalPolicy{}, false
	}
	resources, ok := approvalExpectedResources(c, b, limits)
	if !ok {
		return approvalPolicy{}, false
	}
	return approvalPolicy{b, limits, resources}, true
}

func verifyApproval(wire []byte, compact string, c ApprovalContext, selected ApprovalSuite, suite contentAssertionSuite) (VerifiedApprovalFacts, ApprovalTrustEntry, ApprovalDiagnostic) {
	policy, ok := prepareApproval(c)
	if !ok {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalInvalidContext
	}
	entries, ok := admitApprovalSnapshot(c.Snapshot, selected, c.TrustDomain, policy.assertionBounds, policy.recordBounds)
	if !ok {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalTrustUnavailable
	}
	return verifyAdmittedApproval(wire, compact, c, selected, suite, policy, entries)
}

func verifyAdmittedApproval(wire []byte, compact string, c ApprovalContext, selected ApprovalSuite, suite contentAssertionSuite, policy approvalPolicy, entries map[string]admittedApprovalEntry) (VerifiedApprovalFacts, ApprovalTrustEntry, ApprovalDiagnostic) {
	b, limits := policy.assertionBounds, policy.recordBounds
	// The difference of two bounded NumericDates always fits in int64.
	if age := c.Now - c.Snapshot.AsOf; age < 0 || age > c.MaxStaleness {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalStaleTrust
	}
	parts, header, err := frameContentAssertion(compact, b)
	if err != nil {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalMalformed
	}
	if !suite.matches(header) {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalUnsupportedAlgorithm
	}
	claims, err := decodeContentAssertionPayload(parts, b)
	if err != nil || len(claims.Sub) > limits.StringBytes {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalMalformed
	}
	record, err := decodeApprovalRecord(wire, b, limits)
	if err != nil {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalMalformed
	}
	enrolled, ok := entries[header.kid]
	if !ok {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalUnknownKey
	}
	if suite.verifySignature(compact, parts, enrolled.entry.Key.PublicKey) != nil {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, ApprovalBadSignature
	}
	diagnostic := checkAuthenticatedApproval(wire, claims, record.data(), c, policy.resources, enrolled.entry)
	if diagnostic != ApprovalNoDiagnostic {
		return VerifiedApprovalFacts{}, ApprovalTrustEntry{}, diagnostic
	}
	assertion := suite.verifiedFacts(compact, header.kid, claims, enrolled.fingerprint)
	facts := VerifiedApprovalFacts{data: privateValue(&verifiedApprovalData{selected, c.TrustDomain, record, assertion})}
	return facts, enrolled.entry, ApprovalNoDiagnostic
}

func checkAuthenticatedApproval(wire []byte, a contentAssertionClaims, r *approvalRecordData, c ApprovalContext, resources []string, entry ApprovalTrustEntry) ApprovalDiagnostic {
	if !a.inKeyWindow(entry.Key) {
		return ApprovalKeyWindow
	}
	contentDigest := hashAssertionContent(wire) // the record already satisfied the effective content bound
	profileDigest := ApprovalProfileDigest()
	if a.Profile != ApprovalProfile ||
		subtle.ConstantTimeCompare(a.ProfileDigest[:], profileDigest[:]) != 1 ||
		subtle.ConstantTimeCompare(a.ContentDigest[:], contentDigest[:]) != 1 {
		return ApprovalRecordMismatch
	}
	switch {
	case a.Iss != entry.Issuer:
		return ApprovalIssuerMismatch
	case a.Aud != c.Audience:
		return ApprovalAudienceMismatch
	case r.requestID != c.RequestID || a.Sub != c.RequestID ||
		subtle.ConstantTimeCompare(r.revisionDigest[:], c.RevisionDigest) != 1:
		return ApprovalRequestMismatch
	case r.subject != c.Subject:
		return ApprovalSubjectMismatch
	case r.action != c.Action || !slices.Equal(r.resources, resources):
		return ApprovalScopeMismatch
	case c.Now < a.Nbf:
		return ApprovalNotYetValid
	case c.Now >= a.Exp:
		return ApprovalExpired
	case a.Exp-a.Iat > c.MaxLifetime:
		return ApprovalLifetimeTooLong
	case c.MaxActive != nil && a.Exp-a.Nbf > *c.MaxActive:
		return ApprovalActiveTooLong
	case !slices.Contains(c.Roles, r.approverRole) || !slices.Contains(entry.Roles, r.approverRole):
		return ApprovalRoleNotPermitted
	}
	return ApprovalNoDiagnostic
}

func approvalExpectedResources(c ApprovalContext, b Bounds, limits ApprovalRecordBounds) ([]string, bool) {
	if !validApprovalText(c.TrustDomain, b.IdentifierBytes) ||
		!validContentAssertionIdentifier(c.Audience, b) ||
		!validContentAssertionIdentifier(c.RequestID, b) || len(c.RequestID) > limits.StringBytes ||
		len(c.RevisionDigest) != 32 || !validApprovalText(c.Subject, limits.StringBytes) ||
		!validApprovalText(c.Action, limits.StringBytes) ||
		len(c.Resources) == 0 || len(c.Resources) > limits.ResourceCount ||
		len(c.Roles) == 0 || !validApprovalRoles(c.Roles, limits.StringBytes) ||
		!approvalTime(c.Now, b) || c.MaxStaleness < 0 || !approvalTime(c.MaxStaleness, b) ||
		c.MaxLifetime < 0 || !approvalTime(c.MaxLifetime, b) ||
		(c.MaxActive != nil && (*c.MaxActive < 0 || !approvalTime(*c.MaxActive, b))) {
		return nil, false
	}
	for _, resource := range c.Resources {
		if !validApprovalText(resource, limits.StringBytes) {
			return nil, false
		}
	}
	sorted := slices.Clone(c.Resources)
	slices.Sort(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] == sorted[i] {
			return nil, false
		}
	}
	return sorted, true
}

func approvalTime(value int64, b Bounds) bool {
	magnitude := int64(b.IntegerMagnitude)
	return -magnitude <= value && value <= magnitude
}

func validApprovalRoles(roles []string, maximum int) bool {
	seen := make(map[string]struct{})
	for _, role := range roles {
		if _, ok := seen[role]; ok || !validApprovalText(role, maximum) {
			return false
		}
		seen[role] = struct{}{}
	}
	return true
}

type admittedApprovalEntry struct {
	entry       ApprovalTrustEntry
	fingerprint [32]byte
}

func admitApprovalSnapshot(snapshot *ApprovalTrustSnapshot, selected ApprovalSuite, domain string, b Bounds, limits ApprovalRecordBounds) (map[string]admittedApprovalEntry, bool) {
	if snapshot == nil || snapshot.Suite != selected || snapshot.TrustDomain != domain ||
		!validApprovalText(snapshot.Provenance, b.IdentifierBytes) || !approvalTime(snapshot.AsOf, b) {
		return nil, false
	}
	entries := make(map[string]admittedApprovalEntry, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		key := entry.Key
		if _, ok := entries[key.KeyID]; ok || !validKid(key.KeyID, b.KidBytes) ||
			!validContentAssertionIdentifier(entry.Issuer, b) || !validApprovalRoles(entry.Roles, limits.StringBytes) ||
			!approvalTime(key.ValidFrom, b) ||
			(!key.ValidBeforeUnbounded && (!approvalTime(key.ValidBefore, b) || key.ValidBefore <= key.ValidFrom)) {
			return nil, false
		}
		fingerprint, ok := approvalKeyFingerprint(key.PublicKey, selected)
		if !ok {
			return nil, false
		}
		entries[key.KeyID] = admittedApprovalEntry{entry, fingerprint}
	}
	return entries, true
}

func approvalKeyFingerprint(key []byte, suite ApprovalSuite) ([32]byte, bool) {
	if suite == ApprovalSuiteES256 {
		if len(key) != es256PublicKeyBytes || key[0] != 0x04 ||
			!p256CoordinatesOnCurve(key[1:1+es256CoordinateBytes], key[1+es256CoordinateBytes:]) {
			return [32]byte{}, false
		}
		return contentAssertionES256.fingerprint(key), true
	}
	if !TorsionFree(key) {
		return [32]byte{}, false
	}
	return contentAssertionEdDSA.fingerprint(key), true
}

// RenderApprovalVerification renders a pure result for host-local inspection.
func RenderApprovalVerification(facts VerifiedApprovalFacts, diagnostic ApprovalDiagnostic) string {
	if diagnostic != ApprovalNoDiagnostic {
		return diagnostic.String()
	}
	if facts.data == nil {
		return ApprovalInvalidContext.String()
	}
	return "{:ok, " + facts.String() + "}"
}

// ApprovalRevocationCheck observes whether the enrolled entry or its fingerprint is revoked.
type ApprovalRevocationCheck func(ApprovalTrustEntry, [32]byte) (bool, error)

// ApprovalReplayCheck observes whether the artifact identity has been presented.
type ApprovalReplayCheck func(domain, issuer, artifactID string) (bool, error)

// ApprovalResult is the redacted outcome of pure verification and host observations.
type ApprovalResult struct {
	facts      VerifiedApprovalFacts
	diagnostic ApprovalDiagnostic
}

// Facts returns the verified facts and whether both host observations passed.
func (r ApprovalResult) Facts() (VerifiedApprovalFacts, bool) {
	return r.facts, r.facts.data != nil && r.diagnostic == ApprovalNoDiagnostic
}

// Diagnostic returns the host-local reason code.
func (r ApprovalResult) Diagnostic() ApprovalDiagnostic {
	if r.facts.data == nil && r.diagnostic == ApprovalNoDiagnostic {
		return ApprovalInvalidContext
	}
	return r.diagnostic
}

// PresenterResult returns the closed outcome suitable for the presenter.
func (r ApprovalResult) PresenterResult() string {
	if _, ok := r.Facts(); ok {
		return "approved"
	}
	return "invalid"
}

// RenderPresenterResult renders a disclosure-limited outcome for the presenter.
func (r ApprovalResult) RenderPresenterResult() string {
	if _, ok := r.Facts(); ok {
		return "#BoundedAuthorityProtocol.ActionApproval.V1.Approved<redacted>"
	}
	return "{:error, :invalid}"
}

// String renders the redacted success or the host-local diagnostic.
func (r ApprovalResult) String() string {
	if diagnostic := r.Diagnostic(); diagnostic != ApprovalNoDiagnostic {
		return diagnostic.String()
	}
	return r.RenderPresenterResult()
}

// GoString uses the same redacted rendering for Go-syntax formatting.
func (r ApprovalResult) GoString() string { return r.String() }

// Format uses the redacted rendering for every formatting verb.
func (r ApprovalResult) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(r.String())) }

// MarshalJSON refuses generic JSON serialization with ErrInvalid.
func (ApprovalResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// MarshalText refuses generic text serialization with ErrInvalid.
func (ApprovalResult) MarshalText() ([]byte, error) { return nil, ErrInvalid }

// GobEncode refuses generic gob serialization with ErrInvalid.
func (ApprovalResult) GobEncode() ([]byte, error) { return nil, ErrInvalid }

// CheckApproval verifies approval and calls the read-only revocation and replay predicates
// in that order. Callers still need to claim the operation atomically at execution.
func CheckApproval(wire []byte, compact string, selected ApprovalSuite, expected ApprovalContext, isReplayed ApprovalReplayCheck, isRevoked ApprovalRevocationCheck) ApprovalResult {
	var suite contentAssertionSuite
	switch selected {
	case ApprovalSuiteEdDSA:
		suite = contentAssertionEdDSA
	case ApprovalSuiteES256:
		suite = contentAssertionES256
	default:
		return ApprovalResult{diagnostic: ApprovalInvalidContext}
	}
	facts, entry, diagnostic := verifyApproval(wire, compact, expected, selected, suite)
	if diagnostic != ApprovalNoDiagnostic {
		return ApprovalResult{diagnostic: diagnostic}
	}

	assertion := facts.Assertion()
	revoked, ok := observeApprovalPredicate(func() (bool, error) {
		entry.Key.PublicKey = slices.Clone(entry.Key.PublicKey)
		entry.Roles = slices.Clone(entry.Roles)
		return isRevoked(entry, assertion.AttestorKeyFingerprint())
	})
	if !ok {
		return ApprovalResult{diagnostic: ApprovalPredicateFailed}
	}
	if revoked {
		return ApprovalResult{diagnostic: ApprovalRevokedKey}
	}
	replayed, ok := observeApprovalPredicate(func() (bool, error) {
		return isReplayed(facts.TrustDomain(), assertion.Iss(), assertion.Jti())
	})
	if !ok {
		return ApprovalResult{diagnostic: ApprovalPredicateFailed}
	}
	if replayed {
		return ApprovalResult{diagnostic: ApprovalReplayed}
	}
	return ApprovalResult{facts: facts}
}

func observeApprovalPredicate(observe func() (bool, error)) (observed, ok bool) {
	defer func() { _ = recover() }()
	reached, err := observe()
	return reached, err == nil
}
