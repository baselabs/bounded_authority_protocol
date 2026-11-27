//! Candidate action-approval verifier with host-local diagnostics.
//!
//! The caller chooses the suite, supplies trust and binds the expected operation.
//! Presenter-facing results collapse all failures to the shared closed error.

use crate::approval_record::{
    decode_bounded, ApprovalRecord, RecordBounds, PROFILE, PROFILE_DIGEST,
};
use crate::content_assertion::{
    content_digest, equal_digest, fingerprint, parse, validate_magnitude, AssertionFacts, KeyRef,
    Stage,
};
use crate::facts::NotEvaluated;
use crate::role_attestation::validate_identifier;
use crate::types::ValidityUpperBound;
use crate::{ed25519, Bounds, Invalid, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The assertion suite selected by independent host configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// EdDSA content assertion.
    EdDsa,
    /// ES256 content assertion.
    Es256,
}

impl Suite {
    fn carrier<const ES256: bool>() -> Self {
        if ES256 {
            Self::Es256
        } else {
            Self::EdDsa
        }
    }
}

macro_rules! diagnostics {
    ($($(#[$doc:meta])* $variant:ident => $code:literal),+ $(,)?) => {
        /// Closed, value-free diagnostics for the host's local inspection.
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub enum Diagnostic {
            $($(#[$doc])* $variant),+
        }

        impl Diagnostic {
            /// Stable snake_case code for host-local logging.
            pub const fn code(self) -> &'static str {
                match self { $(Self::$variant => $code),+ }
            }
        }
    };
}

diagnostics! {
    /// Invalid expected operation, policy, or limits.
    InvalidContext => "invalid_context",
    /// Missing or invalid snapshot, metadata, or enrolled entry.
    TrustUnavailable => "trust_unavailable",
    /// Snapshot time is in the future or older than the age ceiling.
    StaleTrust => "stale_trust",
    /// Framing, canonical encoding, bounds or structure failed.
    Malformed => "malformed",
    /// A well-shaped artifact uses a different algorithm or type.
    UnsupportedAlgorithm => "unsupported_algorithm",
    /// The selected snapshot has no entry for the protected key ID.
    UnknownKey => "unknown_key",
    /// The exact JWS signing input failed strict signature verification.
    BadSignature => "bad_signature",
    /// The assertion falls outside the key's historical validity window.
    KeyWindow => "key_window",
    /// The signed content digest or profile identity does not bind the record.
    RecordMismatch => "record_mismatch",
    /// The signed issuer differs from the enrolled issuer.
    IssuerMismatch => "issuer_mismatch",
    /// The signed audience differs from the expected audience.
    AudienceMismatch => "audience_mismatch",
    /// The request ID or revision digest fails exact binding.
    RequestMismatch => "request_mismatch",
    /// The record subject differs from the expected subject.
    SubjectMismatch => "subject_mismatch",
    /// The action or resources differ from the expected scope.
    ScopeMismatch => "scope_mismatch",
    /// The current time precedes the assertion's active window.
    NotYetValid => "not_yet_valid",
    /// The current time is at or beyond the assertion's expiry.
    Expired => "expired",
    /// The issuance-to-expiry span exceeds the caller's ceiling.
    LifetimeTooLong => "lifetime_too_long",
    /// The active window exceeds the caller's ceiling.
    ActiveTooLong => "active_too_long",
    /// The expected role set or the enrolled role set lacks the signed role.
    RoleNotPermitted => "role_not_permitted",
    /// The host reports that the admitted key is revoked.
    RevokedKey => "revoked_key",
    /// The host reports that the assertion was already observed.
    Replayed => "replayed",
    /// A host predicate did not supply a boolean observation.
    PredicateFailed => "predicate_failed",
}

impl From<Stage> for Diagnostic {
    fn from(stage: Stage) -> Self {
        match stage {
            Stage::Malformed => Self::Malformed,
            Stage::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            Stage::BadSignature => Self::BadSignature,
            Stage::KeyWindow => Self::KeyWindow,
            Stage::NotYetValid => Self::NotYetValid,
            Stage::Expired => Self::Expired,
        }
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{:error, :{}}}", self.code())
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Public key and historical validity window in a suite-bound trust snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustKey {
    /// Exact protected key identifier.
    pub key_id: String,
    /// Raw Ed25519 or uncompressed SEC1 P-256 public key, as selected by the snapshot suite.
    pub public_key: Vec<u8>,
    /// Inclusive validity start.
    pub valid_from: i64,
    /// Upper key lifetime endpoint, with equality allowed for assertion expiry.
    pub valid_before: ValidityUpperBound,
}

impl<'a> From<&'a TrustKey> for KeyRef<'a> {
    fn from(key: &'a TrustKey) -> Self {
        Self {
            key_id: &key.key_id,
            public_key: &key.public_key,
            valid_from: key.valid_from,
            valid_before: &key.valid_before,
        }
    }
}

/// Enrolled issuer, one historical public key, and its current approver roles.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustEntry {
    /// Exact issuer identity independently enrolled for the key.
    pub issuer: String,
    /// Enrolled historical key.
    pub key: TrustKey,
    /// Current roles granted to this key. The set may be empty.
    pub roles: Vec<String>,
}

/// Caller-supplied snapshot from one independently configured suite and trust domain.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustSnapshot {
    /// The only suite whose keys this snapshot admits.
    pub suite: Suite,
    /// Independently configured domain.
    pub trust_domain: String,
    /// Independently supplied snapshot provenance.
    pub provenance: String,
    /// Snapshot time as an integral NumericDate.
    pub as_of: i64,
    /// Public entries, with unique key IDs.
    pub entries: Vec<TrustEntry>,
}

/// Expected operation, trust input, and policy ceilings for one verification call.
#[derive(Clone)]
pub struct ApprovalContext {
    /// Independently configured trust domain.
    pub trust_domain: String,
    /// Expected executing audience.
    pub audience: String,
    /// Expected request identity.
    pub request_id: String,
    /// Expected raw revision digest.
    pub revision_digest: [u8; 32],
    /// Expected subject of the operation.
    pub subject: String,
    /// Exact expected action.
    pub action: String,
    /// Expected resource set, in any order and without duplicates.
    pub resources: Vec<String>,
    /// Nonempty set of roles the operation accepts.
    pub roles: Vec<String>,
    /// Caller-supplied time as an integral NumericDate.
    pub now: i64,
    /// Inclusive snapshot age ceiling, in seconds.
    pub max_staleness: i64,
    /// Inclusive assertion lifetime ceiling, in seconds.
    pub max_lifetime: i64,
    /// Optional inclusive ceiling on the active window, in seconds.
    pub max_active: Option<i64>,
    /// Carrier bounds.
    pub bounds: Bounds,
    /// Record-only bounds.
    pub record_bounds: RecordBounds,
    /// Independently supplied trust snapshot, if available.
    pub snapshot: Option<TrustSnapshot>,
}

/// Verified assertion with the provenance of its selected carrier suite.
#[derive(Clone, PartialEq, Eq)]
pub enum VerifiedAssertion {
    /// Verified EdDSA assertion.
    EdDsa(AssertionFacts<false>),
    /// Verified ES256 assertion.
    Es256(AssertionFacts<true>),
}

impl fmt::Debug for VerifiedAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EdDsa(facts) => fmt::Debug::fmt(facts, f),
            Self::Es256(facts) => fmt::Debug::fmt(facts, f),
        }
    }
}

impl From<AssertionFacts<false>> for VerifiedAssertion {
    fn from(value: AssertionFacts<false>) -> Self {
        Self::EdDsa(value)
    }
}

impl From<AssertionFacts<true>> for VerifiedAssertion {
    fn from(value: AssertionFacts<true>) -> Self {
        Self::Es256(value)
    }
}

/// Facts checked against the explicit inputs to the pure verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedApprovalFacts {
    /// Host-selected suite.
    pub suite: Suite,
    /// Independently configured trust domain.
    pub trust_domain: String,
    /// Canonical operation and revision bound by the verified assertion.
    pub record: ApprovalRecord,
    /// Verified content assertion facts with suite provenance.
    pub assertion: VerifiedAssertion,
    /// Operational trust remains a host concern.
    pub trust: NotEvaluated,
}

impl fmt::Debug for VerifiedApprovalFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("#BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts<redacted>")
    }
}

impl fmt::Display for VerifiedApprovalFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Success of the pure verifier and the two read-only host observations.
#[derive(Clone, PartialEq, Eq)]
pub struct Approved {
    /// Verified approval facts.
    pub facts: VerifiedApprovalFacts,
}

impl fmt::Debug for Approved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("#BoundedAuthorityProtocol.ActionApproval.V1.Approved<redacted>")
    }
}

impl fmt::Display for Approved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Host helper outcome. The error is for host-local inspection only.
pub type ApprovalResult = std::result::Result<Approved, Diagnostic>;
type Check<T> = std::result::Result<T, Diagnostic>;

/// Verify the action approval using only the selected EdDSA snapshot.
pub fn verify_approval_eddsa(
    record: &[u8],
    compact: &[u8],
    context: &ApprovalContext,
) -> Check<VerifiedApprovalFacts> {
    pure::<false>(record, compact, context)
}

/// Verify the action approval using only the selected ES256 snapshot.
pub fn verify_approval_es256(
    record: &[u8],
    compact: &[u8],
    context: &ApprovalContext,
) -> Check<VerifiedApprovalFacts> {
    pure::<true>(record, compact, context)
}

fn pure<const ES256: bool>(
    record: &[u8],
    compact: &[u8],
    context: &ApprovalContext,
) -> Check<VerifiedApprovalFacts>
where
    VerifiedAssertion: From<AssertionFacts<ES256>>,
{
    verify_with_entry::<ES256>(
        record,
        compact,
        context.snapshot.as_ref(),
        context.now,
        context.max_lifetime,
        context,
    )
    .map(|(facts, _)| facts)
}

/// Verify the approval and observe the caller's local, read-only revocation and replay predicates.
///
/// The predicates return None when a boolean observation is unavailable. Revocation is
/// observed first. The caller owns any atomic claim required at execution. Predicate panics
/// that unwind collapse to a diagnostic. The host owns its process-wide panic hook and must
/// keep predicate panic payloads out of logs.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    grant: &[u8],
    proof: &[u8],
    trusted_keys: Option<&TrustSnapshot>,
    now: i64,
    max_validity: i64,
    is_replayed: impl FnOnce(&str, &str, &str) -> Option<bool>,
    is_revoked: impl FnOnce(&TrustEntry, &[u8; 32]) -> Option<bool>,
    suite: Suite,
    expected: &ApprovalContext,
) -> ApprovalResult {
    let (facts, entry) = match suite {
        Suite::EdDsa => {
            verify_with_entry::<false>(grant, proof, trusted_keys, now, max_validity, expected)
        }
        Suite::Es256 => {
            verify_with_entry::<true>(grant, proof, trusted_keys, now, max_validity, expected)
        }
    }?;
    let (fingerprint, issuer, id) = match &facts.assertion {
        VerifiedAssertion::EdDsa(f) => (&f.attestor_key_fingerprint, &f.iss, &f.jti),
        VerifiedAssertion::Es256(f) => (&f.attestor_key_fingerprint, &f.iss, &f.jti),
    };
    if observe(|| is_revoked(entry, fingerprint))? {
        return Err(Diagnostic::RevokedKey);
    }
    if observe(|| is_replayed(&facts.trust_domain, issuer, id))? {
        return Err(Diagnostic::Replayed);
    }
    Ok(Approved { facts })
}

fn observe(predicate: impl FnOnce() -> Option<bool>) -> Check<bool> {
    catch_unwind(AssertUnwindSafe(predicate))
        .ok()
        .flatten()
        .ok_or(Diagnostic::PredicateFailed)
}

/// Collapse a host helper result to the closed presenter-facing result.
pub fn presenter_result(result: &ApprovalResult) -> Result<()> {
    result.as_ref().map(|_| ()).map_err(|_| Invalid)
}

/// Render only the redacted success marker or a closed presenter-facing failure.
pub fn render_presenter_result(result: &ApprovalResult) -> String {
    match result {
        Ok(approved) => approved.to_string(),
        Err(_) => "{:error, :invalid}".into(),
    }
}

/// Render redacted facts or a value-free diagnostic for the host's local inspection.
pub fn render_verification_result(result: &Check<VerifiedApprovalFacts>) -> String {
    match result {
        Ok(facts) => format!("{{:ok, {facts}}}"),
        Err(diagnostic) => diagnostic.to_string(),
    }
}

fn verify_with_entry<'a, const ES256: bool>(
    wire: &[u8],
    compact: &[u8],
    snapshot: Option<&'a TrustSnapshot>,
    now: i64,
    max_lifetime: i64,
    context: &ApprovalContext,
) -> Check<(VerifiedApprovalFacts, &'a TrustEntry)>
where
    VerifiedAssertion: From<AssertionFacts<ES256>>,
{
    use Diagnostic::*;

    let ca = &context.bounds;
    let limits = context
        .record_bounds
        .effective(ca)
        .map_err(|_| InvalidContext)?;
    let resources = preflight(context, now, max_lifetime, &limits).map_err(|_| InvalidContext)?;
    let snapshot = snapshot.ok_or(TrustUnavailable)?;
    let entries = admit::<ES256>(snapshot, &context.trust_domain, ca, &limits)
        .map_err(|_| TrustUnavailable)?;
    require(
        (0..=context.max_staleness).contains(&(now - snapshot.as_of)),
        StaleTrust,
    )?;

    let parsed = parse::<ES256>(compact, ca)?;
    let claims = &parsed.claims;
    limits.request_id(&claims.sub, ca).map_err(|_| Malformed)?;
    let record = decode_bounded(wire, ca, &limits).map_err(|_| Malformed)?;
    let &(entry, fingerprint) = entries.get(parsed.key_id.as_str()).ok_or(UnknownKey)?;
    let key = KeyRef::from(&entry.key);
    parsed.verify_signature(key.public_key)?;
    claims.key_window(&key)?;

    let digest = content_digest(wire, ca).map_err(|_| RecordMismatch)?;
    require(
        claims.profile == PROFILE
            && equal_digest(&claims.profile_digest, &PROFILE_DIGEST)
            && equal_digest(&claims.content_digest, &digest),
        RecordMismatch,
    )?;
    require(claims.iss == entry.issuer, IssuerMismatch)?;
    require(claims.aud == context.audience, AudienceMismatch)?;
    require(
        record.request_id == context.request_id
            && claims.sub == context.request_id
            && equal_digest(&record.revision_digest, &context.revision_digest),
        RequestMismatch,
    )?;
    require(record.subject == context.subject, SubjectMismatch)?;
    require(
        record.action == context.action && record.resources == resources,
        ScopeMismatch,
    )?;
    claims.current_window(now)?;
    require(
        claims.expires_at - claims.issued_at <= max_lifetime,
        LifetimeTooLong,
    )?;
    require(
        context
            .max_active
            .is_none_or(|cap| claims.expires_at - claims.not_before <= cap),
        ActiveTooLong,
    )?;
    require(
        context.roles.contains(&record.approver_role)
            && entry.roles.contains(&record.approver_role),
        RoleNotPermitted,
    )?;

    let facts = VerifiedApprovalFacts {
        suite: Suite::carrier::<ES256>(),
        trust_domain: context.trust_domain.clone(),
        record,
        assertion: parsed.facts(compact, fingerprint).into(),
        trust: NotEvaluated,
    };
    Ok((facts, entry))
}

fn preflight<'a>(
    context: &'a ApprovalContext,
    now: i64,
    max_lifetime: i64,
    limits: &RecordBounds,
) -> Result<Vec<&'a str>> {
    let ca = &context.bounds;
    scalar_identity(&context.trust_domain, ca)?;
    validate_identifier(&context.audience, ca)?;
    limits.request_id(&context.request_id, ca)?;
    limits.text(&context.subject)?;
    limits.text(&context.action)?;
    let mut resources = limits.resources(&context.resources)?;
    resources.sort_unstable();
    if resources.windows(2).any(|pair| pair[0] == pair[1]) || context.roles.is_empty() {
        return Err(Invalid);
    }
    validate_roles(&context.roles, limits)?;
    validate_magnitude(now, ca)?;
    // Input magnitudes are at most 2^53-1, so differences are exact in i64.
    for cap in [
        Some(context.max_staleness),
        Some(max_lifetime),
        context.max_active,
    ]
    .into_iter()
    .flatten()
    {
        validate_magnitude(cap, ca)?;
        if cap < 0 {
            return Err(Invalid);
        }
    }
    Ok(resources)
}

type Entries<'a> = BTreeMap<&'a str, (&'a TrustEntry, [u8; 32])>;

fn admit<'a, const ES256: bool>(
    snapshot: &'a TrustSnapshot,
    domain: &str,
    ca: &Bounds,
    limits: &RecordBounds,
) -> Result<Entries<'a>> {
    if snapshot.suite != Suite::carrier::<ES256>() || snapshot.trust_domain != domain {
        return Err(Invalid);
    }
    scalar_identity(&snapshot.provenance, ca)?;
    validate_magnitude(snapshot.as_of, ca)?;

    let mut entries = BTreeMap::new();
    for entry in &snapshot.entries {
        let key = KeyRef::from(&entry.key);
        validate_identifier(&entry.issuer, ca)?;
        validate_roles(&entry.roles, limits)?;
        key.validate_window(ca)?;
        if !ES256 && !ed25519::torsion_free(key.public_key) {
            return Err(Invalid);
        }
        let fingerprint = fingerprint::<ES256>(key.public_key)?;
        if entries.insert(key.key_id, (entry, fingerprint)).is_some() {
            return Err(Invalid);
        }
    }
    Ok(entries)
}

fn scalar_identity(value: &str, ca: &Bounds) -> Result<()> {
    if value.is_empty() || value.len() > ca.identifier_bytes() as usize {
        return Err(Invalid);
    }
    Ok(())
}

fn validate_roles(roles: &[String], limits: &RecordBounds) -> Result<()> {
    let mut seen = BTreeSet::new();
    for role in roles {
        limits.text(role)?;
        if !seen.insert(role) {
            return Err(Invalid);
        }
    }
    Ok(())
}

fn require(condition: bool, diagnostic: Diagnostic) -> Check<()> {
    condition.then_some(()).ok_or(diagnostic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_record::encode_record;
    use crate::base64url_decode;
    use serde_json::Value;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    #[test]
    #[ignore = "performance gate; run in release mode"]
    fn approval_verification_p99() {
        let fixtures: Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/approval-benchmark.json"),
            )
            .unwrap(),
        )
        .unwrap();

        const WARMUP: usize = 30;
        const SAMPLES: usize = 200;
        const CEILING: Duration = Duration::from_millis(5);
        println!(
            "runner={}-{} warmup={WARMUP} samples={SAMPLES} quantile=nearest-rank-p99 ceiling_ms=5",
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
        let mut outcomes = Vec::new();
        for (label, at_cap) in [("500x64", false), ("encoded-cap", true)] {
            outcomes.push(measure::<false>(
                &fixtures, "eddsa", label, at_cap, WARMUP, SAMPLES,
            ));
            outcomes.push(measure::<true>(
                &fixtures, "es256", label, at_cap, WARMUP, SAMPLES,
            ));
        }
        assert!(
            outcomes.iter().all(|p99| *p99 <= CEILING),
            "approval verification exceeded its p99 ceiling"
        );
    }

    fn measure<const ES256: bool>(
        fixtures: &Value,
        suite_name: &str,
        label: &str,
        at_cap: bool,
        warmup: usize,
        samples: usize,
    ) -> Duration
    where
        VerifiedAssertion: From<AssertionFacts<ES256>>,
    {
        let fixture = &fixtures[format!("{suite_name}-{label}")];
        let compact = fixture["compact"].as_str().unwrap().as_bytes();
        let public_key =
            base64url_decode(fixture["public_key"].as_str().unwrap().as_bytes()).unwrap();
        let ca = Bounds::maximum();
        let limits = RecordBounds::default();
        let mut record = ApprovalRecord {
            subject: "image-indexer".into(),
            action: "index".into(),
            request_id: "request-0".into(),
            approver_role: "image-review".into(),
            resources: (0..500)
                .map(|i| {
                    let width = if at_cap { 124 } else { 64 };
                    format!("{i:04}/\"\\\n{}", "x".repeat(width - 8))
                })
                .collect(),
            revision_digest: [0; 32],
        };
        let mut wire = encode_record(&record, &ca, &limits, false).unwrap();
        if at_cap {
            record
                .resources
                .last_mut()
                .unwrap()
                .push_str(&"x".repeat(limits.record_bytes - wire.len()));
            wire = encode_record(&record, &ca, &limits, false).unwrap();
            assert_eq!(wire.len(), limits.record_bytes);
        } else {
            assert!(record.resources.iter().all(|name| name.len() == 64));
        }
        assert_eq!(wire.len() as u64, fixture["record_bytes"].as_u64().unwrap());
        let snapshot = TrustSnapshot {
            suite: Suite::carrier::<ES256>(),
            trust_domain: "image-index".into(),
            provenance: "local configuration".into(),
            as_of: 15,
            entries: vec![TrustEntry {
                issuer: "reviewer".into(),
                key: TrustKey {
                    key_id: "key-0".into(),
                    public_key,
                    valid_from: 0,
                    valid_before: ValidityUpperBound::Bounded(60),
                },
                roles: vec![record.approver_role.clone()],
            }],
        };
        let context = ApprovalContext {
            trust_domain: snapshot.trust_domain.clone(),
            audience: "image-host".into(),
            request_id: record.request_id,
            revision_digest: record.revision_digest,
            subject: record.subject,
            action: record.action,
            resources: record.resources,
            roles: vec![record.approver_role],
            now: 20,
            max_staleness: 5,
            max_lifetime: 50,
            max_active: None,
            snapshot: Some(snapshot),
            bounds: ca,
            record_bounds: limits,
        };
        let snapshot = context.snapshot.as_ref().unwrap();
        let mut verification = Vec::new();
        let mut call = Vec::new();
        let mut admission = Vec::new();
        for index in 0..(warmup + samples) {
            let start = Instant::now();
            let result = pure::<ES256>(black_box(&wire), black_box(compact), black_box(&context));
            let elapsed = start.elapsed();
            assert!(black_box(result).is_ok());

            let start = Instant::now();
            let keys = admit::<ES256>(black_box(snapshot), &context.trust_domain, &ca, &limits);
            let admitted = start.elapsed();
            assert_eq!(black_box(keys.unwrap()).len(), 1);

            if index >= warmup {
                call.push(elapsed);
                admission.push(admitted);
                verification.push(elapsed.saturating_sub(admitted));
            }
        }
        let verification_p99 = p99(&mut verification);
        println!(
            "{suite_name} {label} record_bytes={} verification_p99_ms={:.3} call_with_admission_p99_ms={:.3} snapshot_admission_p99_ms={:.3}",
            wire.len(), ms(verification_p99), ms(p99(&mut call)), ms(p99(&mut admission)),
        );
        verification_p99
    }

    fn p99(samples: &mut [Duration]) -> Duration {
        samples.sort_unstable();
        samples[(samples.len() * 99).div_ceil(100) - 1]
    }

    fn ms(elapsed: Duration) -> f64 {
        elapsed.as_secs_f64() * 1_000.0
    }
}
