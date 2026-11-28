//! Standalone `bap-content-assertion/1` producer, decoder, verifier, digests,
//! and pairwise successor relation. Verification returns facts, never authority.

use crate::base64url::{base64url_decode, base64url_encode};
use crate::bounds::Bounds;
use crate::compact::signing_input_bytes;
use crate::error::{Invalid, Result};
use crate::facts::{NotEvaluated, SignatureAndWindow};
use crate::jcs::jcs_encode;
use crate::json::{json_decode, JsonValue};
use crate::jwk::public_key_thumbprint_raw;
use crate::role_attestation::{validate_content_identifier, validate_identifier, validate_kid};
use crate::types::{
    HistoricalPublicKey, ProducedSigningInput, SigningInput, SigningKind, ValidityUpperBound,
};
use crate::{ed25519, es256, v3};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use sha2::{Digest, Sha256};

const TYP_CONTENT_ASSERTION: &str = "ba+content-assertion";
const TYP_CONTENT_ASSERTION_ES256: &str = "ba+content-assertion-es256";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Malformed,
    UnsupportedAlgorithm,
    BadSignature,
    KeyWindow,
    NotYetValid,
    Expired,
}

impl From<Invalid> for Stage {
    fn from(_: Invalid) -> Self {
        Self::Malformed
    }
}

impl From<Stage> for Invalid {
    fn from(_: Stage) -> Self {
        Self
    }
}

type Staged<T> = std::result::Result<T, Stage>;

fn suite<const ES256: bool>() -> (&'static str, &'static str, SigningKind) {
    if ES256 {
        (
            "ES256",
            TYP_CONTENT_ASSERTION_ES256,
            SigningKind::ContentAssertionEs256,
        )
    } else {
        (
            "EdDSA",
            TYP_CONTENT_ASSERTION,
            SigningKind::ContentAssertion,
        )
    }
}

type IdentifierCheck = fn(&str, &Bounds) -> Result<()>;

fn identifier_check<const ES256: bool>() -> IdentifierCheck {
    if ES256 {
        validate_content_identifier
    } else {
        validate_identifier
    }
}

pub(crate) fn equal_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}
const SIGNATURE_SEGMENT_BYTES: usize = 86;

/// Unsigned content-lineage claims. Signing and content storage belong to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAssertionInput {
    /// Identifier of the attestor public key.
    pub attestor_key_id: String,
    /// Unique signed assertion identifier.
    pub jti: String,
    /// Signed issuer identifier.
    pub iss: String,
    /// Signed audience identifier.
    pub aud: String,
    /// Signed subject identifier.
    pub sub: String,
    /// Exact assertion profile identifier.
    pub profile: String,
    /// Raw SHA-256 digest identifying the expected profile.
    pub profile_digest: [u8; 32],
    /// Domain-separated digest of the content bytes.
    pub content_digest: [u8; 32],
    /// Positive lineage generation; the first generation is one.
    pub generation: i64,
    /// Predecessor assertion digest; all zero bytes for generation one.
    pub previous: [u8; 32],
    /// Signed issuance time in Unix seconds.
    pub issued_at: i64,
    /// Inclusive validity-window start in Unix seconds.
    pub not_before: i64,
    /// Exclusive validity-window end in Unix seconds.
    pub expires_at: i64,
}

/// Caller-trusted attestor and exact expected profile, content, subject and evaluation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedContentAssertion<K = HistoricalPublicKey> {
    /// Already-trusted historical attestor key selected by the caller.
    pub attestor: K,
    /// Expected issuer identifier supplied by the caller.
    pub issuer: String,
    /// Expected audience identifier supplied by the caller.
    pub audience: String,
    /// Expected subject identifier supplied by the caller.
    pub subject: String,
    /// Exact assertion profile identifier.
    pub profile: String,
    /// Raw SHA-256 digest identifying the expected profile.
    pub profile_digest: [u8; 32],
    /// Domain-separated digest of the content bytes.
    pub content_digest: [u8; 32],
    /// Caller-supplied evaluation time in Unix seconds.
    pub now: i64,
    /// Explicit bounded-work limits; callers may tighten protocol maxima.
    pub bounds: Bounds,
}

/// Canonical decoded claims with no signature verification or trust established.
#[derive(Clone, PartialEq, Eq)]
pub struct DecodedAssertionClaims<const ES256: bool> {
    /// Contract-major or sibling-profile version; not a package version.
    pub version: i64,
    /// Identifier of the attestor public key.
    pub attestor_key_id: String,
    /// Unique signed assertion identifier.
    pub jti: String,
    /// Signed issuer identifier.
    pub iss: String,
    /// Signed audience identifier.
    pub aud: String,
    /// Signed subject identifier.
    pub sub: String,
    /// Exact assertion profile identifier.
    pub profile: String,
    /// Raw SHA-256 digest identifying the expected profile.
    pub profile_digest: [u8; 32],
    /// Domain-separated digest of the content bytes.
    pub content_digest: [u8; 32],
    /// Positive lineage generation; the first generation is one.
    pub generation: i64,
    /// Predecessor assertion digest; all zero bytes for generation one.
    pub previous: [u8; 32],
    /// Signed issuance time in Unix seconds.
    pub issued_at: i64,
    /// Inclusive validity-window start in Unix seconds.
    pub not_before: i64,
    /// Exclusive validity-window end in Unix seconds.
    pub expires_at: i64,
    /// Checks completed by this operation; decoding alone does not verify.
    pub verification: NotEvaluated,
}

/// Verified signature and time-window facts. Trust and authorization remain caller decisions.
#[derive(Clone, PartialEq, Eq)]
pub struct AssertionFacts<const ES256: bool> {
    /// Contract-major or sibling-profile version; not a package version.
    pub version: i64,
    /// Identifier of the attestor public key.
    pub attestor_key_id: String,
    /// Raw SHA-256 thumbprint of the attestor public key.
    pub attestor_key_fingerprint: [u8; 32],
    /// Unique signed assertion identifier.
    pub jti: String,
    /// Signed issuer identifier.
    pub iss: String,
    /// Signed audience identifier.
    pub aud: String,
    /// Signed subject identifier.
    pub sub: String,
    /// Exact assertion profile identifier.
    pub profile: String,
    /// Raw SHA-256 digest identifying the expected profile.
    pub profile_digest: [u8; 32],
    /// Domain-separated digest of the content bytes.
    pub content_digest: [u8; 32],
    /// Positive lineage generation; the first generation is one.
    pub generation: i64,
    /// Predecessor assertion digest; all zero bytes for generation one.
    pub previous: [u8; 32],
    /// Signed issuance time in Unix seconds.
    pub issued_at: i64,
    /// Inclusive validity-window start in Unix seconds.
    pub not_before: i64,
    /// Exclusive validity-window end in Unix seconds.
    pub expires_at: i64,
    /// SHA-256 digest of the exact canonical compact bytes.
    pub digest: [u8; 32],
    /// Checks completed by this operation; decoding alone does not verify.
    pub verification: SignatureAndWindow,
    /// Trust is not evaluated by this pure verifier.
    pub trust: NotEvaluated,
}

/// Decoded claims of the EdDSA content-assertion profile.
pub type DecodedContentAssertion = DecodedAssertionClaims<false>;

/// Verified facts of the EdDSA content-assertion profile.
pub type ContentAssertionFacts = AssertionFacts<false>;

pub(crate) struct AssertionClaims {
    jti: String,
    pub(crate) iss: String,
    pub(crate) aud: String,
    pub(crate) sub: String,
    pub(crate) profile: String,
    pub(crate) profile_digest: [u8; 32],
    pub(crate) content_digest: [u8; 32],
    generation: i64,
    previous: [u8; 32],
    pub(crate) issued_at: i64,
    pub(crate) not_before: i64,
    pub(crate) expires_at: i64,
}

pub(crate) struct ParsedAssertion<'a, const ES256: bool> {
    message: &'a [u8],
    signature: [u8; 64],
    pub(crate) key_id: String,
    pub(crate) claims: AssertionClaims,
}

/// Hash nonempty bounded content with the content-assertion domain separator.
pub fn content_digest(content: &[u8], bounds: &Bounds) -> Result<[u8; 32]> {
    if content.is_empty() || content.len() as u64 > bounds.content_bytes() {
        return Err(Invalid);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"BAP1-CONTENT\0");
    hasher.update(content);
    Ok(hasher.finalize().into())
}

/// Validate content-lineage claims and produce the exact canonical JWS signing bytes.
pub fn assertion_signing_input(
    assertion: &ContentAssertionInput,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    produce::<false>(assertion, bounds)
}

pub(crate) fn produce<const ES256: bool>(
    assertion: &ContentAssertionInput,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    let (alg, typ, _) = suite::<ES256>();
    let validate_identifier = identifier_check::<ES256>();
    validate_kid(&assertion.attestor_key_id, bounds)?;
    validate_identifier(&assertion.jti, bounds)?;
    validate_identifier(&assertion.iss, bounds)?;
    validate_identifier(&assertion.aud, bounds)?;
    validate_identifier(&assertion.sub, bounds)?;
    validate_identifier(&assertion.profile, bounds)?;
    validate_numbers(
        assertion.generation,
        assertion.issued_at,
        assertion.not_before,
        assertion.expires_at,
        &assertion.previous,
        bounds,
    )?;
    let header = JsonValue::Object(vec![
        ("alg".into(), JsonValue::String(alg.into())),
        (
            "kid".into(),
            JsonValue::String(assertion.attestor_key_id.clone()),
        ),
        ("typ".into(), JsonValue::String(typ.into())),
    ]);
    let payload = JsonValue::Object(vec![
        ("aud".into(), JsonValue::String(assertion.aud.clone())),
        (
            "content_digest".into(),
            JsonValue::String(b64_string(&assertion.content_digest)?),
        ),
        ("exp".into(), JsonValue::Int(assertion.expires_at)),
        ("gen".into(), JsonValue::Int(assertion.generation)),
        ("iat".into(), JsonValue::Int(assertion.issued_at)),
        ("iss".into(), JsonValue::String(assertion.iss.clone())),
        ("jti".into(), JsonValue::String(assertion.jti.clone())),
        ("nbf".into(), JsonValue::Int(assertion.not_before)),
        (
            "prev".into(),
            JsonValue::String(b64_string(&assertion.previous)?),
        ),
        (
            "profile".into(),
            JsonValue::String(assertion.profile.clone()),
        ),
        (
            "profile_digest".into(),
            JsonValue::String(b64_string(&assertion.profile_digest)?),
        ),
        ("sub".into(), JsonValue::String(assertion.sub.clone())),
        ("v".into(), JsonValue::Int(1)),
    ]);
    build_produced(&header, &payload, bounds)
}

/// Assemble canonical assertion segments and a producer-canonical signature without verifying it.
pub fn assemble_content_assertion_compact(
    input: &SigningInput,
    signature: &[u8; 64],
    bounds: Option<&Bounds>,
) -> Result<Vec<u8>> {
    assemble::<false>(input, signature, bounds)
}

pub(crate) fn assemble<const ES256: bool>(
    input: &SigningInput,
    signature: &[u8; 64],
    bounds: Option<&Bounds>,
) -> Result<Vec<u8>> {
    if input.kind != suite::<ES256>().2 {
        return Err(Invalid);
    }
    let bounds = bounds.copied().unwrap_or_else(Bounds::maximum);
    if input.protected_segment.len() as u64 > bounds.encoded_segment_bytes()
        || input.payload_segment.len() as u64 > bounds.encoded_segment_bytes()
        || SIGNATURE_SEGMENT_BYTES as u64 > bounds.encoded_segment_bytes()
    {
        return Err(Invalid);
    }
    // Erratum 3 (REQ1/REQ2-SIGNING-ed25519-producer-canonical): assembly is a producer
    // surface (it frames a signature and verifies none) so it refuses a signature that
    // fails the keyless part of rule S1 and emits accepted bytes unchanged.
    if ES256 {
        es256::validate_rs_range(signature)?;
    } else if !ed25519::signature_gate(signature) {
        return Err(Invalid);
    }
    let mut compact = Vec::with_capacity(projected_compact_len(
        input.protected_segment.len(),
        input.payload_segment.len(),
    )?);
    compact.extend_from_slice(&input.protected_segment);
    compact.push(b'.');
    compact.extend_from_slice(&input.payload_segment);
    compact.push(b'.');
    compact.extend_from_slice(&base64url_encode(signature));
    parse::<ES256>(&compact, &bounds, identifier_check::<ES256>())?;
    Ok(compact)
}

/// Decode canonical assertion claims without checking a signature or selecting trusted keys.
pub fn decode_content_assertion(
    compact: &[u8],
    bounds: &Bounds,
) -> Result<DecodedContentAssertion> {
    decode::<false>(compact, bounds)
}

pub(crate) fn decode<const ES256: bool>(
    compact: &[u8],
    bounds: &Bounds,
) -> Result<DecodedAssertionClaims<ES256>> {
    let decoded = parse::<ES256>(compact, bounds, identifier_check::<ES256>())?;
    let claims = decoded.claims;
    Ok(DecodedAssertionClaims {
        version: 1,
        attestor_key_id: decoded.key_id,
        jti: claims.jti,
        iss: claims.iss,
        aud: claims.aud,
        sub: claims.sub,
        profile: claims.profile,
        profile_digest: claims.profile_digest,
        content_digest: claims.content_digest,
        generation: claims.generation,
        previous: claims.previous,
        issued_at: claims.issued_at,
        not_before: claims.not_before,
        expires_at: claims.expires_at,
        verification: NotEvaluated,
    })
}

/// Validate canonical assertion bytes and hash the exact compact representation.
pub fn assertion_digest(compact: &[u8], bounds: &Bounds) -> Result<[u8; 32]> {
    digest::<false>(compact, bounds)
}

pub(crate) fn digest<const ES256: bool>(compact: &[u8], bounds: &Bounds) -> Result<[u8; 32]> {
    parse::<ES256>(compact, bounds, identifier_check::<ES256>())?;
    Ok(Sha256::digest(compact).into())
}

/// Verify an assertion against the caller-trusted attestor, content, profile and explicit time.
pub fn verify_content_assertion(
    compact: &[u8],
    expected: &ExpectedContentAssertion,
) -> Result<ContentAssertionFacts> {
    verify::<false, _>(compact, expected, (&expected.attestor).into())
}

pub(crate) struct KeyRef<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) public_key: &'a [u8],
    pub(crate) valid_from: i64,
    pub(crate) valid_before: &'a ValidityUpperBound,
}

impl<'a> From<&'a HistoricalPublicKey> for KeyRef<'a> {
    fn from(key: &'a HistoricalPublicKey) -> Self {
        Self {
            key_id: &key.key_id,
            public_key: &key.public_key,
            valid_from: key.valid_from,
            valid_before: &key.valid_before,
        }
    }
}

impl<'a> From<&'a v3::HistoricalPublicKey> for KeyRef<'a> {
    fn from(key: &'a v3::HistoricalPublicKey) -> Self {
        Self {
            key_id: &key.key_id,
            public_key: &key.public_key,
            valid_from: key.valid_from,
            valid_before: &key.valid_before,
        }
    }
}

pub(crate) fn verify<const ES256: bool, K>(
    compact: &[u8],
    expected: &ExpectedContentAssertion<K>,
    key: KeyRef<'_>,
) -> Result<AssertionFacts<ES256>> {
    let bounds = &expected.bounds;
    key.validate_window(bounds)?;
    let validate_identifier = identifier_check::<ES256>();
    for value in [
        &expected.issuer,
        &expected.audience,
        &expected.subject,
        &expected.profile,
    ] {
        validate_identifier(value, bounds)?;
    }
    validate_magnitude(expected.now, bounds)?;

    let parsed = parse::<ES256>(compact, bounds, identifier_check::<ES256>())?;
    let claims = &parsed.claims;
    if parsed.key_id != key.key_id
        || claims.iss != expected.issuer
        || claims.aud != expected.audience
        || claims.sub != expected.subject
        || claims.profile != expected.profile
        || !equal_digest(&claims.profile_digest, &expected.profile_digest)
        || !equal_digest(&claims.content_digest, &expected.content_digest)
    {
        return Err(Invalid);
    }
    claims.key_window(&key)?;
    claims.current_window(expected.now)?;
    parsed.verify_signature(key.public_key)?;
    let fingerprint = fingerprint::<ES256>(key.public_key)?;
    Ok(parsed.facts(compact, fingerprint))
}

impl KeyRef<'_> {
    pub(crate) fn validate_window(&self, bounds: &Bounds) -> Result<()> {
        validate_kid(self.key_id, bounds)?;
        validate_magnitude(self.valid_from, bounds)?;
        if let ValidityUpperBound::Bounded(valid_before) = self.valid_before {
            validate_magnitude(*valid_before, bounds)?;
            if *valid_before <= self.valid_from {
                return Err(Invalid);
            }
        }
        Ok(())
    }
}

pub(crate) fn fingerprint<const ES256: bool>(raw: &[u8]) -> Result<[u8; 32]> {
    if ES256 {
        v3::public_key_thumbprint_raw(raw.try_into().map_err(|_| Invalid)?)
    } else {
        public_key_thumbprint_raw(raw.try_into().map_err(|_| Invalid)?)
    }
}

impl AssertionClaims {
    pub(crate) fn key_window(&self, key: &KeyRef<'_>) -> Staged<()> {
        if self.issued_at < key.valid_from
            || self.not_before < key.valid_from
            || matches!(key.valid_before, ValidityUpperBound::Bounded(end) if self.expires_at > *end)
        {
            return Err(Stage::KeyWindow);
        }
        Ok(())
    }

    pub(crate) fn current_window(&self, now: i64) -> Staged<()> {
        if now < self.not_before {
            return Err(Stage::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(Stage::Expired);
        }
        Ok(())
    }
}

impl<const ES256: bool> ParsedAssertion<'_, ES256> {
    pub(crate) fn verify_signature(&self, raw: &[u8]) -> Staged<()> {
        if ES256 {
            let key = raw.try_into().map_err(|_| Stage::BadSignature)?;
            es256::verify(key, self.message, &self.signature)
        } else {
            let key = raw.try_into().map_err(|_| Stage::BadSignature)?;
            ed25519::verify(key, self.message, &self.signature)
        }
        .map_err(|_| Stage::BadSignature)
    }

    pub(crate) fn facts(self, compact: &[u8], fingerprint: [u8; 32]) -> AssertionFacts<ES256> {
        let claims = self.claims;
        AssertionFacts {
            version: 1,
            attestor_key_id: self.key_id,
            attestor_key_fingerprint: fingerprint,
            jti: claims.jti,
            iss: claims.iss,
            aud: claims.aud,
            sub: claims.sub,
            profile: claims.profile,
            profile_digest: claims.profile_digest,
            content_digest: claims.content_digest,
            generation: claims.generation,
            previous: claims.previous,
            issued_at: claims.issued_at,
            not_before: claims.not_before,
            expires_at: claims.expires_at,
            digest: Sha256::digest(compact).into(),
            verification: SignatureAndWindow,
            trust: NotEvaluated,
        }
    }
}

/// Check consecutive verified generations and the exact predecessor digest link.
pub fn verify_content_assertion_successor(
    predecessor: &ContentAssertionFacts,
    successor: &ContentAssertionFacts,
    bounds: &Bounds,
) -> Result<()> {
    self::successor::<false>(predecessor, successor, bounds)
}

pub(crate) fn successor<const ES256: bool>(
    predecessor: &AssertionFacts<ES256>,
    successor: &AssertionFacts<ES256>,
    bounds: &Bounds,
) -> Result<()> {
    validate_facts(predecessor, bounds)?;
    validate_facts(successor, bounds)?;
    if predecessor.iss != successor.iss
        || predecessor.aud != successor.aud
        || predecessor.sub != successor.sub
        || predecessor.profile != successor.profile
        || !equal_digest(&predecessor.profile_digest, &successor.profile_digest)
        || predecessor.generation >= bounds.integer_magnitude() as i64
        || successor.generation != predecessor.generation + 1
        || !equal_digest(&successor.previous, &predecessor.digest)
        || successor.issued_at < predecessor.issued_at
        || successor.jti == predecessor.jti
    {
        return Err(Invalid);
    }
    Ok(())
}

pub(crate) fn parse<'a, const ES256: bool>(
    compact: &'a [u8],
    bounds: &Bounds,
    validate_identifier: IdentifierCheck,
) -> Staged<ParsedAssertion<'a, ES256>> {
    validate_compact_size(compact.len(), bounds)?;
    let (protected_segment, payload_segment, signature_segment) = split_compact(compact, bounds)?;
    let protected_bytes = decode_segment(protected_segment, bounds)?;
    let payload_bytes = decode_segment(payload_segment, bounds)?;
    if signature_segment.len() != SIGNATURE_SEGMENT_BYTES {
        return Err(Stage::Malformed);
    }
    let signature = decode_segment(signature_segment, bounds)?
        .try_into()
        .map_err(|_| Stage::Malformed)?;
    let (alg, typ, key_id) = parse_header(&protected_bytes, bounds)?;
    let (expected_alg, expected_typ, _) = suite::<ES256>();
    if alg != expected_alg || typ != expected_typ {
        return Err(Stage::UnsupportedAlgorithm);
    }
    let payload = json_decode(&payload_bytes, bounds)?;
    let claims = validate_payload(&payload, &payload_bytes, bounds, validate_identifier)?;
    let message = &compact[..compact.len() - signature_segment.len() - 1];
    Ok(ParsedAssertion {
        message,
        signature,
        key_id,
        claims,
    })
}

fn parse_header(raw: &[u8], bounds: &Bounds) -> Result<(String, String, String)> {
    let header = json_decode(raw, bounds)?;
    if jcs_encode(&header, bounds)? != raw {
        return Err(Invalid);
    }
    let JsonValue::Object(members) = header else {
        return Err(Invalid);
    };
    if members.len() != 3 {
        return Err(Invalid);
    }
    // Canonical bytes imply object member order. All three values are strings.
    let [alg, kid, typ]: [(String, JsonValue); 3] = members.try_into().map_err(|_| Invalid)?;
    match (alg, kid, typ) {
        ((a, JsonValue::String(alg)), (k, JsonValue::String(kid)), (t, JsonValue::String(typ)))
            if a == "alg" && k == "kid" && t == "typ" =>
        {
            validate_kid(&kid, bounds)?;
            Ok((alg, typ, kid))
        }
        _ => Err(Invalid),
    }
}

fn validate_payload(
    payload: &JsonValue,
    raw: &[u8],
    bounds: &Bounds,
    validate_identifier: IdentifierCheck,
) -> Result<AssertionClaims> {
    let members = match payload {
        JsonValue::Object(members) if members.len() == 13 => members,
        _ => return Err(Invalid),
    };
    let (mut version, mut jti, mut iss, mut aud, mut sub, mut profile) =
        (None, None, None, None, None, None);
    let (mut profile_digest, mut content_digest, mut generation, mut previous) =
        (None, None, None, None);
    let (mut issued_at, mut not_before, mut expires_at) = (None, None, None);
    for (name, value) in members {
        match name.as_str() {
            "v" => version = Some(value),
            "jti" => jti = Some(value),
            "iss" => iss = Some(value),
            "aud" => aud = Some(value),
            "sub" => sub = Some(value),
            "profile" => profile = Some(value),
            "profile_digest" => profile_digest = Some(value),
            "content_digest" => content_digest = Some(value),
            "gen" => generation = Some(value),
            "prev" => previous = Some(value),
            "iat" => issued_at = Some(value),
            "nbf" => not_before = Some(value),
            "exp" => expires_at = Some(value),
            _ => return Err(Invalid),
        }
    }
    if !matches!(version, Some(JsonValue::Int(1))) {
        return Err(Invalid);
    }
    let claims = AssertionClaims {
        jti: take_identifier(jti, bounds, validate_identifier)?,
        iss: take_identifier(iss, bounds, validate_identifier)?,
        aud: take_identifier(aud, bounds, validate_identifier)?,
        sub: take_identifier(sub, bounds, validate_identifier)?,
        profile: take_identifier(profile, bounds, validate_identifier)?,
        profile_digest: take_digest(profile_digest)?,
        content_digest: take_digest(content_digest)?,
        generation: take_integer(generation, bounds)?,
        previous: take_digest(previous)?,
        issued_at: take_integer(issued_at, bounds)?,
        not_before: take_integer(not_before, bounds)?,
        expires_at: take_integer(expires_at, bounds)?,
    };
    validate_numbers(
        claims.generation,
        claims.issued_at,
        claims.not_before,
        claims.expires_at,
        &claims.previous,
        bounds,
    )?;
    if jcs_encode(payload, bounds)?.as_slice() != raw {
        return Err(Invalid);
    }
    Ok(claims)
}

fn validate_facts<const ES256: bool>(facts: &AssertionFacts<ES256>, bounds: &Bounds) -> Result<()> {
    if facts.version != 1 || facts.verification != SignatureAndWindow || facts.trust != NotEvaluated
    {
        return Err(Invalid);
    }
    validate_kid(&facts.attestor_key_id, bounds)?;
    let validate_identifier = identifier_check::<ES256>();
    for value in [
        &facts.jti,
        &facts.iss,
        &facts.aud,
        &facts.sub,
        &facts.profile,
    ] {
        validate_identifier(value, bounds)?;
    }
    validate_numbers(
        facts.generation,
        facts.issued_at,
        facts.not_before,
        facts.expires_at,
        &facts.previous,
        bounds,
    )
}

fn validate_numbers(
    generation: i64,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
    previous: &[u8; 32],
    bounds: &Bounds,
) -> Result<()> {
    for value in [issued_at, not_before, expires_at] {
        validate_magnitude(value, bounds)?;
    }
    if generation < 1
        || generation as u64 > bounds.integer_magnitude()
        || issued_at > not_before
        || not_before >= expires_at
        || ((generation == 1) != (*previous == [0u8; 32]))
    {
        return Err(Invalid);
    }
    Ok(())
}

pub(crate) fn validate_magnitude(value: i64, bounds: &Bounds) -> Result<()> {
    if value.unsigned_abs() > bounds.integer_magnitude() {
        Err(Invalid)
    } else {
        Ok(())
    }
}

fn take_identifier(
    value: Option<&JsonValue>,
    bounds: &Bounds,
    validate_identifier: IdentifierCheck,
) -> Result<String> {
    let value = match value {
        Some(JsonValue::String(value)) => value,
        _ => return Err(Invalid),
    };
    validate_identifier(value, bounds)?;
    Ok(value.clone())
}

fn take_digest(value: Option<&JsonValue>) -> Result<[u8; 32]> {
    let encoded = match value {
        Some(JsonValue::String(value)) => value,
        _ => return Err(Invalid),
    };
    let raw = base64url_decode(encoded.as_bytes())?;
    raw.try_into().map_err(|_| Invalid)
}

fn take_integer(value: Option<&JsonValue>, bounds: &Bounds) -> Result<i64> {
    let value = match value {
        Some(JsonValue::Int(value)) => *value,
        _ => return Err(Invalid),
    };
    validate_magnitude(value, bounds)?;
    Ok(value)
}

fn build_produced(
    header: &JsonValue,
    payload: &JsonValue,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    let header_raw = jcs_encode(header, bounds)?;
    let payload_raw = jcs_encode(payload, bounds)?;
    if header_raw.len() as u64 > bounds.decoded_segment_bytes()
        || payload_raw.len() as u64 > bounds.decoded_segment_bytes()
    {
        return Err(Invalid);
    }
    json_decode(&header_raw, bounds)?;
    json_decode(&payload_raw, bounds)?;
    let protected_segment = base64url_encode(&header_raw);
    let payload_segment = base64url_encode(&payload_raw);
    if protected_segment.len() as u64 > bounds.encoded_segment_bytes()
        || payload_segment.len() as u64 > bounds.encoded_segment_bytes()
        || SIGNATURE_SEGMENT_BYTES as u64 > bounds.encoded_segment_bytes()
    {
        return Err(Invalid);
    }
    validate_compact_size(
        projected_compact_len(protected_segment.len(), payload_segment.len())?,
        bounds,
    )?;
    let message = signing_input_bytes(&protected_segment, &payload_segment);
    Ok(ProducedSigningInput {
        protected_segment,
        payload_segment,
        message,
    })
}

fn validate_compact_size(size: usize, bounds: &Bounds) -> Result<()> {
    let size = u64::try_from(size).map_err(|_| Invalid)?;
    if size == 0 || size > bounds.compact_bytes() || size > bounds.anchor_bytes() {
        Err(Invalid)
    } else {
        Ok(())
    }
}

fn projected_compact_len(protected: usize, payload: usize) -> Result<usize> {
    protected
        .checked_add(payload)
        .and_then(|n| n.checked_add(SIGNATURE_SEGMENT_BYTES + 2))
        .ok_or(Invalid)
}

fn split_compact<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<(&'a [u8], &'a [u8], &'a [u8])> {
    let mut segments = compact.split(|byte| *byte == b'.');
    let protected = segments.next().unwrap_or(&[]);
    let payload = segments.next().ok_or(Invalid)?;
    let signature = segments.next().ok_or(Invalid)?;
    if segments.next().is_some()
        || protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || [protected, payload, signature]
            .iter()
            .any(|segment| segment.len() as u64 > bounds.encoded_segment_bytes())
    {
        return Err(Invalid);
    }
    Ok((protected, payload, signature))
}

fn decode_segment(segment: &[u8], bounds: &Bounds) -> Result<Vec<u8>> {
    if segment.len() as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let projected = projected_decoded_len(segment.len())?;
    if projected as u64 > bounds.decoded_segment_bytes() {
        return Err(Invalid);
    }
    let decoded = base64url_decode(segment)?;
    if decoded.len() != projected {
        return Err(Invalid);
    }
    Ok(decoded)
}

fn projected_decoded_len(encoded: usize) -> Result<usize> {
    let tail = match encoded % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => return Err(Invalid),
    };
    (encoded / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_add(tail))
        .ok_or(Invalid)
}

fn b64_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(base64url_encode(bytes)).map_err(|_| Invalid)
}

impl<const ES256: bool> std::fmt::Debug for AssertionFacts<ES256> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if ES256 {
            f.write_str("#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts<redacted>")
        } else {
            f.write_str(
                "#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts<redacted>",
            )
        }
    }
}

impl<const ES256: bool> std::fmt::Debug for DecodedAssertionClaims<ES256> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if ES256 {
            f.write_str("#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.DecodedContentAssertion<redacted>")
        } else {
            f.write_str(
                "#BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion<redacted>",
            )
        }
    }
}

impl<const ES256: bool> std::fmt::Display for AssertionFacts<ES256> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl<const ES256: bool> std::fmt::Display for DecodedAssertionClaims<ES256> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
