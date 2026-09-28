//! Standalone `bap-content-assertion/1` producer, decoder, verifier, digests,
//! and pairwise successor relation. Verification returns facts, never authority.

use crate::base64url::{base64url_decode, base64url_encode};
use crate::bounds::Bounds;
use crate::ed25519;
use crate::error::{Invalid, Result};
use crate::facts::{NotEvaluated, SignatureAndWindow};
use crate::jcs::jcs_encode;
use crate::json::{json_decode, JsonValue};
use crate::jwk::public_key_thumbprint_raw;
use crate::role_attestation::{validate_identifier, validate_kid};
use crate::types::{
    HistoricalPublicKey, ProducedSigningInput, SigningInput, SigningKind, ValidityUpperBound,
};
use sha2::{Digest, Sha256};

const TYP_CONTENT_ASSERTION: &str = "ba+content-assertion";
const SIGNATURE_SEGMENT_BYTES: usize = 86;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAssertionInput {
    pub attestor_key_id: String,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub profile: String,
    pub profile_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub generation: i64,
    pub previous: [u8; 32],
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedContentAssertion {
    pub attestor: HistoricalPublicKey,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub profile: String,
    pub profile_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub now: i64,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedContentAssertion {
    pub version: i64,
    pub attestor_key_id: String,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub profile: String,
    pub profile_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub generation: i64,
    pub previous: [u8; 32],
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub verification: NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAssertionFacts {
    pub version: i64,
    pub attestor_key_id: String,
    pub attestor_key_fingerprint: [u8; 32],
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub profile: String,
    pub profile_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub generation: i64,
    pub previous: [u8; 32],
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub digest: [u8; 32],
    pub verification: SignatureAndWindow,
    pub trust: NotEvaluated,
}

#[derive(Debug)]
struct AssertionClaims {
    jti: String,
    iss: String,
    aud: String,
    sub: String,
    profile: String,
    profile_digest: [u8; 32],
    content_digest: [u8; 32],
    generation: i64,
    previous: [u8; 32],
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
}

struct DecodedAssertion<'a> {
    protected_segment: &'a [u8],
    payload_segment: &'a [u8],
    signature: [u8; 64],
    key_id: String,
    claims: AssertionClaims,
}

pub fn content_digest(content: &[u8], bounds: &Bounds) -> Result<[u8; 32]> {
    if content.is_empty() || content.len() as u64 > bounds.content_bytes() {
        return Err(Invalid);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"BAP1-CONTENT\0");
    hasher.update(content);
    Ok(hasher.finalize().into())
}

pub fn assertion_signing_input(
    assertion: &ContentAssertionInput,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
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
        ("alg".into(), JsonValue::String("EdDSA".into())),
        (
            "kid".into(),
            JsonValue::String(assertion.attestor_key_id.clone()),
        ),
        (
            "typ".into(),
            JsonValue::String(TYP_CONTENT_ASSERTION.into()),
        ),
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

pub fn assemble_content_assertion_compact(
    input: &SigningInput,
    signature: &[u8; 64],
    bounds: Option<&Bounds>,
) -> Result<Vec<u8>> {
    if input.kind != SigningKind::ContentAssertion {
        return Err(Invalid);
    }
    let bounds = bounds.copied().unwrap_or_else(Bounds::maximum);
    if input.protected_segment.len() as u64 > bounds.encoded_segment_bytes()
        || input.payload_segment.len() as u64 > bounds.encoded_segment_bytes()
        || SIGNATURE_SEGMENT_BYTES as u64 > bounds.encoded_segment_bytes()
    {
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
    decode_parts(&compact, &bounds)?;
    Ok(compact)
}

pub fn decode_content_assertion(
    compact: &[u8],
    bounds: &Bounds,
) -> Result<DecodedContentAssertion> {
    let decoded = decode_parts(compact, bounds)?;
    let claims = decoded.claims;
    Ok(DecodedContentAssertion {
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

pub fn assertion_digest(compact: &[u8], bounds: &Bounds) -> Result<[u8; 32]> {
    decode_parts(compact, bounds)?;
    Ok(Sha256::digest(compact).into())
}

pub fn verify_content_assertion(
    compact: &[u8],
    expected: &ExpectedContentAssertion,
) -> Result<ContentAssertionFacts> {
    validate_expected(expected)?;
    let decoded = decode_parts(compact, &expected.bounds)?;
    let claims = decoded.claims;
    if decoded.key_id != expected.attestor.key_id
        || claims.iss != expected.issuer
        || claims.aud != expected.audience
        || claims.sub != expected.subject
        || claims.profile != expected.profile
        || claims.profile_digest != expected.profile_digest
        || claims.content_digest != expected.content_digest
    {
        return Err(Invalid);
    }
    if claims.issued_at < expected.attestor.valid_from
        || claims.not_before < expected.attestor.valid_from
    {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(valid_before) = expected.attestor.valid_before {
        if claims.expires_at > valid_before {
            return Err(Invalid);
        }
    }
    if expected.now < claims.not_before || expected.now >= claims.expires_at {
        return Err(Invalid);
    }
    let message = signing_input_bytes(decoded.protected_segment, decoded.payload_segment);
    ed25519::verify(&expected.attestor.public_key, &message, &decoded.signature)?;
    Ok(ContentAssertionFacts {
        version: 1,
        attestor_key_id: decoded.key_id,
        attestor_key_fingerprint: public_key_thumbprint_raw(&expected.attestor.public_key),
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
    })
}

pub fn verify_content_assertion_successor(
    predecessor: &ContentAssertionFacts,
    successor: &ContentAssertionFacts,
    bounds: &Bounds,
) -> Result<()> {
    validate_facts(predecessor, bounds)?;
    validate_facts(successor, bounds)?;
    if predecessor.iss != successor.iss
        || predecessor.aud != successor.aud
        || predecessor.sub != successor.sub
        || predecessor.profile != successor.profile
        || predecessor.profile_digest != successor.profile_digest
        || predecessor.generation >= bounds.integer_magnitude() as i64
        || successor.generation != predecessor.generation + 1
        || successor.previous != predecessor.digest
        || successor.issued_at < predecessor.issued_at
        || successor.jti == predecessor.jti
    {
        return Err(Invalid);
    }
    Ok(())
}

fn decode_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedAssertion<'a>> {
    validate_compact_size(compact.len(), bounds)?;
    let (protected_segment, payload_segment, signature_segment) = split_compact(compact, bounds)?;
    let protected_bytes = decode_segment(protected_segment, bounds)?;
    let payload_bytes = decode_segment(payload_segment, bounds)?;
    let signature_bytes = decode_segment(signature_segment, bounds)?;
    if signature_bytes.len() != 64 {
        return Err(Invalid);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);
    let header = json_decode(&protected_bytes, bounds)?;
    let payload = json_decode(&payload_bytes, bounds)?;
    let key_id = validate_header(&header, &protected_bytes, bounds)?;
    let claims = validate_payload(&payload, &payload_bytes, bounds)?;
    Ok(DecodedAssertion {
        protected_segment,
        payload_segment,
        signature,
        key_id,
        claims,
    })
}

fn validate_header(header: &JsonValue, raw: &[u8], bounds: &Bounds) -> Result<String> {
    let members = match header {
        JsonValue::Object(members) if members.len() == 3 => members,
        _ => return Err(Invalid),
    };
    let (mut alg, mut kid, mut typ) = (None, None, None);
    for (name, value) in members {
        match name.as_str() {
            "alg" => alg = Some(value),
            "kid" => kid = Some(value),
            "typ" => typ = Some(value),
            _ => return Err(Invalid),
        }
    }
    if !matches!(alg, Some(JsonValue::String(value)) if value == "EdDSA")
        || !matches!(typ, Some(JsonValue::String(value)) if value == TYP_CONTENT_ASSERTION)
    {
        return Err(Invalid);
    }
    let kid = match kid {
        Some(JsonValue::String(value)) => value,
        _ => return Err(Invalid),
    };
    validate_kid(kid, bounds)?;
    if jcs_encode(header, bounds)?.as_slice() != raw {
        return Err(Invalid);
    }
    Ok(kid.clone())
}

fn validate_payload(payload: &JsonValue, raw: &[u8], bounds: &Bounds) -> Result<AssertionClaims> {
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
        jti: take_identifier(jti, bounds)?,
        iss: take_identifier(iss, bounds)?,
        aud: take_identifier(aud, bounds)?,
        sub: take_identifier(sub, bounds)?,
        profile: take_identifier(profile, bounds)?,
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

fn validate_expected(expected: &ExpectedContentAssertion) -> Result<()> {
    let bounds = &expected.bounds;
    validate_kid(&expected.attestor.key_id, bounds)?;
    validate_identifier(&expected.issuer, bounds)?;
    validate_identifier(&expected.audience, bounds)?;
    validate_identifier(&expected.subject, bounds)?;
    validate_identifier(&expected.profile, bounds)?;
    validate_magnitude(expected.now, bounds)?;
    validate_magnitude(expected.attestor.valid_from, bounds)?;
    if let ValidityUpperBound::Bounded(valid_before) = expected.attestor.valid_before {
        validate_magnitude(valid_before, bounds)?;
        if valid_before <= expected.attestor.valid_from {
            return Err(Invalid);
        }
    }
    Ok(())
}

fn validate_facts(facts: &ContentAssertionFacts, bounds: &Bounds) -> Result<()> {
    if facts.version != 1 || facts.verification != SignatureAndWindow || facts.trust != NotEvaluated
    {
        return Err(Invalid);
    }
    validate_kid(&facts.attestor_key_id, bounds)?;
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

fn validate_magnitude(value: i64, bounds: &Bounds) -> Result<()> {
    if value.unsigned_abs() > bounds.integer_magnitude() {
        Err(Invalid)
    } else {
        Ok(())
    }
}

fn take_identifier(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
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

fn signing_input_bytes(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected.len() + payload.len() + 1);
    out.extend_from_slice(protected);
    out.push(b'.');
    out.extend_from_slice(payload);
    out
}

fn b64_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(base64url_encode(bytes)).map_err(|_| Invalid)
}
