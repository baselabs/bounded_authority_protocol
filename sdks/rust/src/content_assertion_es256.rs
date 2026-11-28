//! Candidate ES256 content assertion. The caller supplies trusted keys and content.

use crate::content_assertion as shared;
use crate::types::{SigningInput, SigningKind};
use crate::{v3, Bounds, Invalid, Result};

pub use shared::{content_digest, ContentAssertionInput};

/// Caller-trusted P-256 attestor and exact expected assertion claims.
pub type ExpectedContentAssertion = shared::ExpectedContentAssertion<v3::HistoricalPublicKey>;

/// Canonical ES256 claims without signature or trust verification.
pub type DecodedContentAssertion = shared::DecodedAssertionClaims<true>;

/// Verified signature-and-window facts with ES256 profile provenance.
pub type ContentAssertionFacts = shared::AssertionFacts<true>;

/// Produce the exact ES256 JWS signing input for an external signer.
pub fn assertion_signing_input(
    assertion: &ContentAssertionInput,
    bounds: &Bounds,
) -> Result<SigningInput> {
    let produced = shared::produce::<true>(assertion, bounds)?;
    Ok(SigningInput {
        kind: SigningKind::ContentAssertionEs256,
        protected_segment: produced.protected_segment,
        payload_segment: produced.payload_segment,
    })
}

/// Assemble canonical segments and an external low-S raw signature without verifying it.
pub fn assemble_compact(
    input: &SigningInput,
    signature: &[u8],
    bounds: Option<&Bounds>,
) -> Result<Vec<u8>> {
    shared::assemble::<true>(input, signature.try_into().map_err(|_| Invalid)?, bounds)
}

/// Decode canonical ES256 claims without checking the signature or selecting a key.
pub fn decode_assertion(compact: &[u8], bounds: &Bounds) -> Result<DecodedContentAssertion> {
    shared::decode::<true>(compact, bounds)
}

/// Hash the exact structurally valid ES256 compact bytes.
pub fn assertion_digest(compact: &[u8], bounds: &Bounds) -> Result<[u8; 32]> {
    shared::digest::<true>(compact, bounds)
}

/// Verify the signature and expected claims with the caller-trusted P-256 attestor.
pub fn verify_assertion(
    compact: &[u8],
    expected: &ExpectedContentAssertion,
) -> Result<ContentAssertionFacts> {
    shared::verify::<true, _>(compact, expected, (&expected.attestor).into())
}

/// Check the lineage relation between verified ES256 assertions.
///
/// A profile change starts a new lineage. The input types admit ES256 facts only.
///
/// ```compile_fail
/// use bounded_authority_protocol::{content_assertion_es256, Bounds, ContentAssertionFacts};
///
/// fn mixed(
///     eddsa: &ContentAssertionFacts,
///     es256: &content_assertion_es256::ContentAssertionFacts,
/// ) {
///     content_assertion_es256::verify_successor(eddsa, es256, &Bounds::maximum());
/// }
/// ```
pub fn verify_successor(
    predecessor: &ContentAssertionFacts,
    successor: &ContentAssertionFacts,
    bounds: &Bounds,
) -> Result<()> {
    shared::successor::<true>(predecessor, successor, bounds)
}
