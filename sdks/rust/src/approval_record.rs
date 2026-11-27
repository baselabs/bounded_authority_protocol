//! Canonical record codec for the candidate `bap-action-approval/1` content profile.

use crate::jcs::{encode_string, encoded_string_len};
use crate::json::decode_string_prefix;
use crate::role_attestation::validate_identifier;
use crate::{base64url_decode, base64url_encode, Bounds, Invalid, Result};

/// Signed identity of the action-approval record profile.
pub const PROFILE: &str = "bap-action-approval/1";
/// SHA-256 of the profile domain separator and the frozen JCS descriptor.
pub const PROFILE_DIGEST: [u8; 32] = [
    0x7e, 0x44, 0xf7, 0x32, 0x17, 0xcd, 0x25, 0x03, 0x78, 0x39, 0xec, 0xc2, 0x58, 0x37, 0xde, 0x84,
    0xaa, 0xd3, 0x67, 0x36, 0x26, 0xb9, 0xb1, 0x25, 0xc9, 0x4c, 0x97, 0xe9, 0x96, 0x7f, 0xa1, 0xeb,
];

const ACTION: &[u8] = br#"{"action":"#;
const ROLE: &[u8] = br#","approver_role":"#;
const REQUEST_ID: &[u8] = br#","request_id":"#;
const RESOURCES: &[u8] = br#","resources":["#;
const REVISION: &[u8] = br#"],"revision_digest":"#;
const SUBJECT: &[u8] = br#","subject":"#;
const END: &[u8] = br#","v":1}"#;

/// Tightenable record ceilings, independent of the general JSON grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordBounds {
    /// Decoded UTF-8 bytes per string, up to 1,024.
    pub string_bytes: usize,
    /// Resource count, up to 4,096.
    pub resource_count: usize,
    /// Encoded record bytes, up to 65,536 and the carrier content ceiling.
    pub record_bytes: usize,
}

impl Default for RecordBounds {
    fn default() -> Self {
        Self {
            string_bytes: 1024,
            resource_count: 4096,
            record_bytes: 65536,
        }
    }
}

impl RecordBounds {
    pub(crate) fn effective(self, ca: &Bounds) -> Result<Self> {
        let max = Self::default();
        if !(1..=max.string_bytes).contains(&self.string_bytes)
            || !(1..=max.resource_count).contains(&self.resource_count)
            || !(1..=max.record_bytes).contains(&self.record_bytes)
        {
            return Err(Invalid);
        }
        Ok(Self {
            record_bytes: self.record_bytes.min(ca.content_bytes() as usize),
            ..self
        })
    }

    pub(crate) fn text(&self, text: &str) -> Result<()> {
        if !(1..=self.string_bytes).contains(&text.len()) {
            return Err(Invalid);
        }
        Ok(())
    }

    pub(crate) fn request_id(&self, text: &str, ca: &Bounds) -> Result<()> {
        self.text(text)?;
        validate_identifier(text, ca)
    }

    pub(crate) fn resources<'a>(&self, resources: &'a [String]) -> Result<Vec<&'a str>> {
        if !(1..=self.resource_count).contains(&resources.len()) {
            return Err(Invalid);
        }
        for resource in resources {
            self.text(resource)?;
        }
        Ok(resources.iter().map(String::as_str).collect())
    }
}

/// The exact operation, revision, resource set and approver role bound by a record.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// Subject of the action.
    pub subject: String,
    /// Exact action on the resource set.
    pub action: String,
    /// Request identifier, also bound in the assertion subject.
    pub request_id: String,
    /// Approver role required by the record.
    pub approver_role: String,
    /// Nonempty, strictly UTF-8-byte-ordered resource names on the wire.
    pub resources: Vec<String>,
    /// Raw 32-byte digest of the exact host request revision.
    pub revision_digest: [u8; 32],
}

impl std::fmt::Debug for ApprovalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("#BoundedAuthorityProtocol.ActionApproval.V1.Record<redacted>")
    }
}

/// Encode canonical bytes. An explicit opt-in sorts and deduplicates the authoring set.
pub fn encode_record(
    record: &ApprovalRecord,
    ca: &Bounds,
    bounds: &RecordBounds,
    canonicalize: bool,
) -> Result<Vec<u8>> {
    let bounds = bounds.effective(ca)?;
    bounds.text(&record.action)?;
    bounds.text(&record.approver_role)?;
    bounds.request_id(&record.request_id, ca)?;
    bounds.text(&record.subject)?;
    let mut resources = bounds.resources(&record.resources)?;
    if canonicalize {
        resources.sort_unstable();
        resources.dedup();
    }
    if resources.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Invalid);
    }
    let revision = base64url_encode(&record.revision_digest);
    let revision = std::str::from_utf8(&revision).map_err(|_| Invalid)?;
    let strings = [
        record.action.as_str(),
        &record.approver_role,
        &record.request_id,
        revision,
        &record.subject,
    ];
    let mut size = [ACTION, ROLE, REQUEST_ID, RESOURCES, REVISION, SUBJECT, END]
        .iter()
        .map(|literal| literal.len())
        .sum::<usize>()
        + resources.len()
        - 1;
    for text in strings.into_iter().chain(resources.iter().copied()) {
        size += encoded_string_len(text);
        if size > bounds.record_bytes {
            return Err(Invalid);
        }
    }
    let mut out = Vec::with_capacity(size);
    for (literal, text) in [
        (ACTION, strings[0]),
        (ROLE, strings[1]),
        (REQUEST_ID, strings[2]),
    ] {
        out.extend_from_slice(literal);
        encode_string(text, &mut out);
    }
    out.extend_from_slice(RESOURCES);
    for (index, resource) in resources.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        encode_string(resource, &mut out);
    }
    for (literal, text) in [(REVISION, revision), (SUBJECT, strings[4])] {
        out.extend_from_slice(literal);
        encode_string(text, &mut out);
    }
    out.extend_from_slice(END);
    Ok(out)
}

/// Decode only the exact bounded JCS representation of a record.
pub fn decode_record(wire: &[u8], ca: &Bounds, bounds: &RecordBounds) -> Result<ApprovalRecord> {
    decode_bounded(wire, ca, &bounds.effective(ca)?)
}

pub(crate) fn decode_bounded(
    wire: &[u8],
    ca: &Bounds,
    bounds: &RecordBounds,
) -> Result<ApprovalRecord> {
    if wire.len() > bounds.record_bytes {
        return Err(Invalid);
    }
    // A fixed member sequence rejects alternate orders, duplicates, extra fields
    // and alternate version lexemes without a general object or array allocation.
    let mut parser = RecordParser {
        remaining: wire,
        canonical: Vec::new(),
    };
    let action = parser.member(ACTION, bounds.string_bytes)?;
    let approver_role = parser.member(ROLE, bounds.string_bytes)?;
    let request_id = parser.member(
        REQUEST_ID,
        bounds.string_bytes.min(ca.identifier_bytes() as usize),
    )?;
    validate_identifier(&request_id, ca)?;
    let mut resources = vec![parser.member(RESOURCES, bounds.string_bytes)?];
    while parser.remaining.first() == Some(&b',') {
        if resources.len() == bounds.resource_count {
            return Err(Invalid);
        }
        let resource = parser.member(b",", bounds.string_bytes)?;
        if resources
            .last()
            .is_some_and(|previous| previous >= &resource)
        {
            return Err(Invalid);
        }
        resources.push(resource);
    }
    let revision = parser.member(REVISION, 43)?;
    let revision_digest = base64url_decode(revision.as_bytes())?
        .try_into()
        .map_err(|_| Invalid)?;
    let subject = parser.member(SUBJECT, bounds.string_bytes)?;
    if parser.remaining != END {
        return Err(Invalid);
    }
    Ok(ApprovalRecord {
        subject,
        action,
        request_id,
        approver_role,
        resources,
        revision_digest,
    })
}

struct RecordParser<'a> {
    remaining: &'a [u8],
    canonical: Vec<u8>,
}

impl RecordParser<'_> {
    fn member(&mut self, literal: &[u8], maximum: usize) -> Result<String> {
        let source = self.remaining.strip_prefix(literal).ok_or(Invalid)?;
        let (text, remaining) = decode_string_prefix(source, maximum)?;
        if text.is_empty() {
            return Err(Invalid);
        }
        let token = &source[..source.len() - remaining.len()];
        // Only escapes can give scalar-valid UTF-8 a second JSON representation.
        if token.len() != text.len() + 2 {
            self.canonical.clear();
            encode_string(&text, &mut self.canonical);
            if self.canonical != token {
                return Err(Invalid);
            }
        }
        self.remaining = remaining;
        Ok(text)
    }
}

impl std::fmt::Display for ApprovalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
