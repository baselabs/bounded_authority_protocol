//! Execute the frozen candidate profile corpora against the public Rust API.
//!
//! The candidate corpora are source-only: they ship in no SDK snapshot until every maintained
//! runner executes them. Set `BAP_CANDIDATE_SOURCE` to a protocol checkout to run them.

mod support;

use bap::action_approval::{
    self, ApprovalContext, ApprovalResult, Diagnostic, Suite, TrustEntry, TrustKey, TrustSnapshot,
    VerifiedApprovalFacts, VerifiedAssertion,
};
use bap::approval_record::{decode_record, encode_record, ApprovalRecord, RecordBounds};
use bap::content_assertion::{self as ca1, AssertionFacts, DecodedAssertionClaims};
use bap::content_assertion_es256 as es256;
use bap::facts::{NotEvaluated, SignatureAndWindow};
use bap::types::{SigningInput, SigningKind, ValidityUpperBound};
use bap::{v1, v2, v3, Bounds, ContentAssertionInput, Invalid};
use bounded_authority_protocol as bap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const APPROVAL: &str = "content-profiles/action-approval/v1";
const ES256: &str = "attestation-profiles/content-assertion-es256/v1";

fn root(profile: &str) -> Option<PathBuf> {
    let source = std::env::var_os("BAP_CANDIDATE_SOURCE")?;
    Some(PathBuf::from(source).join("priv/conformance").join(profile))
}

fn s(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn string(value: &Value) -> String {
    s(value).to_owned()
}

fn raw(value: &Value) -> Vec<u8> {
    bap::base64url_decode(s(value).as_bytes()).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    String::from_utf8(bap::base64url_encode(bytes)).unwrap()
}

fn digest(value: &Value) -> [u8; 32] {
    raw(value).try_into().unwrap()
}

fn n(value: &Value) -> i64 {
    value.as_i64().unwrap()
}

fn suite(value: &Value) -> Suite {
    match s(value) {
        "eddsa" => Suite::EdDsa,
        "es256" => Suite::Es256,
        other => panic!("unknown suite {other}"),
    }
}

fn suite_name(value: Suite) -> &'static str {
    match value {
        Suite::EdDsa => "eddsa",
        Suite::Es256 => "es256",
    }
}

fn upper(value: &Value) -> Option<ValidityUpperBound> {
    if value == "unbounded" {
        Some(ValidityUpperBound::Unbounded)
    } else {
        value.as_i64().map(ValidityUpperBound::Bounded)
    }
}

fn bounds(value: &Value) -> bap::Result<Bounds> {
    Bounds::new(Some(&bap::json_decode(
        &serde_json::to_vec(value).unwrap(),
        &Bounds::maximum(),
    )?))
}

fn limits(value: &Value) -> Option<RecordBounds> {
    let mut bounds = RecordBounds::default();
    for (field, value) in value.as_object()? {
        let value = usize::try_from(value.as_u64()?).ok()?;
        match field.as_str() {
            "string_bytes" => bounds.string_bytes = value,
            "resource_count" => bounds.resource_count = value,
            "record_bytes" => bounds.record_bytes = value,
            _ => return None,
        }
    }
    Some(bounds)
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_owned))
        .collect()
}

fn record(value: &Value) -> Option<ApprovalRecord> {
    Some(ApprovalRecord {
        subject: value["subject"].as_str()?.into(),
        action: value["action"].as_str()?.into(),
        request_id: value["request_id"].as_str()?.into(),
        approver_role: value["approver_role"].as_str()?.into(),
        resources: strings(&value["resources"])?,
        revision_digest: raw(&value["revision_digest"]).try_into().ok()?,
    })
}

fn project_record(record: &ApprovalRecord) -> Value {
    json!({
        "v": 1, "subject": record.subject, "action": record.action, "request_id": record.request_id,
        "approver_role": record.approver_role, "resources": record.resources,
        "revision_digest": b64(&record.revision_digest),
    })
}

fn key(value: &Value) -> Option<TrustKey> {
    if value.as_object()?.len() != 4 {
        return None;
    }
    Some(TrustKey {
        key_id: value["key_id"].as_str()?.into(),
        public_key: bap::base64url_decode(value["public_key"].as_str()?.as_bytes()).ok()?,
        valid_from: value["valid_from"].as_i64()?,
        valid_before: upper(&value["valid_before"])?,
    })
}

fn entry(value: &Value) -> Option<TrustEntry> {
    Some(TrustEntry {
        issuer: value["issuer"].as_str()?.into(),
        key: key(&value["key"])?,
        roles: strings(&value["roles"])?,
    })
}

fn project_entry(entry: &TrustEntry) -> Value {
    let before = match entry.key.valid_before {
        ValidityUpperBound::Bounded(before) => json!(before),
        ValidityUpperBound::Unbounded => json!("unbounded"),
    };
    json!({"issuer": entry.issuer, "roles": entry.roles, "key": {
        "key_id": entry.key.key_id, "public_key": b64(&entry.key.public_key),
        "valid_from": entry.key.valid_from, "valid_before": before,
    }})
}

fn snapshot(value: &Value) -> Option<TrustSnapshot> {
    Some(TrustSnapshot {
        suite: suite(value.get("suite")?),
        trust_domain: value["trust_domain"].as_str()?.into(),
        provenance: value["provenance"].as_str()?.into(),
        as_of: value["as_of"].as_i64()?,
        entries: value["entries"]
            .as_array()?
            .iter()
            .map(entry)
            .collect::<Option<_>>()?,
    })
}

// Rust's typed inputs already exclude malformed field types. A failure to build
// expected values is a context error; a snapshot that cannot be constructed is unavailable.
fn context(value: &Value) -> Option<ApprovalContext> {
    Some(ApprovalContext {
        trust_domain: value["trust_domain"].as_str()?.into(),
        audience: value["audience"].as_str()?.into(),
        request_id: value["request_id"].as_str()?.into(),
        revision_digest: raw(&value["revision_digest"]).try_into().ok()?,
        subject: value["subject"].as_str()?.into(),
        action: value["action"].as_str()?.into(),
        resources: strings(&value["resources"])?,
        roles: strings(&value["roles"])?,
        now: value["now"].as_i64()?,
        max_staleness: value["max_staleness"].as_i64()?,
        max_lifetime: value["max_lifetime"].as_i64()?,
        max_active: match value.get("max_active") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_i64()?),
        },
        bounds: bounds(&value["bounds"]).ok()?,
        record_bounds: limits(&value["record_bounds"])?,
        snapshot: snapshot(&value["snapshot"]),
    })
}

fn pure(case: &Value) -> Result<VerifiedApprovalFacts, Diagnostic> {
    let ctx = context(&case["context"]).ok_or(Diagnostic::InvalidContext)?;
    let wire = raw(&case["record"]);
    let compact = s(&case["compact"]).as_bytes();
    match suite(&case["suite"]) {
        Suite::EdDsa => action_approval::verify_approval_eddsa(&wire, compact, &ctx),
        Suite::Es256 => action_approval::verify_approval_es256(&wire, compact, &ctx),
    }
}

fn project_pure(case: &Value) -> Value {
    match pure(case) {
        Err(d) => json!(d.code()),
        Ok(f) => json!({
            "suite": suite_name(f.suite), "trust_domain": f.trust_domain, "trust": match f.trust { NotEvaluated => "not_evaluated" },
            "record": project_record(&f.record), "assertion": match &f.assertion {
                VerifiedAssertion::EdDsa(f) => project_assertion(f),
                VerifiedAssertion::Es256(f) => project_assertion(f),
            },
        }),
    }
}

fn record_case(case: &Value) -> bap::Result<Value> {
    let ca = bounds(&case["ca_bounds"])?;
    let limits = limits(&case["bounds"]).ok_or(Invalid)?;
    let input = if let Some(value) = case.get("wire") {
        decode_record(&raw(value), &ca, &limits)?
    } else {
        record(&case["author"]).ok_or(Invalid)?
    };
    let wire = encode_record(&input, &ca, &limits, case["canonicalize"] == true)?;
    Ok(json!({"wire": b64(&wire), "content_digest": b64(&ca1::content_digest(&wire, &ca)?)}))
}

fn helper(
    case: &Value,
    replayed: impl FnOnce(&str, &str, &str) -> Option<bool>,
    revoked: impl FnOnce(&TrustEntry, &[u8; 32]) -> Option<bool>,
) -> ApprovalResult {
    let ctx = context(&case["context"]).ok_or(Diagnostic::InvalidContext)?;
    action_approval::verify(
        &raw(&case["record"]),
        s(&case["compact"]).as_bytes(),
        ctx.snapshot.as_ref(),
        ctx.now,
        ctx.max_lifetime,
        replayed,
        revoked,
        suite(&case["suite"]),
        &ctx,
    )
}

fn observation(value: &Value) -> Option<bool> {
    if value == "exception" || value == "cancelled" {
        // Raise an unwind without invoking the process's panic hook.
        std::panic::resume_unwind(Box::new("test predicate failure"));
    }
    value.as_bool()
}

fn helper_case(case: &Value, source: &Value) -> Value {
    let calls = RefCell::new(Vec::new());
    let observations = &case["observations"];
    let result = helper(
        source,
        |domain, issuer, id| {
            calls
                .borrow_mut()
                .push(json!({"predicate": "is_replayed", "arguments": [domain, issuer, id]}));
            observation(&observations["is_replayed"])
        },
        |entry, fingerprint| {
            calls.borrow_mut().push(json!({"predicate": "is_revoked", "arguments": [project_entry(entry), b64(fingerprint)]}));
            observation(&observations["is_revoked"])
        },
    );
    json!({
        "calls": calls.into_inner(),
        "helper": match &result { Ok(_) => "approved", Err(d) => d.code() },
        "presenter": if action_approval::presenter_result(&result).is_ok() { "approved" } else { "invalid" },
        "rendering": action_approval::render_presenter_result(&result),
    })
}

fn rendering_case(case: &Value, source: &Value) -> Value {
    let result = pure(source);
    let output = match s(&case["id"]) {
        "verified-facts" | "host-local-error" => {
            json!(action_approval::render_verification_result(&result))
        }
        "nested-record" => json!(format!("{:?}", result.as_ref().unwrap().record)),
        "nested-assertion" => json!(format!("{:?}", result.as_ref().unwrap().assertion)),
        "presenter-error" => json!(action_approval::render_presenter_result(&Err(result
            .as_ref()
            .unwrap_err()
            .to_owned()))),
        "helper-exception" => {
            let cause = case["inputs"]["provider_cause"].clone();
            let result = helper(
                source,
                |_, _, _| unreachable!(),
                |_, _| std::panic::resume_unwind(Box::new(cause)),
            );
            json!({
                "local": result.as_ref().unwrap_err().to_string(),
                "presenter": action_approval::render_presenter_result(&result),
            })
        }
        other => panic!("unexpected rendering case: {other}"),
    };
    let rendered = [output.to_string(), format!("{result:?}")];
    for spellings in case["forbidden"]
        .as_object()
        .into_iter()
        .flat_map(|map| map.values())
    {
        for spelling in spellings.as_array().unwrap() {
            assert!(rendered.iter().all(|value| !value.contains(s(spelling))));
        }
    }
    output
}

fn project_decoded<const ES: bool>(value: &DecodedAssertionClaims<ES>) -> Value {
    json!({
        "v": value.version, "attestor_key_id": value.attestor_key_id, "jti": value.jti,
        "iss": value.iss, "aud": value.aud, "sub": value.sub, "profile": value.profile,
        "profile_digest": b64(&value.profile_digest), "content_digest": b64(&value.content_digest),
        "gen": value.generation, "prev": b64(&value.previous), "iat": value.issued_at,
        "nbf": value.not_before, "exp": value.expires_at,
    })
}

fn project_assertion<const ES: bool>(value: &AssertionFacts<ES>) -> Value {
    json!({
        "version": value.version, "attestor_key_id": value.attestor_key_id, "jti": value.jti,
        "iss": value.iss, "aud": value.aud, "sub": value.sub, "profile": value.profile,
        "profile_digest": b64(&value.profile_digest), "content_digest": b64(&value.content_digest),
        "gen": value.generation, "prev": b64(&value.previous), "iat": value.issued_at,
        "nbf": value.not_before, "exp": value.expires_at, "digest": b64(&value.digest),
        "attestor_key_fingerprint": b64(&value.attestor_key_fingerprint),
        "verification": match value.verification { SignatureAndWindow => "signature_and_window" }, "trust": match value.trust { NotEvaluated => "not_evaluated" },
    })
}

fn producer(signing: &Value) -> ContentAssertionInput {
    let p = &signing["payload"];
    ContentAssertionInput {
        attestor_key_id: string(&signing["kid"]),
        jti: string(&p["jti"]),
        iss: string(&p["iss"]),
        aud: string(&p["aud"]),
        sub: string(&p["sub"]),
        profile: string(&p["profile"]),
        profile_digest: digest(&p["profile_digest"]),
        content_digest: digest(&p["content_digest"]),
        generation: n(&p["gen"]),
        previous: digest(&p["prev"]),
        issued_at: n(&p["iat"]),
        not_before: n(&p["nbf"]),
        expires_at: n(&p["exp"]),
    }
}

fn facts(value: &Value) -> bap::Result<es256::ContentAssertionFacts> {
    if value["verification"] != "signature_and_window" || value["trust"] != "not_evaluated" {
        return Err(Invalid);
    }
    Ok(AssertionFacts {
        version: n(&value["version"]),
        attestor_key_id: string(&value["attestor_key_id"]),
        jti: string(&value["jti"]),
        iss: string(&value["iss"]),
        aud: string(&value["aud"]),
        sub: string(&value["sub"]),
        profile: string(&value["profile"]),
        profile_digest: digest(&value["profile_digest"]),
        content_digest: digest(&value["content_digest"]),
        generation: n(&value["gen"]),
        previous: digest(&value["prev"]),
        issued_at: n(&value["iat"]),
        not_before: n(&value["nbf"]),
        expires_at: n(&value["exp"]),
        digest: digest(&value["digest"]),
        attestor_key_fingerprint: digest(&value["attestor_key_fingerprint"]),
        trust: NotEvaluated,
        verification: SignatureAndWindow,
    })
}

fn expected_assertion(value: &Value) -> bap::Result<es256::ExpectedContentAssertion> {
    let key = key(&value["attestor"]).ok_or(Invalid)?;
    Ok(es256::ExpectedContentAssertion {
        attestor: v3::HistoricalPublicKey {
            key_id: key.key_id,
            public_key: key.public_key.try_into().map_err(|_| Invalid)?,
            valid_from: key.valid_from,
            valid_before: key.valid_before,
        },
        issuer: string(&value["issuer"]),
        audience: string(&value["audience"]),
        subject: string(&value["subject"]),
        profile: string(&value["profile"]),
        profile_digest: digest(&value["profile_digest"]),
        content_digest: digest(&value["content_digest"]),
        now: n(&value["now"]),
        bounds: Bounds::maximum(),
    })
}

fn foreign_accepts(id: &str, compact: &[u8], b: &Bounds) -> bool {
    let (major, kind) = match id {
        "ca1" => return ca1::decode_content_assertion(compact, b).is_ok(),
        "loopback" => return v1::decode_local_loopback_http_proof(compact, b).is_ok(),
        "role-attestation" => return bap::decode_attestation(compact, b).is_ok(),
        "v1-grant" => return v1::decode_grant(compact, b).is_ok(),
        "v1-proof" => return v1::decode_proof(compact, b).is_ok(),
        "v2-grant" => return v2::decode_grant(compact, b).is_ok(),
        "v2-proof" => return v2::decode_proof(compact, b).is_ok(),
        "v3-grant" => return v3::decode_grant(compact, b).is_ok(),
        "v3-proof" => return v3::decode_proof(compact, b).is_ok(),
        other => other.split_once('-').unwrap(),
    };
    // The major facades expose structure checking for these kinds through assembly.
    let parts: Vec<_> = compact.split(|b| *b == b'.').collect();
    let sig = bap::base64url_decode(parts[2]).unwrap().try_into().unwrap();
    let input = SigningInput {
        kind: match kind {
            "anchor" => SigningKind::ChainAnchor,
            "transition" => SigningKind::KeyTransition,
            _ => panic!("unknown kind"),
        },
        protected_segment: parts[0].to_vec(),
        payload_segment: parts[1].to_vec(),
    };
    let result = match major {
        "v1" => v1::assemble_compact(&input, &sig, Some(b)),
        "v2" => v2::assemble_compact(&input, &sig, Some(b)),
        "v3" => v3::assemble_compact(&input, &sig, Some(b)),
        _ => panic!("unknown major"),
    };
    result.as_deref() == Ok(compact)
}

fn es256_case(name: &str, case: &Value, signing: &SigningInput) -> bap::Result<Value> {
    let b = Bounds::maximum();
    match name {
        "assembly-cases.json" => {
            let compact = es256::assemble_compact(signing, &raw(&case["signature"]), None)?;
            Ok(json!(String::from_utf8(compact).unwrap()))
        }
        "assertion-structure-cases.json" => {
            let compact = s(&case["compact"]).as_bytes();
            let b = bounds(&case["bounds"])?;
            let decoded = es256::decode_assertion(compact, &b);
            let digest = es256::assertion_digest(compact, &b);
            assert_eq!(decoded.is_ok(), digest.is_ok());
            let mut out = project_decoded(&decoded?);
            out["digest"] = json!(b64(&digest?));
            Ok(out)
        }
        "assertion-verification-cases.json" => Ok(project_assertion(&es256::verify_assertion(
            s(&case["compact"]).as_bytes(),
            &expected_assertion(&case["context"])?,
        )?)),
        "digest-cases.json" => Ok(json!(b64(&es256::content_digest(
            &raw(&case["input"]),
            &bounds(&case["bounds"])?,
        )?))),
        "separation-cases.json" => {
            let id = s(&case["id"]);
            let foreign = s(&case["foreign"]).as_bytes();
            let candidate = s(&case["candidate"]).as_bytes();
            assert!(foreign_accepts(id, foreign, &b), "{id}");
            assert!(es256::decode_assertion(candidate, &b).is_ok(), "{id}");
            assert!(es256::decode_assertion(foreign, &b).is_err(), "{id}");
            assert!(!foreign_accepts(id, candidate, &b), "{id}");
            Ok(json!("both_reject"))
        }
        "successor-cases.json" => {
            // A mixed-suite call cannot be expressed by either Rust successor API.
            if suite(&case["previous_suite"]) != Suite::Es256
                || suite(&case["next_suite"]) != Suite::Es256
            {
                return Err(Invalid);
            }
            es256::verify_successor(
                &facts(&case["predecessor"])?,
                &facts(&case["successor"])?,
                &b,
            )?;
            Ok(json!("ok"))
        }
        other => panic!("unknown ES256 case file {other}"),
    }
}

fn run(
    profile: &str,
    pin: &str,
    expected_count: usize,
    outcome: impl Fn(&str, &Value, &Value, &BTreeMap<&str, &Value>) -> Value,
) {
    let Some(root) = root(profile) else {
        eprintln!("{profile}: skipped; set BAP_CANDIDATE_SOURCE to run source-only conformance");
        return;
    };
    let (index, cases) = support::load_index(&root, pin);
    let meta = serde_json::from_slice(&fs::read(root.join("profile.json")).unwrap()).unwrap();
    assert_eq!(cases.len(), expected_count);
    let by_id = cases
        .iter()
        .map(|(_, case)| (s(&case["id"]), case))
        .collect();
    let actual: Vec<_> = cases
        .iter()
        .map(|(file, case)| {
            let computed = outcome(file, case, &meta, &by_id);
            assert_eq!(computed, case["expected"], "{file}/{}", s(&case["id"]));
            json!([format!("{file}/{}", s(&case["id"])), computed])
        })
        .collect();
    let verdict: String = Sha256::digest(serde_json::to_vec(&actual).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(index["verdict_sha256"], verdict);
    let elixir_cases: Vec<_> = actual
        .iter()
        .zip(&cases)
        .filter(|(_, (file, case))| file != "helper-cases.json" && case["owner"] != "sdk_helper")
        .map(|(outcome, _)| outcome)
        .collect();
    let elixir_verdict: String = Sha256::digest(serde_json::to_vec(&elixir_cases).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(index["elixir_verdict_sha256"], elixir_verdict);
    println!(
        "{profile}: {} cases, verdict SHA-256 {verdict}",
        cases.len()
    );
}

#[test]
fn action_approval_candidate() {
    run(
        APPROVAL,
        "35470198349f2b03b0c5df4368569a437eae39847fa4b8df1cd1f24b33d6f826",
        309,
        |name, case, _, by_id| match name {
            "approval-cases.json" | "multi-fault-cases.json" => project_pure(case),
            "record-cases.json" => record_case(case).unwrap_or(json!("invalid")),
            "helper-cases.json" => helper_case(case, by_id[s(&case["pure_case"])]),
            "rendering-cases.json" => rendering_case(case, by_id[s(&case["pure_case"])]),
            other => panic!("unknown approval case file {other}"),
        },
    );
}

#[test]
fn es256_content_assertion_candidate() {
    run(
        ES256,
        "d79329d431de093f162613fbd2a2fe838766b690fa67cfbc1478eafa322b3c63",
        217,
        |name, case, metadata, _| {
            let m = &metadata["signing"];
            let signing = es256::assertion_signing_input(&producer(m), &Bounds::maximum()).unwrap();
            assert_eq!(signing.kind, SigningKind::ContentAssertionEs256);
            assert_eq!(signing.message(), s(&m["expected"]["message"]).as_bytes());
            assert_eq!(
                signing.protected_segment,
                s(&m["expected"]["protected_segment"]).as_bytes()
            );
            assert_eq!(
                signing.payload_segment,
                s(&m["expected"]["payload_segment"]).as_bytes()
            );
            es256_case(name, case, &signing).unwrap_or(json!("invalid"))
        },
    );
}
