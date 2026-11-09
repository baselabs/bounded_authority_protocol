//! Erratum 6 (selector float-zero soundness repair), through the public façades of all three
//! contract-majors: grant decode rejects a float-tagged zero anywhere inside an `equals` value or
//! a `one_of` member and leaves range bounds and inert `all` members alone; the grant
//! signing-input producer refuses every float-tagged integral selector value, range bounds
//! included. Selector values are written as JSON text and decoded with the crate's own
//! tag-preserving decoder, so `0.0` stays a float and `0` an integer.

#![forbid(unsafe_code)]

use bounded_authority_protocol as bap;
use bounded_authority_protocol::types::{GrantInput, GrantOperation, ProducedSigningInput};
use bounded_authority_protocol::{v2, v3, Bounds, JsonValue, Result};

const MAJORS: [u8; 3] = [1, 2, 3];

fn max() -> Bounds {
    Bounds::maximum()
}

/// A grant compact whose single operation carries `selector` (JSON text, inserted verbatim so
/// the lexeme reaches the decoder unchanged). Decode never checks the signature segment.
fn grant_compact(major: u8, selector: &str) -> Vec<u8> {
    let alg = if major == 3 { "ES256" } else { "EdDSA" };
    let header = format!(r#"{{"alg":"{alg}","kid":"issuer","typ":"ba+cap"}}"#);
    let payload = format!(
        concat!(
            r#"{{"aud":["https://resource.example.test"],"#,
            r#""cnf":{{"jkt":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}},"#,
            r#""exp":2000,"iat":1000,"iss":"https://issuer.example.test","#,
            r#""jti":"urn:example:grant:float-zero","nbf":1000,"#,
            r#""operations":[{{"name":"transfer","selectors":[{}]}}],"v":{}}}"#
        ),
        selector, major
    );
    let mut compact = bap::base64url_encode(header.as_bytes());
    compact.push(b'.');
    compact.extend(bap::base64url_encode(payload.as_bytes()));
    compact.push(b'.');
    compact.extend(bap::base64url_encode(&[0x11u8; 64]));
    compact
}

fn decodes(major: u8, selector: &str) -> bool {
    let compact = grant_compact(major, selector);
    match major {
        1 => bap::decode_grant(&compact, &max()).is_ok(),
        2 => v2::decode_grant(&compact, &max()).is_ok(),
        3 => v3::decode_grant(&compact, &max()).is_ok(),
        m => panic!("major {m}"),
    }
}

fn typed(text: &str) -> JsonValue {
    bap::json_decode(text.as_bytes(), &max()).expect("test JSON decodes")
}

fn signs(major: u8, selector: &str) -> bool {
    let grant = GrantInput {
        issuer: "https://issuer.example.test".to_string(),
        grant_id: "urn:example:grant:float-zero".to_string(),
        key_id: "issuer".to_string(),
        holder_thumbprint: [7u8; 32],
        issued_at: 1000,
        not_before: 1000,
        expires_at: 2000,
        audiences: vec!["https://resource.example.test".to_string()],
        operations: vec![GrantOperation {
            name: "transfer".to_string(),
            selectors: vec![typed(selector)],
        }],
    };
    let produced: Result<ProducedSigningInput> = match major {
        1 => bap::grant_signing_input(&grant, &max()),
        2 => v2::grant_signing_input(&grant, &max()),
        3 => v3::grant_signing_input(&grant, &max()),
        m => panic!("major {m}"),
    };
    produced.is_ok()
}

fn equals(value: &str) -> String {
    format!(r#"{{"kind":"equals","path":["x"],"value":{value}}}"#)
}

fn one_of(values: &str) -> String {
    format!(r#"{{"kind":"one_of","path":["x"],"values":{values}}}"#)
}

fn range(kind: &str, bound: &str) -> String {
    format!(r#"{{"kind":"{kind}","path":["x"],"value":{bound}}}"#)
}

#[test]
fn decode_rejects_float_zero_in_equals_and_one_of_at_any_depth() {
    let zeros = [
        "0.0", "-0.0", "0e0", "-0e0", "-0E0", "-0e-5", "0.000", "1e-400", "-1e-400", "0E+3",
    ];
    for major in MAJORS {
        for zero in zeros {
            assert!(!decodes(major, &equals(zero)), "v{major} equals {zero}");
            assert!(
                !decodes(major, &one_of(&format!("[1,{zero}]"))),
                "v{major} one_of {zero}"
            );
            let deep = format!(r#"[{{"a":[true,{{"b":[{zero}]}}]}}]"#);
            assert!(
                !decodes(major, &equals(&deep)),
                "v{major} deep equals {zero}"
            );
            assert!(
                !decodes(major, &one_of(&format!("[{deep}]"))),
                "v{major} deep one_of {zero}"
            );
        }
    }
}

#[test]
fn decode_keeps_integers_non_zero_floats_ranges_and_inert_all_members() {
    for major in MAJORS {
        for value in [
            "0",
            "-0",
            "0.5",
            "-2.25",
            "10.0",
            "1e1",
            "[0,1.5]",
            r#"{"a":0}"#,
        ] {
            assert!(decodes(major, &equals(value)), "v{major} equals {value}");
        }
        assert!(
            decodes(major, &one_of("[0,10.0,-2.25]")),
            "v{major} one_of control"
        );
        for inert in ["0.0", "-0.0", "[-0e0]"] {
            let all = format!(r#"{{"kind":"all","path":["x"],"value":{inert}}}"#);
            assert!(decodes(major, &all), "v{major} all inert {inert}");
        }
    }
    for major in [2, 3] {
        for bound in ["0.0", "-0.0", "-0e0", "1e-400"] {
            assert!(decodes(major, &range("lte", bound)), "v{major} lte {bound}");
            assert!(decodes(major, &range("gte", bound)), "v{major} gte {bound}");
        }
    }
}

#[test]
fn producer_refuses_integral_float_selector_values_at_any_depth() {
    let integral = ["0.0", "-0.0", "10.0", "-3.0", "4503599627370496.0", "1e1"];
    for major in MAJORS {
        for value in integral {
            assert!(!signs(major, &equals(value)), "v{major} equals {value}");
            assert!(
                !signs(major, &one_of(&format!("[1,{value}]"))),
                "v{major} one_of {value}"
            );
            let deep = format!(r#"{{"a":[0.5,{{"b":{value}}}]}}"#);
            assert!(
                !signs(major, &equals(&deep)),
                "v{major} deep equals {value}"
            );
            assert!(
                !signs(major, &one_of(&format!("[{deep}]"))),
                "v{major} deep one_of {value}"
            );
        }
    }
    for major in [2, 3] {
        for bound in integral {
            assert!(!signs(major, &range("lte", bound)), "v{major} lte {bound}");
            assert!(!signs(major, &range("gte", bound)), "v{major} gte {bound}");
        }
    }
}

#[test]
fn producer_still_signs_integers_and_non_integral_floats() {
    for major in MAJORS {
        for value in ["0", "-7", "0.5", "-2.25", r#"[0,1.5,{"a":-0.25}]"#] {
            assert!(signs(major, &equals(value)), "v{major} equals {value}");
        }
        assert!(signs(major, &one_of("[10,0.5]")), "v{major} one_of control");
    }
    for major in [2, 3] {
        for bound in ["0", "10", "0.5", "-2.25"] {
            assert!(signs(major, &range("lte", bound)), "v{major} lte {bound}");
            assert!(signs(major, &range("gte", bound)), "v{major} gte {bound}");
        }
    }
}
