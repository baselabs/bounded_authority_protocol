use bounded_authority_protocol::approval_record::{decode_record, encode_record, RecordBounds};
use bounded_authority_protocol::{Bounds, Invalid, JsonValue};

fn wire(resources: &[u8]) -> Vec<u8> {
    [
        br#"{"action":"index","approver_role":"review","request_id":"request-1","resources":["#.as_slice(),
        resources,
        br#"],"revision_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","subject":"indexer","v":1}"#,
    ]
    .concat()
}

#[test]
fn requires_exact_canonical_tokens_and_scalar_utf8() {
    let bounds = Bounds::maximum();
    let limits = RecordBounds::default();
    for resources in [
        br#""\/", "z""#.as_slice(),
        br#""\/""#,
        br#""\u0061""#,
        br#""\u000A""#,
        br#""\u000a""#,
        br#""\ud800""#,
        br#""\ud83d\ude00""#,
        b"\"\xed\xa0\x80\"",
        b"\"\"",
    ] {
        assert_eq!(
            decode_record(&wire(resources), &bounds, &limits),
            Err(Invalid)
        );
    }
    let mut trailing = wire(br#""a""#);
    trailing.push(b'\n');
    assert_eq!(decode_record(&trailing, &bounds, &limits), Err(Invalid));
    let canonical = wire(br#""\u0000","\n","/","\\""#);
    let decoded = decode_record(&canonical, &bounds, &limits).unwrap();
    assert_eq!(
        encode_record(&decoded, &bounds, &limits, false).unwrap(),
        canonical
    );
}

#[test]
fn resources_sort_by_decoded_utf8_and_are_never_normalized() {
    let bounds = Bounds::maximum();
    let limits = RecordBounds::default();
    let canonical = wire("\"\\n\",\"a\",\"e\u{301}\",\"é\",\"\u{e000}\",\"😀\"".as_bytes());
    let record = decode_record(&canonical, &bounds, &limits).unwrap();
    assert_eq!(
        record.resources,
        ["\n", "a", "e\u{301}", "é", "\u{e000}", "😀"]
    );
    for resources in [
        b"\"a\",\"\\n\"".as_slice(),
        "\"😀\",\"\u{e000}\"".as_bytes(),
        b"\"same\",\"same\"",
    ] {
        assert_eq!(
            decode_record(&wire(resources), &bounds, &limits),
            Err(Invalid)
        );
    }
    let mut author = record.clone();
    author.resources.reverse();
    author.resources.push("a".into());
    assert_eq!(
        encode_record(&author, &bounds, &limits, false),
        Err(Invalid)
    );
    assert_eq!(
        encode_record(&author, &bounds, &limits, true).unwrap(),
        canonical
    );
}

#[test]
fn independent_decoded_string_count_and_encoded_byte_ceilings() {
    let bounds = Bounds::maximum();
    let resources = format!("\"{}\",\"z\"", "é".repeat(5));
    let canonical = wire(resources.as_bytes());
    let limits = RecordBounds {
        string_bytes: 10,
        resource_count: 2,
        record_bytes: canonical.len(),
    };
    // UTF-8 byte order places ASCII before é.
    let canonical = wire(format!("\"z\",\"{}\"", "é".repeat(5)).as_bytes());
    let record = decode_record(&canonical, &bounds, &limits).unwrap();
    for tighter in [
        RecordBounds {
            string_bytes: 9,
            ..limits
        },
        RecordBounds {
            resource_count: 1,
            ..limits
        },
        RecordBounds {
            record_bytes: canonical.len() - 1,
            ..limits
        },
    ] {
        assert_eq!(decode_record(&canonical, &bounds, &tighter), Err(Invalid));
        assert_eq!(
            encode_record(&record, &bounds, &tighter, false),
            Err(Invalid)
        );
    }
    let clamped = Bounds::new(Some(&JsonValue::Object(vec![(
        "content_bytes".into(),
        JsonValue::Int(canonical.len() as i64 - 1),
    )])))
    .unwrap();
    assert_eq!(decode_record(&canonical, &clamped, &limits), Err(Invalid));
}

#[test]
fn request_ids_require_ipv6_for_ip_literals() {
    let bounds = Bounds::maximum();
    let limits = RecordBounds::default();
    let original = String::from_utf8(wire(br#""a""#)).unwrap();
    for request in ["https://[::1]/r", "https://[::ffff:192.0.2.1]:42/r"] {
        let wire = original.replace("request-1", request);
        let parsed = decode_record(wire.as_bytes(), &bounds, &limits).unwrap();
        assert_eq!(parsed.request_id, request);
        assert_eq!(
            encode_record(&parsed, &bounds, &limits, false).unwrap(),
            wire.as_bytes()
        );
    }
    let mut record = decode_record(original.as_bytes(), &bounds, &limits).unwrap();
    for request in [
        "https://[v1.a]/r",
        "https://[VF.a:b]:42/r",
        "https://[v1.]/r",
        "https://[v1.a%20]/r",
        "https://[vg.a]/r",
        "https://[127.0.0.1]/r",
        "https://[::ffff:192.0.02.1]/r",
    ] {
        let wire = original.replace("request-1", request);
        assert_eq!(
            decode_record(wire.as_bytes(), &bounds, &limits),
            Err(Invalid)
        );
        record.request_id = request.into();
        assert_eq!(
            encode_record(&record, &bounds, &limits, false),
            Err(Invalid)
        );
    }
}
