//! Specified diagnostic rendering (spec/diagnostic-rendering.md § Diagnostic rendering), including shared container and printable limits.
use crate::json::JsonValue;

pub(crate) enum Term<'a> {
    Atom(String),
    Scalar(String),
    Binary(Vec<u8>, bool),
    List(Vec<Term<'a>>),
    Tuple(Vec<Term<'a>>),
    Struct(String, Vec<Term<'a>>),
    Tagged(&'a JsonValue),
    Ordinary(&'a JsonValue),
    Array(&'a [JsonValue]),
    Object(&'a [(String, JsonValue)]),
    Path(&'a [JsonValue]),
    Selectors(&'a [JsonValue]),
    Operations(&'a [JsonValue], i64),
    Texts(&'a [String]),
    Unrenderable,
}
fn identifier(v: &str) -> bool {
    let bytes = v.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() && *first != b'_' {
        return false;
    }
    let tail = &bytes[1..];
    let tail = if matches!(tail.last(), Some(b'?' | b'!')) {
        &tail[..tail.len() - 1]
    } else {
        tail
    };
    tail.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}
pub(crate) fn atom(v: &str) -> Term<'static> {
    if identifier(v) {
        Term::Atom(v.into())
    } else {
        Term::Unrenderable
    }
}
pub(crate) fn int(v: i64) -> Term<'static> {
    Term::Scalar(v.to_string())
}
pub(crate) fn text(v: &str) -> Term<'static> {
    raw(v.as_bytes())
}
pub(crate) fn raw(v: &[u8]) -> Term<'static> {
    // Four bytes per scalar bounds both the scan and escaping work.
    Term::Binary(v[..v.len().min(16384)].to_vec(), v.len() > 16384)
}
pub(crate) fn structure<'a>(name: String, fields: Vec<(&str, Term<'a>)>) -> Term<'a> {
    Term::Struct(
        name,
        fields
            .into_iter()
            .map(|(k, v)| Term::Tuple(vec![atom(k), v]))
            .collect(),
    )
}
// Decode only the next scalar; a malformed sequence leaves one raw byte to escape.
fn next_scalar(raw: &[u8]) -> Option<(char, usize)> {
    let width = match *raw.first()? {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let scalar = std::str::from_utf8(raw.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}
fn quoted(raw: &[u8], more: bool) -> Option<String> {
    let mut scan = raw;
    for _ in 0..4096 {
        if scan.is_empty() {
            break;
        }
        let (c, width) = next_scalar(scan)?;
        if !matches!(c as u32,7..=13|27|32..=127|160..=55295|57344..=65533|65536..=1114111) {
            return None;
        }
        scan = &scan[width..];
    }
    let mut out = String::from("\"");
    let mut rest = raw;
    for _ in 0..4096 {
        if rest.is_empty() {
            break;
        }
        if rest.starts_with(b"#{") {
            rest = &rest[2..];
            out.push_str("\\#{");
            continue;
        }
        let Some((c, width)) = next_scalar(rest) else {
            out.push_str(&format!("\\x{:02X}", rest[0]));
            rest = &rest[1..];
            continue;
        };
        rest = &rest[width..];
        match c {
            '\0' => out.push_str("\\0"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\e"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7f}' => out.push_str("\\d"),
            c if matches!(c as u32,0xFEFF|0x061C|0x200E|0x200F|0x200C|0x200D|0x034F|0x00A0|0x200B|0x2060|0x2028|0x2029|0x205F|0x2061..=0x2064|0x202A..=0x202E|0x2066..=0x2069|0xFFF9..=0xFFFC|0x2000..=0x200A) => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c if matches!(c as u32,1..=31|128..=159) => {
                out.push_str(&format!("\\x{:02X}", c as u32))
            }
            '\u{fffe}' | '\u{ffff}' => out.push_str(&format!("\\x{{{:04X}}}", c as u32)),
            _ => out.push(c),
        }
    }
    out.push('"');
    if more || !rest.is_empty() {
        out.push_str(" <> ...");
    }
    Some(out)
}
// Scalar rendering specifies notation separately from the shortest round-trip digits.
fn float(value: f64) -> String {
    if !value.is_finite() {
        return "#unrenderable".into();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .into();
    }
    let shortest = format!("{:e}", value.abs());
    let (coefficient, exponent) = shortest.split_once('e').unwrap();
    let exponent: i32 = exponent.parse().unwrap();
    let digits = coefficient.replace('.', "");
    let scientific = format!(
        "{}.{}e{exponent}",
        &digits[..1],
        if digits.len() == 1 { "0" } else { &digits[1..] }
    );
    let point = exponent + 1;
    let fixed = if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
    } else {
        let point = point as usize;
        format!("{}.{}", &digits[..point], &digits[point..])
    };
    let notation = if value.abs() < 9007199254740992.0 && fixed.len() <= scientific.len() {
        fixed
    } else {
        scientific
    };
    if value.is_sign_negative() {
        format!("-{notation}")
    } else {
        notation
    }
}
pub(crate) fn render(term: &Term<'_>) -> String {
    walk(term, &mut 200)
}
fn container(
    values: &[Term<'_>],
    left: &str,
    right: &str,
    keyword: bool,
    remaining: &mut usize,
) -> String {
    let mut parts = Vec::new();
    for value in values {
        if *remaining == 0 {
            parts.push("...".into());
            break;
        }
        *remaining -= 1;
        if keyword {
            if let Term::Tuple(pair) = value {
                if let Term::Atom(key) = &pair[0] {
                    parts.push(format!("{key}: {}", walk(&pair[1], remaining)));
                }
            }
        } else {
            parts.push(walk(value, remaining));
        }
    }
    format!("{left}{}{right}", parts.join(", "))
}
fn sequence<'a>(
    length: usize,
    get: impl Fn(usize) -> Term<'a>,
    left: &str,
    right: &str,
    keyword: bool,
    remaining: &mut usize,
) -> String {
    let mut parts = Vec::new();
    for index in 0..length {
        if *remaining == 0 {
            parts.push("...".into());
            break;
        }
        *remaining -= 1;
        let value = get(index);
        if keyword {
            if let Term::Tuple(pair) = match value {
                Term::Tagged(v) => tagged(v),
                other => other,
            } {
                if let Term::Atom(key) = &pair[0] {
                    parts.push(format!("{key}: {}", walk(&pair[1], remaining)));
                }
            }
        } else {
            parts.push(walk(&value, remaining));
        }
    }
    format!("{left}{}{right}", parts.join(", "))
}
fn walk(term: &Term<'_>, remaining: &mut usize) -> String {
    match term {
        Term::Unrenderable => "#unrenderable".into(),
        Term::Tagged(v) => walk(&tagged(v), remaining),
        Term::Ordinary(v) => walk(&ordinary(v), remaining),
        Term::Array(v) => sequence(
            v.len(),
            |i| Term::Tagged(&v[i]),
            "[",
            "]",
            v.iter().all(|v| !matches!(v, JsonValue::Null)),
            remaining,
        ),
        Term::Object(v) => sequence(
            v.len(),
            |i| Term::Tuple(vec![text(&v[i].0), Term::Tagged(&v[i].1)]),
            "[",
            "]",
            false,
            remaining,
        ),
        Term::Path(v) => sequence(v.len(), |i| ordinary(&v[i]), "[", "]", false, remaining),
        Term::Selectors(v) => sequence(v.len(), |i| selector(&v[i]), "[", "]", false, remaining),
        Term::Operations(v, version) => sequence(
            v.len(),
            |i| operation(&v[i], *version),
            "[",
            "]",
            false,
            remaining,
        ),
        Term::Texts(v) => sequence(v.len(), |i| text(&v[i]), "[", "]", false, remaining),
        Term::Atom(v) => {
            if matches!(v.as_str(), "true" | "false" | "nil") {
                v.clone()
            } else {
                format!(":{v}")
            }
        }
        Term::Scalar(v) => v.clone(),
        Term::Binary(v, more) => {
            if let Some(s) = quoted(v, *more) {
                return s;
            }
            let count = v.len().min(*remaining);
            let mut parts: Vec<_> = v[..count].iter().map(u8::to_string).collect();
            if *more || count < v.len() {
                parts.push("...".into());
            }
            *remaining = remaining.saturating_sub(v.len());
            format!("<<{}>>", parts.join(", "))
        }
        Term::Struct(name, values) => {
            container(values, &format!("%{name}{{"), "}", true, remaining)
        }
        Term::Tuple(values) => container(values, "{", "}", false, remaining),
        Term::List(values) => {
            let keyword = !values.is_empty()
                && values.iter().all(
                    |v| matches!(v,Term::Tuple(p) if p.len()==2&&matches!(&p[0],Term::Atom(_))),
                );
            container(values, "[", "]", keyword, remaining)
        }
    }
}
pub(crate) fn binary(value: &[u8]) -> String {
    render(&raw(value))
}
pub(crate) fn string(value: &str) -> String {
    render(&text(value))
}
fn member<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    if let JsonValue::Object(m) = value {
        m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    } else {
        None
    }
}
fn tagged(value: &JsonValue) -> Term<'_> {
    let (tag, value) = match value {
        JsonValue::Null => return atom("null"),
        JsonValue::Bool(v) => ("boolean", atom(if *v { "true" } else { "false" })),
        JsonValue::Int(v) => ("integer", int(*v)),
        JsonValue::Float(v) => ("float", Term::Scalar(float(*v))),
        JsonValue::String(v) => ("string", text(v)),
        JsonValue::Array(v) => ("array", Term::Array(v)),
        JsonValue::Object(v) => ("object", Term::Object(v)),
    };
    Term::Tuple(vec![atom(tag), value])
}
fn ordinary(value: &JsonValue) -> Term<'_> {
    match value {
        JsonValue::Null => atom("nil"),
        JsonValue::Bool(v) => atom(if *v { "true" } else { "false" }),
        JsonValue::Int(v) => int(*v),
        JsonValue::Float(v) => Term::Scalar(float(*v)),
        JsonValue::String(v) => text(v),
        JsonValue::Array(v) => Term::Path(v),
        JsonValue::Object(_) => Term::Unrenderable,
    }
}
fn selector(value: &JsonValue) -> Term<'_> {
    let Some(JsonValue::String(kind)) = member(value, "kind") else {
        return Term::Unrenderable;
    };
    if kind == "all" {
        return atom("all");
    }
    let Some(JsonValue::Array(path)) = member(value, "path") else {
        return Term::Unrenderable;
    };
    if !path.iter().all(|v| matches!(v, JsonValue::String(_))) {
        return Term::Unrenderable;
    }
    let operand = if kind == "one_of" {
        let Some(JsonValue::Array(v)) = member(value, "values") else {
            return Term::Unrenderable;
        };
        Term::Array(v)
    } else {
        let Some(v) = member(value, "value") else {
            return Term::Unrenderable;
        };
        Term::Tagged(v)
    };
    Term::Tuple(vec![atom(kind), Term::Path(path), operand])
}
fn operation(value: &JsonValue, version: i64) -> Term<'_> {
    let (Some(name), Some(selectors)) = (member(value, "name"), member(value, "selectors")) else {
        return Term::Unrenderable;
    };
    let selectors = if let JsonValue::Array(v) = selectors {
        Term::Selectors(v)
    } else {
        Term::Ordinary(selectors)
    };
    structure(
        format!("BoundedAuthorityProtocol.V{version}.Operation"),
        vec![("name", Term::Ordinary(name)), ("selectors", selectors)],
    )
}
pub(crate) fn operations(values: &[JsonValue], version: i64) -> Term<'_> {
    if values.is_empty() {
        Term::List(Vec::new())
    } else {
        Term::Operations(values, version)
    }
}
// Test fixtures resolve from the crate root, so the path never leaves the SDK.
#[cfg(test)]
macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/",
            $name
        ))
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn float_notation_matches_specified_fixture_bytes() {
        let gold: serde_json::Value =
            serde_json::from_str(fixture!("decoded-rendering.json")).unwrap();
        for (key, expected) in gold.as_object().unwrap() {
            if let Some(number) = key.strip_prefix("float:") {
                let number = crate::json::JsonValue::Float(number.parse().unwrap());
                let value = super::tagged(&number);
                assert_eq!(
                    super::render(&value),
                    format!("{{:float, {}}}", expected.as_str().unwrap()),
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn binary_notation_matches_reference() {
        let rows: serde_json::Value =
            serde_json::from_str(fixture!("decoded-binary-rendering.json")).unwrap();
        for row in rows.as_array().unwrap() {
            let hex = row["hex"].as_str().unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(
                super::binary(&bytes),
                row["expected"].as_str().unwrap(),
                "{}",
                row["id"]
            );
        }
    }
}

#[cfg(test)]
mod hand_built_tests {
    use super::*;
    fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
        JsonValue::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }
    #[test]
    fn selectors_and_nested_values_are_total() {
        for kind in ["x\ny", "", "Upper", "a-b", "a?b", "é"] {
            let value = object(vec![
                ("kind", JsonValue::String(kind.into())),
                ("path", JsonValue::Array(vec![])),
                ("value", JsonValue::Int(1)),
            ]);
            assert_eq!(
                render(&selector(&value)),
                "{#unrenderable, [], {:integer, 1}}"
            );
        }
        let malformed = vec![
            JsonValue::Int(1),
            object(vec![]),
            object(vec![("kind", JsonValue::Int(1))]),
            object(vec![("kind", JsonValue::String("eq".into()))]),
            object(vec![
                ("kind", JsonValue::String("eq".into())),
                ("path", JsonValue::Int(1)),
                ("value", JsonValue::Int(1)),
            ]),
            object(vec![
                ("kind", JsonValue::String("eq".into())),
                ("path", JsonValue::Array(vec![JsonValue::Int(1)])),
                ("value", JsonValue::Int(1)),
            ]),
            object(vec![
                ("kind", JsonValue::String("eq".into())),
                ("path", JsonValue::Array(vec![])),
            ]),
            object(vec![
                ("kind", JsonValue::String("one_of".into())),
                ("path", JsonValue::Array(vec![])),
                ("values", JsonValue::Int(1)),
            ]),
        ];
        for value in malformed {
            assert_eq!(render(&selector(&value)), "#unrenderable");
        }
        for kind in ["_", "ready?", "run!", "aB_9"] {
            assert_eq!(render(&atom(kind)), format!(":{kind}"));
        }
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                render(&tagged(&JsonValue::Array(vec![JsonValue::Float(value)]))),
                "{:array, [float: #unrenderable]}"
            );
        }
        assert_eq!(render(&operations(&[object(vec![])], 1)), "[#unrenderable]");
        let op = object(vec![
            ("name", object(vec![])),
            ("selectors", JsonValue::Int(1)),
        ]);
        let gold: serde_json::Value =
            serde_json::from_str(fixture!("decoded-rendering.json")).unwrap();
        assert_eq!(
            render(&operations(&[op], 1)),
            gold["handbuilt:operation"].as_str().unwrap()
        );
        let mut nested = JsonValue::Int(1);
        for _ in 0..1000 {
            nested = JsonValue::Array(vec![nested]);
        }
        assert!(render(&tagged(&nested)).contains("..."));
    }
    #[test]
    fn large_binary_conversion_is_bounded() {
        let mut value = vec![0; 4 * 1024 * 1024];
        value[0] = 255;
        let expected = format!("<<255, {}, ...>>", vec!["0"; 199].join(", "));
        assert_eq!(binary(&value), expected);
        assert_eq!(binary(&value[..201]), expected);
        let Term::Binary(prefix, more) = raw(&value) else {
            panic!("binary");
        };
        assert_eq!(prefix.len(), 16384);
        assert!(more);
        let text = "😀".repeat(4096);
        assert_eq!(string(&text), format!("\"{text}\""));
    }
}
