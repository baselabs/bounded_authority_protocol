//! Reference diagnostic notation, including shared container and printable limits.
use crate::json::JsonValue;

pub(crate) enum Term {
    Atom(String),
    Scalar(String),
    Binary(Vec<u8>),
    List(Vec<Term>),
    Tuple(Vec<Term>),
    Struct(String, Vec<Term>),
}
pub(crate) fn atom(v: &str) -> Term {
    Term::Atom(v.into())
}
pub(crate) fn int(v: i64) -> Term {
    Term::Scalar(v.to_string())
}
pub(crate) fn text(v: &str) -> Term {
    Term::Binary(v.as_bytes().to_vec())
}
pub(crate) fn raw(v: &[u8]) -> Term {
    Term::Binary(v.to_vec())
}
pub(crate) fn structure(name: String, fields: Vec<(&str, Term)>) -> Term {
    Term::Struct(
        name,
        fields
            .into_iter()
            .map(|(k, v)| Term::Tuple(vec![atom(k), v]))
            .collect(),
    )
}
fn quoted(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    if !text.chars().take(4096).all(|c| {
        matches!(c as u32,32..=126|160..=55295|57344..=65533|65536..=1114111)
            || "\u{7}\u{8}\t\n\u{b}\u{c}\r\u{1b}".contains(c)
    }) {
        return None;
    }
    let mut out = String::from("\"");
    let mut chars = text.chars().peekable();
    for _ in 0..4096 {
        let Some(c) = chars.next() else { break };
        match c {
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
            '#' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push_str("\\#{");
            }
            c if matches!(c as u32,0xFEFF|0x061C|0x200E|0x200F|0x200C|0x200D|0x034F|0x00A0|0x200B|0x2060|0x2028|0x2029|0x205F|0x2061..=0x2064|0x202A..=0x202E|0x2066..=0x2069|0xFFF9..=0xFFFC|0x2000..=0x200A) => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    if chars.peek().is_some() {
        out.push_str(" <> ...");
    }
    Some(out)
}
pub(crate) fn render(term: &Term) -> String {
    walk(term, &mut 200)
}
fn container(
    values: &[Term],
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
fn walk(term: &Term, remaining: &mut usize) -> String {
    match term {
        Term::Atom(v) => {
            if matches!(v.as_str(), "true" | "false" | "nil") {
                v.clone()
            } else {
                format!(":{v}")
            }
        }
        Term::Scalar(v) => v.clone(),
        Term::Binary(v) => {
            if let Some(s) = quoted(v) {
                return s;
            }
            let count = v.len().min(*remaining);
            let mut parts: Vec<_> = v[..count].iter().map(u8::to_string).collect();
            if count < v.len() {
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
fn tagged(value: &JsonValue) -> Term {
    let (tag, value) = match value {
        JsonValue::Null => return atom("null"),
        JsonValue::Bool(v) => ("boolean", atom(if *v { "true" } else { "false" })),
        JsonValue::Int(v) => ("integer", int(*v)),
        JsonValue::Float(v) => {
            let s = format!("{v:?}");
            let s = if let Some((c, e)) = s.split_once('e') {
                format!("{}{}e{}", c, if c.contains('.') { "" } else { ".0" }, e)
            } else {
                s
            };
            ("float", Term::Scalar(s))
        }
        JsonValue::String(v) => ("string", text(v)),
        JsonValue::Array(v) => ("array", Term::List(v.iter().map(tagged).collect())),
        JsonValue::Object(v) => (
            "object",
            Term::List(
                v.iter()
                    .map(|(k, v)| Term::Tuple(vec![text(k), tagged(v)]))
                    .collect(),
            ),
        ),
    };
    Term::Tuple(vec![atom(tag), value])
}
fn selector(value: &JsonValue) -> Term {
    let Some(JsonValue::String(kind)) = member(value, "kind") else {
        return atom("nil");
    };
    if kind == "all" {
        return atom("all");
    }
    let path = match member(value, "path") {
        Some(JsonValue::Array(v)) => Term::List(
            v.iter()
                .map(|v| match v {
                    JsonValue::String(s) => text(s),
                    _ => atom("nil"),
                })
                .collect(),
        ),
        _ => atom("nil"),
    };
    let operand = if kind == "one_of" {
        match member(value, "values") {
            Some(JsonValue::Array(v)) => Term::List(v.iter().map(tagged).collect()),
            _ => atom("nil"),
        }
    } else {
        member(value, "value")
            .map(tagged)
            .unwrap_or_else(|| atom("nil"))
    };
    Term::Tuple(vec![atom(kind), path, operand])
}
pub(crate) fn operations(values: &[JsonValue], version: i64) -> Term {
    Term::List(
        values
            .iter()
            .map(|v| {
                let name = match member(v, "name") {
                    Some(JsonValue::String(s)) => text(s),
                    _ => atom("nil"),
                };
                let selectors = match member(v, "selectors") {
                    Some(JsonValue::Array(v)) => Term::List(v.iter().map(selector).collect()),
                    _ => atom("nil"),
                };
                structure(
                    format!("BoundedAuthorityProtocol.V{version}.Operation"),
                    vec![("name", name), ("selectors", selectors)],
                )
            })
            .collect(),
    )
}
#[cfg(test)]
mod tests {
    #[test]
    fn binary_notation_matches_reference() {
        let rows: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/decoded-binary-rendering.json")).unwrap();
        for row in rows.as_array().unwrap() {
            let hex = row["hex"].as_str().unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(super::binary(&bytes), row["expected"].as_str().unwrap());
        }
    }
}
