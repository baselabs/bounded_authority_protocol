//! Certified input closure and computed verdict accounting, certified input closure and computed verdict accounting (self-contained SDK distribution contract).
//! Ordering and outcome projections: the corpus distribution contract, index order.
#![allow(dead_code)]
use bounded_authority_protocol as bap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub fn sha(bytes: &[u8]) -> String {
    String::from_utf8(bap::base64url_encode(&Sha256::digest(bytes))).unwrap()
}
fn files(root: &Path) -> BTreeSet<String> {
    fn visit(root: &Path, dir: &Path, found: &mut BTreeSet<String>) {
        for entry in fs::read_dir(dir).expect("corpus directory missing") {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &path, found);
            } else {
                assert!(kind.is_file(), "nonregular corpus input");
                found.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let mut found = BTreeSet::new();
    visit(root, root, &mut found);
    found
}
pub fn outcome(case: &Value) -> Value {
    if let Some(expected) = case.get("expected") {
        return expected.clone();
    }
    let keys: &[&str] = if case.get("valid").is_some() {
        if case["valid"] == true {
            &["valid", "normalized"]
        } else {
            &["valid"]
        }
    } else if case.get("decode_local").is_some() {
        &["decode_local", "decode_standard", "envelope_local"]
    } else if case.get("decode").is_some() {
        &["decode", "verify"]
    } else {
        panic!("case has no declared outcome schema")
    };
    Value::Object(
        keys.iter()
            .map(|key| {
                (
                    key.to_string(),
                    case.get(*key).expect("missing outcome member").clone(),
                )
            })
            .collect(),
    )
}
pub fn canonical(value: &Value) -> Vec<u8> {
    // JCS containers compose without applying protocol wire bounds to tooling aggregates.
    match value {
        Value::Array(values) => {
            let mut bytes = vec![b'['];
            for (n, v) in values.iter().enumerate() {
                if n > 0 {
                    bytes.push(b',');
                }
                bytes.extend(canonical(v));
            }
            bytes.push(b']');
            bytes
        }
        Value::Object(members) => {
            let mut keys: Vec<_> = members.keys().collect();
            keys.sort_by_cached_key(|key| key.encode_utf16().collect::<Vec<_>>());
            let mut bytes = vec![b'{'];
            for (n, key) in keys.iter().enumerate() {
                if n > 0 {
                    bytes.push(b',');
                }
                bytes.extend(canonical(&json!(key)));
                bytes.push(b':');
                bytes.extend(canonical(&members[*key]));
            }
            bytes.push(b'}');
            bytes
        }
        _ => {
            let tagged = match value {
                Value::Null => bap::JsonValue::Null,
                Value::Bool(x) => bap::JsonValue::Bool(*x),
                Value::String(x) => bap::JsonValue::String(x.clone()),
                Value::Number(x) => {
                    if let Some(i) = x.as_i64() {
                        bap::JsonValue::Int(i)
                    } else {
                        bap::JsonValue::Float(x.as_f64().unwrap())
                    }
                }
                _ => unreachable!(),
            };
            bap::jcs_encode(&tagged, &bap::Bounds::maximum()).expect("JCS outcome scalar")
        }
    }
}
pub struct Run {
    root: PathBuf,
    pub cases: Vec<(String, Value)>,
    actual: BTreeMap<String, Value>,
}
pub fn load_index(root: &Path, pin: &str) -> (Value, Vec<(String, Value)>) {
    let bytes = fs::read(root.join("index.json")).expect("index missing");
    let hex = Sha256::digest(&bytes)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();
    assert!(sha(&bytes) == pin || hex == pin, "index SHA mismatch");
    let index: Value = serde_json::from_slice(&bytes).unwrap();
    let mut declared = BTreeSet::from(["index.json".to_owned()]);
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    for entry in index["files"].as_array().unwrap() {
        let name = entry["path"].as_str().unwrap();
        assert!(
            Path::new(name)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "unsafe indexed path"
        );
        assert!(declared.insert(name.to_owned()), "duplicate indexed path");
        let body = fs::read(root.join(name)).expect("indexed file missing");
        let actual = if entry.get("sha256_base64url").is_some() {
            sha(&body)
        } else {
            Sha256::digest(&body)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect()
        };
        let expected = entry.get("sha256_base64url").unwrap_or(&entry["sha256"]);
        assert_eq!(
            Some(actual.as_str()),
            expected.as_str(),
            "{name}: file SHA mismatch"
        );
        if !name.ends_with(".json") || name == "revision.json" {
            continue;
        }
        let doc: Value = serde_json::from_slice(&body).unwrap();
        let members = doc
            .as_array()
            .or_else(|| doc["cases"].as_array())
            .or_else(|| doc["uri_cases"].as_array());
        let count = members.map_or(0, Vec::len);
        if let Some(n) = entry["cases"].as_u64() {
            assert_eq!(count, n as usize, "case count mismatch");
        }
        if let Some(members) = members {
            for case in members {
                assert!(
                    ids.insert(case["id"].as_str().expect("case ID").to_owned()),
                    "duplicate case ID"
                );
                cases.push((name.to_owned(), case.clone()));
            }
        }
    }
    assert_eq!(files(root), declared, "corpus file set mismatch");
    (index, cases)
}

impl Run {
    pub fn new(root: &Path, pin: &str) -> Self {
        let (index, cases) = load_index(root, pin);
        let total = index["total_cases"].as_u64().unwrap_or_else(|| {
            [
                "uri_cases",
                "proof_cases",
                "attestation_cases",
                "digest_cases",
                "assertion_cases",
                "successor_cases",
            ]
            .iter()
            .map(|k| index[*k].as_u64().unwrap_or(0))
            .sum()
        });
        assert_eq!(cases.len() as u64, total, "total case count mismatch");
        Self {
            root: root.to_owned(),
            cases,
            actual: BTreeMap::new(),
        }
    }
    pub fn record(&mut self, id: &str, file: &str, actual: Value) {
        let (declaring, case) = self
            .cases
            .iter()
            .find(|(_, c)| c["id"] == id)
            .expect("unknown executed ID");
        assert_eq!(file, declaring, "wrong declaring file");
        let expected = outcome(case);
        let actual = actual.as_object().expect("missing computed outcome");
        let projection = Value::Object(
            expected
                .as_object()
                .unwrap()
                .keys()
                .filter_map(|k| actual.get(k).map(|v| (k.clone(), v.clone())))
                .collect(),
        );
        assert!(
            self.actual.insert(id.to_owned(), projection).is_none(),
            "duplicate executed ID"
        );
    }
    pub fn finish(&self) {
        assert_eq!(
            self.actual.len(),
            self.cases.len(),
            "execution completeness: skipped cases"
        );
        let pairs: Vec<Value> = self
            .cases
            .iter()
            .map(|(_, c)| {
                json!([
                    c["id"],
                    self.actual
                        .get(c["id"].as_str().unwrap())
                        .expect("skipped case")
                ])
            })
            .collect();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/priv/conformance");
        let manifest: Value =
            serde_json::from_slice(&fs::read(root.join("verdict-digests.json")).unwrap()).unwrap();
        let key = self.root.strip_prefix(&root).unwrap().to_str().unwrap();
        let entry = &manifest["corpora"][key];
        assert_eq!(manifest["format"], "bap-corpus-verdict-digests/1");
        assert_eq!(
            entry["index_sha256_base64url"],
            sha(&fs::read(self.root.join("index.json")).unwrap())
        );
        assert_eq!(entry["case_count"], self.cases.len());
        let digest = sha(&canonical(&json!(pairs)));
        println!("{key}: {} cases, verdict digest {digest}", self.cases.len());
        assert_eq!(
            entry["verdict_digest_sha256_base64url"], digest,
            "computed verdict digest mismatch: {key}"
        );
    }
}
