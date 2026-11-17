"""Certified corpus integrity and execution accounting (ADR 0049 D4-D5).

The digest uses index order, then case order within each file. Profile inputs without
case IDs are fixtures, not cases. Outcome projections follow the profile case schemas.
"""

import base64
import hashlib
import json
from pathlib import Path

from bounded_authority_verifier.error import _unwrap
from bounded_authority_verifier.jcs import jcs_encode
from bounded_authority_verifier.json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString

ROOT = Path(__file__).resolve().parents[1] / "conformance/priv/conformance"


def b64digest(data):
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def tagged(value):
    if value is None:
        return JNull()
    if isinstance(value, bool):
        return JBool(value)
    if isinstance(value, int):
        return JInt(value)
    if isinstance(value, float):
        return JFloat(value)
    if isinstance(value, str):
        return JString(value.encode())
    if isinstance(value, list):
        return JArray(tuple(tagged(x) for x in value))
    if isinstance(value, dict):
        return JObject({k: tagged(v) for k, v in value.items()})
    raise AssertionError(f"not a JSON outcome: {type(value)}")


def canonical(value):
    return _unwrap(jcs_encode(tagged(value)))


def outcome(case):
    if "expected" in case:
        return case["expected"]
    if "valid" in case:
        keys = ["valid", "normalized"] if case["valid"] else ["valid"]
    elif case.get("surface") == "local_loopback_http" or "decode_local" in case:
        keys = ["decode_local", "decode_standard", "envelope_local"]
    elif case.get("surface") == "role_attestation" or "decode" in case:
        keys = ["decode", "verify"]
    else:
        raise AssertionError(f"no declared outcome schema: {case['id']}")
    assert all(k in case for k in keys), "incomplete declared outcome members"
    return {key: case[key] for key in keys}


def integrity(root, pin):
    root = Path(root)
    raw = (root / "index.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == pin or b64digest(raw) == pin, "index SHA mismatch"
    index = json.loads(raw)
    paths = [entry["path"] for entry in index["files"]]
    assert len(paths) == len(set(paths)), "duplicate indexed paths"
    assert all(
        p != "index.json" and not Path(p).is_absolute() and ".." not in Path(p).parts for p in paths
    ), "unsafe indexed path"
    assert not any(p.is_symlink() for p in root.rglob("*")), "nonregular corpus input"
    present = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    assert present == {"index.json", *paths}, "corpus file set mismatch"
    cases = []
    for entry in index["files"]:
        path = entry["path"]
        body = (root / path).read_bytes()
        field = "sha256_base64url" if "sha256_base64url" in entry else "sha256"
        actual = (
            b64digest(body) if field == "sha256_base64url" else hashlib.sha256(body).hexdigest()
        )
        assert actual == entry[field], f"{path}: file SHA mismatch"
        if path.endswith(".raw") or path == "revision.json":
            assert entry.get("cases", 0) == 0, "sidecar declares cases"
            continue
        doc = json.loads(body)
        members = doc if isinstance(doc, list) else doc.get("cases", doc.get("uri_cases", []))
        if "cases" in entry:
            assert len(members) == entry["cases"], f"{path}: case count mismatch"
        cases.extend((path, case) for case in members)
    ids = [case["id"] for _, case in cases]
    assert len(ids) == len(set(ids)), "duplicate case IDs"
    total = index.get(
        "total_cases",
        sum(
            index.get(k, 0)
            for k in (
                "uri_cases",
                "proof_cases",
                "attestation_cases",
                "digest_cases",
                "assertion_cases",
                "successor_cases",
            )
        ),
    )
    assert len(cases) == total, "total case count mismatch"
    return index, cases


class CorpusRun:
    def __init__(self, root, pin):
        self.root = Path(root)
        self.index, self.cases = integrity(root, pin)
        self.declared = {case["id"]: (path, case) for path, case in self.cases}
        self.executed = {}

    def record(self, case_id, actual, path):
        assert case_id in self.declared, f"unknown executed ID {case_id}"
        assert case_id not in self.executed, f"duplicate executed ID {case_id}"
        declaring, case = self.declared[case_id]
        assert path == declaring, f"wrong declaring file for {case_id}"
        assert isinstance(actual, dict), f"missing computed outcome for {case_id}"
        want = outcome(case)
        # Expected keys select the contract's output projection; values always come from execution.
        projected = {key: actual[key] for key in want if key in actual}
        self.executed[case_id] = projected

    def finish(self):
        assert self.executed.keys() == self.declared.keys(), "execution completeness: skipped cases"
        pairs = [[case["id"], self.executed[case["id"]]] for _, case in self.cases]
        digest = b64digest(
            b"["
            + b",".join(
                b"[" + canonical(pair[0]) + b"," + canonical(pair[1]) + b"]" for pair in pairs
            )
            + b"]"
        )
        manifest = json.loads((ROOT / "verdict-digests.json").read_bytes())
        assert manifest["format"] == "bap-corpus-verdict-digests/1"
        key = self.root.relative_to(ROOT).as_posix()
        expected = manifest["corpora"][key]
        assert expected["index_sha256_base64url"] == b64digest(
            (self.root / "index.json").read_bytes()
        )
        assert expected["case_count"] == len(pairs)
        assert expected["verdict_digest_sha256_base64url"] == digest, (
            f"{key}: computed verdict digest mismatch"
        )
        print(f"{key}: {len(pairs)} cases, verdict digest {digest}")
        return digest


def computed(expected, actual, invalid):
    if actual is invalid:
        return {"verdict": "invalid"}
    assert isinstance(actual, dict), "missing computed verdict"
    actual = {
        k: base64.urlsafe_b64encode(v).rstrip(b"=").decode() if isinstance(v, bytes) else v
        for k, v in actual.items()
    }
    value = {"verdict": "valid", **actual}
    return {k: value[k] for k in expected if k in value}
