"""Certified corpus integrity and execution accounting (certified input closure and computed verdict accounting (self-contained SDK distribution contract)).

The digest uses index order, then case order within each file. Profile inputs without
case IDs are fixtures, not cases. Outcome projections follow the profile case schemas.
"""

import base64
import hashlib
import json
import re
from pathlib import Path

from bounded_authority_verifier.error import _unwrap
from bounded_authority_verifier.jcs import jcs_encode
from bounded_authority_verifier.json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString

ROOT = Path(__file__).resolve().parents[1] / "conformance/priv/conformance"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


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
    require(all(k in case for k in keys), "incomplete declared outcome members")
    return {key: case[key] for key in keys}


def integrity(root, pin):
    root = Path(root)
    raw = (root / "index.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == pin or b64digest(raw) == pin, "index SHA mismatch")
    index = json.loads(raw)
    paths = [entry["path"] for entry in index["files"]]
    require(len(paths) == len(set(paths)), "duplicate indexed paths")
    require(
        all(
            p != "index.json" and not Path(p).is_absolute() and ".." not in Path(p).parts
            for p in paths
        ),
        "unsafe indexed path",
    )
    require(not any(p.is_symlink() for p in root.rglob("*")), "nonregular corpus input")
    present = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(present == {"index.json", *paths}, "corpus file set mismatch")
    cases = []
    for entry in index["files"]:
        path = entry["path"]
        body = (root / path).read_bytes()
        field = "sha256_base64url" if "sha256_base64url" in entry else "sha256"
        actual = (
            b64digest(body) if field == "sha256_base64url" else hashlib.sha256(body).hexdigest()
        )
        require(actual == entry[field], f"{path}: file SHA mismatch")
        if path.endswith(".raw") or path == "revision.json":
            require(entry.get("cases", 0) == 0, "sidecar declares cases")
            continue
        doc = json.loads(body)
        members = doc if isinstance(doc, list) else doc.get("cases", doc.get("uri_cases", []))
        if "cases" in entry:
            require(len(members) == entry["cases"], f"{path}: case count mismatch")
        cases.extend((path, case) for case in members)
    ids = [case["id"] for _, case in cases]
    require(len(ids) == len(set(ids)), "duplicate case IDs")
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
    require(len(cases) == total, "total case count mismatch")
    return index, cases


class CorpusRun:
    def __init__(self, root, pin):
        self.root = Path(root)
        self.index, self.cases = integrity(root, pin)
        self.declared = {case["id"]: (path, case) for path, case in self.cases}
        self.executed = {}

    def record(self, case_id, actual, path):
        require(case_id in self.declared, f"unknown executed ID {case_id}")
        require(case_id not in self.executed, f"duplicate executed ID {case_id}")
        declaring, case = self.declared[case_id]
        require(path == declaring, f"wrong declaring file for {case_id}")
        require(isinstance(actual, dict), f"missing computed outcome for {case_id}")
        want = outcome(case)
        # Expected keys select the contract's output projection; values always come from execution.
        projected = {key: actual[key] for key in want if key in actual}
        self.executed[case_id] = projected

    def finish(self):
        require(
            self.executed.keys() == self.declared.keys(), "execution completeness: skipped cases"
        )
        pairs = [[case["id"], self.executed[case["id"]]] for _, case in self.cases]
        digest = b64digest(
            b"["
            + b",".join(
                b"[" + canonical(pair[0]) + b"," + canonical(pair[1]) + b"]" for pair in pairs
            )
            + b"]"
        )
        manifest = json.loads((ROOT / "verdict-digests.json").read_bytes())
        require(
            manifest["format"] == "bap-corpus-verdict-digests/1",
            "conformance invariant: manifest['format'] == 'bap-corpus-verdict-digests/1'",
        )
        key = self.root.relative_to(ROOT).as_posix()
        expected = manifest["corpora"][key]
        require(
            expected["index_sha256_base64url"]
            == b64digest((self.root / "index.json").read_bytes()),
            "conformance invariant: expected['index_sha256_base64url'] == b64digest((self.root / 'index.json').read_bytes())",
        )
        require(
            expected["case_count"] == len(pairs),
            "conformance invariant: expected['case_count'] == len(pairs)",
        )
        require(
            expected["verdict_digest_sha256_base64url"] == digest,
            f"{key}: computed verdict digest mismatch",
        )
        print(f"{key}: {len(pairs)} cases, verdict digest {digest}")
        return digest


def computed(expected, actual, invalid):
    if actual is invalid:
        return {"verdict": "invalid"}
    require(isinstance(actual, dict), "missing computed verdict")
    actual = {
        k: base64.urlsafe_b64encode(v).rstrip(b"=").decode() if isinstance(v, bytes) else v
        for k, v in actual.items()
    }
    value = {"verdict": "valid", **actual}
    return {k: value[k] for k in expected if k in value}


def collect_input_keys(value, target, *, major=1):
    """Fingerprint raw public-key inputs, including declared rejected import attempts.

    RFC 7638 names rejected and producer-only keys too. This input-boundary
    census is separate from successful cryptographic verification imports.
    """

    def raw_key(raw):
        if len(raw) == 32 or (major == 2 and raw):
            jwk = {"crv": "Ed25519", "kty": "OKP", "x": encode(raw)}
        elif major == 3 and len(raw) == 65 and raw[0] == 4:
            jwk = {"crv": "P-256", "kty": "EC", "x": encode(raw[1:33]), "y": encode(raw[33:])}
        else:
            return
        target.add(b64digest(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()))

    def encode(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def decode(text):
        try:
            return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
        except (ValueError, TypeError):
            return b""

    if isinstance(value, list):
        for child in value:
            collect_input_keys(child, target, major=major)
    elif isinstance(value, dict):
        for label, child in value.items():
            if (
                isinstance(child, str)
                and re.search(
                    r"public.*key|key.*public|verification.*key|holder.*key|issuer.*key",
                    label,
                    re.I,
                )
                and not re.search(r"fingerprint|thumbprint|digest|hash", label, re.I)
            ):
                raw_key(decode(child))
            collect_input_keys(child, target, major=major)
