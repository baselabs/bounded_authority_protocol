"""Conformance runner for the bap-selector-float-zero/1 corpus (erratum 6).

Loads the certified corpus from ``priv/conformance/selector-float-zero/``, recomputes every
verdict by driving the SDK's contract-major 1, 2 and 3 surfaces — ``decode_grant``,
``grant_signing_input`` and ``check_envelope`` — and requires exact agreement: a rejected or
refused case is the closed error; an accepted decode names the certified ``key_id``; an accepted
signing input is byte-equal to the certified segments. Typed values travel as JSON TEXT
(``operations_json``, ``cast_arguments_json``) and are decoded with the SDK's own tag-preserving
BAP JSON decoder, so a fraction or exponent stays float-tagged. The index.json SHA-256 is
asserted at startup and every listed file is verified against its per-file SHA-256 before any
case runs. This is the independent conformance proof: the SDK is the implementation under test,
the corpus is the arbiter (erratum 6). Every existing corpus verdict is unchanged.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from bounded_authority_verifier import v1, v2, v3
from bounded_authority_verifier.base64url import base64url_decode
from bounded_authority_verifier.error import InvalidError
from bounded_authority_verifier.json_alg import (
    JArray,
    JObject,
    JString,
    Tagged,
    json_decode,
    str_utf8,
    utf8_str,
)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_CORPUS = _REPO_ROOT / "priv" / "conformance" / "selector-float-zero"

CERTIFIED_INDEX_SHA256 = "97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003"
PROFILE_IDENTITY = "bap-selector-float-zero/1"
REVISION = 1
TOTAL_CASES = 161

_MAJORS: dict[int, Any] = {1: v1, 2: v2, 3: v3}


def _load() -> list[dict]:
    index_bytes = (_CORPUS / "index.json").read_bytes()
    got = hashlib.sha256(index_bytes).hexdigest()
    if got != CERTIFIED_INDEX_SHA256:
        raise AssertionError(f"index.json SHA-256 mismatch: {got}")
    index = json.loads(index_bytes)
    if index["profile"] != PROFILE_IDENTITY or index["revision"] != REVISION or index["total_cases"] != TOTAL_CASES:
        raise AssertionError("corpus identity mismatch")
    cases: list[dict] = []
    for entry in index["files"]:
        raw = (_CORPUS / entry["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise AssertionError(f"{entry['path']}: SHA-256 mismatch")
        if entry["cases"] == 0:
            continue  # profile.json / revision.json: integrity-checked, no cases
        doc_cases = json.loads(raw)["cases"]
        if len(doc_cases) != entry["cases"]:
            raise AssertionError(f"{entry['path']}: case count mismatch")
        cases.extend(doc_cases)
    if len(cases) != TOTAL_CASES:
        raise AssertionError(f"case census {len(cases)} != {TOTAL_CASES}")
    return cases


def _string(v: Tagged) -> str:
    if not isinstance(v, JString):
        raise AssertionError("operations_json: expected a string")
    return utf8_str(v.v)


def _selector_input(sel: Tagged) -> object:
    """A decoded selector object → the producer's SelectorInput: the kind and path as Python
    strings, the value(s) as the decoder's TAGGED values (the int/float tag is the subject)."""
    if not isinstance(sel, JObject):
        raise AssertionError("operations_json: selector object")
    out: dict[str, object] = {}
    for key, value in sel.v.items():
        if key == "kind":
            out[key] = _string(value)
        elif key == "path":
            if not isinstance(value, JArray):
                raise AssertionError("operations_json: path array")
            out[key] = tuple(_string(seg) for seg in value.v)
        elif key == "values":
            if not isinstance(value, JArray):
                raise AssertionError("operations_json: values array")
            out[key] = tuple(value.v)
        else:
            out[key] = value
    return out


def _operations(mod: Any, operations_json: str) -> tuple[Any, ...]:
    ops = json_decode(str_utf8(operations_json))
    if not isinstance(ops, JArray):
        raise AssertionError("operations_json: array")
    built = []
    for op in ops.v:
        if not isinstance(op, JObject) or not isinstance(op.v.get("selectors"), JArray):
            raise AssertionError("operations_json: operation object")
        selectors = op.v["selectors"]
        assert isinstance(selectors, JArray)
        built.append(mod.OperationInput(
            name=_string(op.v["name"]),
            selectors=tuple(_selector_input(s) for s in selectors.v),
        ))
    return tuple(built)


def _signing_input(mod: Any, inp: dict) -> Any:
    return mod.grant_signing_input(mod.GrantProducer(
        key_id=inp["key_id"], issuer=inp["issuer"], grant_id=inp["grant_id"],
        audiences=tuple(inp["audiences"]), issued_at=inp["issued_at"],
        not_before=inp["not_before"], expires_at=inp["expires_at"],
        holder_thumbprint=inp["holder_thumbprint"],
        operations=_operations(mod, inp["operations_json"]),
    ))


def _check_envelope(mod: Any, inp: dict) -> Any:
    e = inp["expected"]
    if "nonce" in e:
        raise AssertionError("envelope: this corpus carries no nonce")
    ti = e["trusted_issuer"]
    return mod.check_envelope(
        str_utf8(inp["grant"]),
        str_utf8(inp["proof"]),
        mod.ExpectedRequest(
            trusted_issuer=mod.TrustedIssuer(
                key_id=ti["key_id"], public_key=base64url_decode(ti["public_key"].encode()),
            ),
            issuer=e["issuer"], audience=e["audience"], method=e["method"],
            target_uri=e["target_uri"], invocation_id=e["invocation_id"],
            operation=e["operation"],
            cast_arguments=json_decode(str_utf8(e["cast_arguments_json"])),
            evaluation_time=e["evaluation_time"], clock_skew=e["clock_skew"],
            proof_max_age=e["proof_max_age"], nonce=mod.NonceNotRequired(),
        ),
    )


def _agrees(case: dict) -> bool:
    mod = _MAJORS[case["major"]]
    surface = case["surface"]
    inp = case["input"]
    expected = case["expected"]
    try:
        if surface == "decode_grant":
            result = mod.decode_grant(str_utf8(inp["compact"]))
        elif surface == "grant_signing_input":
            result = _signing_input(mod, inp)
        elif surface == "check_envelope":
            result = _check_envelope(mod, inp)
        else:
            raise AssertionError(f"{case['id']}: unknown surface {surface}")
    except InvalidError:
        return expected["verdict"] == "invalid"
    if not result.is_ok:
        return expected["verdict"] == "invalid"
    if expected["verdict"] != "valid":
        return False
    if surface == "decode_grant":
        return bool(result.value.key_id == expected["key_id"])
    if surface == "grant_signing_input":
        protected = utf8_str(result.value.protected_segment)
        payload = utf8_str(result.value.payload_segment)
        return (
            protected == expected["protected_segment"]
            and payload == expected["payload_segment"]
            and f"{protected}.{payload}" == expected["message"]
        )
    return True


def run_all() -> dict:
    cases = _load()
    failures: list[str] = []
    rejected = accepted = 0
    for case in cases:
        if not _agrees(case):
            failures.append(f"{case['id']}: expected {case['expected']['verdict']}")
            continue
        if case["expected"]["verdict"] == "valid":
            accepted += 1
        else:
            rejected += 1
    return {"pass": rejected + accepted, "fail": len(failures), "total": len(cases),
            "failures": failures, "rejected": rejected, "accepted": accepted}


if __name__ == "__main__":
    summary = run_all()
    print(f"selector-float-zero: {summary['pass']}/{summary['total']} cases agree "
          f"({summary['rejected']} rejected, {summary['accepted']} accepted)")
    for failure in summary["failures"]:
        print(f"  - {failure}")
    raise SystemExit(1 if summary["fail"] else 0)
