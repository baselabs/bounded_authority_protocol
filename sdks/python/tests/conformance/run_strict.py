#!/usr/bin/env python3
"""Conformance runner for the strict-Ed25519 corpus (profile ``bap-strict-ed25519/1``).

Loads ``priv/conformance/strict-ed25519/`` (an additive corpus: every earlier corpus stays byte
identical), asserts the ``index.json`` SHA-256 and every listed file's SHA-256 before running, then
recomputes EVERY verdict from scratch through the SDK's public surfaces and requires agreement on all
cases. The v1/v2-shaped families reuse the existing v1 and v2 runners' dispatch (the SDK calls are
identical); the primitive, key-acceptance and sibling-profile (loopback, role-attestation,
content-assertion) cases are dispatched here.

A disagreement aborts nonzero with the case id. ``--only FAMILY[,FAMILY]`` restricts the run to named
families (a diagnostic aid; the certified run uses every family).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, NoReturn

_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[4]
_SRC = _HERE.parents[2] / "src"
sys.path.insert(0, str(_SRC))

from bounded_authority_verifier import (  # noqa: E402
    ExpectedAttestation,
    ExpectedContentAssertion,
    ExpectedRequest,
    HistoricalPublicKey,
    NonceRequired,
    TrustedAttestor,
    TrustedIssuer,
    bounds_maximum,
    check_local_loopback_http_envelope,
    decode_assertion,
    decode_attestation,
    decode_local_loopback_http_proof,
    decode_proof,
    jwk_decode_public,
    verify_assertion,
    verify_attestation,
)
from bounded_authority_verifier.base64url import base64url_decode  # noqa: E402
from bounded_authority_verifier.json_alg import str_utf8  # noqa: E402

CORPUS_DIR = _REPO_ROOT / "priv" / "conformance" / "strict-ed25519"
# The certified index.json SHA-256 (ADR 0014 D4). A mismatched corpus fails closed.
CERTIFIED_INDEX_SHA = "732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9"
PROFILE = "bap-strict-ed25519/1"
TOTAL_CASES = 2410


def abort(msg: str) -> NoReturn:
    print(f"conformance(strict): {msg}", file=sys.stderr)
    raise SystemExit(1)


def _load_module(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, _HERE.parent / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_RUN_V1 = _load_module("bap_strict_run_v1", "run.py")
_RUN_V2 = _load_module("bap_strict_run_v2", "run_v2.py")


def _b64d(s: str) -> bytes:
    return base64url_decode(str_utf8(s))


def _verdict(expected: dict[str, Any], accepted: bool) -> bool:
    verdict = expected.get("verdict")
    if verdict not in ("valid", "invalid"):
        abort(f"unknown verdict {verdict!r}")
    return accepted == (verdict == "valid")


# ---- corpus loading ----


def load_corpus() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    index_raw = (CORPUS_DIR / "index.json").read_bytes()
    index_sha = hashlib.sha256(index_raw).hexdigest()
    if index_sha != CERTIFIED_INDEX_SHA:
        abort(f"index.json SHA mismatch: got {index_sha}, certified {CERTIFIED_INDEX_SHA}")
    index = json.loads(index_raw.decode("utf8"))
    if index.get("profile") != PROFILE or index.get("revision") != 1:
        abort("index.json: profile or revision")
    cases: list[dict[str, Any]] = []
    family_counts: dict[str, int] = {}
    for entry in index["files"]:
        body = (CORPUS_DIR / entry["path"]).read_bytes()
        if hashlib.sha256(body).hexdigest() != entry["sha256"]:
            abort(f"{entry['path']}: file SHA mismatch")
        if entry["path"] in ("profile.json", "revision.json"):
            if entry["cases"] != 0:
                abort(f"{entry['path']}: sidecar declares cases")
            continue
        file_json = json.loads(body.decode("utf8"))
        if len(file_json["cases"]) != entry["cases"]:
            abort(f"{entry['path']}: case count mismatch")
        family = file_json["family"]
        family_counts[family] = family_counts.get(family, 0) + len(file_json["cases"])
        for case in file_json["cases"]:
            case["_family"] = family
        cases.extend(file_json["cases"])
    if family_counts != index["families"]:
        abort("family counts differ from the index")
    if len(cases) != index["total_cases"] or len(cases) != TOTAL_CASES:
        abort(f"case count: index says {index['total_cases']}, loaded {len(cases)}")
    if len({c["id"] for c in cases}) != len(cases):
        abort("duplicate case ids")
    return index, cases


# ---- dispatch ----


def _run_primitive(case: dict[str, Any]) -> bool:
    from bounded_authority_verifier.ed25519 import (
        acceptable_public_key,
        torsion_free,
        verify_strict,
    )

    surface, inp, expected = case["surface"], case["input"], case["expected"]
    if surface == "ed25519.verify_strict":
        accepted = verify_strict(
            _b64d(inp["message"]) if inp["message"] else b"",
            _b64d(inp["signature"]),
            _b64d(inp["public_key"]),
        )
    elif surface == "ed25519.acceptable_public_key":
        accepted = acceptable_public_key(_b64d(inp["public_key"]))
    elif surface == "ed25519.torsion_free":
        accepted = torsion_free(_b64d(inp["public_key"]))
    else:
        abort(f"{case['id']}: unknown primitive surface {surface}")
    return _verdict(expected, accepted)


def _run_shaped(case: dict[str, Any]) -> bool:
    module = _RUN_V1 if case["major"] == 1 else _RUN_V2
    if case["major"] not in (1, 2):
        abort(f"{case['id']}: unsupported major {case['major']}")
    surface, inp = case["surface"], case["input"]
    if surface == "jwk.decode_public":
        # The shared v1/v2 runners decode the JWK member directly; the strict corpus exercises the
        # SDK's own public decoder so key acceptance is part of the verdict.
        result = jwk_decode_public(str_utf8(inp["text"]))
        actual: Any = {"public_key": _b64e(result.value)} if result.is_ok else module.INVALID
    else:
        actual = module.dispatch(surface, inp, {})
    return bool(module.compare_verdict(case["expected"], actual))


def _b64e(raw: bytes) -> str:
    return _RUN_V1._b64e(raw)


def _run_loopback(case: dict[str, Any]) -> bool:
    issuer, request = case["issuer"], case["request"]
    expected = ExpectedRequest(
        trusted_issuer=TrustedIssuer(key_id=issuer["key_id"], public_key=_b64d(issuer["public_key"])),
        issuer=issuer["issuer"],
        audience=issuer["audience"],
        method=request["method"],
        target_uri=case["target_uri"],
        invocation_id=request["invocation_id"],
        operation=request["operation"],
        cast_arguments=_RUN_V1._js_to_tagged(request["cast_arguments"]),
        evaluation_time=request["evaluation_time"],
        clock_skew=request["clock_skew"],
        proof_max_age=request["proof_max_age"],
        nonce=NonceRequired(case["nonce"]),
    )
    compact = case["compact"].encode()
    return (
        decode_local_loopback_http_proof(compact).is_ok == case["decode_local"]
        and decode_proof(compact).is_ok == case["decode_standard"]
        and check_local_loopback_http_envelope(case["grant"].encode(), compact, expected).is_ok
        == case["envelope_local"]
    )


def _run_ra1(case: dict[str, Any]) -> bool:
    attestor, subject = case["attestor"], case["subject"]
    expected = ExpectedAttestation(
        attestor=TrustedAttestor(
            key_id=attestor["key_id"],
            public_key=_b64d(attestor["public_key"]),
            valid_from=attestor["valid_from"],
            valid_before=attestor["valid_before"],
        ),
        subject_key_id=subject["key_id"],
        subject_public_key=_b64d(subject["public_key"]),
        now=case["now"],
    )
    compact = case["compact"].encode()
    return (
        decode_attestation(compact).is_ok == case["decode"]
        and verify_attestation(compact, expected).is_ok == case["verify"]
    )


def _run_ca1(case: dict[str, Any]) -> bool:
    attestor, context = case["attestor"], case["expected_context"]
    expected = ExpectedContentAssertion(
        attestor=HistoricalPublicKey(
            key_id=attestor["key_id"],
            public_key=_b64d(attestor["public_key"]),
            valid_from=attestor["valid_from"],
            valid_before=attestor["valid_before"],
        ),
        issuer=context["issuer"],
        audience=context["audience"],
        subject=context["subject"],
        profile=context["profile"],
        profile_digest=_b64d(context["profile_digest"]),
        content_digest=_b64d(context["content_digest"]),
        now=context["now"],
        bounds=bounds_maximum(),
    )
    compact = case["compact"].encode()
    want = case["expected"]
    return (
        decode_assertion(compact).is_ok == (want["decode"] == "valid")
        and verify_assertion(compact, expected).is_ok == (want["verify"] == "valid")
    )


def run_case(case: dict[str, Any]) -> bool:
    surface = case["surface"]
    if surface.startswith("ed25519."):
        return _run_primitive(case)
    if surface == "local_loopback_http":
        return _run_loopback(case)
    if surface == "role_attestation":
        return _run_ra1(case)
    if surface == "content_assertion":
        return _run_ca1(case)
    return _run_shaped(case)


def run_all(only: frozenset[str] | None = None) -> dict[str, Any]:
    index, cases = load_corpus()
    passed = 0
    failures: list[str] = []
    selected = [c for c in cases if only is None or c["_family"] in only]
    for case in selected:
        if run_case(case):
            passed += 1
        else:
            failures.append(case["id"])
    return {
        "pass": passed,
        "fail": len(failures),
        "total": len(selected),
        "index": index,
        "failures": failures,
    }


def main() -> None:
    only: frozenset[str] | None = None
    if "--only" in sys.argv:
        only = frozenset(sys.argv[sys.argv.index("--only") + 1].split(","))
    result = run_all(only)
    print(f"conformance(strict): {result['pass']}/{result['total']} cases agree")
    if result["fail"]:
        print(f"\n{result['fail']} FAILURE(S):", file=sys.stderr)
        for case_id in result["failures"]:
            print(f"  - {case_id}", file=sys.stderr)
        raise SystemExit(1)
    print("conformance(strict): PASS (all cases agree)")


if __name__ == "__main__":
    main()
