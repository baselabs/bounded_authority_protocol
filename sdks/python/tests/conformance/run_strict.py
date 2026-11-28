#!/usr/bin/env python3
"""Conformance runner for the strict-Ed25519 corpus (profile ``bap-strict-ed25519/1``).

Loads ``priv/conformance/strict-ed25519/`` (an additive corpus: every earlier corpus stays byte
identical), asserts the ``index.json`` SHA-256 and every listed file's SHA-256 before running, then
recomputes EVERY verdict from scratch through the SDK's public surfaces and requires agreement on all
cases. Core cases reuse the runner dispatch for their contract major. The primitive,
key-acceptance and sibling-profile (loopback, role-attestation, content-assertion) cases are
dispatched here.

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

from bounded_authority_verifier.error import _unwrap

_HERE = Path(__file__).resolve()
_CORPUS_ROOT = _HERE.parents[2] / "conformance"
_SRC = _HERE.parents[2] / "src"
sys.path.insert(0, str(_SRC))
sys.path.insert(0, str(_HERE.parents[1]))

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
from corpus_support import CorpusRun, canonical, computed, integrity, outcome  # noqa: E402

CORPUS_DIR = _CORPUS_ROOT / "priv" / "conformance" / "strict-ed25519"
# The certified index.json SHA-256 (certified index SHA-256 binding
# (docs/design/conformance-contract.md)). A mismatched corpus fails closed.
CERTIFIED_INDEX_SHA = "732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9"
STRING_OR_URI_INDEX_SHA256 = "3b9a7dffd20b886894ad43fcc257a71f7b768cf9426a9a149ea60c79f218ce82"
PROFILE = "bap-strict-ed25519/1"
TOTAL_CASES = 2410


def abort(msg: str) -> NoReturn:
    print(f"conformance(strict): {msg}", file=sys.stderr)
    raise SystemExit(1)


def _load_module(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, _HERE.parent / filename)
    if not (spec is not None and spec.loader is not None):
        abort("conformance invariant: spec is not None and spec.loader is not None")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_RUN_V1 = _load_module("bap_strict_run_v1", "run.py")
_RUN_V2 = _load_module("bap_strict_run_v2", "run_v2.py")
_RUN_V3 = _load_module("bap_strict_run_v3", "run_v3.py")


def _b64d(s: str) -> bytes:
    return _unwrap(base64url_decode(_unwrap(str_utf8(s))))


def _verdict(expected: dict[str, Any], accepted: bool) -> bool:
    verdict = expected.get("verdict")
    if verdict not in ("valid", "invalid"):
        abort(f"unknown verdict {verdict!r}")
    return accepted == (verdict == "valid")


# ---- corpus loading ----


def load_corpus(root, pin, profile, total) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    integrity(root, pin)
    index_raw = (root / "index.json").read_bytes()
    index_sha = hashlib.sha256(index_raw).hexdigest()
    if index_sha != pin:
        abort(f"index.json SHA mismatch: got {index_sha}, certified {pin}")
    index = json.loads(index_raw.decode("utf8"))
    if index.get("profile") != profile or index.get("revision") != 1:
        abort("index.json: profile or revision")
    cases: list[dict[str, Any]] = []
    family_counts: dict[str, int] = {}
    for entry in index["files"]:
        body = (root / entry["path"]).read_bytes()
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
            case["_file"] = entry["path"]
        cases.extend(file_json["cases"])
    if family_counts != index["families"]:
        abort("family counts differ from the index")
    if len(cases) != index["total_cases"] or len(cases) != total:
        abort(f"case count: index says {index['total_cases']}, loaded {len(cases)}")
    if len({c["id"] for c in cases}) != len(cases):
        abort("duplicate case ids")
    return index, cases


# ---- dispatch ----


def _run_primitive(case: dict[str, Any]) -> dict[str, Any]:
    from bounded_authority_verifier.ed25519 import (
        acceptable_public_key,
        torsion_free,
        verify_strict,
    )

    surface, inp = case["surface"], case["input"]
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
    return {"verdict": "valid" if accepted else "invalid"}


def _run_shaped(case: dict[str, Any]) -> dict[str, Any]:
    module = {1: _RUN_V1, 2: _RUN_V2, 3: _RUN_V3}.get(case["major"])
    if module is None:
        abort(f"{case['id']}: unsupported major {case['major']}")
    surface, inp = case["surface"], case["input"]
    if surface == "jwk.decode_public":
        # The shared v1/v2 runners decode the JWK member directly; the strict corpus exercises the
        # SDK's own public decoder so key acceptance is part of the verdict.
        result = jwk_decode_public(_unwrap(str_utf8(inp["text"])))
        actual: Any = {"public_key": _b64e(result.value)} if result.is_ok else module.INVALID
    else:
        actual = module.dispatch(surface, inp, {})
    return computed(case["expected"], actual, module.INVALID)


def _b64e(raw: bytes) -> str:
    return _RUN_V1._b64e(raw)


def _run_loopback(case: dict[str, Any]) -> dict[str, Any]:
    issuer, request = case["issuer"], case["request"]
    expected = ExpectedRequest(
        trusted_issuer=TrustedIssuer(
            key_id=issuer["key_id"], public_key=_b64d(issuer["public_key"])
        ),
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
    return {
        "decode_local": decode_local_loopback_http_proof(compact).is_ok,
        "decode_standard": decode_proof(compact).is_ok,
        "envelope_local": check_local_loopback_http_envelope(
            case["grant"].encode(), compact, expected
        ).is_ok,
    }


def _run_ra1(case: dict[str, Any]) -> dict[str, Any]:
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
    return {
        "decode": decode_attestation(compact).is_ok,
        "verify": verify_attestation(compact, expected).is_ok,
    }


def _run_ca1(case: dict[str, Any]) -> dict[str, Any]:
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
        bounds=_unwrap(bounds_maximum()),
    )
    compact = case["compact"].encode()
    return {
        "decode": "valid" if decode_assertion(compact).is_ok else "invalid",
        "verify": "valid" if verify_assertion(compact, expected).is_ok else "invalid",
    }


def run_case(case: dict[str, Any]) -> dict[str, Any]:
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


def run_all(
    only: frozenset[str] | None = None,
    *,
    root=CORPUS_DIR,
    pin=CERTIFIED_INDEX_SHA,
    profile=PROFILE,
    total=TOTAL_CASES,
) -> dict[str, Any]:
    index, cases = load_corpus(root, pin, profile, total)
    passed = 0
    failures: list[str] = []
    execution = CorpusRun(root, pin)
    selected = [c for c in cases if only is None or c["_family"] in only]
    for case in selected:
        actual = run_case(case)
        execution.record(case["id"], actual, case["_file"])
        if canonical(actual) == canonical(outcome(case)):
            passed += 1
        else:
            failures.append(case["id"])
    execution.finish()
    return {
        "pass": passed,
        "fail": len(failures),
        "total": len(selected),
        "index": index,
        "failures": failures,
    }


def run_string_or_uri() -> dict[str, Any]:
    return run_all(
        root=CORPUS_DIR.with_name("string-or-uri"),
        pin=STRING_OR_URI_INDEX_SHA256,
        profile="bap-string-or-uri/1",
        total=24,
    )


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
