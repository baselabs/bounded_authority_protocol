"""Conformance runner for the bap-producer-canonicality/1 corpus (erratum 3).

Loads the certified corpus from ``priv/conformance/producer-canonicality/``, recomputes every
verdict by driving the SDK's PRODUCER surfaces — compact assembly for contract-majors 1, 2 and 3
and the three sibling profiles, anchored-export encoding for all three majors — and requires
exact agreement: a refused signature is the closed error; an accepted signature's bytes are
emitted unchanged (byte-equality against the certified compact). The index.json SHA-256 is
asserted at startup and every listed file is verified against its per-file SHA-256 before any
case runs. This is the independent conformance proof: the SDK is the implementation under test,
the corpus is the arbiter (BAP-25, erratum 3). No verification verdict changes anywhere.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from bounded_authority_verifier import content_assertion, role_attestation, v1, v2, v3
from bounded_authority_verifier.base64url import base64url_decode
from bounded_authority_verifier.compact import SigningInput

_REPO_ROOT = Path(__file__).resolve().parents[4]
_CORPUS = _REPO_ROOT / "priv" / "conformance" / "producer-canonicality"

CERTIFIED_INDEX_SHA256 = "99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601"
PROFILE_IDENTITY = "bap-producer-canonicality/1"
REVISION = 1
TOTAL_CASES = 75

_PROFILE_KINDS = {
    "bap-application-proof/local-loopback-http/1": "local_loopback_http_proof",
    "bap-role-attestation/1": "role_attestation",
    "bap-content-assertion/1": "content_assertion",
}


def _load() -> list[dict]:
    index_bytes = (_CORPUS / "index.json").read_bytes()
    got = hashlib.sha256(index_bytes).hexdigest()
    if got != CERTIFIED_INDEX_SHA256:
        raise AssertionError(f"index.json SHA-256 mismatch: {got}")
    index = json.loads(index_bytes)
    if index["profile"] != PROFILE_IDENTITY or index["revision"] != REVISION or index["total_cases"] != TOTAL_CASES:
        raise AssertionError("corpus identity mismatch")
    cases: list[dict] = []
    counted = 0
    for entry in index["files"]:
        raw = (_CORPUS / entry["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise AssertionError(f"{entry['path']}: SHA-256 mismatch")
        if entry["cases"] == 0:
            continue  # profile.json / revision.json: integrity-checked, no cases
        doc = json.loads(raw)
        doc_cases = doc["cases"] if isinstance(doc, dict) else doc
        if len(doc_cases) != entry["cases"]:
            raise AssertionError(f"{entry['path']}: case count mismatch")
        cases.extend(doc_cases)
        counted += len(doc["cases"])
    if counted != TOTAL_CASES:
        raise AssertionError(f"case census {counted} != {TOTAL_CASES}")
    return cases


def _assemble(case: dict) -> object:
    sig_input = case["input"]
    signature = base64url_decode(sig_input["signature"].encode())
    kind = sig_input.get("kind") or _PROFILE_KINDS[case["profile"]]
    # The segments are base64url TEXT (the assembler re-encodes from raw); pass them through.
    si = SigningInput(
        kind=kind,
        protected_segment=sig_input["protected_segment"].encode(),
        payload_segment=sig_input["payload_segment"].encode(),
    )
    major = case.get("major")
    if major == 1:
        return v1.assemble_compact(si, signature)
    if major == 2:
        return v2.assemble_compact(si, signature)
    if major == 3:
        return v3.assemble_compact(si, signature)
    profile = case["profile"]
    if profile == "bap-application-proof/local-loopback-http/1":
        return v1.assemble_local_loopback_http_compact(si, signature)
    if profile == "bap-role-attestation/1":
        return role_attestation.assemble_attestation_compact(si, signature)
    if profile == "bap-content-assertion/1":
        return content_assertion.assemble_content_assertion_compact(si, signature)
    raise AssertionError(f"unknown profile {profile}")


_ZERO_DIGEST = bytes(32)


def _export_expected(case: dict, major: int):
    e = case["input"]["expected"]

    def anchor(a: dict):
        return v1.ExpectedAnchor(
            anchor_id=a["anchor_id"], anchored_at=a["anchored_at"], chain_id=a["chain_id"],
            sequence=a["sequence"], chain_hash=base64url_decode(a["chain_hash"].encode()),
            key_id=a["key_id"], key_fingerprint=base64url_decode(a["key_fingerprint"].encode()),
        )

    transitions = tuple(
        v1.ExpectedKeyTransition(
            transition_id=t["transition_id"], chain_id=t["chain_id"], effective_at=t["effective_at"],
            current_key_id=t["current_key_id"],
            current_key_fingerprint=base64url_decode(t["current_key_fingerprint"].encode()),
            next_key_id=t["next_key_id"],
            next_key_fingerprint=base64url_decode(t["next_key_fingerprint"].encode()),
        ) for t in e["transitions"]
    )
    chain = v1.ExpectedChain(
        chain_id=e["chain"]["chain_id"], first_sequence=e["chain"]["first_sequence"],
        last_sequence=e["chain"]["last_sequence"], row_count=e["chain"]["row_count"],
        previous_hash=base64url_decode(e["chain"]["previous_hash"].encode()),
        last_hash=base64url_decode(e["chain"]["last_hash"].encode()),
    )
    digest = base64url_decode(e["digest"].encode()) if e.get("digest") else _ZERO_DIGEST
    version = e.get("object_version") or f"v{major}"
    if major == 3:
        # The encode side never reads digest/object_version (the verify side owns them); the
        # struct requires them, so v3 cases (whose expected context carries neither) take the
        # same placeholders as v2.
        return v3.ExpectedExport(
            chain=chain, digest=digest, object_version=version,
            start_anchor=anchor(e["start_anchor"]), end_anchor=anchor(e["end_anchor"]),
            transitions=transitions,
        )
    return v1.ExpectedExport(
        chain=chain, digest=digest, object_version=version,
        start_anchor=anchor(e["start_anchor"]), end_anchor=anchor(e["end_anchor"]),
        transitions=transitions,
    )


def _encode(case: dict) -> object:
    sig_input = case["input"]
    e = sig_input["expected"]
    inp = v1.AnchoredExportInput(
        rows=tuple(base64url_decode(r.encode()) for r in sig_input["rows"]),
        start_anchor=sig_input["start_anchor"].encode(),
        end_anchor=sig_input["end_anchor"].encode(),
        transitions=tuple(t.encode() for t in sig_input["transitions"]),
        chain_id=e["chain"]["chain_id"], first_sequence=e["chain"]["first_sequence"],
        last_sequence=e["chain"]["last_sequence"], row_count=e["chain"]["row_count"],
        previous_hash=base64url_decode(e["chain"]["previous_hash"].encode()),
        last_hash=base64url_decode(e["chain"]["last_hash"].encode()),
    )
    major = case["major"]
    if major == 1:
        return v1.encode_anchored_export(inp, _export_expected(case, 1))
    if major == 2:
        return v2.encode_anchored_export(inp, _export_expected(case, 2))
    return v3.encode_anchored_export(inp, _export_expected(case, 3))


def run_all() -> dict:
    cases = _load()
    failures: list[str] = []
    passed = 0
    refused = accepted = 0
    for case in cases:
        want_valid = case["expected"]["verdict"] == "valid"
        if case["surface"] == "assemble_compact":
            result = _assemble(case)
            ok = result.is_ok
            if ok != want_valid:
                failures.append(f"{case['id']}: expected {case['expected']['verdict']}, got ok={ok}")
                continue
            if ok and bytes(result.value) != case["expected"]["compact"].encode():
                failures.append(f"{case['id']}: assembled bytes differ from the certified compact")
                continue
        else:
            result = _encode(case)
            ok = result.is_ok
            if ok != want_valid:
                failures.append(f"{case['id']}: expected {case['expected']['verdict']}, got ok={ok}")
                continue
            if ok:
                failures.append(f"{case['id']}: accepted export-encode case without a certified artifact")
                continue
        if want_valid:
            accepted += 1
        else:
            refused += 1
        passed += 1
    return {"pass": passed, "fail": len(failures), "total": len(cases), "failures": failures,
            "refused": refused, "accepted": accepted}
