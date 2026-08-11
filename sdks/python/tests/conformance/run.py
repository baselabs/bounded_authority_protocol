#!/usr/bin/env python3
"""Conformance runner for ``bounded_authority_verifier`` (BAP-09 T9).

Loads the published corpus from ``priv/conformance/v1/corpus/``, recomputes EVERY verdict from
scratch by calling the SDK façade (``bounded_authority_verifier.v1``), and asserts agreement on all
280 cases. Asserts the ``index.json`` SHA-256 at startup (ADR 0014 D4: the SDK binds to the exact
corpus it was certified against). Runs the two-boundary key census (discovery == verify-import ==
index ``public_key_fingerprints``).

This is the independent conformance proof: the SDK is the implementation under test, the corpus is
the arbiter. A disagreement aborts nonzero with the case id + the expected/actual verdict.

Derivation: the corpus is the published normative artifact (BAP-05); the runner is a consumer.
The SDK façade was derived from protocol-v1.md + ADR 0004 + RFCs; this runner exercises it.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

# Locate the package + corpus. The runner is invoked from sdks/python/, so the repo root is two
# levels up; the package is importable from src/.
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[4]
_SRC = _HERE.parents[2] / "src"
sys.path.insert(0, str(_SRC))

from bounded_authority_verifier import v1  # noqa: E402
from bounded_authority_verifier.base64url import base64url_decode, base64url_encode  # noqa: E402
from bounded_authority_verifier.ed25519 import (  # noqa: E402
    imported_fingerprints,
    reset_census,
    sha256,
)
from bounded_authority_verifier.error import InvalidError  # noqa: E402
from bounded_authority_verifier.jcs import jcs_encode  # noqa: E402
from bounded_authority_verifier.json_alg import (  # noqa: E402
    JArray,
    JBool,
    JFloat,
    JInt,
    JNull,
    JObject,
    JString,
    Tagged,
    json_decode,
    str_utf8,
    utf8_str,
)
from bounded_authority_verifier.jwk import jwk_from_public_key, thumbprint_preimage  # noqa: E402
from bounded_authority_verifier.uri import uri_normalize  # noqa: E402

CORPUS_DIR = _REPO_ROOT / "priv" / "conformance" / "v1" / "corpus"
# The certified index.json SHA-256 (ADR 0014 D4). A mismatched vendored corpus fails closed.
CERTIFIED_INDEX_SHA = "557c1d94d0d3e5556e2f543c04838ca967eeb6f3da13a291bab86abb8e68b03a"

INVALID = object()  # sentinel: any genuine protocol rejection maps to this


def _b64d(s: str) -> bytes:
    return base64url_decode(str_utf8(s))


def _b64e(b: bytes) -> str:
    return utf8_str(base64url_encode(b))


def abort(msg: str) -> NoReturn:
    print(f"conformance: {msg}", file=sys.stderr)
    raise SystemExit(1)


# ---- corpus loading ----


def load_corpus() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, bytes]]:
    index_path = CORPUS_DIR / "index.json"
    index_raw = index_path.read_bytes()
    # ADR 0014 D4: assert the index.json SHA-256 matches the certified snapshot.
    index_sha = hashlib.sha256(index_raw).hexdigest()
    if index_sha != CERTIFIED_INDEX_SHA:
        abort(f"index.json SHA mismatch: got {index_sha}, certified {CERTIFIED_INDEX_SHA}")
    index = json.loads(index_raw.decode("utf8"))
    total_cases = index["total_cases"]
    cases: list[dict[str, Any]] = []
    raws: dict[str, bytes] = {}
    for entry in index["files"]:
        path = entry["path"]
        if path.endswith(".raw"):
            raws[path] = (CORPUS_DIR / path).read_bytes()
            continue
        file_json = json.loads((CORPUS_DIR / path).read_text("utf8"))
        cases.extend(file_json["cases"])
    if len(cases) != total_cases:
        abort(f"corpus case count mismatch: index says {total_cases}, loaded {len(cases)}")
    # Verify each raw sidecar's recorded SHA.
    for entry in index["files"]:
        path = entry["path"]
        if not path.endswith(".raw"):
            continue
        sha = entry.get("sha256_base64url")
        if not sha:
            abort(f"raw {path}: missing hash")
        if _b64e(sha256(raws[path])) != sha:
            abort(f"raw {path}: hash mismatch")
    return index, cases, raws


# ---- tamper application (mirrors corpus.ex tamper_target_bytes/2) ----


def apply_tamper(base_input: dict[str, Any], tamper: dict[str, Any], raws: dict[str, bytes]) -> dict[str, Any]:
    target = tamper.get("target")
    xor = tamper.get("xor", 0)
    byte_index = tamper["byte_index"]
    inp = json.loads(json.dumps(base_input))  # deep copy

    def flip(b: bytes) -> bytes:
        if byte_index < 0 or byte_index >= len(b):
            abort(f"tamper byte_index {byte_index} out of range (len {len(b)})")
        out = bytearray(b)
        out[byte_index] = (out[byte_index] ^ xor) & 0xFF
        return bytes(out)

    def b64flip(enc: str) -> str:
        return _b64e(flip(_b64d(enc)))

    if target in (None, "input.text"):
        if isinstance(inp.get("text"), str):
            inp["text"] = utf8_str(flip(str_utf8(inp["text"])))
            return inp
        if isinstance(inp.get("base64url"), str):
            inp["base64url"] = b64flip(inp["base64url"])
            return inp
    if target == "input.base64url" and isinstance(inp.get("base64url"), str):
        inp["base64url"] = b64flip(inp["base64url"])
        return inp
    if target == "compact" and isinstance(inp.get("compact"), str):
        inp["compact"] = utf8_str(flip(str_utf8(inp["compact"])))
        return inp
    if target == "grant" and isinstance(inp.get("grant"), str):
        inp["grant"] = utf8_str(flip(str_utf8(inp["grant"])))
        return inp
    if target == "proof" and isinstance(inp.get("proof"), str):
        inp["proof"] = utf8_str(flip(str_utf8(inp["proof"])))
        return inp
    m = re.match(r"^(rows|chunks)\[(\d+)\]$", str(target))
    if m:
        key = m.group(1)
        i = int(m.group(2))
        lst = inp.get(key)
        if isinstance(lst, list) and i < len(lst) and isinstance(lst[i], str):
            lst[i] = b64flip(lst[i])
            return inp
    abort(f"unresolved tamper target {target}")


# ---- input extraction helpers ----


def fetch_binary(inp: dict[str, Any], key: str, ctx: str) -> str:
    v = inp.get(key)
    if not isinstance(v, str):
        abort(f"{ctx}: missing {key}")
    return v


def b64_field(inp: dict[str, Any], key: str, ctx: str) -> bytes:
    return _b64d(fetch_binary(inp, key, ctx))


def int_field(inp: dict[str, Any], key: str, ctx: str) -> int:
    v = inp.get(key)
    if not isinstance(v, int) or isinstance(v, bool):
        abort(f"{ctx}: integer {key}")
    return v


def input_bytes(inp: dict[str, Any], raws: dict[str, bytes], ctx: str) -> bytes:
    if isinstance(inp.get("text"), str):
        return str_utf8(inp["text"])
    if isinstance(inp.get("base64url"), str):
        return _b64d(inp["base64url"])
    if isinstance(inp.get("raw_file"), str):
        b = raws.get(inp["raw_file"])
        if b is None:
            abort(f"{ctx}: missing raw_file")
        return b
    abort(f"{ctx}: no input bytes")


def input_public_key(inp: dict[str, Any], ctx: str) -> bytes:
    return _b64d(fetch_binary(inp, "public_key", ctx))


def byte_list(inp: dict[str, Any], key: str, ctx: str) -> list[bytes]:
    lst = inp.get(key)
    if not isinstance(lst, list):
        abort(f"{ctx}: list {key}")
    return [_b64d(item) for item in lst]


# ---- surface dispatch ----


def _run_thunk(fn):
    try:
        return fn()
    except InvalidError:
        return INVALID


def dispatch(surface: str, inp: dict[str, Any], raws: dict[str, bytes]) -> Any:
    if surface == "json.decode":
        b = input_bytes(inp, raws, "json.decode")
        v = _run_thunk(lambda: json_decode(b))
        return INVALID if v is INVALID else {"value": _tagged_to_js(v)}
    if surface == "base64url.decode":
        if isinstance(inp.get("base64url"), str):
            segment = inp["base64url"]
        else:
            segment = utf8_str(input_bytes(inp, {}, "base64url.decode"))
        if len(segment) == 0:
            return INVALID
        decoded = _run_thunk(lambda: _b64d(segment))
        return INVALID if decoded is INVALID else {"decoded": utf8_str(decoded)}
    if surface == "jcs.encode":
        b = input_bytes(inp, raws, "jcs.encode")
        encoded = _run_thunk(lambda: jcs_encode(json_decode(b)))
        return INVALID if encoded is INVALID else {"encoded": utf8_str(encoded)}
    if surface == "uri.normalize":
        b = input_bytes(inp, raws, "uri.normalize")
        r = _run_thunk(lambda: uri_normalize(b))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {"normalized": utf8_str(r.value)}
    if surface == "jwk.encode_public":
        raw = input_public_key(inp, "jwk.encode_public")
        encoded = _run_thunk(lambda: v1.jwk_encode_public(raw))
        return INVALID if encoded is INVALID else {"encoded": utf8_str(encoded)}
    if surface == "jwk.decode_public":
        b = input_bytes(inp, raws, "jwk.decode_public")
        r = _run_thunk(lambda: _b64d(_exact_public_jwk(json_decode(b)).x))
        return INVALID if r is INVALID else {"public_key": _b64e(r)}
    if surface == "jwk.thumbprint_preimage":
        b = input_bytes(inp, raws, "jwk.thumbprint_preimage")
        r = _run_thunk(lambda: thumbprint_preimage(_exact_public_jwk(json_decode(b))))
        return INVALID if r is INVALID else {"preimage": utf8_str(r)}
    if surface == "jwk.thumbprint":
        b = input_bytes(inp, raws, "jwk.thumbprint")
        r = _run_thunk(lambda: _b64e(sha256(thumbprint_preimage(_exact_public_jwk(json_decode(b))))))
        return INVALID if r is INVALID else {"thumbprint": r}
    if surface == "jwk.thumbprint_raw":
        b = input_bytes(inp, raws, "jwk.thumbprint_raw")
        r = _run_thunk(lambda: sha256(thumbprint_preimage(_exact_public_jwk(json_decode(b)))))
        return INVALID if r is INVALID else {"thumbprint_raw": r}
    if surface == "jwk.public_key_thumbprint_raw":
        raw = input_public_key(inp, "jwk.public_key_thumbprint_raw")
        r = _run_thunk(lambda: sha256(thumbprint_preimage(jwk_from_public_key(raw))))
        return INVALID if r is INVALID else {"thumbprint_raw": r}
    if surface == "bounds.new":
        overrides = inp.get("overrides", {})
        r = _run_thunk(lambda: v1.bounds_new(overrides))
        return INVALID if r is INVALID else {"bounds": overrides}
    if surface == "untrusted_key_locator":
        compact = str_utf8(fetch_binary(inp, "compact", "untrusted_key_locator"))
        r = _run_thunk(lambda: v1.untrusted_key_locator(compact))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {"kid": r.value.key_id}
    if surface == "grant_signing_input":
        r = _run_thunk(lambda: v1.grant_signing_input(_build_grant_producer(inp)))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {
            "protected_segment": utf8_str(r.value.protected_segment),
            "payload_segment": utf8_str(r.value.payload_segment),
            "message": f"{utf8_str(r.value.protected_segment)}.{utf8_str(r.value.payload_segment)}",
        }
    if surface == "proof_signing_input":
        r = _run_thunk(lambda: v1.proof_signing_input(_build_proof_producer(inp)))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {
            "protected_segment": utf8_str(r.value.protected_segment),
            "payload_segment": utf8_str(r.value.payload_segment),
            "message": f"{utf8_str(r.value.protected_segment)}.{utf8_str(r.value.payload_segment)}",
        }
    if surface == "boundary_anchor_signing_input":
        r = _run_thunk(lambda: v1.boundary_anchor_signing_input(v1.BoundaryAnchorProducer(
            anchor_id=fetch_binary(inp, "anchor_id", "boundary_anchor_signing_input"),
            anchored_at=int_field(inp, "anchored_at", "boundary_anchor_signing_input"),
            chain_id=fetch_binary(inp, "chain_id", "boundary_anchor_signing_input"),
            sequence=int_field(inp, "sequence", "boundary_anchor_signing_input"),
            chain_hash=b64_field(inp, "chain_hash", "boundary_anchor_signing_input"),
            key_id=fetch_binary(inp, "key_id", "boundary_anchor_signing_input"),
            public_key=b64_field(inp, "public_key", "boundary_anchor_signing_input"),
        )))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {
            "protected_segment": utf8_str(r.value.protected_segment),
            "payload_segment": utf8_str(r.value.payload_segment),
            "message": f"{utf8_str(r.value.protected_segment)}.{utf8_str(r.value.payload_segment)}",
        }
    if surface == "key_transition_signing_input":
        r = _run_thunk(lambda: v1.key_transition_signing_input(v1.KeyTransitionProducer(
            transition_id=fetch_binary(inp, "transition_id", "key_transition_signing_input"),
            chain_id=fetch_binary(inp, "chain_id", "key_transition_signing_input"),
            effective_at=int_field(inp, "effective_at", "key_transition_signing_input"),
            current_key_id=fetch_binary(inp, "current_key_id", "key_transition_signing_input"),
            current_public_key=b64_field(inp, "current_public_key", "key_transition_signing_input"),
            next_key_id=fetch_binary(inp, "next_key_id", "key_transition_signing_input"),
            next_public_key=b64_field(inp, "next_public_key", "key_transition_signing_input"),
        )))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {
            "protected_segment": utf8_str(r.value.protected_segment),
            "payload_segment": utf8_str(r.value.payload_segment),
            "message": f"{utf8_str(r.value.protected_segment)}.{utf8_str(r.value.payload_segment)}",
        }
    if surface == "assemble_compact":
        kind = fetch_binary(inp, "kind", "assemble_compact")
        r = _run_thunk(lambda: v1.assemble_compact(
            v1.SigningInput(
                kind=kind,
                protected_segment=str_utf8(fetch_binary(inp, "protected_segment", "assemble_compact")),
                payload_segment=str_utf8(fetch_binary(inp, "payload_segment", "assemble_compact")),
            ),
            b64_field(inp, "signature", "assemble_compact"),
        ))
        return INVALID if (r is INVALID or not r.is_ok) else {"compact": utf8_str(r.value)}
    if surface == "decode_grant":
        compact = str_utf8(fetch_binary(inp, "compact", "decode_grant"))
        r = _run_thunk(lambda: v1.decode_grant(compact))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {"key_id": r.value.key_id}
    if surface == "decode_proof":
        compact = str_utf8(fetch_binary(inp, "compact", "decode_proof"))
        r = _run_thunk(lambda: v1.decode_proof(compact))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {"proof_id": r.value.proof_id}
    if surface == "encode_consumption_entry":
        r = _run_thunk(lambda: v1.encode_consumption_entry(v1.ConsumptionEntry(
            chain_id=fetch_binary(inp, "chain_id", "encode_consumption_entry"),
            sequence=int_field(inp, "sequence", "encode_consumption_entry"),
            previous_hash=b64_field(inp, "previous_hash", "encode_consumption_entry"),
            commitment=b64_field(inp, "commitment", "encode_consumption_entry"),
        )))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {"bytes": utf8_str(r.value.bytes_), "hash": _b64e(r.value.hash_)}
    if surface == "check_chain":
        rows = tuple(byte_list(inp, "rows", "check_chain"))
        expected = v1.ExpectedChain(
            chain_id=fetch_binary(inp, "chain_id", "check_chain"),
            first_sequence=int_field(inp, "first_sequence", "check_chain"),
            last_sequence=int_field(inp, "last_sequence", "check_chain"),
            row_count=int_field(inp, "row_count", "check_chain"),
            previous_hash=b64_field(inp, "previous_hash", "check_chain"),
            last_hash=b64_field(inp, "last_hash", "check_chain"),
        )
        chain = v1.ChainInput(
            rows=rows, chain_id=expected.chain_id, first_sequence=expected.first_sequence,
            last_sequence=expected.last_sequence, row_count=expected.row_count,
            previous_hash=expected.previous_hash, last_hash=expected.last_hash,
        )
        r = _run_thunk(lambda: v1.check_chain(chain, expected))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {}
    if surface == "request_digest":
        operation = fetch_binary(inp, "operation", "request_digest")
        cast_args = _js_to_tagged(inp["cast_arguments"])
        r = _run_thunk(lambda: v1.request_digest(operation, cast_args))
        return INVALID if (r is INVALID or not r.is_ok) else {"digest": _b64e(r.value)}
    if surface == "verify_grant":
        r = _run_thunk(lambda: v1.verify_grant(
            str_utf8(fetch_binary(inp, "compact", "verify_grant")),
            v1.TrustedIssuer(
                key_id=fetch_binary(inp, "key_id", "verify_grant"),
                public_key=b64_field(inp, "public_key", "verify_grant"),
            ),
            v1.ExpectedGrant(
                issuer=fetch_binary(inp, "issuer", "verify_grant"),
                audience=fetch_binary(inp, "audience", "verify_grant"),
                evaluation_time=int_field(inp, "evaluation_time", "verify_grant"),
                clock_skew=int_field(inp, "clock_skew", "verify_grant"),
            ),
        ))
        if r is INVALID or not r.is_ok:
            return INVALID
        f = r.value
        return {
            "version": f.version, "issuer": f.issuer, "grant_id": f.grant_id,
            "issuer_key_fingerprint": _b64e(f.issuer_key_fingerprint),
            "holder_thumbprint": _b64e(f.holder_thumbprint),
            "matched_audience": f.matched_audience,
            "issued_at": f.issued_at, "not_before": f.not_before, "expires_at": f.expires_at,
            "authorization": f.authorization,
        }
    if surface == "verify_historical_anchor":
        key = _build_historical_key(inp.get("key") or {}, "verify_historical_anchor key")
        expected = _build_expected_anchor(inp.get("expected") or {}, "verify_historical_anchor expected")
        r = _run_thunk(lambda: v1.verify_historical_anchor(
            str_utf8(fetch_binary(inp, "compact", "verify_historical_anchor")), key, expected))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {}
    if surface == "verify_key_transition":
        current = _build_historical_key(inp.get("current_key") or {}, "verify_key_transition current")
        nxt = _build_historical_key(inp.get("next_key") or {}, "verify_key_transition next")
        expected = _build_expected_transition(inp.get("expected") or {}, "verify_key_transition expected")
        r = _run_thunk(lambda: v1.verify_key_transition(
            str_utf8(fetch_binary(inp, "compact", "verify_key_transition")), current, nxt, expected))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {}
    if surface == "check_envelope":
        expected = inp.get("expected") or {}
        ti = expected.get("trusted_issuer") or {}
        cast_args = _js_to_tagged(expected["cast_arguments"])
        nonce = _build_nonce(expected.get("nonce"))
        r = _run_thunk(lambda: v1.check_envelope(
            str_utf8(fetch_binary(inp, "grant", "check_envelope")),
            str_utf8(fetch_binary(inp, "proof", "check_envelope")),
            v1.ExpectedRequest(
                trusted_issuer=v1.TrustedIssuer(
                    key_id=fetch_binary(ti, "key_id", "check_envelope"),
                    public_key=b64_field(ti, "public_key", "check_envelope"),
                ),
                issuer=fetch_binary(expected, "issuer", "check_envelope"),
                audience=fetch_binary(expected, "audience", "check_envelope"),
                method=fetch_binary(expected, "method", "check_envelope"),
                target_uri=fetch_binary(expected, "target_uri", "check_envelope"),
                invocation_id=fetch_binary(expected, "invocation_id", "check_envelope"),
                operation=fetch_binary(expected, "operation", "check_envelope"),
                cast_arguments=cast_args,
                evaluation_time=int_field(expected, "evaluation_time", "check_envelope"),
                clock_skew=int_field(expected, "clock_skew", "check_envelope"),
                proof_max_age=int_field(expected, "proof_max_age", "check_envelope"),
                nonce=nonce,
            ),
        ))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {}
    if surface == "encode_anchored_export":
        rows = tuple(byte_list(inp, "rows", "encode_anchored_export"))
        transitions_list = inp.get("transitions") or []
        transitions = tuple(str_utf8(t) for t in transitions_list)
        full_expected = _build_export_expected(inp)
        chain = full_expected.chain
        r = _run_thunk(lambda: v1.encode_anchored_export(
            v1.AnchoredExportInput(
                rows=rows,
                start_anchor=str_utf8(fetch_binary(inp, "start_anchor", "encode_anchored_export")),
                end_anchor=str_utf8(fetch_binary(inp, "end_anchor", "encode_anchored_export")),
                transitions=transitions,
                chain_id=chain.chain_id, first_sequence=chain.first_sequence,
                last_sequence=chain.last_sequence, row_count=chain.row_count,
                previous_hash=chain.previous_hash, last_hash=chain.last_hash,
            ),
            full_expected,
        ))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {"digest": _b64e(r.value.digest), "byte_count": len(r.value.archive)}
    if surface == "verify_anchored_export":
        chunks = tuple(byte_list(inp, "chunks", "verify_anchored_export"))
        version = fetch_binary(inp, "version", "verify_anchored_export")
        keys = tuple(_build_historical_key(k, f"verify_anchored_export key {i}") for i, k in enumerate(inp.get("keys") or []))
        expected = _build_export_expected(inp)
        r = _run_thunk(lambda: v1.verify_anchored_export(
            v1.ArchivedObject(chunks=chunks, version=version),
            v1.HistoricalKeyChain(keys=keys), expected))
        if r is INVALID or not r.is_ok:
            return INVALID
        return {}
    abort(f"unknown surface: {surface}")


def _build_grant_producer(inp: dict[str, Any]) -> v1.GrantProducer:
    return v1.GrantProducer(
        key_id=fetch_binary(inp, "key_id", "grant_signing_input"),
        issuer=fetch_binary(inp, "issuer", "grant_signing_input"),
        grant_id=fetch_binary(inp, "grant_id", "grant_signing_input"),
        audiences=inp.get("audiences"),
        issued_at=int_field(inp, "issued_at", "grant_signing_input"),
        not_before=int_field(inp, "not_before", "grant_signing_input"),
        expires_at=int_field(inp, "expires_at", "grant_signing_input"),
        holder_thumbprint=fetch_binary(inp, "holder_thumbprint", "grant_signing_input"),
        operations=tuple(
            v1.OperationInput(name=op["name"], selectors=tuple(op["selectors"]))
            for op in inp.get("operations", [])
        ),
    )


def _build_proof_producer(inp: dict[str, Any]) -> v1.ProofProducer:
    cast_args = _js_to_tagged(inp["cast_arguments"])
    return v1.ProofProducer(
        holder_public_key=b64_field(inp, "holder_public_key", "proof_signing_input"),
        proof_id=fetch_binary(inp, "proof_id", "proof_signing_input"),
        method=fetch_binary(inp, "method", "proof_signing_input"),
        target_uri=fetch_binary(inp, "target_uri", "proof_signing_input"),
        issued_at=int_field(inp, "issued_at", "proof_signing_input"),
        invocation_id=fetch_binary(inp, "invocation_id", "proof_signing_input"),
        operation=fetch_binary(inp, "operation", "proof_signing_input"),
        grant_compact=str_utf8(fetch_binary(inp, "grant_compact", "proof_signing_input")),
        cast_arguments=cast_args,
        nonce=inp.get("nonce"),
    )


def _build_historical_key(k: dict[str, Any], ctx: str) -> v1.HistoricalPublicKey:
    vb = k.get("valid_before")
    return v1.HistoricalPublicKey(
        key_id=fetch_binary(k, "key_id", ctx),
        public_key=b64_field(k, "public_key", ctx),
        valid_from=int_field(k, "valid_from", ctx),
        valid_before=None if vb is None else vb,
    )


def _build_expected_anchor(e: dict[str, Any], ctx: str) -> v1.ExpectedAnchor:
    return v1.ExpectedAnchor(
        anchor_id=fetch_binary(e, "anchor_id", ctx), anchored_at=int_field(e, "anchored_at", ctx),
        chain_id=fetch_binary(e, "chain_id", ctx), sequence=int_field(e, "sequence", ctx),
        chain_hash=b64_field(e, "chain_hash", ctx), key_id=fetch_binary(e, "key_id", ctx),
        key_fingerprint=b64_field(e, "key_fingerprint", ctx),
    )


def _build_expected_transition(e: dict[str, Any], ctx: str) -> v1.ExpectedKeyTransition:
    return v1.ExpectedKeyTransition(
        transition_id=fetch_binary(e, "transition_id", ctx), chain_id=fetch_binary(e, "chain_id", ctx),
        effective_at=int_field(e, "effective_at", ctx),
        current_key_id=fetch_binary(e, "current_key_id", ctx),
        current_key_fingerprint=b64_field(e, "current_key_fingerprint", ctx),
        next_key_id=fetch_binary(e, "next_key_id", ctx),
        next_key_fingerprint=b64_field(e, "next_key_fingerprint", ctx),
    )


def _build_nonce(nonce: Any) -> v1.NonceNotRequired | v1.NonceRequired:
    if nonce is None:
        return v1.NonceNotRequired()
    if isinstance(nonce, dict) and isinstance(nonce.get("required"), str):
        return v1.NonceRequired(value=nonce["required"])
    abort("check_envelope: expected nonce shape")


def _build_export_expected(inp: dict[str, Any]) -> v1.ExpectedExport:
    expected = inp.get("expected") or {}
    chain = expected.get("chain") or {}
    return v1.ExpectedExport(
        chain=v1.ExpectedChain(
            chain_id=fetch_binary(chain, "chain_id", "export chain"),
            first_sequence=int_field(chain, "first_sequence", "export chain"),
            last_sequence=int_field(chain, "last_sequence", "export chain"),
            row_count=int_field(chain, "row_count", "export chain"),
            previous_hash=b64_field(chain, "previous_hash", "export chain"),
            last_hash=b64_field(chain, "last_hash", "export chain"),
        ),
        digest=b64_field(expected, "digest", "export"),
        start_anchor=_build_expected_anchor(expected.get("start_anchor") or {}, "export start_anchor"),
        end_anchor=_build_expected_anchor(expected.get("end_anchor") or {}, "export end_anchor"),
        transitions=tuple(
            _build_expected_transition(t, "export transition")
            for t in (expected.get("transitions") or [])
        ),
        object_version=fetch_binary(expected, "object_version", "export"),
    )


# ---- tagged JSON <-> Python conversion ----


def _tagged_to_js(v: Tagged) -> Any:
    if isinstance(v, JNull):
        return None
    if isinstance(v, JBool):
        return v.v
    if isinstance(v, (JInt, JFloat)):
        return v.v
    if isinstance(v, JString):
        return utf8_str(v.v)
    if isinstance(v, JArray):
        return [_tagged_to_js(i) for i in v.v]
    if isinstance(v, JObject):
        return {k: _tagged_to_js(val) for k, val in v.v.items()}
    abort("tagged_to_js: unknown tag")


def _js_to_tagged(value: Any) -> Tagged:
    if value is None:
        return JNull()
    if isinstance(value, bool):
        return JBool(value)
    if isinstance(value, int):
        return JInt(value)
    if isinstance(value, float):
        return JFloat(value)
    if isinstance(value, str):
        return JString(str_utf8(value))
    if isinstance(value, list):
        return JArray(tuple(_js_to_tagged(i) for i in value))
    if isinstance(value, dict):
        return JObject({k: _js_to_tagged(val) for k, val in value.items()})
    abort("js_to_tagged: unsupported value")


def _exact_public_jwk(value: Tagged):
    if not isinstance(value, JObject):
        abort("jwk: object")
    crv = value.v.get("crv")
    kty = value.v.get("kty")
    x = value.v.get("x")
    if not isinstance(crv, JString) or utf8_str(crv.v) != "Ed25519":
        abort("jwk: crv")
    if not isinstance(kty, JString) or utf8_str(kty.v) != "OKP":
        abort("jwk: kty")
    if not isinstance(x, JString):
        abort("jwk: x")
    if len(value.v) != 3:
        abort("jwk: closed members")
    raw = _b64d(utf8_str(x.v))
    if len(raw) != 32:
        abort("jwk: x width")
    from bounded_authority_verifier.jwk import OkpPublic

    return OkpPublic(crv="Ed25519", kty="OKP", x=utf8_str(x.v))


# ---- verdict comparison ----


def compare_verdict(expected: dict[str, Any], actual: Any) -> bool:
    verdict = expected.get("verdict")
    if verdict == "invalid":
        return actual is INVALID
    if verdict == "valid":
        if actual is INVALID:
            return False
        for key, expected_value in expected.items():
            if key == "verdict":
                continue
            # Missing key → mismatch; present-but-None is a legitimate value (e.g. value: null).
            if not isinstance(actual, dict) or key not in actual:
                return False
            actual_value = actual[key]
            if not _compare_field(key, expected_value, actual_value):
                return False
        return True
    return False


def _compare_field(key: str, expected: Any, actual: Any) -> bool:
    if key in ("value", "decoded", "bounds", "thumbprint_raw"):
        return _canonical_json(expected) == _canonical_json(actual)
    # Object.is semantics: value equality for numbers/strings/bools, identity for the rest.
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        # Guard against bool/int confusion (True == 1 in Python): require same type for numbers.
        if isinstance(expected, bool) != isinstance(actual, bool):
            return False
        return expected == actual
    if isinstance(expected, str) and isinstance(actual, str):
        return expected == actual
    return expected is actual


def _canonical_json(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (bytes, bytearray)):
        return _b64e(bytes(v))
    if isinstance(v, list):
        return "[" + ",".join(_canonical_json(i) for i in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())
        return "{" + ",".join(f"{json.dumps(k)}:{_canonical_json(v[k])}" for k in keys) + "}"
    return str(v)


# ---- census (two-boundary: discovery == verify-import == index) ----

_PUBLIC_KEY_LABEL = re.compile(r"public.*key|key.*public|verification.*key|holder.*key|issuer.*key", re.IGNORECASE)
_PUBLIC_KEY_DENY = re.compile(r"fingerprint|thumbprint|digest|hash", re.IGNORECASE)
_VERIFICATION_SURFACES = frozenset({
    "verify_grant", "verify_historical_anchor", "verify_key_transition", "check_envelope", "verify_anchored_export",
})
_RAW_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _is_census_key_label(key: str) -> bool:
    if _PUBLIC_KEY_DENY.search(key):
        return False
    return _PUBLIC_KEY_LABEL.search(key) is not None


def _decode_census_raw_key(value: Any) -> bytes | None:
    if isinstance(value, str) and _RAW_KEY_RE.match(value):
        b = _b64d(value)
        return b if len(b) == 32 else None
    return None


def _collect_case_keys(value: Any, target: set[str]) -> None:
    if isinstance(value, list):
        for item in value:
            _collect_case_keys(item, target)
        return
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if _is_census_key_label(key):
            raw = _decode_census_raw_key(child)
            if raw is not None:
                target.add(_b64e(sha256(thumbprint_preimage(jwk_from_public_key(raw)))))
        _collect_case_keys(child, target)


def run_census(index: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    declared = list(index["public_key_fingerprints"])
    declared_sorted = sorted(set(declared))
    if declared != declared_sorted:
        abort("census: index public_key_fingerprints not sorted/unique")
    discovery: set[str] = set()
    for c in cases:
        _collect_case_keys(c["input"], discovery)
    discovery_sorted = sorted(discovery)
    if discovery_sorted != declared:
        abort(
            "census: discovery != index public_key_fingerprints\n"
            f"  discovery=[{','.join(discovery_sorted)}]\n"
            f"  declared=[{','.join(declared)}]"
        )
    verify_import = sorted(imported_fingerprints())
    expected_verify: set[str] = set()
    for c in cases:
        if c.get("class") == "valid" and c["surface"] in _VERIFICATION_SURFACES:
            _collect_case_keys(c["input"], expected_verify)
    if len(expected_verify) == 0:
        abort("census: no valid verification-surface keys discovered (corpus lost its verify cases)")
    for fp in expected_verify:
        if fp not in verify_import:
            abort(
                f"census: key {fp} declared by a valid verification case but never imported at the "
                "Ed25519 verify boundary"
            )


# ---- main ----


def run_all() -> dict[str, Any]:
    index, cases, raws = load_corpus()
    reset_census()
    passed = 0
    failed = 0
    failures: list[str] = []
    for c in cases:
        inp = c["input"]
        tamper = c.get("tamper")
        if tamper:
            base = next((b for b in cases if b["id"] == tamper["base_case"]), None)
            if base is None:
                abort(f"{c['id']}: tamper base_case {tamper['base_case']} not found")
            inp = apply_tamper(base["input"], tamper, raws)
        actual = dispatch(c["surface"], inp, raws)
        if compare_verdict(c["expected"], actual):
            passed += 1
        else:
            failed += 1
            failures.append(c["id"])
    run_census(index, cases)
    return {"pass": passed, "fail": failed, "total": len(cases), "index": index, "cases": cases, "failures": failures}


def run_census_standalone() -> None:
    result = run_all()
    index = result["index"]
    total = result["total"]
    passed = result["pass"]
    failed = result["fail"]
    print(f"census: ran {total} cases ({passed} agree, {failed} disagree) to populate the verify-import boundary")
    fp_count = len(index["public_key_fingerprints"])
    print(f"census: discovery == verify-import ⊇ expected-verify-keys == index public_key_fingerprints ({fp_count} keys)")
    if failed > 0:
        raise SystemExit(1)
    print("census: PASS (two-boundary equal)")


def main() -> None:
    result = run_all()
    passed = result["pass"]
    failed = result["fail"]
    total = result["total"]
    index = result["index"]
    print(f"conformance: {passed}/{total} cases agree")
    fp_count = len(index["public_key_fingerprints"])
    print(f"census: discovery == verify-import == index public_key_fingerprints ({fp_count} keys)")
    if failed > 0:
        print(f"\n{failed} FAILURE(S):", file=sys.stderr)
        for fid in result["failures"]:
            print(f"  - {fid}", file=sys.stderr)
        raise SystemExit(1)
    print("conformance: PASS (all cases agree + census two-way equal)")


if __name__ == "__main__":
    main()
