#!/usr/bin/env python3
"""Build the language-neutral ``bap-content-assertion/1`` corpus.

This generator is independent of every verifier implementation. It derives bytes from the
normative specification, uses real ephemeral Ed25519/ECDSA keys, and serializes public material
only. Private keys remain in process memory and are never written.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "priv/conformance/attestation-profiles/content-assertion/v1"
PROFILE = "bap-content-assertion/1"
REVISION = 1
ZERO = bytes(32)
PRE_URI_INDEX_SHA256 = "6ed668d5b6ef2af9a4d5db3ac09fd4cdfd6f0ea1373b1bdc50fe24391664898d"
PRE_URI_AUTHORITY_INDEX_SHA256 = "13074fcc4ed7d77ec9c0d33ee8ee7c58df65fde69c4d219def1a15d8856bfdd8"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def json_file(path: Path, value: object) -> None:
    path.write_bytes(canonical(value) + b"\n")


def raw_public(private: ed25519.Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def compact_from_bytes(
    header_bytes: bytes,
    payload_bytes: bytes,
    signer: ed25519.Ed25519PrivateKey,
) -> str:
    signing = b64(header_bytes) + "." + b64(payload_bytes)
    return signing + "." + b64(signer.sign(signing.encode("ascii")))


def compact(
    header: dict[str, object],
    payload: dict[str, object],
    signer: ed25519.Ed25519PrivateKey,
) -> str:
    return compact_from_bytes(canonical(header), canonical(payload), signer)


def decoded_segment(compact_value: str, index: int) -> bytes:
    segment = compact_value.split(".")[index]
    return base64.urlsafe_b64decode(segment + "==")


def tamper_signature(compact_value: str) -> str:
    protected, payload, signature = compact_value.split(".")
    raw = bytearray(base64.urlsafe_b64decode(signature + "=="))
    raw[len(raw) // 2] ^= 1
    return ".".join((protected, payload, b64(bytes(raw))))


def valid_legacy_compact(major: int) -> str:
    base = ROOT / f"priv/conformance/v{major}/corpus/cases"
    for path in sorted(base.rglob("*.json")):
        value = json.loads(path.read_text())
        for case in value.get("cases", []):
            if (
                case.get("surface") == "verify_grant"
                and case.get("expected", {}).get("verdict") == "valid"
            ):
                return case["input"]["compact"]
    raise RuntimeError(f"no valid v{major} grant compact found")


def uri_check_cases(
    header: dict[str, object],
    payload: dict[str, object],
    signer: ed25519.Ed25519PrivateKey,
) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for case_id, class_, jti, verdict in (
        ("uri-single-fragment-valid-control", "valid", "urn:x#a", "valid"),
        ("uri-double-fragment-rejected", "invalid_claim", "urn:x#a#b", "invalid"),
        ("uri-raw-brackets-rejected", "invalid_claim", "urn:x[foo]", "invalid"),
    ):
        cases.append(
            {
                "id": case_id,
                "class": class_,
                "compact": compact(header, {**payload, "jti": jti}, signer),
                "expected": {"decode": verdict, "verify": verdict},
                "attestor": "uri_check",
            }
        )
    return cases


def uri_authority_check_cases(
    header: dict[str, object],
    payload: dict[str, object],
    signer: ed25519.Ed25519PrivateKey,
) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for case_id, class_, jti, verdict in (
        (
            "uri-userinfo-escaped-brackets-valid-control",
            "valid",
            "urn://user%5Binfo%5D@example.com/x",
            "valid",
        ),
        (
            "uri-userinfo-raw-bracket-rejected",
            "invalid_claim",
            "urn://user[info]@example.com/x",
            "invalid",
        ),
        ("uri-ipv6-literal-valid-control", "valid", "urn://[::1]/x", "valid"),
        (
            "uri-invalid-bracketed-host-rejected",
            "invalid_claim",
            "urn://[abc]/x",
            "invalid",
        ),
    ):
        cases.append(
            {
                "id": case_id,
                "class": class_,
                "compact": compact(header, {**payload, "jti": jti}, signer),
                "expected": {"decode": verdict, "verify": verdict},
                "attestor": "uri_authority_check",
            }
        )
    return cases


def add_uri_checks() -> None:
    index_path = OUT / "index.json"
    actual_index_sha = hashlib.sha256(index_path.read_bytes()).hexdigest()
    if actual_index_sha != PRE_URI_INDEX_SHA256:
        raise RuntimeError(
            f"incremental URI checks require index {PRE_URI_INDEX_SHA256}, got {actual_index_sha}"
        )

    profile_path = OUT / "profile.json"
    structure_path = OUT / "assertion-structure-cases.json"
    verification_path = OUT / "assertion-verification-cases.json"
    profile = json.loads(profile_path.read_text())
    structure_cases = json.loads(structure_path.read_text())
    verification_cases = json.loads(verification_path.read_text())
    existing_ids = {case["id"] for case in structure_cases}
    new_ids = {
        "uri-single-fragment-valid-control",
        "uri-double-fragment-rejected",
        "uri-raw-brackets-rejected",
    }
    if existing_ids & new_ids or "uri_check" in profile["attestors"]:
        raise RuntimeError("incremental URI checks are already present")

    uri_private = ed25519.Ed25519PrivateKey.generate()
    uri_public = raw_public(uri_private)
    primary = profile["attestors"]["primary"]
    profile["attestors"]["uri_check"] = {
        "key_id": "attestor-ca-uri-check",
        "public_key": b64(uri_public),
        "valid_from": primary["valid_from"],
        "valid_before": primary["valid_before"],
    }

    baseline = next(case for case in structure_cases if case["id"] == "valid-genesis")
    header = json.loads(decoded_segment(baseline["compact"], 0))
    payload = json.loads(decoded_segment(baseline["compact"], 1))
    header["kid"] = "attestor-ca-uri-check"
    structure_cases.extend(uri_check_cases(header, payload, uri_private))
    json_file(profile_path, profile)
    json_file(structure_path, structure_cases)

    index = json.loads(index_path.read_text())
    index["assertion_cases"] = len(structure_cases) + len(verification_cases)
    for entry in index["files"]:
        path = OUT / entry["path"]
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    json_file(index_path, index)

    print(
        json.dumps(
            {
                "assertion_cases": index["assertion_cases"],
                "digest_cases": index["digest_cases"],
                "successor_cases": index["successor_cases"],
                "index_sha256": hashlib.sha256(index_path.read_bytes()).hexdigest(),
                "profile_bytes": profile_path.stat().st_size,
                "structure_bytes": structure_path.stat().st_size,
            },
            sort_keys=True,
        )
    )


def add_uri_authority_checks() -> None:
    index_path = OUT / "index.json"
    actual_index_sha = hashlib.sha256(index_path.read_bytes()).hexdigest()
    if actual_index_sha != PRE_URI_AUTHORITY_INDEX_SHA256:
        raise RuntimeError(
            "incremental URI authority checks require index "
            f"{PRE_URI_AUTHORITY_INDEX_SHA256}, got {actual_index_sha}"
        )

    profile_path = OUT / "profile.json"
    structure_path = OUT / "assertion-structure-cases.json"
    verification_path = OUT / "assertion-verification-cases.json"
    profile = json.loads(profile_path.read_text())
    structure_cases = json.loads(structure_path.read_text())
    verification_cases = json.loads(verification_path.read_text())
    existing_ids = {case["id"] for case in structure_cases}
    new_ids = {
        "uri-userinfo-escaped-brackets-valid-control",
        "uri-userinfo-raw-bracket-rejected",
        "uri-ipv6-literal-valid-control",
        "uri-invalid-bracketed-host-rejected",
    }
    if existing_ids & new_ids or "uri_authority_check" in profile["attestors"]:
        raise RuntimeError("incremental URI authority checks are already present")

    uri_private = ed25519.Ed25519PrivateKey.generate()
    uri_public = raw_public(uri_private)
    primary = profile["attestors"]["primary"]
    profile["attestors"]["uri_authority_check"] = {
        "key_id": "attestor-ca-uri-authority-check",
        "public_key": b64(uri_public),
        "valid_from": primary["valid_from"],
        "valid_before": primary["valid_before"],
    }

    baseline = next(case for case in structure_cases if case["id"] == "valid-genesis")
    header = json.loads(decoded_segment(baseline["compact"], 0))
    payload = json.loads(decoded_segment(baseline["compact"], 1))
    header["kid"] = "attestor-ca-uri-authority-check"
    structure_cases.extend(uri_authority_check_cases(header, payload, uri_private))
    json_file(profile_path, profile)
    json_file(structure_path, structure_cases)

    index = json.loads(index_path.read_text())
    index["assertion_cases"] = len(structure_cases) + len(verification_cases)
    for entry in index["files"]:
        path = OUT / entry["path"]
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    json_file(index_path, index)

    print(
        json.dumps(
            {
                "assertion_cases": index["assertion_cases"],
                "digest_cases": index["digest_cases"],
                "successor_cases": index["successor_cases"],
                "index_sha256": hashlib.sha256(index_path.read_bytes()).hexdigest(),
                "profile_bytes": profile_path.stat().st_size,
                "structure_bytes": structure_path.stat().st_size,
            },
            sort_keys=True,
        )
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    primary_private = ed25519.Ed25519PrivateKey.generate()
    rotated_private = ed25519.Ed25519PrivateKey.generate()
    other_private = ed25519.Ed25519PrivateKey.generate()
    uri_private = ed25519.Ed25519PrivateKey.generate()
    uri_authority_private = ed25519.Ed25519PrivateKey.generate()
    primary_public = raw_public(primary_private)
    rotated_public = raw_public(rotated_private)
    other_public = raw_public(other_private)
    uri_public = raw_public(uri_private)
    uri_authority_public = raw_public(uri_authority_private)

    content_base = b"urn:example:content:1"
    pattern = b"urn:example:content:"
    content_maximum = (pattern * (65_536 // len(pattern) + 1))[:65_536]
    content_over_limit = (pattern * (65_537 // len(pattern) + 1))[:65_537]
    (OUT / "content-base.raw").write_bytes(content_base)
    (OUT / "content-maximum.raw").write_bytes(content_maximum)
    (OUT / "content-over-limit.raw").write_bytes(content_over_limit)

    profile_digest = hashlib.sha256(b"urn:example:content-profile:1").digest()
    base_content_digest = hashlib.sha256(b"BAP1-CONTENT\x00" + content_base).digest()
    changed_content_digest = hashlib.sha256(b"BAP1-CONTENT\x00urn:example:content:2").digest()

    attestors = {
        "primary": {
            "key_id": "attestor-ca-1",
            "public_key": b64(primary_public),
            "valid_from": 1_735_689_000,
            "valid_before": 1_735_694_000,
        },
        "rotated": {
            "key_id": "attestor-ca-2",
            "public_key": b64(rotated_public),
            "valid_from": 1_735_693_000,
            "valid_before": 1_735_698_000,
        },
        "other": {
            "key_id": "attestor-ca-other",
            "public_key": b64(other_public),
            "valid_from": 1_735_689_000,
            "valid_before": 1_735_694_000,
        },
        "negative": {
            "key_id": "attestor-ca-negative",
            "public_key": b64(primary_public),
            "valid_from": -2_000,
            "valid_before": -1_000,
        },
        "uri_check": {
            "key_id": "attestor-ca-uri-check",
            "public_key": b64(uri_public),
            "valid_from": 1_735_689_000,
            "valid_before": 1_735_694_000,
        },
        "uri_authority_check": {
            "key_id": "attestor-ca-uri-authority-check",
            "public_key": b64(uri_authority_public),
            "valid_from": 1_735_689_000,
            "valid_before": 1_735_694_000,
        },
    }
    baseline_expected = {
        "issuer": "urn:example:issuer:1",
        "audience": "urn:example:audience:1",
        "subject": "urn:example:lineage:1",
        "profile": "urn:example:content-profile:1",
        "profile_digest": b64(profile_digest),
        "content_digest": b64(base_content_digest),
        "now": 1_735_691_000,
    }
    profile = {
        "profile": PROFILE,
        "revision": REVISION,
        "attestors": attestors,
        "expected": baseline_expected,
        "content": {
            "path": "content-base.raw",
            "sha256": hashlib.sha256(content_base).hexdigest(),
            "digest": b64(base_content_digest),
        },
    }
    json_file(OUT / "profile.json", profile)

    base_header: dict[str, object] = {
        "alg": "EdDSA",
        "kid": attestors["primary"]["key_id"],
        "typ": "ba+content-assertion",
    }
    base_payload: dict[str, object] = {
        "aud": baseline_expected["audience"],
        "content_digest": b64(base_content_digest),
        "exp": 1_735_693_200,
        "gen": 1,
        "iat": 1_735_689_500,
        "iss": baseline_expected["issuer"],
        "jti": "urn:example:assertion:1",
        "nbf": 1_735_689_600,
        "prev": b64(ZERO),
        "profile": baseline_expected["profile"],
        "profile_digest": b64(profile_digest),
        "sub": baseline_expected["subject"],
        "v": 1,
    }
    baseline_compact = compact(base_header, base_payload, primary_private)

    assertion_cases: list[dict[str, Any]] = []

    def assertion_case(
        case_id: str,
        class_: str,
        compact_value: str,
        decode: str,
        verify: str,
        **extra: object,
    ) -> None:
        case: dict[str, Any] = {
            "id": case_id,
            "class": class_,
            "compact": compact_value,
            "expected": {"decode": decode, "verify": verify},
        }
        case.update(extra)
        assertion_cases.append(case)

    assertion_case("valid-genesis", "valid", baseline_compact, "valid", "valid")
    assertion_cases.extend(
        uri_check_cases(
            {**base_header, "kid": attestors["uri_check"]["key_id"]},
            base_payload,
            uri_private,
        )
    )
    assertion_cases.extend(
        uri_authority_check_cases(
            {**base_header, "kid": attestors["uri_authority_check"]["key_id"]},
            base_payload,
            uri_authority_private,
        )
    )

    for member in ("alg", "kid", "typ"):
        header = dict(base_header)
        del header[member]
        assertion_case(
            f"missing-header-{member}",
            "invalid_header",
            compact(header, base_payload, primary_private),
            "invalid",
            "invalid",
        )
    for member in sorted(base_payload):
        payload = dict(base_payload)
        del payload[member]
        assertion_case(
            f"missing-payload-{member.replace('_', '-')}",
            "invalid_claim",
            compact(base_header, payload, primary_private),
            "invalid",
            "invalid",
        )

    header_extra = {**base_header, "extra": "urn:example:extra"}
    assertion_case(
        "unknown-header-member",
        "invalid_header",
        compact(header_extra, base_payload, primary_private),
        "invalid",
        "invalid",
    )
    payload_extra = {**base_payload, "extra": "urn:example:extra"}
    assertion_case(
        "unknown-payload-member",
        "invalid_claim",
        compact(base_header, payload_extra, primary_private),
        "invalid",
        "invalid",
    )

    for name, value in (
        ("wrong-alg", "none"),
        ("wrong-typ", "ba+role-attestation"),
        ("wrong-kid-type", 1),
    ):
        header = dict(base_header)
        header[{"wrong-alg": "alg", "wrong-typ": "typ", "wrong-kid-type": "kid"}[name]] = value
        assertion_case(
            name,
            "invalid_header",
            compact(header, base_payload, primary_private),
            "invalid",
            "invalid",
        )
    for member, value in (
        ("jti", 1),
        ("iss", 1),
        ("aud", [baseline_expected["audience"]]),
        ("sub", 1),
        ("profile", 1),
        ("profile_digest", 1),
        ("content_digest", 1),
        ("prev", 1),
        ("gen", "1"),
        ("iat", "1735689500"),
        ("nbf", "1735689600"),
        ("exp", "1735693200"),
    ):
        payload = {**base_payload, member: value}
        assertion_case(
            f"wrong-type-{member.replace('_', '-')}",
            "invalid_claim",
            compact(base_header, payload, primary_private),
            "invalid",
            "invalid",
        )
    for member in ("v", "gen", "iat", "nbf", "exp"):
        payload = {**base_payload, member: float(base_payload[member])}
        assertion_case(
            f"float-lexeme-{member}",
            "invalid_claim",
            compact(base_header, payload, primary_private),
            "invalid",
            "invalid",
        )
    assertion_case(
        "wrong-version",
        "invalid_claim",
        compact(base_header, {**base_payload, "v": 2}, primary_private),
        "invalid",
        "invalid",
    )

    for member in ("profile_digest", "content_digest", "prev"):
        for label, value in (
            ("short", b64(b"s" * 31)),
            ("long", b64(b"l" * 33)),
            ("padded", b64(b"p" * 32) + "="),
            ("alphabet", "+" + b64(b"a" * 32)[1:]),
            ("tagged", "sha256:" + b64(b"t" * 32)),
        ):
            payload = {**base_payload, member: value}
            assertion_case(
                f"{member.replace('_', '-')}-{label}",
                "invalid_encoding",
                compact(base_header, payload, primary_private),
                "invalid",
                "invalid",
            )

    for case_id, changes in (
        ("genesis-nonzero-prev", {"prev": b64(b"x" * 32)}),
        ("nongenenesis-zero-prev", {"gen": 2}),
        ("generation-zero", {"gen": 0}),
        ("iat-after-nbf", {"iat": base_payload["nbf"] + 1}),
        ("empty-window", {"exp": base_payload["nbf"]}),
        ("inverted-window", {"exp": base_payload["nbf"] - 1}),
    ):
        assertion_case(
            case_id,
            "invalid_claim",
            compact(base_header, {**base_payload, **changes}, primary_private),
            "invalid",
            "invalid",
        )

    noncanonical_header = b'{"typ":"ba+content-assertion","kid":"attestor-ca-1","alg":"EdDSA"}'
    assertion_case(
        "noncanonical-header-order",
        "invalid_encoding",
        compact_from_bytes(noncanonical_header, canonical(base_payload), primary_private),
        "invalid",
        "invalid",
    )
    noncanonical_payload = json.dumps(
        dict(reversed(tuple(base_payload.items()))),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode()
    assertion_case(
        "noncanonical-payload-order",
        "invalid_encoding",
        compact_from_bytes(canonical(base_header), noncanonical_payload, primary_private),
        "invalid",
        "invalid",
    )
    duplicate_header = canonical(base_header).replace(b'{"alg":', b'{"alg":"EdDSA","alg":', 1)
    assertion_case(
        "duplicate-header-member",
        "invalid_encoding",
        compact_from_bytes(duplicate_header, canonical(base_payload), primary_private),
        "invalid",
        "invalid",
    )
    duplicate_payload = canonical(base_payload).replace(
        b'{"aud":', b'{"aud":"urn:example:audience:1","aud":', 1
    )
    assertion_case(
        "duplicate-payload-member",
        "invalid_encoding",
        compact_from_bytes(canonical(base_header), duplicate_payload, primary_private),
        "invalid",
        "invalid",
    )

    for case_id, overrides in (
        ("expected-issuer-mismatch", {"issuer": "urn:example:issuer:other"}),
        ("expected-audience-mismatch", {"audience": "urn:example:audience:other"}),
        ("expected-subject-mismatch", {"subject": "urn:example:lineage:other"}),
        ("expected-profile-mismatch", {"profile": "urn:example:content-profile:other"}),
        ("expected-profile-digest-mismatch", {"profile_digest": b64(b"p" * 32)}),
        ("expected-content-digest-mismatch", {"content_digest": b64(b"c" * 32)}),
        ("expected-content-digest-wrong-width", {"content_digest": b64(b"c" * 31)}),
        ("now-before-window", {"now": base_payload["nbf"] - 1}),
        ("now-at-exp", {"now": base_payload["exp"]}),
    ):
        assertion_case(
            case_id,
            "invalid_context",
            baseline_compact,
            "valid",
            "invalid",
            expected_overrides=overrides,
        )
    assertion_case(
        "now-at-nbf",
        "valid",
        baseline_compact,
        "valid",
        "valid",
        expected_overrides={"now": base_payload["nbf"]},
    )
    assertion_case(
        "wrong-attestor-key-id",
        "invalid_context",
        baseline_compact,
        "valid",
        "invalid",
        expected_overrides={"attestor_key_id": "attestor-ca-other"},
    )
    assertion_case(
        "wrong-attestor-public-key",
        "invalid_signature",
        baseline_compact,
        "valid",
        "invalid",
        expected_overrides={"attestor_public_key": b64(other_public)},
    )
    assertion_case(
        "iat-before-key-window",
        "invalid_time",
        compact(
            base_header,
            {**base_payload, "iat": attestors["primary"]["valid_from"] - 1},
            primary_private,
        ),
        "valid",
        "invalid",
    )
    assertion_case(
        "nbf-before-key-window",
        "invalid_time",
        compact(
            base_header,
            {
                **base_payload,
                "iat": attestors["primary"]["valid_from"] - 1,
                "nbf": attestors["primary"]["valid_from"] - 1,
            },
            primary_private,
        ),
        "valid",
        "invalid",
    )
    exp_at_ceiling_payload = {
        **base_payload,
        "exp": attestors["primary"]["valid_before"],
    }
    exp_at_ceiling = compact(base_header, exp_at_ceiling_payload, primary_private)
    assertion_case(
        "exp-at-key-window-ceiling",
        "valid",
        exp_at_ceiling,
        "valid",
        "valid",
    )
    assertion_case(
        "exp-beyond-key-window",
        "invalid_time",
        compact(
            base_header,
            {**base_payload, "exp": attestors["primary"]["valid_before"] + 1},
            primary_private,
        ),
        "valid",
        "invalid",
    )

    assertion_case(
        "tampered-signature-byte",
        "tamper_meaningful_byte",
        tamper_signature(baseline_compact),
        "valid",
        "invalid",
        tamper={
            "target": "compact.signature",
            "meaning": "middle byte of the Ed25519 signature",
            "xor": 1,
        },
    )
    wrong_signer = compact(base_header, base_payload, other_private)
    assertion_case(
        "signature-by-other-key",
        "invalid_signature",
        wrong_signer,
        "valid",
        "invalid",
    )
    assertion_case(
        "truncated-compact",
        "invalid_encoding",
        ".".join(baseline_compact.split(".")[:2]),
        "invalid",
        "invalid",
    )
    es_private = ec.generate_private_key(ec.SECP256R1())
    es_header = {**base_header, "alg": "ES256"}
    es_signing = b64(canonical(es_header)) + "." + b64(canonical(base_payload))
    der = es_private.sign(es_signing.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    es_compact = es_signing + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    assertion_case(
        "es256-signed-confusion",
        "invalid_algorithm",
        es_compact,
        "invalid",
        "invalid",
    )

    for bound_name in ("anchor_bytes", "compact_bytes"):
        assertion_case(
            f"{bound_name.replace('_bytes', '')}-bound-exact",
            "valid_bound",
            baseline_compact,
            "valid",
            "valid",
            bounds={bound_name: len(baseline_compact)},
        )
        assertion_case(
            f"{bound_name.replace('_bytes', '')}-bound-minus-one",
            "maximum_plus_one",
            baseline_compact,
            "invalid",
            "invalid",
            bounds={bound_name: len(baseline_compact) - 1},
        )

    encoded_segments = baseline_compact.split(".")
    decoded_segments = [decoded_segment(baseline_compact, index) for index in range(3)]
    header_bytes, payload_bytes = decoded_segments[:2]
    header_value = json.loads(header_bytes)
    payload_value = json.loads(payload_bytes)
    string_values = [
        value
        for document in (header_value, payload_value)
        for value in document.values()
        if isinstance(value, str)
    ]
    integer_values = [
        value
        for value in payload_value.values()
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    deciding_limits = {
        "encoded_segment_bytes": max(len(segment) for segment in encoded_segments),
        "decoded_segment_bytes": max(len(segment) for segment in decoded_segments),
        "json_bytes": max(len(header_bytes), len(payload_bytes)),
        "jcs_bytes": max(len(header_bytes), len(payload_bytes)),
        "kid_bytes": len(str(base_header["kid"]).encode()),
        "string_bytes": max(len(value.encode()) for value in string_values),
        "key_bytes": max(
            len(key.encode()) for document in (header_value, payload_value) for key in document
        ),
        "object_members": max(len(header_value), len(payload_value)),
        "total_nodes": max(len(header_value), len(payload_value)) + 1,
        "number_lexeme_bytes": max(len(str(value).encode()) for value in integer_values),
    }
    for bound_name, exact in deciding_limits.items():
        case_stem = bound_name.replace("_bytes", "").replace("_", "-")
        assertion_case(
            f"{case_stem}-bound-exact",
            "valid_bound",
            baseline_compact,
            "valid",
            "valid",
            bounds={bound_name: exact},
        )
        assertion_case(
            f"{case_stem}-bound-minus-one",
            "maximum_plus_one",
            baseline_compact,
            "invalid",
            "invalid",
            bounds={bound_name: exact - 1},
        )

    assertion_case(
        "depth-bound-exact",
        "valid_bound",
        baseline_compact,
        "valid",
        "valid",
        bounds={"depth": 1},
    )
    assertion_case(
        "depth-bound-below-minimum",
        "invalid_bounds",
        baseline_compact,
        "invalid",
        "invalid",
        bounds={"depth": 0},
    )
    longest_identifier = max(
        len(str(base_payload[key]).encode()) for key in ("jti", "iss", "aud", "sub", "profile")
    )
    assertion_case(
        "identifier-bound-exact",
        "valid_bound",
        baseline_compact,
        "valid",
        "valid",
        bounds={"identifier_bytes": longest_identifier},
    )
    assertion_case(
        "identifier-bound-minus-one",
        "maximum_plus_one",
        baseline_compact,
        "invalid",
        "invalid",
        bounds={"identifier_bytes": longest_identifier - 1},
    )
    negative_payload = {
        **base_payload,
        "iat": -2_000,
        "nbf": -1_900,
        "exp": -1_800,
    }
    negative_header = {**base_header, "kid": attestors["negative"]["key_id"]}
    negative_compact = compact(negative_header, negative_payload, primary_private)
    assertion_case(
        "negative-magnitude-bound-exact",
        "valid_bound",
        negative_compact,
        "valid",
        "valid",
        attestor="negative",
        bounds={"integer_magnitude": 2_000},
        expected_overrides={"now": -1_900},
    )
    assertion_case(
        "negative-magnitude-bound-minus-one",
        "maximum_plus_one",
        negative_compact,
        "invalid",
        "invalid",
        attestor="negative",
        bounds={"integer_magnitude": 1_999},
        expected_overrides={"now": -1_900},
    )
    positive_magnitude = max(abs(value) for value in integer_values)
    assertion_case(
        "positive-magnitude-bound-exact",
        "valid_bound",
        baseline_compact,
        "valid",
        "valid",
        bounds={"integer_magnitude": positive_magnitude},
        expected_overrides={"attestor_valid_before": positive_magnitude},
    )
    assertion_case(
        "positive-magnitude-bound-minus-one",
        "maximum_plus_one",
        baseline_compact,
        "invalid",
        "invalid",
        bounds={"integer_magnitude": positive_magnitude - 1},
    )
    assertion_case(
        "bounds-widening-refused",
        "invalid_bounds",
        baseline_compact,
        "invalid",
        "invalid",
        bounds={"content_bytes": 65_537},
    )
    assertion_case(
        "fixed-width-change-refused",
        "invalid_bounds",
        baseline_compact,
        "invalid",
        "invalid",
        bounds={"digest_bytes": 31},
    )

    legacy_compacts = {
        "v1_grant": valid_legacy_compact(1),
        "v2_grant": valid_legacy_compact(2),
        "v3_grant": valid_legacy_compact(3),
        "loopback": json.loads(
            (
                ROOT
                / "priv/conformance/application-profiles/local-loopback-http/v1/proof-cases.json"
            ).read_text()
        )[0]["compact"],
        "role_attestation": json.loads(
            (
                ROOT
                / "priv/conformance/attestation-profiles/role-attestation/v1/attestation-cases.json"
            ).read_text()
        )[0]["compact"],
    }
    for legacy, compact_value in legacy_compacts.items():
        assertion_case(
            f"cross-profile-{legacy.replace('_', '-')}-rejected",
            "cross_profile",
            compact_value,
            "invalid",
            "invalid",
            legacy_accepts=[legacy],
        )

    digest_cases: list[dict[str, Any]] = [
        {
            "id": "content-base",
            "class": "valid",
            "input": {"content_file": "content-base.raw", "bounds": {}},
            "expected": {"verdict": "valid", "digest": b64(base_content_digest)},
        },
        {
            "id": "content-one-byte",
            "class": "valid_bound",
            "input": {"content_base64url": b64(b"x"), "bounds": {}},
            "expected": {
                "verdict": "valid",
                "digest": b64(hashlib.sha256(b"BAP1-CONTENT\x00x").digest()),
            },
        },
        {
            "id": "content-empty",
            "class": "invalid_claim",
            "input": {"content_base64url": "", "bounds": {}},
            "expected": {"verdict": "invalid"},
        },
        {
            "id": "content-maximum",
            "class": "valid_bound",
            "input": {"content_file": "content-maximum.raw", "bounds": {}},
            "expected": {
                "verdict": "valid",
                "digest": b64(hashlib.sha256(b"BAP1-CONTENT\x00" + content_maximum).digest()),
            },
        },
        {
            "id": "content-over-limit",
            "class": "maximum_plus_one",
            "input": {"content_file": "content-over-limit.raw", "bounds": {}},
            "expected": {"verdict": "invalid"},
        },
        {
            "id": "content-tightened-exact",
            "class": "valid_bound",
            "input": {"content_base64url": b64(b"abcd"), "bounds": {"content_bytes": 4}},
            "expected": {
                "verdict": "valid",
                "digest": b64(hashlib.sha256(b"BAP1-CONTENT\x00abcd").digest()),
            },
        },
        {
            "id": "content-tightened-too-long",
            "class": "maximum_plus_one",
            "input": {"content_base64url": b64(b"abcde"), "bounds": {"content_bytes": 4}},
            "expected": {"verdict": "invalid"},
        },
        {
            "id": "content-bound-widening",
            "class": "invalid_bounds",
            "input": {"content_base64url": b64(b"x"), "bounds": {"content_bytes": 65_537}},
            "expected": {"verdict": "invalid"},
        },
        {
            "id": "content-changed-byte",
            "class": "tamper_meaningful_byte",
            "input": {"content_base64url": b64(b"urn:example:content:2"), "bounds": {}},
            "expected": {"verdict": "valid", "digest": b64(changed_content_digest)},
            "tamper": {
                "base_case": "content-base",
                "target": "content",
                "meaning": "last content byte changes from ASCII 1 to ASCII 2",
            },
        },
    ]

    predecessor_digest = hashlib.sha256(baseline_compact.encode()).digest()
    successor_payload = {
        **base_payload,
        "content_digest": b64(changed_content_digest),
        "exp": 1_735_697_000,
        "gen": 2,
        "iat": 1_735_693_100,
        "jti": "urn:example:assertion:2",
        "nbf": 1_735_693_200,
        "prev": b64(predecessor_digest),
    }
    successor_header = {**base_header, "kid": attestors["rotated"]["key_id"]}

    def artifact(
        compact_value: str,
        attestor: str,
        overrides: dict[str, object] | None = None,
        **extra: object,
    ) -> dict[str, object]:
        result: dict[str, object] = {"compact": compact_value, "attestor": attestor}
        if overrides:
            result["expected_overrides"] = overrides
        result.update(extra)
        return result

    predecessor_artifact = artifact(
        baseline_compact,
        "primary",
        {"now": base_payload["nbf"]},
    )

    successor_cases: list[dict[str, Any]] = []

    def successor_case(
        case_id: str,
        class_: str,
        successor_payload_value: dict[str, object],
        relation: str,
        *,
        signer: ed25519.Ed25519PrivateKey = rotated_private,
        attestor: str = "rotated",
        header: dict[str, object] | None = None,
        facts_overrides: dict[str, object] | None = None,
        artifact_verdict: str = "valid",
        compact_override: str | None = None,
    ) -> None:
        compact_value = compact_override or compact(
            header or successor_header, successor_payload_value, signer
        )
        overrides: dict[str, object] = {
            "issuer": successor_payload_value["iss"],
            "audience": successor_payload_value["aud"],
            "subject": successor_payload_value["sub"],
            "profile": successor_payload_value["profile"],
            "profile_digest": successor_payload_value["profile_digest"],
            "content_digest": successor_payload_value["content_digest"],
            "now": successor_payload_value["nbf"],
        }
        successor_cases.append(
            {
                "id": case_id,
                "class": class_,
                "predecessor": predecessor_artifact,
                "successor": artifact(
                    compact_value,
                    attestor,
                    overrides,
                    **({"facts_overrides": facts_overrides} if facts_overrides else {}),
                ),
                "expected": {
                    "predecessor": "valid",
                    "successor": artifact_verdict,
                    "relation": relation,
                },
            }
        )

    successor_case(
        "successor-expired-predecessor-rotated-key-content-change",
        "valid",
        successor_payload,
        "valid",
    )
    for case_id, key, value in (
        ("successor-issuer-mismatch", "iss", "urn:example:issuer:other"),
        ("successor-audience-mismatch", "aud", "urn:example:audience:other"),
        ("successor-subject-mismatch", "sub", "urn:example:lineage:other"),
        ("successor-profile-mismatch", "profile", "urn:example:content-profile:other"),
        ("successor-profile-digest-mismatch", "profile_digest", b64(b"p" * 32)),
        ("successor-generation-jump", "gen", 3),
        ("successor-wrong-predecessor", "prev", b64(b"x" * 32)),
        ("successor-repeated-jti", "jti", base_payload["jti"]),
    ):
        successor_case(
            case_id,
            "invalid_successor_relation",
            {**successor_payload, key: value},
            "invalid",
        )
    backdated_payload = {
        **successor_payload,
        "iat": base_payload["iat"] - 1,
        "nbf": base_payload["nbf"],
        "exp": base_payload["exp"],
    }
    successor_case(
        "successor-backdated-iat",
        "invalid_successor_relation",
        backdated_payload,
        "invalid",
        signer=primary_private,
        attestor="primary",
        header=base_header,
    )
    successor_case(
        "successor-forged-verification-marker",
        "invalid_facts",
        successor_payload,
        "invalid",
        facts_overrides={"verification": "not_evaluated"},
    )
    successor_case(
        "successor-forged-trust-marker",
        "invalid_facts",
        successor_payload,
        "invalid",
        facts_overrides={"trust": "evaluated"},
    )
    successor_case(
        "successor-malformed-facts-digest",
        "invalid_facts",
        successor_payload,
        "invalid",
        facts_overrides={"digest": b64(b"x" * 31)},
    )
    invalid_successor_compact = tamper_signature(
        compact(successor_header, successor_payload, rotated_private)
    )
    successor_case(
        "successor-invalid-cryptographic-artifact",
        "invalid_signature",
        successor_payload,
        "not_run",
        artifact_verdict="invalid",
        compact_override=invalid_successor_compact,
    )

    structural_classes = {"valid", "invalid_header", "invalid_claim", "invalid_encoding"}
    assertion_structure_cases = [
        case for case in assertion_cases if case["class"] in structural_classes
    ]
    assertion_verification_cases = [
        case for case in assertion_cases if case["class"] not in structural_classes
    ]
    json_file(OUT / "digest-cases.json", digest_cases)
    json_file(OUT / "assertion-structure-cases.json", assertion_structure_cases)
    json_file(OUT / "assertion-verification-cases.json", assertion_verification_cases)
    json_file(OUT / "successor-cases.json", successor_cases)
    (OUT / "assertion-cases.json").unlink(missing_ok=True)

    indexed_paths = [
        "profile.json",
        "digest-cases.json",
        "assertion-structure-cases.json",
        "assertion-verification-cases.json",
        "successor-cases.json",
        "content-base.raw",
        "content-maximum.raw",
        "content-over-limit.raw",
    ]
    for name in indexed_paths[:4]:
        size = (OUT / name).stat().st_size
        if size > 65_536:
            raise RuntimeError(f"{name} exceeds corpus-loader json_bytes: {size}")
    index = {
        "profile": PROFILE,
        "revision": REVISION,
        "assertion_cases": len(assertion_cases),
        "digest_cases": len(digest_cases),
        "successor_cases": len(successor_cases),
        "files": [
            {
                "path": path,
                "sha256": hashlib.sha256((OUT / path).read_bytes()).hexdigest(),
            }
            for path in indexed_paths
        ],
        "private_material_tracked": False,
    }
    json_file(OUT / "index.json", index)
    print(
        json.dumps(
            {
                "assertion_cases": len(assertion_cases),
                "digest_cases": len(digest_cases),
                "successor_cases": len(successor_cases),
                "index_sha256": hashlib.sha256((OUT / "index.json").read_bytes()).hexdigest(),
                "sizes": {path: (OUT / path).stat().st_size for path in indexed_paths},
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--add-uri-checks",
        action="store_true",
        help="incrementally add URI conformance cases without rotating existing signed bytes",
    )
    parser.add_argument(
        "--add-uri-authority-checks",
        action="store_true",
        help="incrementally add URI authority cases without rotating existing signed bytes",
    )
    arguments = parser.parse_args()
    if arguments.add_uri_checks and arguments.add_uri_authority_checks:
        parser.error("choose only one incremental corpus update")
    if arguments.add_uri_checks:
        add_uri_checks()
    elif arguments.add_uri_authority_checks:
        add_uri_authority_checks()
    else:
        main()
