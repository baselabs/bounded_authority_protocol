#!/usr/bin/env python3
"""Generate and independently check the holder custody attestation vectors."""

import argparse
import json

from cryptography.hazmat.primitives.asymmetric import ed25519

from build_approval_corpora import (
    CA_MAX,
    CORPORA,
    ED_ORDER,
    b64,
    bounded_object,
    canonical,
    ed_identity,
    ed_multiply,
    ed_point,
    effective,
    fingerprint,
    freeze,
    identifier,
    integer,
    kid_ok,
    legacy_vectors,
    replace_sig,
    sha,
    signed,
    unb64,
    valid_signature,
)

PROFILE = "bap-holder-custody-attestation/1"
TYP = "ba+holder-custody-attestation"
HEADER = {"alg": "EdDSA", "kid": "custody-attestor", "typ": TYP}
CLAIMS = {"custody_class", "exp", "jti", "key_id", "nbf", "public_key", "v"}


class Rejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def key_ok(public):
    try:
        return not ed_identity(ed_multiply(ed_point(public), 8))
    except ValueError:
        return False


def parse_object(data, limits, segment):
    try:
        return bounded_object(data, limits)
    except ValueError as error:
        raise Rejected(f"{segment}_encoding") from error


def parse(compact, limits):
    require(len(compact) <= min(limits["anchor_bytes"], limits["compact_bytes"]), "compact_size")
    parts = compact.split(".")
    require(len(parts) == 3, "segments")
    require(all(len(part) <= limits["encoded_segment_bytes"] for part in parts), "encoded_size")
    try:
        head, body, signature = map(unb64, parts)
    except ValueError as error:
        raise Rejected("base64url") from error
    require(all(len(part) <= limits["decoded_segment_bytes"] for part in (head, body, signature)),
            "decoded_size")
    require(len(signature) == 64, "signature_width")

    header = parse_object(head, limits, "header")
    require(header.keys() == HEADER.keys(), "header_members")
    require(header["typ"] == TYP, "typ")
    require(header["alg"] == "EdDSA", "alg")
    require(kid_ok(header["kid"], limits), "kid")

    payload = parse_object(body, limits, "payload")
    require(payload.keys() == CLAIMS, "claim_members")
    require(type(payload["v"]) is int and payload["v"] == 1, "version")
    require(identifier(payload["jti"], limits["identifier_bytes"]), "jti")
    require(kid_ok(payload["key_id"], limits), "subject_id")
    try:
        public = unb64(payload["public_key"])
    except ValueError as error:
        raise Rejected("subject_key") from error
    require(key_ok(public), "subject_key")
    require(payload["custody_class"] in ("standard", "hosted"), "custody_class")
    require(all(integer(payload[k], limits["integer_magnitude"]) for k in ("nbf", "exp")),
            "numeric_date")
    require(payload["nbf"] < payload["exp"], "window_order")
    return header, payload, ".".join(parts[:2]).encode(), signature


def verify(header, payload, message, signature, context, limits):
    attestor = context["attestor"]
    attestor_public = unb64(attestor["public_key"])
    subject = context["subject"]
    require(key_ok(attestor_public), "attestor_key")
    require(key_ok(unb64(subject["public_key"])), "expected_subject_key")
    require(integer(context["now"], limits["integer_magnitude"]), "now")
    require(header["kid"] == attestor["key_id"], "attestor_id")
    require(payload["key_id"] == subject["key_id"], "subject_id_mismatch")
    require(payload["public_key"] == subject["public_key"], "subject_key_mismatch")
    require(payload["key_id"] != attestor["key_id"], "self_id")
    require(payload["public_key"] != attestor["public_key"], "self_key")
    require(payload["nbf"] >= attestor["valid_from"], "window_starts_before_attestor")
    require(attestor["valid_before"] == "unbounded" or payload["exp"] <= attestor["valid_before"],
            "window_outlives_attestor")
    require(payload["nbf"] <= context["now"] < payload["exp"], "now_outside_window")
    require(valid_signature(message, signature, attestor_public, "eddsa"), "signature")
    return dict(version=1, attestor_key_id=attestor["key_id"],
                attestor_key_fingerprint=fingerprint(attestor_public, "eddsa"),
                subject_key_id=subject["key_id"],
                subject_key_fingerprint=fingerprint(unb64(subject["public_key"]), "eddsa"),
                custody_class=payload["custody_class"], jti=payload["jti"],
                nbf=payload["nbf"], exp=payload["exp"],
                verification="signature_and_window", trust="not_evaluated")


def artifact(path, field="compact"):
    cases = json.loads((CORPORA / path).read_bytes())
    return cases[0][field]


def vectors():
    signer, holder, other = [
        ed25519.Ed25519PrivateKey.from_private_bytes(sha(f"BAP custody fixture {name}".encode()))
        for name in ("attestor", "holder", "other")
    ]
    attestor_key, holder_key, other_key = [
        b64(key.public_key().public_bytes_raw()) for key in (signer, holder, other)
    ]
    attestor = dict(key_id=HEADER["kid"], public_key=attestor_key, valid_from=100, valid_before=200)
    subject = dict(key_id="holder-key", public_key=holder_key)
    profile = dict(profile=PROFILE, revision=1, attestor=attestor, subject=subject, now=150)
    base = dict(v=1, jti="urn:example:custody:1", key_id=subject["key_id"], public_key=holder_key,
                custody_class="standard", nbf=100, exp=200)

    def sign(payload=base, header=HEADER, key=signer):
        return signed(key, "eddsa", header, payload)

    standard = sign()
    hosted = sign(base | {"custody_class": "hosted"})
    cases = []

    def add(case_id, compact=standard, reason=None, **overrides):
        context = profile | overrides
        limits = effective(context.get("bounds", {}), CA_MAX)
        decoded = facts = "invalid"
        observed = None
        try:
            header, payload, message, signature = parse(compact, limits)
            decoded = dict({k: v for k, v in payload.items() if k != "v"}, version=1,
                           attestor_key_id=header["kid"], verification="not_evaluated")
            facts = verify(header, payload, message, signature, context, limits)
        except Rejected as error:
            observed = str(error)
        if observed != reason:
            raise ValueError(f"{case_id}: expected {reason}, observed {observed}")
        cases.append(dict(id=case_id, compact=compact, expected=dict(decode=decoded, verify=facts),
                          **({"reason": reason} if reason else {}), **overrides))

    add("valid-standard")
    add("valid-hosted", hosted)
    add("now-at-nbf", now=100)
    add("now-before-exp", now=199)
    add("unbounded-attestor", attestor=attestor | {"valid_before": "unbounded"})
    add("now-before-nbf", reason="now_outside_window", now=99)
    add("now-at-exp", reason="now_outside_window", now=200)
    add("invalid-now", reason="now", now=150.5)
    add("starts-before-attestor", sign(base | {"nbf": 99}), "window_starts_before_attestor")
    add("outlives-attestor", sign(base | {"exp": 201}), "window_outlives_attestor")
    add("empty-window", sign(base | {"exp": 100}), "window_order")
    add("reversed-window", sign(base | {"exp": 99}), "window_order")
    add("float-window", sign(base | {"nbf": 100.5}), "numeric_date")
    add("over-limit-window", sign(base | {"exp": 1 << 53}), "numeric_date")
    add("unknown-custody-class", sign(base | {"custody_class": "holder"}), "custody_class")
    add("numeric-custody-class", sign(base | {"custody_class": 1}), "custody_class")
    add("wrong-typ", sign(header=HEADER | {"typ": "ba+role-attestation"}), "typ")
    add("wrong-alg", sign(header=HEADER | {"alg": "ES256"}), "alg")
    add("invalid-kid", sign(header=HEADER | {"kid": "attestor!"}), "kid")
    add("invalid-subject-id", sign(base | {"key_id": "holder!"}), "subject_id")
    add("invalid-jti", sign(base | {"jti": "1:invalid"}), "jti")
    add("invalid-subject-key", sign(base | {"public_key": b64(bytes(32))}), "subject_key")
    add("wrong-version", sign(base | {"v": 2}), "version")
    add("float-version", sign(base | {"v": 1.0}), "version")
    for key in HEADER:
        add(f"missing-header-{key}", sign(header={k: v for k, v in HEADER.items() if k != key}),
            "header_members")
    add("extra-header", sign(header=HEADER | {"crit": "extra"}), "header_members")
    for key in sorted(base):
        add(f"missing-claim-{key}", sign({k: v for k, v in base.items() if k != key}),
            "claim_members")
    add("extra-claim", sign(base | {"aud": "recipient"}), "claim_members")
    add("noncanonical-header", sign(header=b" " + canonical(HEADER)), "header_encoding")
    add("noncanonical-payload", sign(canonical(base) + b" "), "payload_encoding")
    add("duplicate-header", sign(header=canonical(HEADER)[:-1] + b',"alg":"EdDSA"}'),
        "header_encoding")
    add("duplicate-claim", sign(canonical(base)[:-1] + b',"v":1}'), "payload_encoding")
    add("attestor-id-mismatch", sign(header=HEADER | {"kid": "other-attestor"}), "attestor_id")
    add("subject-id-mismatch", reason="subject_id_mismatch", subject=subject | {"key_id": "other"})
    add("subject-key-mismatch", reason="subject_key_mismatch",
        subject=subject | {"public_key": other_key})
    add("self-id", sign(base | {"key_id": attestor["key_id"]}), "self_id",
        subject=subject | {"key_id": attestor["key_id"]})
    add("self-key", sign(base | {"public_key": attestor_key}), "self_key",
        subject=subject | {"public_key": attestor_key})
    add("invalid-attestor-key", reason="attestor_key",
        attestor=attestor | {"public_key": b64(bytes(32))})
    add("invalid-expected-subject-key", reason="expected_subject_key",
        subject=subject | {"public_key": b64(bytes(32))})
    add("wrong-signature", sign(key=other), "signature")
    signature = unb64(standard.rsplit(".", 1)[1])
    changed_header = sign(header=HEADER | {"kid": "other-attestor"}).rsplit(".", 1)[0]
    add("protected-kid-tamper", changed_header + "." + b64(signature), "signature",
        attestor=attestor | {"key_id": "other-attestor"})
    add("short-signature", replace_sig(standard, signature[:-1]), "signature_width")
    add("noncanonical-scalar", replace_sig(standard, signature[:32] + ED_ORDER.to_bytes(32, "little")),
        "signature")
    add("small-order-r", replace_sig(standard, bytes(32) + signature[32:]), "signature")
    add("signed-class-tamper", hosted.rsplit(".", 1)[0] + "." + b64(signature), "signature")
    add("compact-at-bound", bounds={"anchor_bytes": len(standard)})
    add("compact-over-bound", reason="compact_size", bounds={"anchor_bytes": len(standard) - 1})
    add("encoded-over-bound", reason="encoded_size",
        bounds={"encoded_segment_bytes": max(map(len, standard.split("."))) - 1})
    add("decoded-over-bound", reason="decoded_size",
        bounds={"decoded_segment_bytes": max(map(len, map(unb64, standard.split(".")))) - 1})
    add("invalid-base64url", standard + "=", "base64url")
    add("extra-segment", standard + ".extra", "segments")

    paths = {
        "ca1": "attestation-profiles/content-assertion/v1/assertion-structure-cases.json",
        "ca-es256": "attestation-profiles/content-assertion-es256/v1/assertion-structure-cases.json",
    }
    foreign = dict(legacy_vectors()) | {name: artifact(path) for name, path in paths.items()}
    separation = [
        dict(id=name, foreign=compact, candidate=standard, expected="both_reject")
        for name, compact in sorted(foreign.items())
    ]
    separation.append(dict(
        id="action-approval-record",
        foreign=artifact("content-profiles/action-approval/v1/record-cases.json", "wire"),
        candidate=standard,
        expected="both_reject",
    ))
    profile["signing"] = dict(payload=base, compact=standard, signature=b64(signature))
    return {"profile.json": profile, "attestation-cases.json": cases,
            "custody-separation-cases.json": separation}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    freeze(CORPORA / "attestation-profiles/holder-custody-attestation/v1",
           PROFILE, vectors(), args.verify)
