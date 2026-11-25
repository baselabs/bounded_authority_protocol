#!/usr/bin/env python3
"""Generate and independently check the candidate ES256 assertion and approval vectors."""

import argparse
import base64
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

ROOT = Path(__file__).resolve().parents[1]
CORPORA = ROOT / "priv/conformance"
ES = "bap-content-assertion-es256/1"
APPROVAL = "bap-action-approval/1"
HEADERS = {
    "es256": {"alg": "ES256", "kid": "approver-key", "typ": "ba+content-assertion-es256"},
    "eddsa": {"alg": "EdDSA", "kid": "approver-key", "typ": "ba+content-assertion"},
}
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MAGNITUDE = (1 << 53) - 1
ZERO = bytes(32)
RECORD_FIELDS = set("v subject action request_id approver_role resources revision_digest".split())
STRINGS = "jti iss aud sub profile".split()
DIGESTS = "profile_digest content_digest prev".split()
INTEGERS = "gen iat nbf exp".split()


def sha(raw):
    return hashlib.sha256(raw).digest()


def canonical(value):
    # Every object name in the wire formats and fixture envelope is ASCII.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(encoded):
    demand(isinstance(encoded, str) and re.fullmatch(r"[A-Za-z0-9_-]+", encoded))
    data = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    demand(b64(data) == encoded)
    return data


def demand(condition):
    if not condition:
        raise ValueError("invalid")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        demand(key not in result)
        result[key] = value
    return result


def load_object(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    demand(isinstance(value, dict) and canonical(value) == raw)
    return value


def string(value, cap):
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= cap


def identifier(value, cap):
    if not string(value, cap):
        return False
    if ":" not in value:
        return True
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9/?:#\[\]@!$&'()*+,;=._~-]|%[0-9A-Fa-f]{2})*", value):
        return False
    return bool(urlsplit(value).scheme)


def integer(value, cap):
    return type(value) is int and -cap <= value <= cap


def effective(overrides, maxima):
    demand(isinstance(overrides, dict) and overrides.keys() <= maxima.keys())
    for key, value in overrides.items():
        demand(type(value) is int and 1 <= value <= maxima[key])
    return maxima | overrides


CA_MAX = dict(anchor_bytes=8192, compact_bytes=65536, encoded_segment_bytes=32768,
              decoded_segment_bytes=24576, json_bytes=65536, jcs_bytes=65536,
              depth=32, object_members=64, array_items=256, total_nodes=4096,
              string_bytes=8192, key_bytes=128, number_lexeme_bytes=64,
              identifier_bytes=512, content_bytes=65536, kid_bytes=128,
              integer_magnitude=MAGNITUDE)
RECORD_MAX = dict(string_bytes=1024, resource_count=4096, record_bytes=65536)


def scopes(names, bounds, strict=True):
    return (
        isinstance(names, list) and 0 < len(names) <= bounds["resource_count"]
        and all(string(name, bounds["string_bytes"]) for name in names)
        and (not strict or names == sorted(set(names), key=str.encode))
    )


def author_record(record, ca, bounds, sort_set=False):
    demand(record.keys() == RECORD_FIELDS and type(record["v"]) is int and record["v"] == 1)
    demand(all(string(record[k], bounds["string_bytes"]) for k in
               ("subject", "action", "approver_role", "request_id")))
    demand(identifier(record["request_id"], ca["identifier_bytes"]))
    demand(len(unb64(record["revision_digest"])) == 32)
    demand(scopes(record["resources"], bounds, not sort_set))
    if sort_set:
        record = record | {"resources": sorted(set(record["resources"]), key=str.encode)}
    wire = canonical(record)
    demand(len(wire) <= min(ca["content_bytes"], bounds["record_bytes"]))
    return wire


def parse_record(raw, ca, bounds):
    demand(0 < len(raw) <= min(ca["content_bytes"], bounds["record_bytes"]))
    record = load_object(raw)
    demand(author_record(record, ca, bounds) == raw)
    return record


def kid_ok(kid, ca):
    return string(kid, ca["kid_bytes"]) and re.fullmatch(r"[A-Za-z0-9._~-]+", kid)


def bounded_object(raw, ca):
    demand(len(raw) <= min(ca["json_bytes"], ca["jcs_bytes"]))
    obj = load_object(raw)
    demand(len(obj) <= ca["object_members"] and len(obj) + 1 <= ca["total_nodes"])
    for key, value in obj.items():
        demand(len(key.encode()) <= ca["key_bytes"])
        if type(value) is int:
            demand(len(str(value)) <= ca["number_lexeme_bytes"])
        if isinstance(value, str):
            demand(len(value.encode()) <= ca["string_bytes"])
    return obj


def frame(compact, ca):
    demand(len(compact) <= min(ca["anchor_bytes"], ca["compact_bytes"]))
    segments = compact.split(".")
    demand(len(segments) == 3 and all(len(item) <= ca["encoded_segment_bytes"] for item in segments))
    header, payload, sig = map(unb64, segments)
    demand(all(len(item) <= ca["decoded_segment_bytes"] for item in (header, payload, sig)))
    demand(len(sig) == 64)
    h = bounded_object(header, ca)
    demand(h.keys() == {"alg", "typ", "kid"} and kid_ok(h["kid"], ca))
    demand(isinstance(h["alg"], str) and isinstance(h["typ"], str))
    return h, payload, ".".join(segments[:2]).encode("ascii"), sig


def suite_matches(header, suite):
    return all(header[key] == HEADERS[suite][key] for key in ("alg", "typ"))


def claims(raw, ca):
    p = bounded_object(raw, ca)
    demand(p.keys() == set(STRINGS + DIGESTS + INTEGERS + ["v"]))
    demand(type(p["v"]) is int and p["v"] == 1)
    demand(all(identifier(p[key], ca["identifier_bytes"]) for key in STRINGS))
    demand(all(len(unb64(p[key])) == 32 for key in DIGESTS))
    demand(all(integer(p[key], ca["integer_magnitude"]) for key in INTEGERS))
    demand(p["gen"] >= 1 and ((p["gen"] == 1) == (unb64(p["prev"]) == ZERO)))
    demand(p["iat"] <= p["nbf"] < p["exp"])
    return p


def public_bytes(key, suite):
    if suite == "es256":
        return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key.public_bytes_raw()


def fingerprint(public, suite):
    if suite == "es256":
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
        demand(len(public) == 65 and public[0] == 4)
        jwk = dict(crv="P-256", kty="EC", x=b64(public[1:33]), y=b64(public[33:]))
    else:
        ed25519.Ed25519PublicKey.from_public_bytes(public)
        # All Ed25519 admission controls use generated prime-order keys, except
        # explicit identity and zero encodings, independently known to be torsion.
        demand(public not in (bytes(32), b"\1" + bytes(31)))
        jwk = dict(crv="Ed25519", kty="OKP", x=b64(public))
    return b64(sha(canonical(jwk)))


def scalar_valid(sig):
    return (len(sig) == 64 and 0 < int.from_bytes(sig[:32], "big") < ORDER
            and 0 < int.from_bytes(sig[32:], "big") <= ORDER // 2)


def valid_signature(message, sig, public, suite):
    try:
        if suite == "es256":
            demand(scalar_valid(sig) and len(public) == 65 and public[0] == 4)
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
            der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def fixture_keys():
    material = sha(b"BAP public candidate vector derivation")
    ec_scalar = int.from_bytes(material, "big") % (ORDER - 1) + 1
    return {"es256": ec.derive_private_key(ec_scalar, ec.SECP256R1()),
            "eddsa": ed25519.Ed25519PrivateKey.from_private_bytes(material)}


def signed(signer, suite, header, payload):
    header = canonical(header) if isinstance(header, dict) else header
    payload = canonical(payload) if isinstance(payload, dict) else payload
    message = b64(header) + "." + b64(payload)
    if suite == "es256":
        der = signer.sign(message.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + min(s, ORDER - s).to_bytes(32, "big")
    else:
        sig = signer.sign(message.encode())
    demand(valid_signature(message.encode(), sig, public_bytes(signer.public_key(), suite), suite))
    return message + "." + b64(sig)


def replace_sig(compact, signature):
    return compact.rsplit(".", 1)[0] + "." + b64(signature)


def content_digest(raw):
    return b64(sha(b"BAP1-CONTENT\0" + raw))


def facts(h, p, compact, public, suite):
    carried = {key: p[key] for key in STRINGS + DIGESTS + INTEGERS}
    return carried | dict(version=1, attestor_key_id=h["kid"],
                          attestor_key_fingerprint=fingerprint(public, suite),
                          digest=b64(sha(compact.encode())), trust="not_evaluated",
                          verification="signature_and_window")


def roles(names, bounds):
    return (isinstance(names, list)
            and all(string(name, bounds["string_bytes"]) for name in names)
            and len(names) == len(set(names)))


def approval(record_bytes, compact, context, suite, profile_digest):
    try:
        ca = effective(context["bounds"], CA_MAX)
        bounds = effective(context["record_bounds"], RECORD_MAX)
        cap = ca["integer_magnitude"]
        demand(string(context["trust_domain"], ca["identifier_bytes"]))
        demand(identifier(context["audience"], ca["identifier_bytes"]))
        demand(identifier(context["request_id"], min(bounds["string_bytes"], ca["identifier_bytes"])))
        demand(len(unb64(context["revision_digest"])) == 32)
        demand(all(string(context[k], bounds["string_bytes"]) for k in ("subject", "action")))
        demand(scopes(context["resources"], bounds) and context["roles"] and roles(context["roles"], bounds))
        demand(integer(context["now"], cap))
        for field in ("max_lifetime", "max_staleness", "max_active"):
            if field != "max_active" or field in context:
                demand(integer(context[field], cap) and context[field] >= 0)
    except (KeyError, ValueError, TypeError):
        return "invalid_context"

    keys = {}
    try:
        snapshot = context["snapshot"]
        demand(snapshot["trust_domain"] == context["trust_domain"] and snapshot["suite"] == suite)
        demand(string(snapshot["provenance"], ca["identifier_bytes"]) and integer(snapshot["as_of"], cap))
        for entry in snapshot["entries"]:
            key = entry["key"]
            kid = key["key_id"]
            demand(kid_ok(kid, ca) and kid not in keys)
            demand(identifier(entry["issuer"], ca["identifier_bytes"]) and roles(entry["roles"], bounds))
            demand(integer(key["valid_from"], cap))
            before = key["valid_before"]
            demand(before == "unbounded" or (integer(before, cap) and before > key["valid_from"]))
            fingerprint(unb64(key["public_key"]), suite)
            keys[kid] = entry
    except (KeyError, ValueError, TypeError):
        return "trust_unavailable"

    now = context["now"]
    if not 0 <= now - snapshot["as_of"] <= context["max_staleness"]:
        return "stale_trust"
    try:
        header, payload, message, signature = frame(compact, ca)
    except (ValueError, TypeError):
        return "malformed"
    if not suite_matches(header, suite):
        return "unsupported_algorithm"
    try:
        p = claims(payload, ca)
        record = parse_record(record_bytes, ca, bounds)
    except (ValueError, TypeError):
        return "malformed"
    entry = keys.get(header["kid"])
    if entry is None:
        return "unknown_key"
    key = entry["key"]
    public = unb64(key["public_key"])
    if not valid_signature(message, signature, public, suite):
        return "bad_signature"

    before = key["valid_before"]
    outcomes = [
        (p["iat"] >= key["valid_from"] and p["nbf"] >= key["valid_from"]
         and (before == "unbounded" or p["exp"] <= before), "key_window"),
        (p["content_digest"] == content_digest(record_bytes)
         and p["profile"] == APPROVAL and p["profile_digest"] == profile_digest, "record_mismatch"),
        (p["iss"] == entry["issuer"], "issuer_mismatch"),
        (p["aud"] == context["audience"], "audience_mismatch"),
        (record["request_id"] == context["request_id"] == p["sub"]
         and record["revision_digest"] == context["revision_digest"], "request_mismatch"),
        (record["subject"] == context["subject"], "subject_mismatch"),
        (record["action"] == context["action"] and record["resources"] == context["resources"],
         "scope_mismatch"),
        (p["nbf"] <= now, "not_yet_valid"),
        (now < p["exp"], "expired"),
        (p["exp"] - p["iat"] <= context["max_lifetime"], "lifetime_too_long"),
        ("max_active" not in context or p["exp"] - p["nbf"] <= context["max_active"], "active_too_long"),
        (record["approver_role"] in context["roles"] and record["approver_role"] in entry["roles"],
         "role_not_permitted"),
    ]
    for passed, reason in outcomes:
        if not passed:
            return reason
    return dict(suite=suite, trust_domain=context["trust_domain"], record=record,
                assertion=facts(header, p, compact, public, suite), trust="not_evaluated")


def record_vectors(record):
    cases = []

    def add(case_id, *, wire=None, author=None, sort=False, ca=None, bounds=None, valid=False):
        ca = ca or {}
        bounds = bounds or {}
        case = dict(id=case_id, bounds=bounds, ca_bounds=ca, canonicalize=sort)
        try:
            ca_eff, bound_eff = effective(ca, CA_MAX), effective(bounds, RECORD_MAX)
            if wire is not None:
                parse_record(wire, ca_eff, bound_eff)
                encoded = wire
            else:
                encoded = author_record(author, ca_eff, bound_eff, sort)
            actual = dict(wire=b64(encoded), content_digest=content_digest(encoded))
        except (ValueError, TypeError, KeyError):
            actual = "invalid"
        assert (actual != "invalid") == valid, case_id
        case.update(expected=actual, **({"wire": b64(wire)} if wire is not None else {"author": author}))
        cases.append(case)

    wire = canonical(record)
    add("canonical", wire=wire, valid=True)
    add("unicode-utf8-order-and-no-normalization", wire=canonical(record | {
        "resources": ["e\u0301", "\u00e9", "\ue000", "\U00010000"]}), valid=True)
    add("utf16-order-refused", wire=canonical(record | {"resources": ["\U00010000", "\ue000"]}))
    for name in sorted(RECORD_FIELDS):
        missing = record.copy()
        del missing[name]
        add("missing-" + name, wire=canonical(missing))
        add("wrong-type-" + name, wire=canonical(record | {name: None}))
    for key in ("action", "subject", "request_id", "approver_role"):
        add("empty-" + key, wire=canonical(record | {key: ""}))
    for name, data in [
        ("unknown-field", canonical(record | {"extra": 1})),
        ("float-version", wire.replace(b'"v":1', b'"v":1.0')),
        ("exponent-version", wire.replace(b'"v":1', b'"v":1e0')),
        ("boolean-version", wire.replace(b'"v":1', b'"v":true')),
        ("wrong-version", wire.replace(b'"v":1', b'"v":2')),
        ("trailing-lf", wire + b"\n"),
        ("bom", b"\xef\xbb\xbf" + wire),
        ("duplicate", wire.replace(b'"v":1', b'"v":1,"v":1')),
        ("escaped-duplicate", wire.replace(b'"v":1', b'"v":1,"\\u0076":1')),
        ("alternate-escape", wire.replace(b'"v"', b'"\\u0076"')),
        ("surrogate", wire.replace(b'"v":1', b'"v":1').replace(b'"read"', b'"\\ud800"')),
        ("invalid-utf8", wire.replace(b'"read"', b'"\xff"')),
        ("noncanonical-member-order", b'{"v":1,' + wire[1:].replace(b',"v":1', b'')),
        ("duplicate-resource", canonical(record | {"resources": ["a", "a"]})),
        ("empty-resources", canonical(record | {"resources": []})),
        ("empty-resource", canonical(record | {"resources": [""]})),
        ("wrong-type-resource", canonical(record | {"resources": [1]})),
        ("short-revision", canonical(record | {"revision_digest": b64(bytes(31))})),
        ("padded-revision", canonical(record | {"revision_digest": record["revision_digest"] + "="})),
        ("invalid-request-id", canonical(record | {"request_id": "1:invalid"})),
    ]:
        add(name, wire=data)
    add("canonicalize", author=record | {"resources": ["z", "a", "z"]}, sort=True, valid=True)
    add("authoring-explicit-only", author=record | {"resources": ["z", "a", "z"]})
    add("authoring-input-count", author=record | {"resources": ["a"] * 3}, sort=True,
        bounds={"resource_count": 2})
    add("authoring-input-byte-size", author=record | {"resources": ["a", "a" * 17]}, sort=True,
        bounds={"string_bytes": 16})
    add("ascii-string-max", author=record | {"resources": ["x" * 1024]}, valid=True)
    add("ascii-string-max-plus", author=record | {"resources": ["x" * 1025]})
    add("utf8-string-max", author=record | {"resources": ["\u00e9" * 512]}, valid=True)
    add("utf8-string-max-plus", author=record | {"resources": ["\u00e9" * 513]})
    add("request-ca-tightening-exact", wire=wire, ca={"identifier_bytes": len(record["request_id"])}, valid=True)
    add("request-ca-tightening-over", wire=wire, ca={"identifier_bytes": len(record["request_id"]) - 1})
    add("request-record-tightening-over", wire=canonical(record | {"request_id": "r" * 33}),
        bounds={"string_bytes": 32}, ca={"identifier_bytes": 64})
    add("resource-count-exact", wire=canonical(record | {"resources": [f"{i:04}" for i in range(4096)]}), valid=True)
    add("resource-count-plus", wire=canonical(record | {"resources": [f"{i:04}" for i in range(4097)]}))
    names = [f"{i:02}" + chr(1) * 1022 for i in range(10)]
    tail = 65536 - len(canonical(record | {"resources": names + ["z"]}))
    names += ["z" + "x" * min(tail, 1023)]
    # Fill the remaining byte budget across two already ordered strings.
    if len(canonical(record | {"resources": names})) < 65536:
        remaining = 65536 - len(canonical(record | {"resources": names + ["zz"]}))
        names += ["zz" + chr(1) * (remaining // 6) + "x" * (remaining % 6)]
    boundary = canonical(record | {"resources": names})
    assert len(boundary) == 65536, len(boundary)
    add("encoded-size-exact", wire=boundary, valid=True)
    add("encoded-size-plus", wire=boundary.replace(b'"subject":"', b'"subject":"x'))
    add("ca-content-size-over", wire=wire, ca={"content_bytes": len(wire) - 1})
    add("record-size-over", wire=wire, bounds={"record_bytes": len(wire) - 1})
    simultaneous = record | {"resources": ["x" * 12, "y" * 12]}
    bounds = {"resource_count": 2, "string_bytes": 12, "record_bytes": len(canonical(simultaneous))}
    add("simultaneous-exact", author=simultaneous, bounds=bounds, valid=True)
    add("escape-heavy-over", author=record | {"resources": [f"{i:03}" + "\x01" * 61 for i in range(500)]})
    return cases


def legacy_vectors():
    for major in (1, 2, 3):
        for kind, path in [
            ("grant", "grant-decode/decode.json"),
            ("proof", "proof-decode/decode.json"),
            ("anchor", "boundary-anchor/verify.json"),
            ("transition", "key-transition/verify.json"),
        ]:
            data = json.loads((CORPORA / f"v{major}/corpus/cases" / path).read_bytes())
            case = next(case for case in data["cases"] if case["expected"]["verdict"] == "valid")
            yield f"v{major}-{kind}", case["input"]["compact"]
    for kind, path in [
        ("loopback", "application-profiles/local-loopback-http/v1/proof-cases.json"),
        ("role-attestation", "attestation-profiles/role-attestation/v1/attestation-cases.json"),
    ]:
        cases = json.loads((CORPORA / path).read_bytes())
        yield kind, cases[0]["compact"]


def assertion_vectors(keys, base):
    suite = "es256"
    signer = keys[suite]
    header = HEADERS[suite]
    public = public_bytes(signer.public_key(), suite)
    valid = signed(signer, suite, header, base)
    h, raw, msg, sig = frame(valid, CA_MAX)
    assert claims(raw, CA_MAX) == base
    structures, verifications, successors, cross = [], [], [], []

    def add(case_id, compact, expected=False, bounds=None):
        overrides = bounds or {}
        limits = effective(overrides, CA_MAX)
        try:
            head, body, _, _ = frame(compact, limits)
            demand(suite_matches(head, suite))
            parsed = claims(body, limits)
            result = dict(parsed, attestor_key_id=head["kid"], digest=b64(sha(compact.encode())))
        except (ValueError, TypeError):
            result = "invalid"
        assert (result != "invalid") == expected, case_id
        structures.append(dict(id=case_id, compact=compact, bounds=overrides, expected=result))

    def sign(payload=base, head=header):
        return signed(signer, suite, head, payload)

    add("canonical", valid, True)
    for key in header:
        add("missing-header-" + key, sign(head={k: v for k, v in header.items() if k != key}))
        add("wrong-header-type-" + key, sign(head=header | {key: 1}))
    for key in base:
        add("missing-claim-" + key, sign({k: v for k, v in base.items() if k != key}))
        add("wrong-claim-type-" + key, sign(base | {key: []}))
    for key in STRINGS:
        add("empty-claim-" + key, sign(base | {key: ""}))
        add("invalid-uri-" + key, sign(base | {key: "1:invalid"}))
    for key in DIGESTS:
        add("short-digest-" + key, sign(base | {key: b64(bytes(31))}))
        add("padded-digest-" + key, sign(base | {key: base[key] + "="}))
    for name, compact in [
        ("unknown-header", sign(head=header | {"jwk": {}})),
        ("unknown-claim", sign(base | {"extra": 1})),
        ("empty-kid", sign(head=header | {"kid": ""})),
        ("invalid-kid", sign(head=header | {"kid": "invalid!"})),
        ("overlong-kid", sign(head=header | {"kid": "a" * 129})),
        ("alternate-typ", sign(head=header | {"typ": HEADERS["eddsa"]["typ"]})),
        ("alternate-alg", sign(head=header | {"alg": "EdDSA"})),
        ("eddsa-equation-with-es256-header", signed(keys["eddsa"], "eddsa", header, base)),
        ("noncanonical-header", sign(head=canonical(header) + b" ")),
        ("noncanonical-payload", sign(raw + b" ")),
        ("duplicate-header", sign(head=canonical(header)[:-1] + b',"kid":"extra"}')),
        ("escaped-duplicate-claim", sign(raw[:-1] + b',"\\u0076":1}')),
        ("unknown-version", sign(base | {"v": 2})),
        ("float-version", sign(raw.replace(b'"v":1', b'"v":1.0'))),
        ("exponent-numeric-date", sign(raw.replace(b'"iat":10', b'"iat":1e1'))),
        ("genesis-nonzero-prev", sign(base | {"prev": b64(sha(b"prev"))})),
        ("successor-zero-prev", sign(base | {"gen": 2})),
        ("zero-generation", sign(base | {"gen": 0})),
        ("generation-overflow", sign(base | {"gen": MAGNITUDE + 1, "prev": b64(sha(b"prev"))})),
        ("negative-time-overflow", sign(base | {"iat": -MAGNITUDE - 1})),
        ("time-reversed", sign(base | {"iat": base["nbf"] + 1})),
        ("empty-window", sign(base | {"nbf": base["exp"]})),
        ("short-signature", replace_sig(valid, sig[:-1])),
        ("long-signature", replace_sig(valid, sig + b"x")),
        ("der-signature", replace_sig(valid, utils.encode_dss_signature(
            int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")))),
        ("bad-framing-dot", valid + "."),
        ("padded-signature", valid + "="),
        ("padded-payload", valid.split(".")[0] + "." +
         valid.split(".")[1] + "=." + valid.split(".")[2]),
        ("empty-payload", valid.split(".")[0] + ".." + valid.split(".")[2]),
    ]:
        if name == "eddsa-equation-with-es256-header":
            add(name, compact, True)
        else:
            add(name, compact)
    h_seg, p_seg, s_seg = valid.split(".")
    for bound, exact in [
        ("anchor_bytes", len(valid)), ("compact_bytes", len(valid)),
        ("encoded_segment_bytes", max(map(len, [h_seg, p_seg, s_seg]))),
        ("decoded_segment_bytes", max(len(canonical(h)), len(raw), len(sig))),
        ("json_bytes", len(raw)), ("jcs_bytes", len(raw)),
        ("identifier_bytes", max(len(base[k]) for k in STRINGS)),
        ("kid_bytes", len(h["kid"])), ("integer_magnitude", base["exp"]),
        ("total_nodes", len(base) + 1), ("object_members", len(base)),
        ("key_bytes", max(map(len, base))), ("number_lexeme_bytes", len(str(base["exp"]))),
        ("string_bytes", max(len(base[k]) for k in DIGESTS)),
    ]:
        add(bound + "-exact", valid, True, {bound: exact})
        add(bound + "-minus", valid, False, {bound: exact - 1})
    add("signed-date-extremes", sign(base | {"iat": -MAGNITUDE, "exp": MAGNITUDE}), True)

    key = dict(key_id=h["kid"], public_key=b64(public), valid_from=10, valid_before=40)
    expected = dict(attestor=key, issuer=base["iss"], audience=base["aud"], subject=base["sub"],
                    profile=base["profile"], profile_digest=base["profile_digest"],
                    content_digest=base["content_digest"], now=20)

    def check(case_id, compact=valid, overrides=None, ok=False):
        context = expected | (overrides or {})
        try:
            head, body, message, signature = frame(compact, CA_MAX)
            demand(suite_matches(head, suite))
            p = claims(body, CA_MAX)
            a = context["attestor"]
            demand(head["kid"] == a["key_id"])
            for member, other in (
                ("iss", "issuer"), ("aud", "audience"), ("sub", "subject"), ("profile", "profile"),
                ("profile_digest", "profile_digest"), ("content_digest", "content_digest"),
            ):
                demand(p[member] == context[other])
            demand(p["iat"] >= a["valid_from"] and p["nbf"] >= a["valid_from"])
            demand(a["valid_before"] == "unbounded" or p["exp"] <= a["valid_before"])
            demand(p["nbf"] <= context["now"] < p["exp"])
            point = unb64(a["public_key"])
            demand(valid_signature(message, signature, point, suite))
            result = facts(head, p, compact, point, suite)
        except (TypeError, ValueError):
            result = "invalid"
        assert (result != "invalid") == ok, case_id
        verifications.append(dict(id=case_id, compact=compact, context=context, expected=result))

    check("verified", ok=True)
    check("inclusive-nbf", overrides={"now": base["nbf"]}, ok=True)
    check("unbounded-key-ceiling", overrides={"attestor": key | {"valid_before": "unbounded"}}, ok=True)
    check("before-window", overrides={"now": base["nbf"] - 1})
    check("exclusive-expiry", overrides={"now": base["exp"]})
    for field in ("issuer", "audience", "subject", "profile"):
        check(field + "-mismatch", overrides={field: "different"})
    for field in ("profile_digest", "content_digest"):
        check(field + "-mismatch", overrides={field: b64(ZERO)})
    check("key-id", overrides={"attestor": key | {"key_id": "different"}})
    check("key-window-lower", overrides={"attestor": key | {"valid_from": base["iat"] + 1}})
    check("key-window-upper", overrides={"attestor": key | {"valid_before": base["exp"] - 1}})
    for name, point in [
        ("off-curve", b"\x04" + bytes(64)),
        ("coordinates-out-of-range", b"\x04" + b"\xff" * 64),
        ("compressed", b"\x02" + public[1:33]),
        ("edwards", public_bytes(keys["eddsa"].public_key(), "eddsa")),
        ("wrong-key", public_bytes(ec.derive_private_key(1, ec.SECP256R1()).public_key(), suite)),
    ]:
        check(name, overrides={"attestor": key | {"public_key": b64(point)}})
    r = sig[:32]
    s = int.from_bytes(sig[32:], "big")
    for name, raw_sig in [
        ("high-s", r + (ORDER - s).to_bytes(32, "big")),
        ("r-zero", ZERO + sig[32:]), ("s-zero", r + ZERO),
        ("r-order", ORDER.to_bytes(32, "big") + sig[32:]),
        ("s-order", r + ORDER.to_bytes(32, "big")),
        ("low-s-bound-exact", r + (ORDER // 2).to_bytes(32, "big")),
        ("low-s-bound-plus", r + (ORDER // 2 + 1).to_bytes(32, "big")),
        ("bad-equation", r + ((s % (ORDER // 2 - 1)) + 1).to_bytes(32, "big")),
        ("wrong-algorithm-equation", unb64(signed(keys["eddsa"], "eddsa", header, base).split(".")[-1])),
    ]:
        compact = replace_sig(valid, raw_sig)
        check(name, compact)
        add("structural-" + name, compact, True)

    predecessor = facts(h, base, valid, public, suite)
    next_base = base | {"jti": "next-approval", "gen": 2, "prev": predecessor["digest"]}
    next_compact = sign(next_base)
    check("successor", next_compact, ok=True)
    successor = facts(h, next_base, next_compact, public, suite)

    def next_case(case_id, changes, expected, previous_suite=suite, next_suite=suite):
        new = successor | changes
        actual = (
            previous_suite == next_suite == suite
            and all(new[k] == predecessor[k] for k in ["iss", "aud", "sub", "profile", "profile_digest"])
            and new["gen"] == predecessor["gen"] + 1 and new["prev"] == predecessor["digest"]
            and new["iat"] >= predecessor["iat"] and new["jti"] != predecessor["jti"]
        )
        assert actual == expected
        successors.append(dict(id="pair-" + case_id, predecessor=predecessor, successor=new,
                               previous_suite=previous_suite, next_suite=next_suite,
                               expected="ok" if actual else "invalid"))

    next_case("successor", {}, True)
    next_case("mixed-predecessor", {}, False, previous_suite="eddsa")
    next_case("mixed-successor", {}, False, next_suite="eddsa")
    for field in ("iss", "aud", "sub", "profile"):
        next_case("changed-" + field, {field: "mismatch"}, False)
    next_case("changed-profile-digest", {"profile_digest": b64(sha(b"other profile"))}, False)
    next_case("wrong-generation", {"gen": 3}, False)
    next_case("wrong-predecessor", {"prev": b64(sha(b"other compact"))}, False)
    next_case("backdated", {"iat": predecessor["iat"] - 1}, False)
    next_case("reused-jti", {"jti": predecessor["jti"]}, False)

    ed = signed(keys["eddsa"], "eddsa", HEADERS["eddsa"], base)
    for kind, foreign in [("ca1", ed), *legacy_vectors()]:
        assert not suite_matches(json.loads(unb64(foreign.split(".")[0])), suite)
        assert json.loads(unb64(foreign.split(".")[0]))["typ"] != h["typ"]
        add("foreign-" + kind, foreign)
        cross.append(dict(id=kind, foreign=foreign, candidate=valid, expected="both_reject"))

    signing = dict(id="exact-signing-input", compact=valid, payload=base, kid=h["kid"],
                   signature=b64(sig), expected=dict(kind="content_assertion_es256", message=msg.decode(),
                                                      protected_segment=h_seg, payload_segment=p_seg))
    assembly = [dict(id="assembly-" + name, signature=item["compact"].split(".")[-1],
                     expected=replace_sig(valid, unb64(item["compact"].split(".")[-1]))
                     if scalar_valid(unb64(item["compact"].split(".")[-1])) else "invalid")
                for name, item in [(case["id"], case) for case in verifications
                                   if case["id"] in {"verified", "high-s", "r-zero", "s-zero",
                                                     "r-order", "s-order", "low-s-bound-exact",
                                                     "low-s-bound-plus"}]]
    digest_cases = [
        dict(id="digest-" + name, input=b64(raw_content), bounds=limits,
             expected=content_digest(raw_content) if 0 < len(raw_content) <= limits.get("content_bytes", 65536)
             else "invalid")
        for name, raw_content, limits in [
            ("shared-content", b"asserted bytes", {}),
            ("raw-nul-and-invalid-utf8", b"\0\xff", {}),
            ("empty", b"", {}), ("maximum", b"x" * 65536, {}),
            ("maximum-plus", b"x" * 65537, {}),
            ("tightened-exact", b"ab", {"content_bytes": 2}),
            ("tightened-plus", b"abc", {"content_bytes": 2}),
        ]
    ]
    return {
        "digest-cases.json": digest_cases,
        "assertion-structure-cases.json": structures,
        "assertion-verification-cases.json": verifications,
        "successor-cases.json": successors,
        "separation-cases.json": cross,
        "assembly-cases.json": assembly,
        "profile.json": dict(profile=ES, revision=1, signing=signing),
    }


def approval_vectors(keys, record, base, digest):
    singles, multi = [], []

    def build(case_id, expected, suite="es256", claim=None, head=None, ctx=None, snapshot=None,
              key=None, entry=None, wire=None, compact=None, corrupt=False, combined=False):
        pub = public_bytes(keys[suite].public_key(), suite)
        entry_key = dict(key_id=HEADERS[suite]["kid"], public_key=b64(pub), valid_from=10, valid_before=40)
        enrolled = dict(issuer=base["iss"], key=entry_key | (key or {}), roles=[record["approver_role"]])
        trust = dict(trust_domain="release-domain", suite=suite, provenance="configured-snapshot", as_of=15,
                     entries=[enrolled | (entry or {})]) | (snapshot or {})
        context = dict(trust_domain=trust["trust_domain"], audience=base["aud"], request_id=record["request_id"],
                       revision_digest=record["revision_digest"], subject=record["subject"], action=record["action"],
                       resources=record["resources"], roles=[record["approver_role"]], now=20,
                       max_lifetime=30, max_staleness=5, max_active=25, bounds={}, record_bounds={},
                       snapshot=trust) | (ctx or {})
        if compact is None:
            compact = signed(keys[suite], suite, HEADERS[suite] | (head or {}), base | (claim or {}))
        if corrupt:
            compact = replace_sig(compact, bytes(64))
        if wire is None:
            wire = canonical(record)
        actual = approval(wire, compact, context, suite, digest)
        assert ("verified" if isinstance(actual, dict) else actual) == expected, (case_id, actual)
        case = dict(id=case_id, suite=suite, context=context, record=b64(wire), compact=compact, expected=actual)
        (multi if combined else singles).append(case)
        return case

    es_ok = build("es256-verified", "verified")
    ed_ok = build("eddsa-verified", "verified", suite="eddsa")
    build("zero-resource-ceiling", "invalid_context", ctx={"record_bounds": {"record_bytes": 0}})
    build("unknown-resource-ceiling", "invalid_context", ctx={"record_bounds": {"unknown": 5}})
    build("widened-resource-ceiling", "invalid_context", ctx={"record_bounds": {"resource_count": 4097}})
    build("invalid-context-bool-time", "invalid_context", ctx={"now": True})
    build("duplicate-expected-role", "invalid_context", ctx={"roles": [record["approver_role"]] * 2})
    build("missing-trust", "trust_unavailable", ctx={"snapshot": None})
    build("wrong-trust-suite", "trust_unavailable", snapshot={"suite": "eddsa"})
    build("wrong-trust-domain", "trust_unavailable", ctx={"trust_domain": "other"})
    build("malformed-provenance", "trust_unavailable", snapshot={"provenance": ""})
    build("torsion-entry", "trust_unavailable", suite="eddsa", key={"public_key": b64(b"\1" + bytes(31))})
    build("invalid-point-entry", "trust_unavailable", key={"public_key": b64(b"\4" + bytes(64))})
    entries = es_ok["context"]["snapshot"]["entries"]
    build("duplicate-key-entry", "trust_unavailable", snapshot={"entries": entries * 2})
    build("duplicate-enrolled-role", "trust_unavailable", entry={"roles": [record["approver_role"]] * 2})
    unused = deepcopy(entries[0])
    unused.update(issuer="x" * 65, key=unused["key"] | {"key_id": "different"})
    build("bounds-tightened-unselected-entry", "trust_unavailable",
          ctx={"bounds": {"identifier_bytes": 64}}, snapshot={"entries": entries + [unused]})
    build("future-trust", "stale_trust", snapshot={"as_of": 21})
    build("old-trust", "stale_trust", snapshot={"as_of": 14})
    build("malformed-compact", "malformed", compact="x")
    build("malformed-record", "malformed", wire=b"{}")
    first = build("foreign-eddsa", "unsupported_algorithm", compact=ed_ok["compact"])
    second = build("foreign-es256", "unsupported_algorithm", suite="eddsa", compact=es_ok["compact"])
    for case in [first, second]:
        case["expected_calls"] = {"payload_parser": 0, "key_lookup": 0, "foreign_verifier": 0}
    build("unknown-key", "unknown_key", head={"kid": "different"})
    build("bad-signature", "bad_signature", corrupt=True)
    build("key-window-lower", "key_window", key={"valid_from": 11})
    build("key-window-upper", "key_window", key={"valid_before": 39})
    build("unbounded-key-ceiling", "verified", key={"valid_before": "unbounded"})
    for field in ("content_digest", "profile_digest"):
        build("wrong-" + field, "record_mismatch", claim={field: b64(ZERO)})
    build("wrong-profile", "record_mismatch", claim={"profile": "other"})
    build("issuer-mismatch", "issuer_mismatch", claim={"iss": "other"})
    build("audience-mismatch", "audience_mismatch", claim={"aud": "other"})
    build("request-expected", "request_mismatch", ctx={"request_id": "other"})
    build("request-signed", "request_mismatch", claim={"sub": "other"})
    build("revision-mismatch", "request_mismatch", ctx={"revision_digest": b64(ZERO)})
    build("subject-mismatch", "subject_mismatch", ctx={"subject": "other"})
    build("action-mismatch", "scope_mismatch", ctx={"action": "other"})
    build("resources-mismatch", "scope_mismatch", ctx={"resources": ["other"]})
    build("not-yet-valid", "not_yet_valid", claim={"nbf": 21})
    build("expired", "expired", ctx={"now": 40}, snapshot={"as_of": 40})
    build("lifetime-too-long", "lifetime_too_long", ctx={"max_lifetime": 29})
    build("active-too-long", "active_too_long", ctx={"max_active": 24})
    build("role-not-required", "role_not_permitted", ctx={"roles": ["other"]})
    build("empty-enrolled-roles", "role_not_permitted", entry={"roles": []})
    build("zero-freshness-cap", "verified", ctx={"max_staleness": 0}, snapshot={"as_of": 20})
    build("zero-lifetime-cap", "lifetime_too_long", ctx={"max_lifetime": 0})
    build("opposite-sign-lifetime", "lifetime_too_long",
          claim={"iat": -MAGNITUDE, "exp": MAGNITUDE},
          key={"valid_from": -MAGNITUDE, "valid_before": MAGNITUDE},
          ctx={"max_lifetime": MAGNITUDE, "max_active": MAGNITUDE})
    build("opposite-sign-snapshot-age", "stale_trust", ctx={"now": MAGNITUDE, "max_staleness": MAGNITUDE},
          snapshot={"as_of": -MAGNITUDE})

    def dual(case_id, reason, **kwargs):
        build(case_id, reason, combined=True, **kwargs)

    dual("context-before-snapshot-and-bytes", "invalid_context", ctx={"now": False, "snapshot": None}, compact=".")
    dual("unavailable-before-stale-and-malformed", "trust_unavailable", snapshot={"as_of": 0, "provenance": ""}, compact=".")
    dual("stale-before-shape", "stale_trust", snapshot={"as_of": 0}, compact=".")
    dual("stale-before-key", "stale_trust", head={"kid": "different"}, snapshot={"as_of": 0})
    dual("shape-before-suite", "malformed", head={"typ": "other", "kid": "!"})
    dual("signature-width-before-suite", "malformed", compact=replace_sig(ed_ok["compact"], b"short"))
    dual("suite-before-claims", "unsupported_algorithm",
         compact=signed(keys["eddsa"], "eddsa", HEADERS["eddsa"], b"not-json"))
    dual("suite-before-key", "unsupported_algorithm", head={"typ": "other", "kid": "different"})
    dual("record-shape-before-key", "malformed", wire=b"{}", head={"kid": "different"})
    dual("key-before-signature", "unknown_key", head={"kid": "different"}, corrupt=True)
    dual("signature-before-times", "bad_signature", claim={"nbf": 21}, key={"valid_from": 11}, corrupt=True)
    dual("key-window-before-record-binding", "key_window", key={"valid_from": 11}, claim={"profile": "other"})
    dual("record-binding-before-issuer", "record_mismatch", claim={"profile": "other", "iss": "other"})
    dual("issuer-before-audience", "issuer_mismatch", claim={"iss": "other", "aud": "other"})
    dual("audience-before-request", "audience_mismatch", claim={"aud": "other", "sub": "other"})
    dual("request-before-scope", "request_mismatch", ctx={"request_id": "other", "resources": ["other"]})
    dual("subject-before-scope", "subject_mismatch", ctx={"subject": "other", "action": "other"})
    dual("scope-before-time", "scope_mismatch", ctx={"resources": ["other"]}, claim={"nbf": 21})
    dual("window-before-duration", "not_yet_valid", ctx={"max_lifetime": 0}, claim={"nbf": 21})
    dual("lifetime-before-active", "lifetime_too_long", ctx={"max_lifetime": 0, "max_active": 0})
    dual("active-before-role", "active_too_long", ctx={"max_active": 0, "roles": ["other"]})

    helpers = []
    rendering = "#BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts<redacted>"
    for case in singles + multi:
        pure = case["expected"]
        if isinstance(pure, str):
            helpers.append(dict(id="pure-" + case["id"], pure_case=case["id"], observations={},
                                expected=dict(calls=[], helper=pure, presenter="invalid",
                                              rendering="{:error, :invalid}")))
    verified = es_ok["expected"]
    revocation = dict(predicate="is_revoked",
                      arguments=[entries[0], verified["assertion"]["attestor_key_fingerprint"]])
    replay = dict(predicate="is_replayed",
                  arguments=[verified["trust_domain"], verified["assertion"]["iss"], verified["assertion"]["jti"]])
    outcomes = [(True, None), (False, True), (False, False)]
    outcomes += [(failure, None) for failure in ("unavailable", "exception", "cancelled", "non_bool")]
    outcomes += [(False, failure) for failure in ("unavailable", "exception", "cancelled", "non_bool")]
    for index, (revoked, replayed) in enumerate(outcomes):
        calls = [revocation]
        if revoked is True:
            result = "revoked_key"
        elif revoked is not False:
            result = "predicate_failed"
        else:
            calls.append(replay)
            result = ("replayed" if replayed is True else
                      "approved" if replayed is False else "predicate_failed")
        observations = dict(is_revoked=revoked)
        if replayed is not None:
            observations["is_replayed"] = replayed
        helpers.append(dict(id=f"predicate-{index}", pure_case=es_ok["id"], observations=observations,
                            expected=dict(calls=calls, helper=result,
                                          presenter="approved" if result == "approved" else "invalid",
                                          rendering="#BoundedAuthorityProtocol.ActionApproval.V1.Approved<redacted>"
                                          if result == "approved" else "{:error, :invalid}")))
    return {
        "approval-cases.json": singles,
        "multi-fault-cases.json": multi,
        "helper-cases.json": helpers,
        "rendering-cases.json": [
            dict(id="verified-facts", pure_case=es_ok["id"], expected="{:ok, " + rendering + "}"),
            dict(id="host-local-error", pure_case="unknown-key", expected="{:error, :unknown_key}"),
            dict(id="presenter-error", pure_case="unknown-key", expected="{:error, :invalid}"),
        ],
    }


def freeze(root, profile, files, verify):
    encoded = {name: canonical(content) + b"\n" for name, content in files.items()}
    cases = [(name, content) for name, content in sorted(files.items()) if isinstance(content, list)]
    all_ids = [name + "/" + item["id"] for name, content in cases for item in content]
    demand(len({item["id"] for _, content in cases for item in content}) == len(all_ids))
    verdicts = [[name + "/" + case["id"], case["expected"]] for name, content in cases for case in content]
    index = dict(profile=profile, revision=1, private_material_tracked=False,
                 verdict_sha256=sha(canonical(verdicts)).hex(),
                 files=[dict(path=name, sha256=sha(raw).hex(),
                             **({"cases": len(files[name])} if isinstance(files[name], list) else {}))
                        for name, raw in sorted(encoded.items())])
    encoded["index.json"] = canonical(index) + b"\n"
    if verify:
        demand(set(encoded) == {p.name for p in root.iterdir()})
        for name, raw in encoded.items():
            if raw != (root / name).read_bytes():
                raise ValueError(f"fixture drift: {root.name}/{name}")
    else:
        root.mkdir(parents=True, exist_ok=True)
        for name, raw in encoded.items():
            (root / name).write_bytes(raw)
    print(profile, "cases", len(all_ids), "index hex", sha(encoded["index.json"]).hex(),
          "index base64url", b64(sha(encoded["index.json"])), "verdict", index["verdict_sha256"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    descriptor = (ROOT / "spec/profiles/bap-action-approval-v1.descriptor.json").read_bytes()
    demand(canonical(load_object(descriptor)) == descriptor)
    preimage = APPROVAL.encode() + b"\0" + descriptor
    digest = sha(preimage)
    record = dict(v=1, action="read", subject="subject-\u00e9", request_id="request",
                  approver_role="reviewer", resources=["field-\u00e9", "field-\ue000"],
                  revision_digest=b64(sha(b"fixture revision")))
    base = dict(v=1, jti="event", iss="issuer", aud="executor", sub=record["request_id"],
                profile=APPROVAL, profile_digest=b64(digest), content_digest=content_digest(canonical(record)),
                gen=1, prev=b64(ZERO), iat=10, nbf=15, exp=40)
    keys = fixture_keys()
    assertions = assertion_vectors(keys, base)
    approvals = approval_vectors(keys, record, base, b64(digest))
    approvals["record-cases.json"] = record_vectors(record)
    approvals["profile.json"] = dict(profile=APPROVAL, revision=1, profile_preimage_hex=preimage.hex(),
                                     profile_digest_hex=digest.hex())
    freeze(CORPORA / "attestation-profiles/content-assertion-es256/v1", ES, assertions, args.verify)
    freeze(CORPORA / "content-profiles/action-approval/v1", APPROVAL, approvals, args.verify)
    if args.verify:
        spec = (ROOT / "spec/bap-action-approval-v1.md").read_text()
        demand(preimage.hex() in spec and digest.hex() in spec)
        runtime = (ROOT / "lib/bounded_authority_protocol/action_approval/v1.ex").read_text()
        demand(digest.hex() in runtime)
    print("descriptor bytes", len(descriptor), "preimage bytes", len(preimage), "profile digest", digest.hex())


if __name__ == "__main__":
    main()
