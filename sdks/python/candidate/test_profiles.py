"""Execute the frozen source candidate corpora from the repository root."""

import ast
import base64
import hashlib
import inspect
import json
import logging
import tracemalloc
from asyncio import CancelledError
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from bounded_authority_verifier import (
    MAXIMUM_BOUNDS,
    Bounds,
    HistoricalPublicKey,
    role_attestation,
    v1,
    v2,
    v3,
)
from bounded_authority_verifier import action_approval as approval
from bounded_authority_verifier import content_assertion as eddsa
from bounded_authority_verifier import content_assertion_es256 as es256
from bounded_authority_verifier.approval_record import (
    PROFILE,
    PROFILE_DIGEST,
    ApprovalRecord,
    RecordBounds,
    decode_record,
    encode_record,
)
from bounded_authority_verifier.compact import _parse_compact
from bounded_authority_verifier.error import InvalidError, Ok, _unwrap
from bounded_authority_verifier.json_alg import json_decode

SOURCE = Path("priv/conformance")
APPROVAL = "content-profiles/action-approval/v1"
ES256 = "attestation-profiles/content-assertion-es256/v1"
PINS = {
    APPROVAL: "35470198349f2b03b0c5df4368569a437eae39847fa4b8df1cd1f24b33d6f826",
    ES256: "d79329d431de093f162613fbd2a2fe838766b690fa67cfbc1478eafa322b3c63",
}
BINARY = frozenset(
    ("attestor_key_fingerprint", "content_digest", "digest", "prev",
     "profile_digest", "public_key", "revision_digest")
)
ASSERTION = (
    "version", "attestor_key_id", "jti", "iss", "aud", "sub", "profile",
    "profile_digest", "content_digest", "gen", "prev", "iat", "nbf", "exp",
)
RECORD = ("subject", "action", "request_id", "approver_role", "resources", "revision_digest")
VERIFY = {"eddsa": approval.verify_approval_eddsa, "es256": approval.verify_approval_es256}


def raw(text):
    if not isinstance(text, str):
        return text
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def load(corpus):
    root = SOURCE / corpus
    index_wire = (root / "index.json").read_bytes()
    assert sha(index_wire) == PINS[corpus]
    index = json.loads(index_wire)
    paths = [item["path"] for item in index["files"]]
    assert len(paths) == len(set(paths))
    assert {p.name for p in root.iterdir()} == {"index.json", *paths}
    cases = []
    metadata = {}
    for item in index["files"]:
        name = item["path"]
        path = root / name
        assert path.is_file() and not path.is_symlink()
        data = path.read_bytes()
        assert sha(data) == item["sha256"]
        doc = json.loads(data)
        if "cases" in item:
            assert len(doc) == item["cases"]
            cases.extend((name, case) for case in doc)
        else:
            assert name == "profile.json"
            metadata = doc
    assert len({c["id"] for _, c in cases}) == len(cases)
    return index, metadata, cases


def binary_fields(values):
    return {name: raw(value) if name in BINARY else value for name, value in values.items()}


def key(values):
    if not isinstance(values, dict) or set(values) != {
        "key_id", "public_key", "valid_from", "valid_before",
    }:
        return None
    values = binary_fields(values)
    if values["valid_before"] == "unbounded":
        values["valid_before"] = None
    return HistoricalPublicKey(**values)


def sequence(value):
    return tuple(value) if isinstance(value, list) else value


def trust_entry(values):
    if not isinstance(values, dict):
        return values
    return approval.TrustEntry(values["issuer"], key(values["key"]), sequence(values["roles"]))


def snapshot(values):
    if values is None:
        return None
    fields = values.copy()
    fields["suite"] = approval.Suite(fields["suite"])
    if isinstance(fields["entries"], list):
        fields["entries"] = tuple(map(trust_entry, fields["entries"]))
    return approval.TrustSnapshot(**fields)


def record_bounds(values):
    if set(values) <= {"string_bytes", "resource_count", "record_bytes"}:
        return RecordBounds(**values)
    return values


def context(case):
    fields = binary_fields(case["context"])
    for name in ("roles", "resources"):
        fields[name] = sequence(fields[name])
    fields["snapshot"] = snapshot(fields["snapshot"])
    fields["bounds"] = Bounds(fields["bounds"])
    fields["record_bounds"] = record_bounds(fields["record_bounds"])
    return approval.ApprovalContext(**fields)


def project(value):
    if isinstance(value, bytes):
        return b64(value)
    if isinstance(value, dict):
        return {k: project(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return list(map(project, value))
    return value


def assertion(value, *, verified):
    names = (*ASSERTION, "attestor_key_fingerprint", "digest", "trust", "verification") if verified else ASSERTION
    return project({name: getattr(value, name) for name in names})


def pure_result(case):
    return VERIFY[case["suite"]](raw(case["record"]), case["compact"].encode(), context(case))


def approval_outcome(value):
    if isinstance(value, approval.Diagnostic):
        return value.value
    return {
        "suite": value.suite.value,
        "trust_domain": value.trust_domain,
        "assertion": assertion(value.assertion, verified=True),
        "record": project({name: getattr(value.record, name) for name in RECORD} | {"v": 1}),
        "trust": value.trust,
    }


def record_outcome(case):
    ca = Bounds(case["ca_bounds"])
    limits = record_bounds(case["bounds"])
    if "wire" in case:
        decoded = decode_record(raw(case["wire"]), ca, limits)
        if not isinstance(decoded, Ok):
            return "invalid"
        record = decoded.value
    else:
        fields = {k: v for k, v in binary_fields(case["author"]).items() if k != "v"}
        fields["resources"] = sequence(fields["resources"])
        record = ApprovalRecord(**fields)
    result = encode_record(record, ca, limits, canonicalize=case.get("canonicalize", False))
    if not isinstance(result, Ok):
        return "invalid"
    return {"wire": b64(result.value), "content_digest": b64(_unwrap(eddsa.content_digest(result.value, ca)))}


def invoke_helper(case, revoked, replayed):
    ctx = context(case)
    return approval.verify(
        raw(case["record"]), case["compact"].encode(), ctx.snapshot, ctx.now, ctx.max_lifetime,
        replayed, revoked, suite=approval.Suite(case["suite"]), expected=ctx,
    )


def _observation(value):
    if value == "exception":
        raise RuntimeError("test predicate failure")
    if value == "cancelled":
        raise CancelledError()
    if value == "unavailable":
        return None
    if value == "non_bool":
        return 1
    return value


def helper_outcome(case, pure, caplog):
    calls = []

    def revoked(entry, fingerprint):
        entry = project(asdict(entry))
        if entry["key"]["valid_before"] is None:
            entry["key"]["valid_before"] = "unbounded"
        calls.append({"predicate": "is_revoked", "arguments": [entry, b64(fingerprint)]})
        return _observation(case["observations"]["is_revoked"])

    def replayed(*identity):
        calls.append({"predicate": "is_replayed", "arguments": list(identity)})
        return _observation(case["observations"]["is_replayed"])

    caplog.clear()
    result = invoke_helper(pure, revoked, replayed)
    presenter = approval.presenter_result(result)
    rendering = approval.render_presenter_result(result)
    log_render(result, caplog, rendering)
    return {
        "calls": calls,
        "helper": "approved" if isinstance(result, approval.Approved) else result.value,
        "presenter": presenter,
        "rendering": rendering,
    }


def rendering_outcome(case, pure, caplog):
    example = case["id"]
    caplog.clear()
    if example == "helper-exception":
        def revoked(*_args):
            try:
                raise RuntimeError(case["inputs"]["chained_context"])
            except RuntimeError as cause:
                failure = RuntimeError(case["inputs"]["provider_cause"])
                failure.add_note(case["inputs"]["traceback"])
                raise failure from cause

        replay_calls = []

        def replayed(*args):
            replay_calls.append(args)
            return False

        result = invoke_helper(pure, revoked, replayed)
        assert replay_calls == []
        assert isinstance(result, approval.Diagnostic)
        assert result.value == "predicate_failed"
        output = {"local": repr(result), "presenter": approval.render_presenter_result(result)}
    elif example in {"host-local-error", "presenter-error"}:
        result = pure_result(pure)
        assert isinstance(result, approval.Diagnostic)
        assert result.value == pure["expected"]
        output = repr(result) if example == "host-local-error" else approval.render_presenter_result(result)
    else:
        result = pure_result(pure)
        assert isinstance(result, approval.VerifiedApprovalFacts)
        if example == "verified-facts":
            output = approval.render_verification_result(result)
        elif example == "nested-record":
            result = result.record
            output = repr(result)
        elif example == "nested-assertion":
            result = result.assertion
            output = repr(result)
        else:
            pytest.fail(f"unknown rendering case {example}")

    display = tuple(output.values()) if isinstance(output, dict) else (output,)
    rendered = (repr(result), str(result), repr(Ok(result)), *display, log_render(result, caplog, *display))
    for spellings in case.get("forbidden", {}).values():
        for spelling in spellings:
            assert all(spelling not in text for text in rendered)
    return output


def log_render(value, caplog, *display):
    logging.getLogger(__name__).warning("%r %s", value, value)
    for text in display:
        logging.getLogger(__name__).warning("%s", text)
    assert all(record.exc_info is None for record in caplog.records)
    assert "Traceback (most recent call last)" not in caplog.text
    assert "was the direct cause of the following exception" not in caplog.text
    assert "During handling of the above exception" not in caplog.text
    return caplog.text


def signing_input(meta):
    return _unwrap(es256.assertion_signing_input(producer(meta)))


def producer(meta):
    signing = meta["signing"]
    payload = {k: v for k, v in binary_fields(signing["payload"]).items() if k != "v"}
    return es256.ContentAssertion(signing["kid"], **payload)


def foreign_accepts(identifier, compact):
    if identifier == "ca1":
        return eddsa.decode_assertion(compact).is_ok
    if identifier == "loopback":
        return v1.decode_local_loopback_http_proof(compact).is_ok
    if identifier == "role-attestation":
        return role_attestation.decode_attestation(compact).is_ok
    major, kind = identifier.split("-")
    facade = {"v1": v1, "v2": v2, "v3": v3}[major]
    if kind in {"grant", "proof"}:
        return getattr(facade, f"decode_{kind}")(compact).is_ok
    try:
        segments = _parse_compact(compact, MAXIMUM_BOUNDS)
        getattr(facade, f"_parse_{kind}_header")(segments, MAXIMUM_BOUNDS)
        payload = _unwrap(json_decode(segments.payload_bytes))
        getattr(facade, f"_validate_{kind}_payload")(payload, segments.payload_bytes, MAXIMUM_BOUNDS)
    except InvalidError:
        return False
    return True


def es256_outcome(name, case, meta):
    if name == "digest-cases.json":
        result = es256.content_digest(raw(case["input"]), Bounds(case["bounds"]))
    elif name == "assembly-cases.json":
        result = es256.assemble_compact(signing_input(meta), raw(case["signature"]))
        return result.value.decode() if isinstance(result, Ok) else "invalid"
    elif name == "assertion-structure-cases.json":
        compact = case["compact"].encode()
        bounds = Bounds(case["bounds"])
        decoded = es256.decode_assertion(compact, bounds)
        digest = es256.assertion_digest(compact, bounds)
        assert decoded.is_ok == digest.is_ok
        if not isinstance(decoded, Ok):
            return "invalid"
        facts = assertion(decoded.value, verified=False)
        version = facts["version"]
        del facts["version"]
        return facts | {"v": version, "digest": b64(_unwrap(digest))}
    elif name == "assertion-verification-cases.json":
        expected = binary_fields(case["context"])
        expected["attestor"] = key(expected["attestor"])
        expected["bounds"] = MAXIMUM_BOUNDS
        result = es256.verify_assertion(case["compact"].encode(), es256.ExpectedContentAssertion(**expected))
        return assertion(result.value, verified=True) if isinstance(result, Ok) else "invalid"
    elif name == "successor-cases.json":
        types = {"es256": es256.ContentAssertionFacts, "eddsa": eddsa.ContentAssertionFacts}
        prev = types[case["previous_suite"]](**binary_fields(case["predecessor"]))
        next_ = types[case["next_suite"]](**binary_fields(case["successor"]))
        return "ok" if es256.verify_successor(prev, next_, MAXIMUM_BOUNDS).is_ok else "invalid"
    elif name == "separation-cases.json":
        foreign, candidate = case["foreign"].encode(), case["candidate"].encode()
        assert foreign_accepts(case["id"], foreign)
        assert es256.decode_assertion(candidate).is_ok
        assert not es256.decode_assertion(foreign).is_ok
        assert not foreign_accepts(case["id"], candidate)
        return "both_reject"
    else:
        pytest.fail(f"unknown case file {name}")
    return b64(result.value) if isinstance(result, Ok) else "invalid"


@pytest.mark.parametrize("corpus", [APPROVAL, ES256])
def test_candidate_corpus(corpus, caplog):
    caplog.set_level(logging.DEBUG)
    index, meta, cases = load(corpus)
    by_id = {case["id"]: case for _, case in cases}
    executed = []
    for name, case in cases:
        if corpus == ES256:
            actual = es256_outcome(name, case, meta)
        elif name in ("approval-cases.json", "multi-fault-cases.json"):
            caplog.clear()
            result = pure_result(case)
            actual = approval_outcome(result)
            if isinstance(case["expected"], str):
                assert_redacted_rejection(case, result, case["expected"], caplog)
        elif name == "helper-cases.json":
            actual = helper_outcome(case, by_id[case["pure_case"]], caplog)
        elif name == "rendering-cases.json":
            actual = rendering_outcome(case, by_id[case["pure_case"]], caplog)
        elif name == "record-cases.json":
            actual = record_outcome(case)
        else:
            pytest.fail(f"unknown case file {name}")
        assert actual == case["expected"], case["id"]
        executed.append([f"{name}/{case['id']}", actual])
    assert sha(json_bytes(executed)) == index["verdict_sha256"]


def assert_redacted_rejection(case, result, code, caplog):
    assert isinstance(result, approval.Diagnostic)
    shown = repr(result) + str(result) + log_render(result, caplog)
    assert result.value == code
    assert repr(result) == str(result)
    original = case["compact"].split(".")
    for segment in original:
        if len(segment) > 12:
            assert segment not in shown
    for key_name in ("record", "compact"):
        if len(case[key_name]) > 12:
            assert case[key_name] not in shown


def test_profile_known_answers():
    _, meta, _ = load(APPROVAL)
    preimage = bytes.fromhex(meta["profile_preimage_hex"])
    descriptor = Path("spec/profiles/bap-action-approval-v1.descriptor.json").read_bytes()
    assert preimage == PROFILE.encode() + b"\x00" + descriptor
    assert PROFILE_DIGEST.hex() == sha(preimage) == meta["profile_digest_hex"]

    _, meta, _ = load(ES256)
    signing = signing_input(meta)
    assert {
        "kind": signing.kind,
        "message": (signing.protected_segment + b"." + signing.payload_segment).decode(),
        "payload_segment": signing.payload_segment.decode(),
        "protected_segment": signing.protected_segment.decode(),
    } == meta["signing"]["expected"]
    compact = _unwrap(es256.assemble_compact(signing, raw(meta["signing"]["signature"])))
    assert compact.decode() == meta["signing"]["compact"]
    assert not es256.assemble_compact(replace(signing, kind="content_assertion"), raw(meta["signing"]["signature"])).is_ok
    assert not eddsa.assemble_content_assertion_compact(signing, raw(meta["signing"]["signature"])).is_ok


@pytest.mark.parametrize("ceiling", ["json_bytes", "number_lexeme_bytes"])
def test_es256_producer_and_consumer_share_json_ceilings(ceiling):
    _, meta, _ = load(ES256)
    claims = producer(meta)
    signing = signing_input(meta)
    if ceiling == "json_bytes":
        required = max(len(raw(segment.decode())) for segment in (
            signing.protected_segment, signing.payload_segment,
        ))
    else:
        required = max(len(str(value)) for value in (claims.iat, claims.nbf, claims.exp, claims.gen, 1))
    compact = meta["signing"]["compact"].encode()
    exact, below = Bounds({ceiling: required}), Bounds({ceiling: required - 1})
    assert _unwrap(es256.assertion_signing_input(claims, exact)) == signing
    assert es256.decode_assertion(compact, exact).is_ok
    assert not es256.assertion_signing_input(claims, below).is_ok
    assert not es256.decode_assertion(compact, below).is_ok


@pytest.mark.parametrize("buffer_kind", [bytearray, lambda raw: memoryview(raw).cast("I")])
@pytest.mark.parametrize(
    "surface",
    ["decode", "assertion_digest", "content_digest", "assemble_protected", "assemble_payload", "assemble_signature"],
)
def test_es256_rejects_oversized_buffers_before_copy(buffer_kind, surface):
    _, meta, _ = load(ES256)
    signing = signing_input(meta)
    signature = raw(meta["signing"]["signature"])
    oversized = buffer_kind(bytearray(2 * 1024 * 1024))
    operations = {
        "decode": lambda: es256.decode_assertion(oversized),
        "assertion_digest": lambda: es256.assertion_digest(oversized),
        "content_digest": lambda: es256.content_digest(oversized),
        "assemble_protected": lambda: es256.assemble_compact(replace(signing, protected_segment=oversized), signature),
        "assemble_payload": lambda: es256.assemble_compact(replace(signing, payload_segment=oversized), signature),
        "assemble_signature": lambda: es256.assemble_compact(signing, oversized),
    }
    tracemalloc.start()
    try:
        result = operations[surface]()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not result.is_ok
    assert peak < 1024 * 1024


def test_es256_accepts_mutable_buffers_at_effective_ceilings():
    _, meta, _ = load(ES256)
    signing = signing_input(meta)
    signature = raw(meta["signing"]["signature"])
    compact = meta["signing"]["compact"].encode()
    exact = Bounds({"anchor_bytes": len(compact), "content_bytes": len(compact)})
    below = Bounds({"anchor_bytes": len(compact) - 1, "content_bytes": len(compact) - 1})
    parse = (es256.decode_assertion, es256.assertion_digest, es256.content_digest)
    for operation in parse:
        assert operation(memoryview(compact), exact).is_ok
        assert not operation(memoryview(compact), below).is_ok
    input_ = replace(signing, payload_segment=bytearray(signing.payload_segment))
    assert _unwrap(es256.assemble_compact(input_, bytearray(signature), exact)) == compact
    assert not es256.assemble_compact(input_, bytearray(signature), below).is_ok


def test_es256_content_digest_counts_memoryview_bytes():
    view = memoryview(b"abcdefgh").cast("I")
    assert len(view) < view.nbytes
    assert es256.content_digest(view, Bounds({"content_bytes": view.nbytes})).is_ok
    assert not es256.content_digest(view, Bounds({"content_bytes": view.nbytes - 1})).is_ok


@pytest.mark.parametrize("case_id", ["foreign-eddsa", "foreign-es256"])
def test_foreign_suite_stops_before_payload_and_lookup(case_id, monkeypatch):
    _, _, cases = load(APPROVAL)
    case = next(case for _, case in cases if case["id"] == case_id)

    def forbidden(*_args):
        pytest.fail("foreign suite reached a later verification stage")

    with monkeypatch.context() as patch:
        patch.setattr(approval, "_payload", forbidden)
        patch.setattr(approval, "_find_entry", forbidden)
        patch.setattr(approval, "_signature_matches", forbidden)
        assert pure_result(case) is approval.Diagnostic.UNSUPPORTED_ALGORITHM


def _diagnostic_guard(statements, code):
    for index, statement in enumerate(statements):
        if not isinstance(statement, ast.If):
            continue
        for item in statement.body:
            if isinstance(item, ast.Return) and ast.unparse(item.value) == f"Diagnostic.{code}":
                return index
    raise AssertionError(f"missing guard {code}")


def _mutated_verify(edit):
    from textwrap import dedent

    parsed = ast.parse(dedent(inspect.getsource(approval._verify)))
    edit(parsed.body[0].body)
    namespace = dict(vars(approval))
    exec(compile(ast.fix_missing_locations(parsed), "<approval mutation>", "exec"), namespace)
    return namespace["_verify"]


def _try_stage(body, code):
    return next(
        index for index, node in enumerate(body)
        if isinstance(node, ast.Try)
        and any(
            isinstance(item, ast.Return) and ast.unparse(item.value) == f"Diagnostic.{code}"
            for handler in node.handlers for item in handler.body
        )
    )


@pytest.mark.parametrize(
    ("case_id", "boundary", "wrong"),
    [
        ("context-before-snapshot-and-bytes", "context", approval.Diagnostic.TRUST_UNAVAILABLE),
        ("unavailable-before-stale-and-malformed", "snapshot", approval.Diagnostic.STALE_TRUST),
        ("es256-missing-public_key-unselected-stale", "snapshot", approval.Diagnostic.STALE_TRUST),
        ("eddsa-missing-valid_from-unselected-stale", "snapshot", approval.Diagnostic.STALE_TRUST),
        ("stale-before-shape", "freshness", approval.Diagnostic.MALFORMED),
        ("shape-before-suite", "framing", approval.Diagnostic.UNSUPPORTED_ALGORITHM),
        ("signature-width-before-suite", "framing", approval.Diagnostic.UNSUPPORTED_ALGORITHM),
        ("suite-before-claims", "suite_payload", approval.Diagnostic.MALFORMED),
        ("suite-before-key", "suite_lookup", approval.Diagnostic.UNKNOWN_KEY),
        ("noncanonical-record-before-key", "record", approval.Diagnostic.UNKNOWN_KEY),
        ("record-shape-before-key", "record", approval.Diagnostic.UNKNOWN_KEY),
        ("signed-sub-bound-before-key", "record", approval.Diagnostic.UNKNOWN_KEY),
    ],
)
def test_mutation_reorders_preflight_and_parsing(case_id, boundary, wrong, monkeypatch):
    _, _, cases = load(APPROVAL)
    case = next(case for _, case in cases if case["id"] == case_id)
    assert pure_result(case).value == case["expected"]

    def reorder(body):
        snapshot = _try_stage(body, "TRUST_UNAVAILABLE")
        freshness = _diagnostic_guard(body, "STALE_TRUST")
        framing = _try_stage(body, "MALFORMED")
        suite = _diagnostic_guard(body, "UNSUPPORTED_ALGORITHM")
        lookup = _diagnostic_guard(body, "UNKNOWN_KEY")
        if boundary == "context":
            # Look at snapshot availability before validating explicit context.
            body[:0] = ast.parse(
                "if context.snapshot is None: return Diagnostic.TRUST_UNAVAILABLE"
            ).body
        elif boundary == "snapshot":
            body[snapshot:snapshot] = body[snapshot + 1:freshness + 1]
            del body[freshness + 1:freshness + 3]
        elif boundary == "freshness":
            body[freshness], body[framing] = body[framing], body[freshness]
        elif boundary == "framing":
            # Read just the selector, ahead of validating the compact and header shape.
            body[framing:framing] = ast.parse(
                "from base64 import urlsafe_b64decode\n"
                "from json import loads\n"
                "encoded = compact.partition(b'.')[0]\n"
                "early = loads(urlsafe_b64decode(encoded + b'=' * (-len(encoded) % 4)))\n"
                "if (early['alg'].encode(), early['typ'].encode()) != (suite.alg, suite.typ):\n"
                "    return Diagnostic.UNSUPPORTED_ALGORITHM\n"
            ).body
        elif boundary == "suite_payload":
            body[suite], body[suite + 1] = body[suite + 1], body[suite]
        else:
            # Lookup needs the parsed header only. Move it ahead of suite or payload admission.
            target = suite if boundary == "suite_lookup" else suite + 1
            body[target:lookup + 1] = body[lookup - 1:lookup + 1] + body[target:lookup - 1]

    monkeypatch.setattr(approval, "_verify", _mutated_verify(reorder))
    assert pure_result(case) is wrong


@pytest.mark.parametrize(
    ("case_id", "earlier", "later"),
    [
        ("signature-before-times", "BAD_SIGNATURE", "KEY_WINDOW"),
        ("key-window-before-record-binding", "KEY_WINDOW", "RECORD_MISMATCH"),
        ("record-binding-before-issuer", "RECORD_MISMATCH", "ISSUER_MISMATCH"),
        ("issuer-before-audience", "ISSUER_MISMATCH", "AUDIENCE_MISMATCH"),
        ("audience-before-request", "AUDIENCE_MISMATCH", "REQUEST_MISMATCH"),
        ("request-before-subject", "REQUEST_MISMATCH", "SUBJECT_MISMATCH"),
        ("subject-before-scope", "SUBJECT_MISMATCH", "SCOPE_MISMATCH"),
        ("scope-before-time", "SCOPE_MISMATCH", "NOT_YET_VALID"),
        ("window-before-duration", "NOT_YET_VALID", "LIFETIME_TOO_LONG"),
        ("lifetime-before-active", "LIFETIME_TOO_LONG", "ACTIVE_TOO_LONG"),
        ("active-before-role", "ACTIVE_TOO_LONG", "ROLE_NOT_PERMITTED"),
    ],
)
def test_mutation_reorders_precedence(case_id, earlier, later, monkeypatch):
    _, _, cases = load(APPROVAL)
    case = next(case for _, case in cases if case["id"] == case_id)
    assert pure_result(case).value == case["expected"]

    def reorder(body):
        i, j = _diagnostic_guard(body, earlier), _diagnostic_guard(body, later)
        body[i], body[j] = body[j], body[i]

    monkeypatch.setattr(approval, "_verify", _mutated_verify(reorder))
    assert pure_result(case).value == later.lower()


@pytest.mark.parametrize(
    ("case_id", "code", "wrong"),
    [
        ("key-before-signature", "UNKNOWN_KEY", "bad_signature"),
        ("signature-before-times", "BAD_SIGNATURE", "key_window"),
        ("expired", "EXPIRED", None),
        ("role-not-required", "ROLE_NOT_PERMITTED", None),
    ],
)
def test_mutation_drops_checked_stage(case_id, code, wrong, monkeypatch):
    _, _, cases = load(APPROVAL)
    case = next(case for _, case in cases if case["id"] == case_id)
    assert pure_result(case).value == case["expected"]

    def remove(body):
        index = _diagnostic_guard(body, code)
        if code == "UNKNOWN_KEY":
            # A wrong selector that falls through to the already enrolled key.
            body[index - 1] = ast.parse("enrolled = next(iter(entries.values()))").body[0]
        else:
            body[index].test = ast.Constant(value=False)

    monkeypatch.setattr(approval, "_verify", _mutated_verify(remove))
    result = pure_result(case)
    if wrong is None:
        assert isinstance(result, approval.VerifiedApprovalFacts)
    else:
        assert result is approval.Diagnostic(wrong)


@pytest.mark.parametrize(
    ("case_id", "code", "clause"),
    [
        ("wrong-profile", "RECORD_MISMATCH", "claims.profile != PROFILE"),
        ("wrong-profile_digest", "RECORD_MISMATCH", "not compare_digest(claims.profile_digest, PROFILE_DIGEST)"),
        ("wrong-content_digest", "RECORD_MISMATCH", "not compare_digest(claims.content_digest, _unwrap(content_digest(wire, b)))"),
        ("request-record", "REQUEST_MISMATCH", "record.request_id != context.request_id"),
        ("request-signed", "REQUEST_MISMATCH", "claims.sub != context.request_id"),
        ("revision-mismatch", "REQUEST_MISMATCH", "not compare_digest(record.revision_digest, context.revision_digest)"),
        ("action-mismatch", "SCOPE_MISMATCH", "record.action != context.action"),
        ("resources-mismatch", "SCOPE_MISMATCH", "tuple(item.encode('utf-8') for item in record.resources) != resources"),
        ("role-not-required", "ROLE_NOT_PERMITTED", "record.approver_role not in context.roles"),
        ("empty-enrolled-roles", "ROLE_NOT_PERMITTED", "record.approver_role not in entry.roles"),
    ],
)
def test_mutation_drops_independent_authenticated_clause(case_id, code, clause, monkeypatch):
    _, _, cases = load(APPROVAL)
    by_id = {case["id"]: case for _, case in cases}
    if case_id == "request-record":
        case = by_id["request-signed"]
        # The signed subject is now the expected ID, leaving only the record side unequal.
        case = dict(case, context=dict(case["context"], request_id="other"))
    else:
        case = by_id[case_id]
    assert pure_result(case) is approval.Diagnostic[code]

    def remove(body):
        guard = body[_diagnostic_guard(body, code)]
        assert isinstance(guard.test, ast.BoolOp)
        target = ast.dump(ast.parse(clause, mode="eval").body)
        matches = [index for index, node in enumerate(guard.test.values) if ast.dump(node) == target]
        assert len(matches) == 1, clause
        guard.test.values[matches[0]] = ast.Constant(value=False)

    monkeypatch.setattr(approval, "_verify", _mutated_verify(remove))
    assert isinstance(pure_result(case), approval.VerifiedApprovalFacts)


def test_verification_leaves_module_state_unchanged():
    import sys

    modules = {
        name: module
        for name, module in sys.modules.items()
        if name.startswith("bounded_authority_verifier") or name == "bounded_authority_verifier"
    }

    def saved_state(module):
        return {
            name: value.copy() if type(value) in (list, set, dict) else value
            for name, value in vars(module).items()
        }

    _, _, cases = load(APPROVAL)
    before = {name: saved_state(module) for name, module in modules.items()}
    for name, case in cases:
        if name not in {"approval-cases.json", "multi-fault-cases.json"}:
            continue
        assert approval_outcome(pure_result(case)) == case["expected"]
    assert {name: saved_state(module) for name, module in modules.items()} == before


def test_signature_backend_failure_discards_cause(monkeypatch, caplog):
    _, _, cases = load(APPROVAL)
    case = next(case for _, case in cases if case["id"] == "rendering-canaries-verified")
    assert isinstance(pure_result(case), approval.VerifiedApprovalFacts)

    def failed(*_args):
        try:
            raise ValueError("inner signature cause")
        except ValueError as cause:
            raise RuntimeError("outer signature cause") from cause

    monkeypatch.setattr(approval, "_signature_matches", failed)
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    result = pure_result(case)
    assert result is approval.Diagnostic.BAD_SIGNATURE
    assert "signature cause" not in log_render(result, caplog)
