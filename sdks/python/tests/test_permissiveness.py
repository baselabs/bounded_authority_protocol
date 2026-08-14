"""T9 permissiveness mutation-gate — the per-language falsifier the frozen corpus cannot be
(ADR 0005:240-246; ADR 0014 Decision 6/7). The corpus has no parser-layer permissiveness cases
(host parsers are not in its input algebra), so each closure below is proven red-capable IN THE
LANGUAGE WHOSE HOST RUNTIME IT TARGETS: construct the host-specific permissive defect the closure
defeats, assert the SDK REJECTs it.

DEFECT-INJECTION BATTERY (8 items — the ADR 0005:240-246 "prove red-when-removed" half). Each
item below was defect-injected at authoring: the named closure/gate was mechanically removed or
broken, the named test/gate went RED, and the change was reverted. The record:
  1. duplicate-reject (REQ1-JSON-no-duplicate): remove the `if name in members: fail(...)` in
     json_alg.py → "duplicate member at depth 3" goes RED.
  2. __class__/dunder null-prototype (REQ1-SELECTOR-semantic-identity): switch JObject.v to a
     dict-subclass-with-`__getattr__` (the Python defect — attribute collision) →
     "__class__ member preserved as data" + "does not collapse identity" go RED.
  3. raw-lexeme 64-byte ceiling (REQ1-JSON-raw-lexeme): remove the lexeme length check in
     json_alg.py → "66-byte number lexeme" goes RED (the 66-byte tiny-float value 1e-64 passes
     magnitude but fails ONLY the lexeme ceiling — a genuinely falsifiable case).
  4. single-value/trailing (REQ1-JSON-single-value): remove the `ctx.pos != len(src)` check in
     json_alg.py → "trailing bytes" + "two top-level values" go RED.
  5. int/float tag distinction: collapse the float decode to JInt in json_alg._parse_number
     (return JInt(int(n)) instead of JFloat(n)) → "integer 1 and float 1.0 distinct identity" +
     "equals selector distinguishes" go RED.
  6. census two-boundary (ADR 0014 D9): make import_public_key in ed25519.py NOT register the
     fingerprint → conformance/run.py census aborts ("declared by a valid verification case but
     never imported at the Ed25519 verify boundary").
  7. purity lint (ADR 0014 D8): inject `datetime.now()` into a src/ module → tools/purity_check.py
     fails ("forbidden call: datetime.now").
  8. license check (ADR 0014 D8): add a non-allowlisted runtime dep to pyproject.toml →
     tools/license_check.py fails ("not in the allowlist").

Closures (design § Invariant conformance — Python-specific):
  1. REQ1-JSON-no-duplicate — hand-rolled duplicate-rejecting decoder (NOT json.loads).
  2. REQ1-SELECTOR-semantic-identity / __class__ — plain dict with dict[key] subscription only
     (never getattr), so __class__/__proto__ keys are data. THE PYTHON DEFECT differs from TS:
     Python's risk is dunder/attribute collision, not prototype absorption.
  3. REQ1-JSON-raw-lexeme — number magnitude + 64-byte ceiling scanned on the raw lexeme.
  4. REQ1-JSON-single-value — trailing bytes after the top-level value reject.
  5. int/float tag distinction — 1 != 1.0 in selector semantic identity.
"""

from __future__ import annotations

import base64
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bounded_authority_verifier.bounds import Bounds, bounds_new
from bounded_authority_verifier.ed25519 import reset_census, sha256
from bounded_authority_verifier.error import InvalidError
from bounded_authority_verifier.json_alg import (
    JArray,
    JFloat,
    JInt,
    JNull,
    JObject,
    JString,
    Tagged,
    json_decode,
)
from bounded_authority_verifier.jwk import public_key_thumbprint_raw
from bounded_authority_verifier.selector import (
    parse_selector,
    selector_matches,
    semantic_identity,
)
from bounded_authority_verifier.v1 import (
    ARCHIVE_PREFIX,
    ROW_PREFIX,
    AnchoredExportInput,
    ArchivedObject,
    BoundaryAnchorProducer,
    ChainInput,
    ConsumptionEntry,
    ExpectedAnchor,
    ExpectedChain,
    ExpectedExport,
    ExpectedGrant,
    ExpectedKeyTransition,
    ExpectedRequest,
    GrantProducer,
    HistoricalKeyChain,
    HistoricalPublicKey,
    KeyTransitionProducer,
    NonceNotRequired,
    OperationInput,
    ProofProducer,
    SigningInput,
    TrustedIssuer,
    assemble_compact,
    assemble_segments,
    boundary_anchor_signing_input,
    check_chain,
    check_envelope,
    decode_grant,
    encode_anchored_export,
    encode_consumption_entry,
    grant_signing_input,
    key_transition_signing_input,
    proof_signing_input,
    request_digest,
    untrusted_key_locator,
    verify_anchored_export,
    verify_grant,
)

dec = json_decode


def rejects(label: str):
    """Decorator: the body must raise InvalidError."""

    def deco(fn):
        return pytest.mark.raises(InvalidError)(fn)

    return deco


def _to_hex(b: bytes) -> str:
    return b.hex()


# 1. REQ1-JSON-no-duplicate — the host defect: json.loads silently last-wins duplicates. The SDK's
# hand-rolled decoder rejects at EVERY depth. (The corpus catches depth-1 duplicates via json/decode
# invalid_duplicate; this closure's distinct value is depth>=3 + the guarantee that no host-parser
# fallback exists anywhere in the SDK path.)
def test_duplicate_member_at_depth_3():
    with pytest.raises(InvalidError):
        dec(b'{"a":{"b":{"c":1,"c":2}}}')


def test_distinct_members_accepted():
    v = dec(b'{"a":1,"b":2}')
    assert isinstance(v, JObject)


# 2. __class__/dunder null-prototype — the Python defect: a dict-subclass-with-__getattr__ would
# collide a "__class__" key with the attribute, so the member would resolve to the type object
# instead of the data value, collapsing identity. The SDK uses plain dict + dict[key] subscription
# only (never getattr), so __class__ is DATA.
def test_dunder_member_preserved_as_data():
    """A __class__ key must be stored as ordinary data, not collide with dict.__class__."""
    v = dec(b'{"__class__":{"evil":1},"ok":2}')
    assert isinstance(v, JObject)
    # dict[key] subscription (the SDK's only access path) returns the DATA value, not dict.__class__.
    assert "__class__" in v.v
    assert "ok" in v.v
    class_member = v.v["__class__"]
    assert isinstance(class_member, JObject)  # the data value, NOT <class 'dict'>
    evil = class_member.v["evil"]
    assert isinstance(evil, JInt) and evil.v == 1


def test_dunder_does_not_collapse_identity():
    """Two objects differing ONLY in a __class__ member must have distinct semantic identity.

    If the closure were removed (a dict-subclass-with-__getattr__ absorbed __class__), both would
    canonicalize identically because the __class__ member would resolve to the type object (or
    vanish), collapsing the distinction.
    """
    a = dec(b'{"__class__":1,"x":2}')
    b = dec(b'{"x":2}')
    assert _to_hex(semantic_identity(a)) != _to_hex(semantic_identity(b))


# 3. REQ1-JSON-raw-lexeme — the host defect: float() rounds a long lexeme to a finite value, so a
# magnitude check AFTER conversion accepts it. The SDK scans the raw lexeme (64-byte ceiling) BEFORE
# conversion. The 66-byte tiny-float below has value 1e-64 (finite, within magnitude) — it is
# rejected ONLY by the lexeme ceiling.
def test_66_byte_number_lexeme():
    with pytest.raises(InvalidError):
        dec(b"0." + b"0" * 63 + b"1")


def test_integer_magnitude_over_bound():
    with pytest.raises(InvalidError):
        dec(b"9007199254740992")  # MAXIMA.integer_magnitude + 1


# 4. REQ1-JSON-single-value — the host defect: json.loads accepts trailing data after the top-level
# value in some configurations. The SDK rejects any byte after the single value (whitespace-only).
def test_trailing_bytes():
    with pytest.raises(InvalidError):
        dec(b"{} junk")


def test_two_top_level_values():
    with pytest.raises(InvalidError):
        dec(b"1 2")


# 5. int/float tag distinction — the host defect: a naive JSON loader collapses `1` and `1.0` to the
# same value, so a selector identity comparison that used the raw value would treat them as equal.
# The SDK's tagged algebra preserves the distinction; the typed projection wraps them differently.
def test_integer_and_float_distinct_identity():
    int_one = dec(b"1")
    float_one = dec(b"1.0")
    assert isinstance(int_one, JInt)
    assert isinstance(float_one, JFloat)
    assert _to_hex(semantic_identity(int_one)) != _to_hex(semantic_identity(float_one))


def test_equals_selector_distinguishes_int_from_float():
    args = dec(b'{"n":1}')  # integer 1
    sel_int = parse_selector(dec(b'{"kind":"equals","path":["n"],"value":1}'))
    sel_float = parse_selector(dec(b'{"kind":"equals","path":["n"],"value":1.0}'))
    assert selector_matches(sel_int, args) is True
    assert selector_matches(sel_float, args) is False  # float 1.0 != integer 1


# 6. JCS float canonicalization (RFC 8785 §3.2.2 / ECMAScript Number.prototype.toString). The host
# defect: Python repr(1.0)=="1.0" but ECMAScript emits "1"; repr(1e-7)=="1e-07" but ECMAScript emits
# "1e-7". A wrong float serialization makes a Python verifier compute a different request digest
# (ba_req) than an Elixir/TS signer for any float-valued cast_argument — a cross-implementation
# divergence the corpus cannot express (its digest cases are integer-only). These cases pin the
# ECMAScript serialization; removing the _format_float normalization → they go RED.
@pytest.mark.parametrize(
    "lexeme,expected",
    [
        (b"1.0", b'{"x":1}'),
        (b"10.0", b'{"x":10}'),
        (b"100.0", b'{"x":100}'),
        (b"0.0", b'{"x":0}'),
        (b"1e-7", b'{"x":1e-7}'),
        (b"1.5", b'{"x":1.5}'),
        (b"0.0001", b'{"x":0.0001}'),
        (b"1e-6", b'{"x":0.000001}'),
        (b"9e15", b'{"x":9000000000000000}'),
        (b"123.456", b'{"x":123.456}'),
    ],
)
def test_jcs_float_canonicalization_matches_ecmascript(lexeme, expected):
    from bounded_authority_verifier.jcs import jcs_encode

    v = dec(b'{"x":' + lexeme + b"}")
    assert jcs_encode(v) == expected


def test_jcs_astral_codepoint_emits_4_byte_utf8():
    """RFC 8785: astral code points (cp >= 0x10000) emit as 4-byte UTF-8, not a malformed 3-byte
    sequence. The defect: a 3-byte-cap _append_utf8_bytes produces F0 80 80 ... for astral chars.
    """
    from bounded_authority_verifier.jcs import jcs_encode

    # U+10000 (𐀀) encoded as a JSON \uXXXX surrogate pair.
    v = dec(b'"\\ud800\\udc00"')
    out = jcs_encode(v)
    # The string value between the quotes is the raw 4-byte UTF-8 of U+10000: F0 90 80 80.
    assert out == b'"' + bytes([0xF0, 0x90, 0x80, 0x80]) + b'"'


# === BAP-09 cross-vendor remediation — fail-closed + reference-parity closures (defect-injected) ===
# Each closure below was verified divergent against the RUNNING Elixir reference, fixed to match the
# reference verdict, then proven red-capable by mechanically removing/breaking the fix and watching
# the named test go RED. The reference verdict is the contract (AGENTS rule 7); RFC 8785 is cited
# only where the reference agrees with it.

def test_lone_high_surrogate_at_eof_is_invalid_not_indexerror():
    """Claude opus cross-vendor finding: a lone high-surrogate \\uXXXX escape at end-of-buffer
    (b'\"\\\\uD800') must fail closed as InvalidError, not raise IndexError on src[ctx.pos+1].
    The TS sibling is safe (out-of-range Uint8Array access yields undefined); Python raises.
    Defect: revert json_alg.py to `if src[ctx.pos] != 0x5C ...` (no _byte_at guard) → IndexError.
    """
    with pytest.raises(InvalidError):
        json_decode(b'"\\uD800')
    with pytest.raises(InvalidError):
        json_decode(b'"\\uD800\\')
    # Control: a lone high surrogate WITH a closing quote already failed closed; still does.
    with pytest.raises(InvalidError):
        json_decode(b'"\\uD800"')
    # Control: a valid surrogate pair still succeeds (decodes to U+103FF).
    assert json_decode(b'"\\uD800\\uDFFF"') == JString(v=bytes([0xF0, 0x90, 0x8F, 0xBF]))


def test_malformed_utf8_member_name_is_invalid():
    """Cross-vendor #14: an object member name with invalid UTF-8 bytes (e.g. 0xff) must fail closed
    as InvalidError, not raise UnicodeDecodeError past the closed-error whitelist. The reference
    returns {:error,:invalid} (json.ex rescues). Defect: revert to bare `name_bytes.decode('utf-8')`
    → UnicodeDecodeError.
    """
    with pytest.raises(InvalidError):
        json_decode(b'{"\xff":1}')
    # Control: a valid name still decodes.
    assert json_decode(b'{"a":1}') == JObject(v={"a": JInt(v=1)})


def test_float_magnitude_checked_on_raw_lexeme_not_lossy_conversion():
    """Cross-vendor #7: a float lexeme whose value exceeds the maximum but rounds to it under
    float() (9007199254740991.0001 → 9007199254740991.0) MUST be rejected. The reference checks the
    raw lexeme by decimal arithmetic (json.ex magnitude_within?). Defect: revert to the post-
    conversion `abs(n) > MAX_FLOAT` check → this lexeme is accepted (lossy).
    """
    with pytest.raises(InvalidError):
        json_decode(b"9007199254740991.0001")
    # Controls: exactly MAX is valid (int); MAX+1 as int is rejected on the raw lexeme too.
    assert json_decode(b"9007199254740991") == JInt(v=9007199254740991)
    with pytest.raises(InvalidError):
        json_decode(b"9007199254740992")
    # A float strictly under MAX is valid.
    assert isinstance(json_decode(b"9007199254740990.5"), JFloat)


def test_malformed_ipv6_literal_rejected():
    """Cross-vendor #6: a structurally-invalid IPv6 literal (e.g. [:::]) must be rejected, not
    normalized. The reference (uri.ex valid_ipv6_literal?) validates group count + compression
    rules; the prior implementation only checked the character class. Defect: revert _ipv6_kind to
    the regex-only branch → [:::] normalizes to Ok.
    """
    from bounded_authority_verifier.error import Err
    from bounded_authority_verifier.uri import uri_normalize

    assert isinstance(uri_normalize(b"https://[:::]/"), Err)
    assert isinstance(uri_normalize(b"https://[1:2:3:4:5:6:7:8:9]/"), Err)
    assert isinstance(uri_normalize(b"https://[1::2::3]/"), Err)
    assert isinstance(uri_normalize(b"https://[gggg]/"), Err)
    # Cross-vendor re-review Finding 1: a non-tail IPv4-style group must reject (the reference's
    # ipv6_groups_length checks non-last groups as hex-only). The prior fix accepted this.
    assert isinstance(uri_normalize(b"https://[1.2.3.4:5::6]/"), Err), "non-tail IPv4 group must reject"
    # Controls: valid IPv6 literals still normalize.
    assert uri_normalize(b"https://[::1]/").is_ok
    assert uri_normalize(b"https://[2001:db8::1]/").is_ok
    assert uri_normalize(b"https://[1:2:3:4:5:6:7:8]/").is_ok
    assert uri_normalize(b"https://[::ffff:192.0.2.1]/").is_ok


def test_jcs_del_emits_raw_byte_matching_reference():
    """Cross-vendor #8: JCS serialization of DEL (U+007F) MUST emit the raw byte 0x7f. This is
    RFC-CONFORMANT, not a deviation: RFC 8785 §3.2.2.2 escapes only U+0000–U+001F plus quote (0x22)
    and backslash (0x5c); DEL (0x7f) is outside that range, so it is serialized "as is" (raw). The
    reference (jcs.ex:142-148: the < 0x20 branch skips DEL, the general codepoint clause emits it
    raw) and the SDK source comment (jcs.py:261-266) already state this correctly. Defect: revert to
    the `\\u007f` branch → this test's byte comparison fails.
    """
    from bounded_authority_verifier.jcs import jcs_encode

    v = JString(v=b"x\x7fy")
    assert list(jcs_encode(v)) == [34, 120, 127, 121, 34]  # "x<raw DEL>y"


def test_jcs_enforces_per_node_bounds_at_encode():
    """Cross-vendor #9: the JCS encoder MUST enforce per-node resource bounds DURING encode (mirrors
    jcs.ex:27-101 encode_value), not only the final jcs_bytes total. A 257-item array (array_items
    bound 256), a depth-33 nested array (depth bound 32), and an 8193-byte string (string_bytes bound
    8192) must all reject — the reference rejects each. Defect: revert _emit to the boundless
    recurse (no level/nodes/length checks) → all three encode successfully.
    """
    from bounded_authority_verifier.jcs import jcs_encode

    # 257-item array (over array_items=256).
    with pytest.raises(InvalidError):
        jcs_encode(JArray(v=tuple(JInt(i) for i in range(257))))
    # Control: 256 items is the boundary and encodes.
    assert isinstance(jcs_encode(JArray(v=tuple(JInt(i) for i in range(256)))), bytes)
    # depth-33 nested array (over depth=32).
    deep = JInt(0)
    for _ in range(33):
        deep = JArray(v=(deep,))
    with pytest.raises(InvalidError):
        jcs_encode(deep)
    # Control: depth-32 encodes.
    deep32 = JInt(0)
    for _ in range(32):
        deep32 = JArray(v=(deep32,))
    assert isinstance(jcs_encode(deep32), bytes)
    # oversized string (over string_bytes=8192).
    with pytest.raises(InvalidError):
        jcs_encode(JString(v=b"x" * 8193))
    # Control: exactly 8192 bytes encodes.
    assert isinstance(jcs_encode(JString(v=b"x" * 8192)), bytes)


# === FIX-C cross-vendor remediation — v1 façade closed-boundary (defect-injected) ===

def test_untrusted_key_locator_decodes_only_protected_segment():
    """Cross-vendor #13: untrusted_key_locator MUST decode ONLY the protected segment — the reference
    (v1.ex:21-34) splits on '.' and never decodes payload/signature. A compact with a valid grant
    header but garbage (non-base64url) payload+signature must return the kid (Ok), not reject. The
    prior implementation called parse_compact (decodes all 3) → wrongly rejected. Defect: revert to
    parse_compact → the garbage-payload case returns Err.
    """
    from bounded_authority_verifier.error import Ok
    from bounded_authority_verifier.v1 import untrusted_key_locator

    protected = b"eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIiwidHlwIjoiYmErY2FwIn0"
    # Garbage payload + signature (non-base64url bytes).
    r = untrusted_key_locator(protected + b".!!.!!!")
    assert isinstance(r, Ok) and r.value.key_id == "k1"
    # Valid-base64 non-JSON payload + signature — reference also returns Ok.
    assert isinstance(untrusted_key_locator(protected + b".YWFh.YmJi"), Ok)
    # 2- and 4-segment inputs reject (reference requires exactly 3).
    assert not untrusted_key_locator(protected + b".!!").is_ok
    assert not untrusted_key_locator(protected + b".!!.!!.!!").is_ok


def test_check_envelope_rejects_null_trusted_issuer_fail_closed():
    """Cross-vendor #22: a null trusted_issuer must fail closed (return Err), not raise
    AttributeError on the .public_key deref. The _trying wrapper only catches InvalidError, so without
    the guard an AttributeError propagates out of the public API. Defect: revert the
    `if t is None: fail(...)` guard → AttributeError is raised (not caught).
    """
    from bounded_authority_verifier.v1 import ExpectedRequest, check_envelope

    junk = b"aaa.bbb.ccc"
    # Must return Err (fail-closed); without the guard this raises AttributeError.
    r = check_envelope(junk, junk, ExpectedRequest(
        trusted_issuer=None,  # type: ignore[arg-type]
        issuer="x", audience="x", method="GET", target_uri="https://x.example/",
        invocation_id="550e8400-e29b-41d4-a716-446655440000", operation="read",
        cast_arguments={"t": "null", "v": None}, evaluation_time=100, clock_skew=0,
        proof_max_age=300, nonce=("not_required",)))
    assert not r.is_ok


def test_check_envelope_rejects_fractional_and_zero_temporal_context():
    """Cross-vendor #19: the reference requires is_integer(evaluation_time), is_integer(clock_skew),
    and proof_max_age > 0 (strictly positive). A range-only `< 0` check accepts fractional times and
    proof_max_age=0. These guards fire BEFORE grant parsing, so a junk compact suffices. Defect:
    revert the isinstance/`<= 0` guards → fractional/zero values pass the guard and the junk compact
    fails later at grant parse (so the guard's rejection is indistinguishable — but the integer
    boundary is the contract, and a valid grant under a fractional eval time would wrongly verify).
    """
    from bounded_authority_verifier.v1 import ExpectedRequest, TrustedIssuer, check_envelope

    junk = b"aaa.bbb.ccc"
    issuer = TrustedIssuer(key_id=b"k", public_key=b"\x00" * 32)
    base = {
        "issuer": "x", "audience": "x", "method": "GET", "target_uri": "https://x.example/",
        "invocation_id": "550e8400-e29b-41d4-a716-446655440000", "operation": "read",
        "cast_arguments": {"t": "null", "v": None}, "nonce": ("not_required",),
    }

    def call(**overrides):
        return check_envelope(junk, junk, ExpectedRequest(trusted_issuer=issuer, **{**base, **overrides}))

    # All of these must return Err (the guard rejects). A valid-integer context also returns Err
    # here only because the junk compact fails at grant parse — so the test's load-bearing assertion
    # is that the fractional/zero cases do NOT raise and DO return Err, matching the integer control.
    assert not call(evaluation_time=150.5, clock_skew=0, proof_max_age=300).is_ok
    assert not call(evaluation_time=150, clock_skew=10.5, proof_max_age=300).is_ok
    assert not call(evaluation_time=150, clock_skew=0, proof_max_age=0).is_ok
    assert not call(evaluation_time=150, clock_skew=0, proof_max_age=300).is_ok


# === BAP-09 #2/#3/#15/#16/#17/#18 cross-vendor remediation — chain/archive verify + encode paths ===
# Each closure was verified divergent against the RUNNING Elixir reference (the verification agents
# confirmed precise behaviors), fixed to match the reference verdict, then proven red-capable by
# mechanically reverting the named fix and watching the test go RED. The reference bytes are the
# contract (AGENTS rule 7).
#
# The SDK is verify-only (public keys; AGENTS rule 6), so to build red-capable deny cases for the
# archive path we mint throwaway Ed25519 keys via `cryptography`, sign anchors/transitions through the
# SDK's own producers, assemble archives via encode_anchored_export, and then mutate one variable per
# finding. The producer/encode tests (#16, #17) need no signatures.


def _fresh_key() -> tuple[bytes, Ed25519PrivateKey]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pub, priv


def _must_assemble(si: SigningInput, sig: bytes) -> bytes:
    """Unwrap the low-level assembler's Result in test helpers (failure is a test-setup bug). Uses
    assemble_segments (not the validating façade) so permissiveness cases can build compacts freely
    and then prove the VERIFY path (or the façade) rejects them."""
    c = assemble_segments(si, sig)
    assert c.is_ok, "assemble_segments failed in test helper"
    return c.value


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _signed_anchor_compact(anchor: BoundaryAnchorProducer, priv: Ed25519PrivateKey) -> bytes:
    si = boundary_anchor_signing_input(anchor)
    assert si.is_ok, "anchor signing input failed"
    message = f"{si.value.protected_segment.decode('ascii')}.{si.value.payload_segment.decode('ascii')}".encode("ascii")
    sig = priv.sign(message)
    return _must_assemble(si.value, sig)


Z32 = bytes(32)


def _build_archive(
    keys: list[tuple[bytes, Ed25519PrivateKey]],
    effective_ats: list[int] | None = None,
    end_anchored_at: int | None = None,
):
    """A self-contained archive builder. Produces signed anchors + transitions, encodes the row via
    encode_consumption_entry, and assembles the archive. By default effective_at increases strictly;
    pass effective_ats to override (used by the #2 non-monotone test). The builder does NOT validate
    the path, so a malformed path can be assembled and offered to verify_anchored_export to prove the
    chronology/cycle gate fires."""
    chain_id = "urn:example:chain"
    zero_prev = Z32
    row_entry = ConsumptionEntry(chain_id=chain_id, sequence=1, previous_hash=zero_prev, commitment=bytes([7] * 32))
    encoded = encode_consumption_entry(row_entry)
    assert encoded.is_ok, "row encode failed"
    row_bytes = encoded.value.bytes_
    last_hash = sha256(ROW_PREFIX, row_bytes)
    start_pub, start_priv = keys[0]
    start_compact = _signed_anchor_compact(
        BoundaryAnchorProducer(
            anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id=chain_id, sequence=0,
            chain_hash=zero_prev, key_id="k0", public_key=start_pub,
        ),
        start_priv,
    )
    transitions: list[bytes] = []
    expected_transitions: list[ExpectedKeyTransition] = []
    for i in range(len(keys) - 1):
        cur_pub, cur_priv = keys[i]
        nxt_pub, _ = keys[i + 1]
        from_fp = public_key_thumbprint_raw(cur_pub)
        to_fp = public_key_thumbprint_raw(nxt_pub)
        effective_at = effective_ats[i] if effective_ats is not None else 1500 + 500 * i
        tp = KeyTransitionProducer(
            transition_id=f"urn:example:transition:{i}", chain_id=chain_id, effective_at=effective_at,
            current_key_id=f"k{i}", current_public_key=cur_pub,
            next_key_id=f"k{i + 1}", next_public_key=nxt_pub,
        )
        si = key_transition_signing_input(tp)
        assert si.is_ok, "transition signing input failed"
        message = f"{si.value.protected_segment.decode('ascii')}.{si.value.payload_segment.decode('ascii')}".encode("ascii")
        sig = cur_priv.sign(message)
        transitions.append(_must_assemble(si.value, sig))
        expected_transitions.append(ExpectedKeyTransition(
            transition_id=f"urn:example:transition:{i}", chain_id=chain_id, effective_at=effective_at,
            current_key_id=f"k{i}", current_key_fingerprint=from_fp,
            next_key_id=f"k{i + 1}", next_key_fingerprint=to_fp,
        ))
    end_pub, end_priv = keys[-1]
    last_effective_at = expected_transitions[-1].effective_at if expected_transitions else 1000
    end_at = end_anchored_at if end_anchored_at is not None else max(last_effective_at + 1, 1000 + 500 * len(keys))
    end_compact = _signed_anchor_compact(
        BoundaryAnchorProducer(
            anchor_id="urn:example:anchor:end", anchored_at=end_at, chain_id=chain_id, sequence=1,
            chain_hash=last_hash, key_id=f"k{len(keys) - 1}", public_key=end_pub,
        ),
        end_priv,
    )
    chain = ExpectedChain(
        chain_id=chain_id, first_sequence=1, last_sequence=1, row_count=1,
        previous_hash=zero_prev, last_hash=last_hash,
    )
    input_ = AnchoredExportInput(
        rows=(row_bytes,), start_anchor=start_compact, end_anchor=end_compact,
        transitions=tuple(transitions), chain_id=chain_id, first_sequence=1, last_sequence=1, row_count=1,
        previous_hash=zero_prev, last_hash=last_hash,
    )
    start_anchor = ExpectedAnchor(
        anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id=chain_id, sequence=0,
        chain_hash=zero_prev, key_id="k0", key_fingerprint=public_key_thumbprint_raw(start_pub),
    )
    end_anchor = ExpectedAnchor(
        anchor_id="urn:example:anchor:end", anchored_at=end_at, chain_id=chain_id, sequence=1,
        chain_hash=last_hash, key_id=f"k{len(keys) - 1}", key_fingerprint=public_key_thumbprint_raw(end_pub),
    )
    # encode_anchored_export validates inputs (incl. the key path) — for the malformed-path archives
    # (#2 non-monotone / cycle), bypass encode-time validation by hand-assembling the frames.
    if effective_ats is None:
        enc = encode_anchored_export(input_, ExpectedExport(
            chain=chain, digest=bytes(32), start_anchor=start_anchor, end_anchor=end_anchor,
            transitions=tuple(expected_transitions), object_version="v1",
        ))
        assert enc.is_ok, "archive encode failed"
        archive = enc.value.archive
        digest = enc.value.digest
    else:
        archive = _hand_frame_archive(input_)
        digest = sha256(archive)
    expected = ExpectedExport(
        chain=chain, digest=digest, start_anchor=start_anchor, end_anchor=end_anchor,
        transitions=tuple(expected_transitions), object_version="v1",
    )
    key_chain = HistoricalKeyChain(
        keys=tuple(HistoricalPublicKey(key_id=f"k{i}", public_key=pub, valid_from=0, valid_before=None) for i, (pub, _) in enumerate(keys))
    )
    return {
        "archive": archive, "digest": digest, "expected": expected, "key_chain": key_chain,
        "input": input_, "chain": chain, "start_anchor": start_anchor, "end_anchor": end_anchor,
        "expected_transitions": expected_transitions,
    }


def _hand_frame_archive(input_: AnchoredExportInput) -> bytes:
    """Hand-assemble the archive byte stream (mirrors encode_anchored_export's framing) WITHOUT the
    encode-time key-path validation — used to build malformed-path archives for the #2 tests."""
    from bounded_authority_verifier.jcs import jcs_encode

    members = {
        "chain_id": JString(v=input_.chain_id.encode("utf-8")),
        "first_sequence": JInt(v=input_.first_sequence),
        "last_hash": JString(v=_b64url(input_.last_hash).encode("ascii")),
        "last_sequence": JInt(v=input_.last_sequence),
        "previous_hash": JString(v=_b64url(input_.previous_hash).encode("ascii")),
        "row_count": JInt(v=input_.row_count),
        "transition_count": JInt(v=len(input_.transitions)),
        "v": JInt(v=1),
    }
    header_bytes = jcs_encode(JObject(v=members))

    def frame(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    parts = [ARCHIVE_PREFIX, frame(header_bytes), frame(input_.start_anchor)]
    parts.extend(frame(t) for t in input_.transitions)
    parts.extend(frame(r) for r in input_.rows)
    parts.append(frame(input_.end_anchor))
    return b"".join(parts)


def test_encode_consumption_entry_rejects_genesis_row_with_nonzero_previous_hash():
    """Cross-vendor #16: encode_consumption_entry MUST reject a sequence-1 row whose previous_hash is
    not the all-zero hash (consumption_chain.ex:123 validate_entry genesis invariant). Defect: revert
    the genesis check → Ok."""
    nonzero = bytes([9] * 32)
    r = encode_consumption_entry(ConsumptionEntry(
        chain_id="urn:example:chain", sequence=1, previous_hash=nonzero, commitment=bytes(32),
    ))
    assert not r.is_ok, "sequence-1 with non-zero previous_hash must reject"
    ok = encode_consumption_entry(ConsumptionEntry(
        chain_id="urn:example:chain", sequence=1, previous_hash=Z32, commitment=bytes(32),
    ))
    assert ok.is_ok


def test_boundary_anchor_signing_input_rejects_genesis_anchor_with_nonzero_chain_hash():
    """Cross-vendor #16: boundary_anchor_signing_input MUST reject a sequence-0 (genesis) anchor whose
    chain_hash is not the all-zero hash (boundary_anchor_codec.ex:185-189 valid_anchor_binding?).
    Defect: revert the genesis check → Ok."""
    pub, _ = _fresh_key()
    nonzero = bytes([9] * 32)
    r = boundary_anchor_signing_input(BoundaryAnchorProducer(
        anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id="urn:example:chain",
        sequence=0, chain_hash=nonzero, key_id="k0", public_key=pub,
    ))
    assert not r.is_ok, "sequence-0 with non-zero chain_hash must reject"
    ok = boundary_anchor_signing_input(BoundaryAnchorProducer(
        anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id="urn:example:chain",
        sequence=0, chain_hash=Z32, key_id="k0", public_key=pub,
    ))
    assert ok.is_ok


def test_check_chain_rejects_noncanonical_row_and_sequence_zero():
    """Cross-vendor #15: check_chain MUST re-encode each row canonically and require byte-equality
    (consumption_chain.ex:96 parse_row), and reject sequence 0 (consumption_chain.ex:163 value > 0).
    Defect A: revert the canonical check → a whitespace-padded row passes. Defect B: revert the
    sequence-positive check → a sequence-0 row passes."""
    from bounded_authority_verifier.jcs import jcs_encode
    from bounded_authority_verifier.v1 import ExpectedChain

    def expected_of(chain: ChainInput) -> ExpectedChain:
        return ExpectedChain(
            chain_id=chain.chain_id, first_sequence=chain.first_sequence,
            last_sequence=chain.last_sequence, row_count=chain.row_count,
            previous_hash=chain.previous_hash, last_hash=chain.last_hash,
        )

    enc = encode_consumption_entry(ConsumptionEntry(
        chain_id="urn:example:chain", sequence=1, previous_hash=Z32, commitment=bytes([7] * 32),
    ))
    assert enc.is_ok
    canonical = enc.value.bytes_
    last_hash = enc.value.hash_
    good_chain = ChainInput(
        rows=(canonical,), chain_id="urn:example:chain", first_sequence=1, last_sequence=1, row_count=1,
        previous_hash=Z32, last_hash=last_hash,
    )
    # Control: the canonical row verifies.
    assert check_chain(good_chain, expected_of(good_chain)).is_ok
    # Defect A: a row with leading whitespace (valid JSON but NOT canonical) must reject.
    # Recompute last_hash from the padded row's ACTUAL hash so the hash-chain check passes and ONLY
    # the canonical re-encode check is the load-bearing gate (otherwise the hash mismatch rejects
    # first, masking a regression to the canonical check specifically).
    padded = b" " + canonical
    padded_last_hash = sha256(ROW_PREFIX, padded)
    padded_chain = ChainInput(
        rows=(padded,), chain_id="urn:example:chain", first_sequence=1, last_sequence=1, row_count=1,
        previous_hash=Z32, last_hash=padded_last_hash,
    )
    assert not check_chain(padded_chain, expected_of(padded_chain)).is_ok, "noncanonical (whitespace) row must reject"
    # Defect B: a sequence-0 row (hand-rolled canonical bytes) must reject.
    seq_zero = jcs_encode(JObject(v={
        "chain_id": JString(v=b"urn:example:chain"),
        "commitment": JString(v=_b64url(bytes([7] * 32)).encode("ascii")),
        "previous": JString(v=_b64url(Z32).encode("ascii")),
        "sequence": JInt(v=0),
        "v": JInt(v=1),
    }))
    seq_zero_chain = ChainInput(
        rows=(seq_zero,), chain_id="urn:example:chain", first_sequence=0, last_sequence=0, row_count=1,
        previous_hash=Z32, last_hash=sha256(ROW_PREFIX, seq_zero),
    )
    assert not check_chain(seq_zero_chain, expected_of(seq_zero_chain)).is_ok, "sequence-0 row must reject"


def test_encode_anchored_export_rejects_transition_count_over_bound():
    """Cross-vendor #17: encode_anchored_export MUST validate inputs before framing — at minimum the
    transition count <= key_transitions bound (256). The SDK previously accepted 257 transitions.
    Defect: revert the bound check -> encode returns Ok.

    FIX-D delta-review FINDING 2: supply 257 matching ExpectedKeyTransition entries over a 258-key
    chain so the count-mismatch check passes and the key_transitions=256 BOUND check is the
    load-bearing gate (otherwise transitions=() makes count-mismatch fire first). The 258-key path is
    chronology-clean (distinct keys, strictly-increasing effective_at, no fingerprint cycle)."""
    keys = [_fresh_key() for _ in range(258)]
    row_entry = ConsumptionEntry(chain_id="urn:example:chain", sequence=1, previous_hash=Z32, commitment=bytes(32))
    encoded = encode_consumption_entry(row_entry)
    assert encoded.is_ok
    row_bytes = encoded.value.bytes_
    last_hash = encoded.value.hash_
    start_pub, start_priv = keys[0]
    end_pub, end_priv = keys[257]
    start_compact = _signed_anchor_compact(BoundaryAnchorProducer(
        anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id="urn:example:chain",
        sequence=0, chain_hash=Z32, key_id="k0", public_key=start_pub,
    ), start_priv)
    end_compact = _signed_anchor_compact(BoundaryAnchorProducer(
        anchor_id="urn:example:anchor:end", anchored_at=100000, chain_id="urn:example:chain",
        sequence=1, chain_hash=last_hash, key_id="k257", public_key=end_pub,
    ), end_priv)
    expected_transitions = tuple(
        ExpectedKeyTransition(
            transition_id=f"urn:example:t:{i}", chain_id="urn:example:chain", effective_at=2000 + i,
            current_key_id=f"k{i}", current_key_fingerprint=public_key_thumbprint_raw(keys[i][0]),
            next_key_id=f"k{i + 1}", next_key_fingerprint=public_key_thumbprint_raw(keys[i + 1][0]),
        )
        for i in range(257)
    )
    chain = ExpectedChain(chain_id="urn:example:chain", first_sequence=1, last_sequence=1, row_count=1, previous_hash=Z32, last_hash=last_hash)
    r = encode_anchored_export(
        AnchoredExportInput(
            rows=(row_bytes,), start_anchor=start_compact, end_anchor=end_compact,
            transitions=tuple(b"x" for _ in range(257)), chain_id="urn:example:chain",
            first_sequence=1, last_sequence=1, row_count=1, previous_hash=Z32, last_hash=last_hash,
        ),
        ExpectedExport(
            chain=chain, digest=bytes(32),
            start_anchor=ExpectedAnchor(anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id="urn:example:chain", sequence=0, chain_hash=Z32, key_id="k0", key_fingerprint=public_key_thumbprint_raw(start_pub)),
            end_anchor=ExpectedAnchor(anchor_id="urn:example:anchor:end", anchored_at=100000, chain_id="urn:example:chain", sequence=1, chain_hash=last_hash, key_id="k257", key_fingerprint=public_key_thumbprint_raw(end_pub)),
            transitions=expected_transitions, object_version="v1",
        ),
    )
    assert not r.is_ok, "257 transitions must reject (over the key_transitions=256 bound)"


def test_encode_anchored_export_rejects_misbound_start_anchor():
    """Cross-vendor #17 (anchor binding): encode_anchored_export MUST reject when the start anchor's
    sequence != chain.first_sequence - 1 (anchored_export_codec.ex:364). Defect: revert the binding
    check → encode returns Ok with a mis-bound anchor."""
    pub, priv = _fresh_key()
    built = _build_archive([(pub, priv)])
    bad_expected = ExpectedExport(
        chain=built["chain"], digest=built["digest"],
        start_anchor=ExpectedAnchor(**{**built["start_anchor"].__dict__, "sequence": 5}),
        end_anchor=built["end_anchor"], transitions=built["expected"].transitions, object_version="v1",
    )
    r = encode_anchored_export(built["input"], bad_expected)
    assert not r.is_ok, "start anchor sequence != first_sequence-1 must reject"


def test_verify_anchored_export_accepts_valid_one_key_zero_transition_archive():
    """Cross-vendor #3: a valid 1-key / 0-transition archive MUST verify
    (anchored_export_codec.ex:94-99 validate_historical_key_shapes accepts keys == transitions+1 with
    NO minimum). The SDK previously gated on keys.length < 2 and falsely rejected it. Defect: revert
    to the `< 2` gate → this valid archive returns Err."""
    reset_census()
    built = _build_archive([_fresh_key()])
    r = verify_anchored_export(
        ArchivedObject(chunks=(built["archive"],), version="v1"),
        built["key_chain"], built["expected"],
    )
    assert r.is_ok, "a valid 1-key/0-transition archive must verify"
    assert r.value.transition_count == 0


def test_verify_anchored_export_rejects_zero_key_chain_fail_closed():
    """Cross-vendor re-review F2: a zero-key key chain MUST fail closed (Err), not raise
    IndexError on key_chain.keys[0]. The length check (keys == transitions+1) must fire BEFORE the
    keys[0] deref. Defect: revert the length-check-before-deref ordering → IndexError propagates."""
    from bounded_authority_verifier.v1 import HistoricalKeyChain

    reset_census()
    built = _build_archive([_fresh_key()])
    empty_chain = HistoricalKeyChain(keys=())
    r = verify_anchored_export(
        ArchivedObject(chunks=(built["archive"],), version="v1"),
        empty_chain, built["expected"],
    )
    assert not r.is_ok, "zero-key chain must reject (keys != transitions+1), fail closed"


def test_verify_anchored_export_rejects_bad_chunk_lists():
    """Cross-vendor #18: verify_anchored_export MUST validate the chunk list BEFORE concatenation
    (anchored_export_codec.ex:333-342 validate_chunks): reject empty chunks, reject chunk count >=
    archive_chunks, reject total > archive_bytes. Defect: revert _validate_chunks → these pass."""
    reset_census()
    built = _build_archive([_fresh_key()])
    # Empty chunk in the list.
    with_empty = ArchivedObject(chunks=(built["archive"], b""), version="v1")
    assert not verify_anchored_export(with_empty, built["key_chain"], built["expected"]).is_ok, "empty chunk must reject"
    # Too many chunks: archive_chunks bound is 65796 and the reference accepts UP TO 65796 inclusive
    # (validate_chunks guard `count < archive_chunks` on the recursive clause, start 0). The count
    # guard itself fires only at 65797 (> archive_chunks). At exactly 65796 one-byte chunks the count
    # guard PASSES (65796 > 65796 is false), so a rejection there is the digest check, not the count
    # guard — vacuous w.r.t. the closure it claims to prove. Feed 65797 so the count guard is the
    # falsifier.
    too_many = ArchivedObject(chunks=tuple(b"\x01" for _ in range(65797)), version="v1")
    assert not verify_anchored_export(too_many, built["key_chain"], built["expected"]).is_ok, "chunk count over bound must reject"
    # Control: a single-chunk split of the valid archive still verifies.
    assert verify_anchored_export(ArchivedObject(chunks=(built["archive"],), version="v1"), built["key_chain"], built["expected"]).is_ok


def test_verify_anchored_export_rejects_non_monotonic_rollover():
    """Cross-vendor #2: verify_anchored_export MUST enforce rollover chronology (effective_at strictly
    increasing) and reject fingerprint cycles (anchored_export_codec.ex:516-572). The signed
    transitions are built with the actual non-monotonic effective_at sequence (each compact
    individually valid), so the chronology check is the load-bearing gate. Defect: revert
    _validate_key_path + the chronology loop → this archive wrongly verifies."""
    reset_census()
    a = _fresh_key()
    b = _fresh_key()
    c = _fresh_key()
    valid = _build_archive([a, b, c])
    assert verify_anchored_export(ArchivedObject(chunks=(valid["archive"],), version="v1"), valid["key_chain"], valid["expected"]).is_ok, "control: valid 3-key archive verifies"
    # transition[1].effective_at (1400) < transition[0].effective_at (1500): each compact is validly
    # signed with its own effective_at, so _verify_transition_compact passes; only chronology rejects.
    non_mono = _build_archive([a, b, c], effective_ats=[1500, 1400], end_anchored_at=2000)
    assert not verify_anchored_export(ArchivedObject(chunks=(non_mono["archive"],), version="v1"), non_mono["key_chain"], non_mono["expected"]).is_ok, "non-monotonic effective_at must reject"
    # Strict-`>` boundary: EQUAL consecutive effective_at must also reject (strictly_after? is `>`,
    # not `>=`; anchored_export_codec.ex:722). Each compact is individually valid; only the strict
    # chronology check rejects.
    equal_at = _build_archive([a, b, c], effective_ats=[1500, 1500], end_anchored_at=2000)
    assert not verify_anchored_export(ArchivedObject(chunks=(equal_at["archive"],), version="v1"), equal_at["key_chain"], equal_at["expected"]).is_ok, "equal consecutive effective_at must reject (strict >)"


def test_verify_anchored_export_rejects_fingerprint_cycle():
    """Cross-vendor #2 (cycle): a key-path where a fingerprint repeats (A→B→A) must reject. Built with
    a REAL repeated key (positions 0 and 2 reuse key A) so each transition (A→B, B→A) is individually
    valid, and the cycle check is the load-bearing gate. Defect: revert _validate_key_path → verifies."""
    reset_census()
    a = _fresh_key()
    b = _fresh_key()
    cyclic = _build_archive([a, b, a], effective_ats=[1500, 2000], end_anchored_at=3000)
    assert not verify_anchored_export(ArchivedObject(chunks=(cyclic["archive"],), version="v1"), cyclic["key_chain"], cyclic["expected"]).is_ok, "fingerprint cycle A→B→A must reject"


# === BAP-09 #10/#11 cross-vendor remediation — caller-supplied bounds threaded through verify/decode ===
# The reference resolves Bounds.coerce(expected.bounds) once per entry point and threads the result
# into EVERY bound-sensitive check (runtime.ex:186,204; consumption_chain.ex check_chain;
# anchored_export_codec.ex:84-185): valid_key_id?(kid, bounds.kid_bytes), Json.decode(bytes, bounds),
# valid_identifier?(iss/grant_id, bounds), decode_audiences(aud, bounds), operations(ops, bounds),
# validate_chunks / parse_archive frame reads, etc. The SDK previously passed bounds ONLY to
# parse_compact and hardcoded MAXIMUM_BOUNDS in every subsequent validator, so a caller tightening had
# no effect. Each test below proves a tightening now rejects at the named gate. Defect: revert the
# threading (any helper back to MAXIMUM_BOUNDS, or the bounds param removed) → the named deny goes
# GREEN (Err→Ok regression), proving the test is red-capable.
#
# The falsifiable case: a grant whose kid is 13 bytes ("issuer-123456") is valid at MAX (kid_bytes
# 128), but MUST be rejected under bounds_new({"kid_bytes": 5}) via valid_key_id? (the reference's
# decode_grant(grant, %{kid_bytes: 5}) rejects it). Each test drives one entry point.

# A typed JSON-null cast-arguments value (the Tagged null variant carries no `v`).
_NULL_ARGS: Tagged = json_decode(b"null")


def _signed_grant(kid: str = "issuer-123456"):
    """Build a real Ed25519-signed grant with a chosen kid (13 bytes by default). Returns the compact
    + the issuer key material needed for verify_grant / check_envelope."""
    issuer_pub, issuer_priv = _fresh_key()
    holder_pub, _ = _fresh_key()
    holder_fp = public_key_thumbprint_raw(holder_pub)
    grant = GrantProducer(
        key_id=kid, issuer="https://issuer.example.test", grant_id="urn:example:grant:1",
        audiences=("https://resource.example.test",), issued_at=1000, not_before=1000, expires_at=2000,
        holder_thumbprint=_b64url(holder_fp),
        operations=(OperationInput(name="read", selectors=("all",)),),
    )
    si = grant_signing_input(grant)
    assert si.is_ok, "grant signing input failed"
    message = f"{si.value.protected_segment.decode('ascii')}.{si.value.payload_segment.decode('ascii')}".encode("ascii")
    sig = issuer_priv.sign(message)
    return {
        "compact": _must_assemble(si.value, sig),
        "issuer": TrustedIssuer(key_id=kid, public_key=issuer_pub),
        "issuer_pub": issuer_pub, "issuer_priv": issuer_priv,
        "holder_pub": holder_pub, "holder_fp": holder_fp,
    }


def _signed_proof(grant_compact: bytes, holder_pub: bytes, holder_priv: Ed25519PrivateKey) -> bytes:
    """Build a valid proof binding to the grant (holder signs). Drives the check_envelope path."""
    proof = ProofProducer(
        holder_public_key=holder_pub,
        proof_id="urn:example:proof:1", method="POST", target_uri="https://resource.example.test/invoke",
        issued_at=1400, invocation_id="550e8400-e29b-41d4-a716-446655440000", operation="read",
        grant_compact=grant_compact, cast_arguments=_NULL_ARGS,
    )
    si = proof_signing_input(proof)
    assert si.is_ok, "proof signing input failed"
    message = f"{si.value.protected_segment.decode('ascii')}.{si.value.payload_segment.decode('ascii')}".encode("ascii")
    sig = holder_priv.sign(message)
    return _must_assemble(si.value, sig)


def test_decode_grant_honors_caller_bounds():
    """#10/#11: decode_grant MUST thread caller-supplied bounds into _require_kid (valid_key_id?). A
    grant with a 13-byte kid is accepted at MAX, rejected under kid_bytes=5. Defect: revert
    _require_kid to MAXIMUM_BOUNDS → the tightened call returns Ok."""
    g = _signed_grant()
    # Control: no bounds (MAX) → the 13-byte kid is accepted.
    assert decode_grant(g["compact"]).is_ok, "13-byte kid must be accepted at MAX"
    # Tightened: kid_bytes=5 → the 13-byte kid must be rejected (the reference's valid_key_id? gate).
    assert not decode_grant(g["compact"], bounds_new({"kid_bytes": 5})).is_ok, "kid_bytes=5 must reject a 13-byte kid"


def test_decode_grant_threads_caller_bounds_into_selector_decode():
    """#10 delta-review F1: decode_grant MUST thread caller bounds into parse_selector (the reference's
    selector/2 enforces one_of_values, path_segments, selector value node bounds). A grant with a
    one_of selector of 2 values is accepted at MAX, rejected under one_of_values=1. Defect: revert
    the parse_selector(s) call to default bounds → the tightened call returns Ok."""
    issuer_pub, issuer_priv = _fresh_key()
    holder_pub, _ = _fresh_key()
    holder_fp = public_key_thumbprint_raw(holder_pub)
    grant = GrantProducer(
        key_id="k1", issuer="https://issuer.example.test", grant_id="urn:example:grant:1",
        audiences=("https://resource.example.test",), issued_at=1000, not_before=1000, expires_at=2000,
        holder_thumbprint=_b64url(holder_fp),
        operations=(OperationInput(name="read", selectors=(
            {"kind": "one_of", "path": ("x",), "values": (JInt(v=1), JInt(v=2))},
        ),),),
    )
    si = grant_signing_input(grant)
    assert si.is_ok, "grant signing input failed"
    message = f"{si.value.protected_segment.decode('ascii')}.{si.value.payload_segment.decode('ascii')}".encode("ascii")
    compact = _must_assemble(si.value, issuer_priv.sign(message))
    # Control: at MAX, a one_of with 2 values is accepted.
    assert decode_grant(compact).is_ok, "one_of with 2 values must be accepted at MAX"
    # Tightened: one_of_values=1 → the 2-value selector must be rejected (parse_selector threads bounds).
    assert not decode_grant(compact, bounds_new({"one_of_values": 1})).is_ok, "one_of_values=1 must reject a 2-value selector"


def test_verify_grant_honors_caller_bounds():
    """#10/#11: verify_grant MUST thread ExpectedGrant.bounds into _require_kid (valid_key_id?). The
    grant is validly signed, so the only load-bearing gate under the tightening is the kid bound.
    Defect: revert verify_grant's bounds threading → the tightened call returns Ok."""
    reset_census()
    g = _signed_grant()
    expected_max = ExpectedGrant(
        issuer="https://issuer.example.test", audience="https://resource.example.test",
        evaluation_time=1500, clock_skew=60,
    )
    # Control: no bounds (MAX) → verifies.
    assert verify_grant(g["compact"], g["issuer"], expected_max).is_ok, "13-byte kid must verify at MAX"
    # Tightened: kid_bytes=5 → rejected via the kid gate (signature would otherwise verify).
    expected_tight = ExpectedGrant(
        issuer="https://issuer.example.test", audience="https://resource.example.test",
        evaluation_time=1500, clock_skew=60, bounds=bounds_new({"kid_bytes": 5}),
    )
    assert not verify_grant(g["compact"], g["issuer"], expected_tight).is_ok, "kid_bytes=5 must reject a 13-byte kid"


def test_check_envelope_honors_caller_bounds():
    """#10/#11: check_envelope MUST thread ExpectedRequest.bounds into the grant header parse. The
    grant + proof are both validly signed; the only load-bearing gate under the tightening is the
    grant kid bound. Defect: revert check_envelope's bounds threading → the tightened call returns Ok."""
    reset_census()
    issuer_pub, issuer_priv = _fresh_key()
    holder_pub, holder_priv = _fresh_key()
    holder_fp = public_key_thumbprint_raw(holder_pub)
    grant = GrantProducer(
        key_id="issuer-123456", issuer="https://issuer.example.test", grant_id="urn:example:grant:1",
        audiences=("https://resource.example.test",), issued_at=1000, not_before=1000, expires_at=2000,
        holder_thumbprint=_b64url(holder_fp),
        operations=(OperationInput(name="read", selectors=("all",)),),
    )
    gsi = grant_signing_input(grant)
    assert gsi.is_ok
    gmsg = f"{gsi.value.protected_segment.decode('ascii')}.{gsi.value.payload_segment.decode('ascii')}".encode("ascii")
    grant_compact = _must_assemble(gsi.value, issuer_priv.sign(gmsg))
    proof_compact = _signed_proof(grant_compact, holder_pub, holder_priv)
    base = ExpectedRequest(
        trusted_issuer=TrustedIssuer(key_id="issuer-123456", public_key=issuer_pub),
        issuer="https://issuer.example.test", audience="https://resource.example.test",
        method="POST", target_uri="https://resource.example.test/invoke",
        invocation_id="550e8400-e29b-41d4-a716-446655440000", operation="read",
        cast_arguments=_NULL_ARGS, evaluation_time=1500, clock_skew=60, proof_max_age=300,
        nonce=NonceNotRequired(),
    )
    # Control: no bounds (MAX) → envelope verifies.
    assert check_envelope(grant_compact, proof_compact, base).is_ok, "13-byte kid must verify at MAX"
    # Tightened: kid_bytes=5 → rejected via the grant kid gate.
    tight = ExpectedRequest(
        trusted_issuer=TrustedIssuer(key_id="issuer-123456", public_key=issuer_pub),
        issuer="https://issuer.example.test", audience="https://resource.example.test",
        method="POST", target_uri="https://resource.example.test/invoke",
        invocation_id="550e8400-e29b-41d4-a716-446655440000", operation="read",
        cast_arguments=_NULL_ARGS, evaluation_time=1500, clock_skew=60, proof_max_age=300,
        nonce=NonceNotRequired(), bounds=bounds_new({"kid_bytes": 5}),
    )
    assert not check_envelope(grant_compact, proof_compact, tight).is_ok, "kid_bytes=5 must reject a 13-byte kid"


def test_expected_structs_bounds_absent_defaults_to_max():
    """#11 control: bounds absent on every Expected* MUST default to MAX (the conformance runner
    constructs Expected* without bounds; a missing default would break 283/283). The 13-byte kid grant
    verifies at MAX via every entry point that takes an Expected*."""
    reset_census()
    g = _signed_grant()
    eg = ExpectedGrant(
        issuer="https://issuer.example.test", audience="https://resource.example.test",
        evaluation_time=1500, clock_skew=60,
    )
    assert verify_grant(g["compact"], g["issuer"], eg).is_ok
    assert decode_grant(g["compact"]).is_ok



def test_assemble_segments_and_request_digest_return_result_contract():
    """The low-level assembler (assemble_segments) + request_digest return Ok/Err (the Result
    contract), not raw values + throw. Invalid inputs return Err; a minimal well-shaped input
    returns Ok. Mirrors the Elixir {:ok,_}|{:error,:invalid}. The PUBLIC assemble_compact façade
    adds per-kind content validation (tested separately)."""
    # assemble_segments: bad kind -> Err (not raise).
    bad = assemble_segments(
        SigningInput(kind="bogus", protected_segment=b"a", payload_segment=b"b"),  # type: ignore[arg-type]
        b"\x00" * 64,
    )
    assert not bad.is_ok, "bad kind must return Err"
    # assemble_segments: short signature -> Err.
    short = assemble_segments(
        SigningInput(kind="grant", protected_segment=b"a", payload_segment=b"b"),
        b"\x00" * 32,
    )
    assert not short.is_ok, "short signature must return Err"
    # assemble_segments: minimal well-shaped input -> Ok (content is NOT validated here).
    valid = assemble_segments(
        SigningInput(kind="grant", protected_segment=b"a", payload_segment=b"b"),
        b"\x00" * 64,
    )
    assert valid.is_ok and isinstance(valid.value, bytes)
    # request_digest: valid -> Ok (raw 32 bytes).
    rd = request_digest("read", JInt(v=1))
    assert rd.is_ok and len(rd.value) == 32
    # request_digest: invalid (empty operation) -> Err.
    rd_bad = request_digest("", JInt(v=1))
    assert not rd_bad.is_ok, "empty operation must return Err"


def test_check_envelope_rejects_bool_temporal_context():
    """Cross-vendor re-review F4: Python's isinstance(True, int) is True, so a bool-typed
    evaluation_time/clock_skew/proof_max_age passed the isinstance(x, int) check. The reference
    requires is_integer; booleans are not integers. Defect: revert _is_int to isinstance(x, int) ->
    bool values pass the guard."""
    from bounded_authority_verifier.v1 import ExpectedRequest, TrustedIssuer, check_envelope

    junk = b"aaa.bbb.ccc"
    issuer = TrustedIssuer(key_id=b"k", public_key=b"\x00" * 32)
    base = {
        "issuer": "x", "audience": "x", "method": "GET", "target_uri": "https://x.example/",
        "invocation_id": "550e8400-e29b-41d4-a716-446655440000", "operation": "read",
        "cast_arguments": {"t": "null", "v": None}, "nonce": ("not_required",),
    }

    def call(**overrides):
        return check_envelope(junk, junk, ExpectedRequest(trusted_issuer=issuer, **{**base, **overrides}))

    # bool evaluation_time -> reject (isinstance(True, int) is True in Python, but bool is not int).
    assert not call(evaluation_time=True, clock_skew=0, proof_max_age=300).is_ok
    assert not call(evaluation_time=False, clock_skew=0, proof_max_age=300).is_ok
    # bool clock_skew -> reject.
    assert not call(evaluation_time=150, clock_skew=True, proof_max_age=300).is_ok
    # bool proof_max_age -> reject.
    assert not call(evaluation_time=150, clock_skew=0, proof_max_age=True).is_ok


def test_forged_widening_bounds_rejected_at_entry_points():
    """Cross-vendor F2: a hand-crafted Bounds with a widening override bypasses bounds_new; resolve()
    trusts it. Every entry point must re-validate (mirrors reference Bounds.coerce). Defect: revert
    coerce_bounds -> a forged widening is honored."""
    reset_census()
    g = _signed_grant()
    forged = Bounds({"compact_bytes": 1000000})  # > MAXIMA.compact_bytes (65536)
    assert forged.resolve("compact_bytes") == 1000000, "control: forged override honored by resolve()"
    eg = ExpectedGrant(
        issuer="https://issuer.example.test", audience="https://resource.example.test",
        evaluation_time=1500, clock_skew=60, bounds=forged,
    )
    assert not verify_grant(g["compact"], g["issuer"], eg).is_ok, "forged widening bounds must reject"


def test_jcs_encode_rejects_non_integer_int_tag():
    """Cross-vendor F3: a non-integer int-tag value (1.5) or a bool must fail closed at jcs_encode
    (reference guard `when is_integer(value)`, jcs.ex:38). Defect: remove the isinstance check ->
    JInt(1.5) emits b'1.5', JInt(True) emits b'True'."""
    from bounded_authority_verifier.jcs import jcs_encode

    assert jcs_encode(JInt(2)) == b"2", "control: integer int-tag encodes"
    with pytest.raises(InvalidError):
        jcs_encode(JInt(1.5))  # type: ignore[arg-type]
    with pytest.raises(InvalidError):
        jcs_encode(JInt(True))  # type: ignore[arg-type]


def test_jcs_encode_rejects_invalid_utf8_string():
    """Cross-vendor (JCS UTF-8): a programmatically-built JString with invalid UTF-8 must fail closed
    (reference String.valid?, jcs.ex:58), not raise UnicodeDecodeError past the Result contract.
    Defect: remove the is_valid_utf8 gate -> invalid bytes reach utf8_str -> UnicodeDecodeError."""
    from bounded_authority_verifier.jcs import jcs_encode

    with pytest.raises(InvalidError):
        jcs_encode(JString(b"\x80\x81"))


def test_untrusted_key_locator_accepts_empty_payload_signature_segments():
    """Cross-vendor (key-locator empty segments): the reference (v1.ex:24) accepts empty
    payload/signature segments — it decodes ONLY the protected segment. Defect: re-add the empty-
    segment rejection -> RED."""
    reset_census()
    g = _signed_grant()
    protected_seg = g["compact"].split(b".")[0]
    empty_ps = protected_seg + b".."
    r = untrusted_key_locator(empty_ps)
    assert r.is_ok, "empty payload+signature segments must be accepted (reference decodes protected only)"
    assert r.value.key_id == g["issuer"].key_id


def test_verify_anchored_export_rejects_nested_bounds_mismatch():
    """Cross-vendor (nested bounds pinning): the reference pins every nested bounds == top-level
    (anchored_export_codec.ex:352-354). A tightened top + nested default-MAX must reject. Defect:
    remove _require_bounds_equal -> a tightened top silently overrides nested."""
    reset_census()
    built = _build_archive([_fresh_key()])
    tightened = ExpectedExport(
        chain=built["expected"].chain, start_anchor=built["expected"].start_anchor,
        end_anchor=built["expected"].end_anchor, transitions=built["expected"].transitions,
        digest=built["expected"].digest, object_version=built["expected"].object_version,
        bounds=bounds_new({"identifier_bytes": 4}),
    )
    assert not verify_anchored_export(built["archive"], built["key_chain"], tightened).is_ok, \
        "nested bounds absent under a tightened top must reject (reference pin)"


def test_check_chain_rejects_genesis_previous_hash_mismatch():
    """Cross-vendor F4: genesis chain must not return an unchecked chain.previous_hash as a verified
    fact. The SDK now validates chain.previous_hash == expected.previous_hash in BOTH cases. Defect:
    revert the equality check + return chain.previous_hash -> a forged genesis input flows through."""
    reset_census()
    zero = bytes(32)
    chain_id = "ba://chain-f4"
    commitment = sha256(b"commitment-f4")
    row0 = encode_consumption_entry(ConsumptionEntry(chain_id=chain_id, sequence=1, previous_hash=zero, commitment=commitment))
    assert row0.is_ok
    last_hash = sha256(ROW_PREFIX, row0.value.bytes_)
    chain = ChainInput(rows=(row0.value.bytes_,), chain_id=chain_id, first_sequence=1, last_sequence=1,
                       row_count=1, previous_hash=zero, last_hash=last_hash)
    expected = ExpectedChain(chain_id=chain_id, first_sequence=1, last_sequence=1, row_count=1,
                             previous_hash=zero, last_hash=last_hash)
    assert check_chain(chain, expected).is_ok, "control: genesis chain with matching previous_hash verifies"
    forged = ChainInput(rows=chain.rows, chain_id=chain_id, first_sequence=1, last_sequence=1,
                        row_count=1, previous_hash=sha256(b"forged"), last_hash=last_hash)
    assert not check_chain(forged, expected).is_ok, \
        "genesis chain.previous_hash != expected.previous_hash must reject (F4)"


def test_malformed_trusted_issuer_fails_closed():
    """Cross-vendor (fail-closed shallow): a malformed trusted issuer (missing public_key/key_id) must
    fail closed as Err, not raise AttributeError past the Result contract. Defect: revert the shape
    check -> AttributeError."""
    reset_census()
    g = _signed_grant()
    eg = ExpectedGrant(issuer="https://issuer.example.test", audience="https://resource.example.test",
                       evaluation_time=1500, clock_skew=60)
    # A TrustedIssuer missing public_key/key_id: must return Err, not raise.
    bad = TrustedIssuer.__new__(TrustedIssuer)  # bypass __init__ -> no attributes
    assert not verify_grant(g["compact"], bad, eg).is_ok, "malformed trusted issuer must fail closed"
    er = ExpectedRequest(trusted_issuer=bad, issuer="https://issuer.example.test",
                         audience="https://resource.example.test", method="POST",
                         target_uri="https://resource.example.test/invoke", invocation_id="i",
                         operation="read", cast_arguments=JNull(),  # type: ignore[arg-type]
                         evaluation_time=1500, clock_skew=60, proof_max_age=300, nonce=NonceNotRequired())
    assert not check_envelope(g["compact"], g["compact"], er).is_ok, "malformed trusted issuer must fail closed (check_envelope)"


# === BAP-09 derisk: cross-vendor reference-divergence tripwires (TS/Python derisk, pre-BAP-07) ===

# The corpus grant/proof protected headers (typ=ba+cap / typ=dpop+jwt) — used by the #11 façade tests.
_DERISK_GRANT_PROTECTED = b"eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9"
_DERISK_PROOF_PROTECTED = (
    b"eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ilcxczd5RTlmR0RNQmJtZHBx"
    b"WVZ3UTFoRENYdHpPZVBVRDNmSWYxdDdGRGsifSwidHlwIjoiZHBvcCtqd3QifQ"
)


def test_proof_signing_input_rejects_malformed_grant_compact():
    """#9: proof_signing_input MUST scan the grant compact (shape+size, not canonicity) before hashing
    it into ath (compact_jws.ex:16-27 scan gates ath/hash). A 2-segment grant compact is not a valid
    compact JWS; the producer must reject it rather than embed sha256(garbage) in the proof."""
    pub = _fresh_key()[0]
    proof = ProofProducer(
        holder_public_key=pub,
        proof_id="urn:example:proof:1", method="POST", target_uri="https://resource.example.test/invoke",
        issued_at=1400, invocation_id="550e8400-e29b-41d4-a716-446655440000", operation="read",
        grant_compact=b"aaa.bbb",  # one dot — not a 3-segment compact
        cast_arguments=JNull(),
    )
    r = proof_signing_input(proof)
    assert not r.is_ok, "malformed (2-segment) grant compact must be rejected"


def test_encode_anchored_export_rejects_when_archive_chunks_exceeded():
    """#4: encode_anchored_export MUST enforce archive_chunks (frame count) during encode
    (anchored_export_codec.ex:69 validate_chunks), not only archive_bytes. A 2-key archive frames
    into 6 chunks (prefix+header+start+transition+row+end); tightening archive_chunks to 5 rejects
    even though archive_bytes is still ample."""
    built = _build_archive([_fresh_key(), _fresh_key()])  # 1 transition + 1 row → 6 frames
    r = encode_anchored_export(
        built["input"],
        ExpectedExport(
            chain=built["chain"], digest=built["digest"],
            start_anchor=built["start_anchor"], end_anchor=built["end_anchor"],
            transitions=built["expected"].transitions, object_version="v1",
            bounds=bounds_new({"archive_chunks": 5}),
        ),
    )
    assert not r.is_ok, "6 frames > archive_chunks=5 must reject"


def test_assemble_compact_facade_rejects_invalid_signing_input():
    """#11: the public assemble_compact façade MUST validate the signing input (kind↔typ, segment
    bounds, base64url payload) and re-parse the composed compact per kind (runtime.ex:151
    validate_assembled_compact). It must NOT assemble a mislabeled or malformed compact."""
    sig = b"\x00" * 64
    # kind/typ mismatch: grant kind but a proof (dpop+jwt) protected header.
    r = assemble_compact(SigningInput(kind="grant", protected_segment=_DERISK_PROOF_PROTECTED, payload_segment=b"e30"), sig)
    assert not r.is_ok, "kind/typ mismatch must reject"
    # oversized protected segment (> encoded_segment_bytes=32768).
    r = assemble_compact(SigningInput(kind="grant", protected_segment=b"A" * 32769, payload_segment=b"e30"), sig)
    assert not r.is_ok, "oversized protected segment must reject"
    # non-base64url payload segment.
    r = assemble_compact(SigningInput(kind="grant", protected_segment=_DERISK_GRANT_PROTECTED, payload_segment=b"not-valid!@#"), sig)
    assert not r.is_ok, "non-base64url payload must reject"
    # structurally-invalid grant payload (empty object) — the per-kind re-parse rejects it.
    r = assemble_compact(SigningInput(kind="grant", protected_segment=_DERISK_GRANT_PROTECTED, payload_segment=b"e30"), sig)
    assert not r.is_ok, "malformed grant payload must reject (re-parse)"


def test_assemble_compact_facade_rejects_numeric_iss():
    """#11 (codex): the grant re-parse must validate FIELD values, not just the closed key-set. A
    payload with every required key + a numeric iss passes the structural validator but must be
    rejected by the full decode_grant re-parse."""
    json_payload = (
        b'{"v":1,"iss":123,"jti":"urn:example:g:1","aud":["https://resource.example.test"],'
        b'"iat":1000,"nbf":1000,"exp":2000,"cnf":{"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},'
        b'"operations":[{"name":"read","selectors":[{"kind":"all"}]}]}'
    )
    payload_segment = base64.urlsafe_b64encode(json_payload).rstrip(b"=")
    r = assemble_compact(
        SigningInput(kind="grant", protected_segment=_DERISK_GRANT_PROTECTED, payload_segment=payload_segment),
        b"\x00" * 64,
    )
    assert not r.is_ok, "numeric iss must reject (field re-parse)"


def test_assemble_compact_facade_rejects_noncanonical_anchor():
    """Canonical-form (boundary_anchor_codec.ex:95-96,118-119): the protected AND payload segments of
    an anchor compact must be the exact JCS encoding. The façade (and verify) now enforce this on
    both segments — without the check the façade accepts the non-canonical compact."""
    import json as _json

    def _reorder(segment_text: bytes) -> bytes:
        # segment_text is base64url TEXT; decode, reverse the JSON member order (values unchanged),
        # re-encode — non-canonical bytes, same valid fields.
        pad = b"=" * (-len(segment_text) % 4)
        obj = _json.loads(base64.urlsafe_b64decode(segment_text + pad).decode("utf-8"))
        keys = list(reversed(list(obj.keys())))
        body = "{" + ",".join(_json.dumps(k) + ":" + _json.dumps(obj[k]) for k in keys) + "}"
        return base64.urlsafe_b64encode(body.encode("utf-8")).rstrip(b"=")

    pub = _fresh_key()[0]
    si = boundary_anchor_signing_input(BoundaryAnchorProducer(
        anchor_id="urn:example:anchor:start", anchored_at=1000, chain_id="urn:example:chain",
        sequence=0, chain_hash=Z32, key_id="archive-a", public_key=pub,
    ))
    assert si.is_ok, "anchor signing input failed"
    canon_header, canon_payload = si.value.protected_segment, si.value.payload_segment
    sig = b"\x00" * 64
    # Non-canonical protected header, canonical payload → reject (header canonical check).
    r = assemble_compact(
        SigningInput(kind="boundary_anchor", protected_segment=_reorder(canon_header), payload_segment=canon_payload), sig)
    assert not r.is_ok, "non-canonical anchor header must reject"
    # Canonical header, non-canonical payload → reject (payload canonical check).
    r = assemble_compact(
        SigningInput(kind="boundary_anchor", protected_segment=canon_header, payload_segment=_reorder(canon_payload)), sig)
    assert not r.is_ok, "non-canonical anchor payload must reject"


def test_assemble_compact_facade_rejects_noncanonical_transition():
    """Canonical-form (key_transition_codec.ex:127-128,151-152): the protected AND payload segments
    of a transition compact must be the exact JCS encoding. Symmetric to the anchor test above —
    proves the transition canonical checks fire (without them the façade accepts the non-canonical
    compact)."""
    import json as _json

    def _reorder(segment_text: bytes) -> bytes:
        pad = b"=" * (-len(segment_text) % 4)
        obj = _json.loads(base64.urlsafe_b64decode(segment_text + pad).decode("utf-8"))
        keys = list(reversed(list(obj.keys())))
        body = "{" + ",".join(_json.dumps(k) + ":" + _json.dumps(obj[k]) for k in keys) + "}"
        return base64.urlsafe_b64encode(body.encode("utf-8")).rstrip(b"=")

    cur_pub = _fresh_key()[0]
    nxt_pub = _fresh_key()[0]
    si = key_transition_signing_input(KeyTransitionProducer(
        transition_id="urn:example:transition:a-b", chain_id="urn:example:chain", effective_at=1500,
        current_key_id="anchor-a", current_public_key=cur_pub,
        next_key_id="anchor-b", next_public_key=nxt_pub,
    ))
    assert si.is_ok, "transition signing input failed"
    canon_header, canon_payload = si.value.protected_segment, si.value.payload_segment
    sig = b"\x00" * 64
    # Non-canonical protected header, canonical payload → reject (header canonical check).
    r = assemble_compact(
        SigningInput(kind="key_transition", protected_segment=_reorder(canon_header), payload_segment=canon_payload), sig)
    assert not r.is_ok, "non-canonical transition header must reject"
    # Canonical header, non-canonical payload → reject (payload canonical check).
    r = assemble_compact(
        SigningInput(kind="key_transition", protected_segment=canon_header, payload_segment=_reorder(canon_payload)), sig)
    assert not r.is_ok, "non-canonical transition payload must reject"


def test_decode_grant_rejects_wrong_signature_width():
    """Reference parse_grant (runtime.ex:237) requires byte_size(signature) == signature_bytes (64).
    The SDK decode path (parse_compact) now enforces this; a grant compact with a 32-byte signature
    rejects where it previously decoded to Ok."""
    g = _signed_grant()
    parts = g["compact"].split(b".")
    bad = parts[0] + b"." + parts[1] + b"." + base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=")
    r = decode_grant(bad)
    assert not r.is_ok, "wrong-width signature must reject"




# ============================================================================
# Encode-path validation parity (reference anchored_export_codec.ex encode):
# the row chain re-check + gated parses + full matches for both anchors and
# every transition. One red-capable leg per NEW clause (red-capability proven
# by neutralizing the encode wiring — the pre-parity state — in the task log).
# ============================================================================

_KEY_A = bytes([7]) * 32
_KEY_B = bytes([8]) * 32
_Z32P = bytes(32)
_SIG64 = bytes(64)
_SIG32 = bytes(32)


def _b64e(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _conformant_export():
    row_r = encode_consumption_entry(
        ConsumptionEntry(chain_id="chain-x", sequence=1, previous_hash=_Z32P, commitment=bytes([5]) * 32)
    )
    assert row_r.is_ok
    row, head = row_r.value.bytes_, row_r.value.hash_
    fp_a = public_key_thumbprint_raw(_KEY_A)
    fp_b = public_key_thumbprint_raw(_KEY_B)
    start_r = boundary_anchor_signing_input(
        BoundaryAnchorProducer(
            anchor_id="anchor-start", anchored_at=1000, chain_id="chain-x",
            sequence=0, chain_hash=_Z32P, key_id="anchor-a", public_key=_KEY_A,
        )
    )
    assert start_r.is_ok
    start = assemble_compact(start_r.value, _SIG64).value
    end_r = boundary_anchor_signing_input(
        BoundaryAnchorProducer(
            anchor_id="anchor-end", anchored_at=1600, chain_id="chain-x",
            sequence=1, chain_hash=head, key_id="anchor-b", public_key=_KEY_B,
        )
    )
    assert end_r.is_ok
    end = assemble_compact(end_r.value, _SIG64).value
    t_r = key_transition_signing_input(
        KeyTransitionProducer(
            transition_id="transition-1", chain_id="chain-x", effective_at=1500,
            current_key_id="anchor-a", current_public_key=_KEY_A,
            next_key_id="anchor-b", next_public_key=_KEY_B,
        )
    )
    assert t_r.is_ok
    t = assemble_compact(t_r.value, _SIG64).value
    chain = ExpectedChain(
        chain_id="chain-x", first_sequence=1, last_sequence=1, row_count=1,
        previous_hash=_Z32P, last_hash=head,
    )
    expected = ExpectedExport(
        chain=chain,
        digest=_Z32P,
        start_anchor=ExpectedAnchor(
            anchor_id="anchor-start", anchored_at=1000, chain_id="chain-x",
            sequence=0, chain_hash=_Z32P, key_id="anchor-a", key_fingerprint=fp_a,
        ),
        end_anchor=ExpectedAnchor(
            anchor_id="anchor-end", anchored_at=1600, chain_id="chain-x",
            sequence=1, chain_hash=head, key_id="anchor-b", key_fingerprint=fp_b,
        ),
        transitions=[
            ExpectedKeyTransition(
                transition_id="transition-1", chain_id="chain-x", effective_at=1500,
                current_key_id="anchor-a", current_key_fingerprint=fp_a,
                next_key_id="anchor-b", next_key_fingerprint=fp_b,
            )
        ],
        object_version="v1",
    )
    input_ = AnchoredExportInput(
        rows=[row], start_anchor=start, end_anchor=end, transitions=[t],
        chain_id="chain-x", first_sequence=1, last_sequence=1,
        row_count=1, previous_hash=_Z32P, last_hash=head,
    )
    return input_, expected


def _expect_encode_err(input_, expected):
    r = encode_anchored_export(input_, expected)
    assert not r.is_ok, "encode must reject"


def test_encode_parity_control_encodes():
    input_, expected = _conformant_export()
    r = encode_anchored_export(input_, expected)
    assert r.is_ok


def test_encode_parity_tampered_row_rejects():
    input_, expected = _conformant_export()
    bad = bytearray(input_.rows[0])
    bad[0] ^= 1
    _expect_encode_err(replace_row(input_, bytes(bad)), expected)


def replace_row(input_, row):
    from dataclasses import replace

    return replace(input_, rows=[row])


def test_encode_parity_start_anchor_mismatch_rejects():
    input_, expected = _conformant_export()
    wrong = boundary_anchor_signing_input(
        BoundaryAnchorProducer(
            anchor_id="anchor-WRONG", anchored_at=1000, chain_id="chain-x",
            sequence=0, chain_hash=_Z32P, key_id="anchor-a", public_key=_KEY_A,
        )
    )
    from dataclasses import replace

    _expect_encode_err(replace(input_, start_anchor=assemble_compact(wrong.value, _SIG64).value), expected)


def test_encode_parity_end_anchor_mismatch_rejects():
    input_, expected = _conformant_export()
    wrong = boundary_anchor_signing_input(
        BoundaryAnchorProducer(
            anchor_id="anchor-WRONG", anchored_at=1600, chain_id="chain-x",
            sequence=1, chain_hash=expected.chain.last_hash, key_id="anchor-b", public_key=_KEY_B,
        )
    )
    from dataclasses import replace

    _expect_encode_err(replace(input_, end_anchor=assemble_compact(wrong.value, _SIG64).value), expected)


def _swap_segment(compact: bytes, index: int, replacement_b64: bytes) -> bytes:
    segs = compact.split(b".")
    segs[index] = replacement_b64
    return b".".join(segs)


def _reversed_payload(compact: bytes) -> bytes:
    import json as _json

    segs = compact.split(b".")
    pad = b"=" * (-len(segs[1]) % 4)
    obj = _json.loads(base64.urlsafe_b64decode(segs[1] + pad).decode("utf-8"))
    body = "{" + ",".join(
        _json.dumps(k) + ":" + _json.dumps(obj[k]) for k in reversed(list(obj.keys()))
    ) + "}"
    return b".".join([segs[0], _b64e(body.encode("utf-8")), segs[2]])


def test_encode_parity_end_anchor_noncanonical_rejects():
    input_, expected = _conformant_export()
    from dataclasses import replace

    _expect_encode_err(replace(input_, end_anchor=_reversed_payload(input_.end_anchor)), expected)


def test_encode_parity_end_anchor_width_rejects():
    input_, expected = _conformant_export()
    from dataclasses import replace

    _expect_encode_err(
        replace(input_, end_anchor=_swap_segment(input_.end_anchor, 2, _b64e(_SIG32))), expected
    )


def test_encode_parity_transition_mismatch_rejects():
    input_, expected = _conformant_export()
    wrong = key_transition_signing_input(
        KeyTransitionProducer(
            transition_id="transition-1", chain_id="chain-x", effective_at=1501,
            current_key_id="anchor-a", current_public_key=_KEY_A,
            next_key_id="anchor-b", next_public_key=_KEY_B,
        )
    )
    from dataclasses import replace

    _expect_encode_err(
        replace(input_, transitions=[assemble_compact(wrong.value, _SIG64).value]), expected
    )


def test_encode_parity_transition_noncanonical_rejects():
    input_, expected = _conformant_export()
    from dataclasses import replace

    _expect_encode_err(
        replace(input_, transitions=[_reversed_payload(input_.transitions[0])]), expected
    )


def test_encode_parity_transition_width_rejects():
    input_, expected = _conformant_export()
    from dataclasses import replace

    _expect_encode_err(
        replace(input_, transitions=[_swap_segment(input_.transitions[0], 2, _b64e(_SIG32))]),
        expected,
    )


def test_encode_parity_tightened_outer_bounds_row_rejects():
    """Correctness-lens F1: the encode row re-check must run under the caller's OUTER
    bounds (the reference threads %{expected.chain | bounds: bounds}); a tightened outer
    with the chain's nested bounds absent is the reference's nested-bounds pin rejecting
    (anchored_export_codec.ex:352-354). A 157-byte row under chain_row_bytes=156 -> Err."""
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    tight = bounds_new({"chain_row_bytes": 156})
    r = encode_anchored_export(input_, _replace(expected, bounds=tight))
    assert not r.is_ok, "tightened outer bounds must take effect at the encode row walk"


def test_encode_parity_nested_anchor_bounds_mismatch_rejects():
    """The reference pins ALL FOUR nested bounds to the outer (anchored_export_codec.ex:352-354,
    :404-406); this leg pins the anchor sweep beyond the F1 chain pin."""
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    tight = bounds_new({"chain_row_bytes": 156})
    r = encode_anchored_export(input_, _replace(expected, start_anchor=_replace(expected.start_anchor, bounds=tight)))
    assert not r.is_ok, "nested anchor-bounds mismatch must reject at encode"


def test_encode_parity_identity_overrides_are_not_tightening():
    """An outer bounds built from an explicit MAXIMUM value is an identity override: the
    reference merges it into the full maximum struct and accepts absent nested bounds
    (struct equality); map-size gating wrong-rejected this (cross-vendor)."""
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    identity = bounds_new({"chain_row_bytes": 4096})  # == MAXIMA
    r = encode_anchored_export(input_, _replace(expected, bounds=identity))
    assert r.is_ok, "identity overrides must encode (not tightening)"


def test_encode_parity_nested_end_anchor_bounds_mismatch_rejects():
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    tight = bounds_new({"chain_row_bytes": 156})
    r = encode_anchored_export(input_, _replace(expected, end_anchor=_replace(expected.end_anchor, bounds=tight)))
    assert not r.is_ok, "end-anchor nested-bounds mismatch must reject at encode"


def test_encode_parity_nested_transition_bounds_mismatch_rejects():
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    tight = bounds_new({"chain_row_bytes": 156})
    r = encode_anchored_export(input_, _replace(expected, transitions=[_replace(expected.transitions[0], bounds=tight)]))
    assert not r.is_ok, "transition nested-bounds mismatch must reject at encode"


def test_encode_parity_chain_pin_isolated_rejects():
    """Isolates the CHAIN nested-bounds pin from the row walk: the tightened outer
    stays above the row size, so only the pin fires on the mismatched chain.bounds."""
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    # Isolated the diff-review's way: the OUTER stays at maximum (the sibling
    # absent-nested pins pass); ONLY chain.bounds is mismatched (4000 < 4096,
    # row-safe).
    chain_nested = bounds_new({"chain_row_bytes": 4000})
    r = encode_anchored_export(input_, _replace(expected, chain=_replace(expected.chain, bounds=chain_nested)))
    assert not r.is_ok, "chain nested-bounds mismatch must reject (isolated)"


def test_encode_parity_tightened_anchor_bytes_rejects():
    """Round-2 codex probe: anchor_bytes=1 tightened outer — parse_compact only gates
    compact_bytes, so without the explicit per-anchor ceiling the ~440-byte anchors
    framed fine (the reference gates anchor_bytes at :82/:114)."""
    from dataclasses import replace as _replace

    from bounded_authority_verifier.bounds import bounds_new

    input_, expected = _conformant_export()
    tight = bounds_new({"anchor_bytes": 1})
    r = encode_anchored_export(input_, _replace(expected, bounds=tight))
    assert not r.is_ok, "tightened anchor_bytes must reject the anchor compacts at encode"


def test_encode_parity_expected_bool_rejected():
    """Round-2: Python ``1 == True`` — an untyped boolean expected field would equal a
    decoded 0/1 at the match; the type-strict gate refuses it."""
    from dataclasses import replace as _replace

    input_, expected = _conformant_export()
    bad = _replace(expected, end_anchor=_replace(expected.end_anchor, sequence=True))
    r = encode_anchored_export(input_, bad)
    assert not r.is_ok, "a boolean expected sequence must reject (type-strict)"


def test_verify_parity_expected_anchor_chain_id_rejects():
    """Round-2: the static expected↔chain bindings at verify (the reference enforces
    the six at :362-371 via :92/:387); a caller-inconsistent expected end-anchor
    chain_id rejects before any parse."""
    from dataclasses import replace as _replace

    from bounded_authority_verifier.v1 import (
        ArchivedObject,
        HistoricalKeyChain,
        HistoricalPublicKey,
    )

    input_, expected = _conformant_export()
    enc = encode_anchored_export(input_, expected)
    assert enc.is_ok
    archive = enc.value.archive
    chunks = []
    off = 20
    while off < len(archive):
        (ln,) = struct.unpack_from(">I", archive, off)
        chunks.append(archive[off + 4 : off + 4 + ln])
        off += 4 + ln
    obj = ArchivedObject(chunks=chunks, version="v1")
    keys = HistoricalKeyChain(
        keys=[
            HistoricalPublicKey(key_id="anchor-a", public_key=_KEY_A, valid_from=900, valid_before=None),
            HistoricalPublicKey(key_id="anchor-b", public_key=_KEY_B, valid_from=1400, valid_before=None),
        ]
    )
    v_expected = ExpectedExport(
        chain=expected.chain,
        digest=enc.value.digest,
        start_anchor=expected.start_anchor,
        end_anchor=_replace(expected.end_anchor, chain_id="chain-OTHER"),
        transitions=expected.transitions,
        object_version="v1",
    )
    r = verify_anchored_export(obj, keys, v_expected)
    assert not r.is_ok, "caller-inconsistent expected anchor chain_id must reject at verify"


def test_bounds_magnitude_gate_rejects():
    """The key-window magnitude gate (all-SDK convergence — the Rust round-4 fix
    mirrored): a REAL runtime signature so the control verifies Ok and only the
    magnitude gate rejects the bad case."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from bounded_authority_verifier.v1 import verify_historical_anchor

    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    si = boundary_anchor_signing_input(
        BoundaryAnchorProducer(
            anchor_id="anchor-mag", anchored_at=1000, chain_id="chain-x",
            sequence=0, chain_hash=_Z32P, key_id="anchor-a", public_key=pub,
        )
    )
    assert si.is_ok
    _msg = si.value.protected_segment + b"." + si.value.payload_segment
    sig = priv.sign(_msg)
    from bounded_authority_verifier.jwk import public_key_thumbprint_raw

    expected = ExpectedAnchor(
        anchor_id="anchor-mag", anchored_at=1000, chain_id="chain-x",
        sequence=0, chain_hash=_Z32P, key_id="anchor-a",
        key_fingerprint=public_key_thumbprint_raw(pub), bounds=None,
    )
    key_kw = {
        "key_id": "anchor-a",
        "public_key": pub,
        "valid_from": 0,
        "valid_before": None,
    }
    from bounded_authority_verifier.v1 import HistoricalPublicKey

    # Control: normal windows verify Ok (the real signature).
    ok_key = HistoricalPublicKey(valid_before=2000, **{k: v for k, v in key_kw.items() if k != "valid_before"})
    compact = si.value.protected_segment + b"." + si.value.payload_segment + b"." + _b64e(sig)
    assert verify_historical_anchor(compact, ok_key, expected).is_ok
    # Huge bounded valid_before (2^62): membership holds; the magnitude gate fires.
    from bounded_authority_verifier.v1 import HistoricalPublicKey as HPK

    bad_key = HPK(valid_before=4611686018427387904, **{k: v for k, v in key_kw.items() if k != "valid_before"})
    assert not verify_historical_anchor(compact, bad_key, expected).is_ok


def test_bounds_magnitude_valid_from_half_rejects():
    """The valid_from half (negative out-of-magnitude — membership holds; the
    unsigned-abs sign symmetry fires)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from bounded_authority_verifier.jwk import public_key_thumbprint_raw
    from bounded_authority_verifier.v1 import HistoricalPublicKey, verify_historical_anchor

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    si = boundary_anchor_signing_input(
        BoundaryAnchorProducer(
            anchor_id="anchor-mag2", anchored_at=1000, chain_id="chain-x",
            sequence=0, chain_hash=_Z32P, key_id="anchor-a", public_key=pub,
        )
    )
    assert si.is_ok
    msg = si.value.protected_segment + b"." + si.value.payload_segment
    sig = priv.sign(msg)
    compact = si.value.protected_segment + b"." + si.value.payload_segment + b"." + _b64e(sig)
    expected = ExpectedAnchor(
        anchor_id="anchor-mag2", anchored_at=1000, chain_id="chain-x",
        sequence=0, chain_hash=_Z32P, key_id="anchor-a",
        key_fingerprint=public_key_thumbprint_raw(pub), bounds=None,
    )
    ok = HistoricalPublicKey(key_id="anchor-a", public_key=pub, valid_from=0, valid_before=2000)
    assert verify_historical_anchor(compact, ok, expected).is_ok
    bad = HistoricalPublicKey(
        key_id="anchor-a", public_key=pub, valid_from=-4611686018427387904, valid_before=2000
    )
    assert not verify_historical_anchor(compact, bad, expected).is_ok
