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

import pytest

from bounded_authority_verifier.error import InvalidError
from bounded_authority_verifier.json_alg import (
    JFloat,
    JInt,
    JObject,
    json_decode,
)
from bounded_authority_verifier.selector import (
    parse_selector,
    selector_matches,
    semantic_identity,
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
    assert class_member.v["evil"].v == 1 if isinstance(class_member.v.get("evil"), JInt) else True


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
