"""Unit tests for rule S1 (strict Ed25519 verification) and key acceptance.

Rule S1, checked in this order before any backend call: exact widths; A and R canonical; neither A
nor R of small order (one table serves both); S < L; then the cofactorless equation.

Every expectation about WHICH encodings are small-order or canonical is derived by curve arithmetic
in ``ed25519_reference`` (finding 12), never copied from the SDK, so a wrong table entry in the SDK
goes red here. Backend-redundant clauses (R canonical, S < L) are tested directly on the byte-level
gate, because the cofactorless backend would reject those inputs anyway and only a gate test can
show the clause exists.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ed25519_reference as ref
from bounded_authority_verifier import jwk as sdk_jwk
from bounded_authority_verifier.base64url import base64url_encode
from bounded_authority_verifier.ed25519 import (
    acceptable_public_key,
    import_public_key,
    strict_gate,
    torsion_free,
    verify_strict,
)
from bounded_authority_verifier.error import InvalidError
from bounded_authority_verifier.jwk import (
    OkpPublic,
    jwk_decode_public,
    jwk_encode_public,
    jwk_from_public_key,
    public_key_thumbprint_raw,
    thumbprint,
    thumbprint_digest_unchecked,
    thumbprint_preimage,
    thumbprint_raw,
)

SMALL_ORDER = ref.small_order_encodings()
ALIASES = ref.noncanonical_aliases()
MESSAGE = b"strict ed25519 message"


def _seed() -> bytes:
    return os.urandom(32)


def _honest(message: bytes = MESSAGE) -> tuple[bytes, bytes, bytes]:
    seed = _seed()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return seed, private.public_key().public_bytes_raw(), private.sign(message)


def _with_s(signature: bytes, s: int) -> bytes:
    return signature[:32] + s.to_bytes(32, "little")


# --- the reference itself is anchored to the backend, so the derived sets mean something ---


def test_reference_derives_eight_distinct_points_and_agrees_with_the_backend() -> None:
    assert len(set(SMALL_ORDER)) == 8
    seed, public, signature = _honest()
    assert ref.public_key(seed) == public
    assert ref.sign_for_encoded_key(seed, public, MESSAGE) == signature
    assert ref.verifies(signature, public, MESSAGE)
    assert len(ALIASES) == 40 and len(set(ALIASES)) == 40


# --- widths ---


@pytest.mark.parametrize("key_len", [0, 1, 31, 33, 64])
def test_key_width_is_exactly_32(key_len: int) -> None:
    _seed_, public, signature = _honest()
    bad = (public + bytes(64))[:key_len]
    assert verify_strict(MESSAGE, signature, bad) is False
    assert acceptable_public_key(bad) is False
    assert torsion_free(bad) is False


@pytest.mark.parametrize("key_len", [0, 31, 33])
@pytest.mark.parametrize("sig_len", [0, 63, 65])
def test_strict_gate_checks_widths_itself(key_len: int, sig_len: int) -> None:
    """The gate owns clause 1: a backend would also refuse a wrong width, so only a direct gate test
    shows the clause is present."""
    _seed_, public, signature = _honest()
    assert strict_gate(signature, (public + bytes(64))[:key_len]) is False
    assert strict_gate((signature + bytes(64))[:sig_len], public) is False
    assert strict_gate(signature, public) is True


@pytest.mark.parametrize("sig_len", [0, 32, 63, 65, 128])
def test_signature_width_is_exactly_64(sig_len: int) -> None:
    _seed_, public, signature = _honest()
    bad = (signature + bytes(64))[:sig_len]
    assert verify_strict(MESSAGE, bad, public) is False


def test_honest_signature_is_accepted_and_tamper_is_rejected() -> None:
    for _ in range(8):
        _seed_, public, signature = _honest()
        assert verify_strict(MESSAGE, signature, public) is True
        assert verify_strict(MESSAGE + b"!", signature, public) is False
        flipped = bytes([signature[0] ^ 1]) + signature[1:]
        assert verify_strict(MESSAGE, flipped, public) is False


def test_rfc8032_test_1_vector() -> None:
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert verify_strict(b"", signature, public) is True
    assert acceptable_public_key(public) is True
    assert torsion_free(public) is True


# --- clause: A is not small-order (each of the 8, derived by arithmetic) ---


@pytest.mark.parametrize("index", range(8))
def test_small_order_key_is_rejected_by_gate_and_acceptance(index: int) -> None:
    weak = SMALL_ORDER[index]
    _seed_, _public, signature = _honest()
    assert strict_gate(signature, weak) is False
    assert acceptable_public_key(weak) is False
    assert torsion_free(weak) is False
    assert verify_strict(MESSAGE, signature, weak) is False


def test_identity_key_forgery_with_identity_r_and_zero_s_is_rejected() -> None:
    forged = ref.encode(ref.IDENTITY) + bytes(32)
    identity = ref.encode(ref.IDENTITY)
    assert ref.verifies(forged, identity, MESSAGE), "the forgery satisfies the bare equation"
    assert verify_strict(MESSAGE, forged, identity) is False
    for weak in SMALL_ORDER:
        assert verify_strict(MESSAGE, forged, weak) is False


# --- clause: R is not small-order (the same table serves R) ---


@pytest.mark.parametrize("index", range(8))
def test_small_order_r_is_rejected_by_the_gate(index: int) -> None:
    _seed_, public, signature = _honest()
    assert strict_gate(SMALL_ORDER[index] + signature[32:], public) is False


def test_honest_a_with_identity_r_is_rejected_though_the_equation_holds() -> None:
    seed = _seed()
    public = ref.public_key(seed)
    signature = ref.identity_r_signature(seed, MESSAGE)
    assert ref.verifies(signature, public, MESSAGE), "key-holder construction is sound"
    Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(signature, MESSAGE)
    assert verify_strict(MESSAGE, signature, public) is False


@pytest.mark.parametrize("index", range(8))
def test_mixed_order_a_with_each_small_order_r_is_rejected(index: int) -> None:
    """mixedA-smallR-{0..7}: the key holder builds R = e_j so the bare equation holds under A + T."""
    seed = _seed()
    torsion = ref.order_8_point()
    a_pt = ref.mul(ref.secret_scalar(seed), ref.BASE)
    key_enc = ref.encode(ref.add(a_pt, torsion))
    r_enc = SMALL_ORDER[index]
    assert ref.decode(r_enc) is not None
    a = ref.secret_scalar(seed)
    for counter in range(4000):
        message = MESSAGE + counter.to_bytes(4, "big")
        k = ref.challenge(r_enc, key_enc, message)
        signature = r_enc + ((k * a) % ref.L).to_bytes(32, "little")
        if ref.verifies(signature, key_enc, message):
            assert verify_strict(message, signature, key_enc) is False
            assert strict_gate(signature, key_enc) is False
            return
    pytest.fail("no message found whose challenge cancels the torsion (construction bug)")


# --- clause: canonical encodings of A and R ---


def test_every_noncanonical_alias_is_rejected_as_a_key_and_as_r() -> None:
    _seed_, public, signature = _honest()
    for alias in ALIASES:
        assert acceptable_public_key(alias) is False, alias.hex()
        assert torsion_free(alias) is False, alias.hex()
        assert strict_gate(signature, alias) is False, alias.hex()
        assert strict_gate(alias + signature[32:], public) is False, alias.hex()


def test_noncanonical_aliases_that_are_not_small_order_isolate_the_canonical_clause() -> None:
    """Of the 40 aliases only 6 alias a small-order point; the rest would slip past a table-only
    gate, so rejecting them is the canonical clause's own work (for A and for R)."""
    table = set(SMALL_ORDER)
    assert all(alias not in table for alias in ALIASES), "aliases are never the canonical encodings"
    # Non-small-order aliases: decode the alias with the sign/y reduced and check the point's order.
    isolating = []
    for alias in ALIASES:
        v = int.from_bytes(alias, "little")
        reduced = ((v & ((1 << 255) - 1)) % ref.P) | (v & (1 << 255))
        point = ref.decode(reduced.to_bytes(32, "little"))
        if point is not None and ref.mul(8, point) != ref.IDENTITY:
            isolating.append(alias)
    assert len(isolating) >= 10
    _seed_, public, signature = _honest()
    for alias in isolating:
        assert strict_gate(signature, alias) is False
        assert strict_gate(alias + signature[32:], public) is False


def test_x_zero_with_sign_bit_is_noncanonical() -> None:
    identity_signed = (1 | (1 << 255)).to_bytes(32, "little")
    order2_signed = ((ref.P - 1) | (1 << 255)).to_bytes(32, "little")
    _seed_, public, signature = _honest()
    for enc in (identity_signed, order2_signed):
        assert acceptable_public_key(enc) is False
        assert strict_gate(signature, enc) is False
        assert strict_gate(enc + signature[32:], public) is False


def test_y_equal_p_boundary_is_noncanonical_and_p_minus_one_is_not_the_boundary() -> None:
    _seed_, public, signature = _honest()
    y_eq_p = ref.P.to_bytes(32, "little")
    assert strict_gate(signature, y_eq_p) is False
    assert strict_gate(y_eq_p + signature[32:], public) is False
    # y = p - 2 is canonical (and not small-order): the gate must not reject on canonicity.
    below = (ref.P - 2).to_bytes(32, "little")
    assert below not in set(SMALL_ORDER)
    assert strict_gate(signature, below) is True
    assert strict_gate(below + signature[32:], public) is True


# --- clause: S < L ---


@pytest.mark.parametrize(
    "s",
    [ref.L, ref.L + 1, ref.L + 12345, 2 * ref.L, (1 << 256) - 1, (1 << 255), (1 << 253)],
)
def test_s_at_or_above_l_is_rejected_by_the_gate(s: int) -> None:
    _seed_, public, signature = _honest()
    assert strict_gate(_with_s(signature, s), public) is False
    assert verify_strict(MESSAGE, _with_s(signature, s), public) is False


def test_s_below_l_is_not_rejected_by_the_gate() -> None:
    _seed_, public, signature = _honest()
    assert strict_gate(_with_s(signature, ref.L - 1), public) is True
    assert strict_gate(_with_s(signature, 0), public) is True
    s = int.from_bytes(signature[32:], "little")
    assert s < ref.L
    assert strict_gate(signature, public) is True


def test_s_plus_l_malleability_is_rejected_though_the_scalar_is_congruent() -> None:
    _seed_, public, signature = _honest()
    s = int.from_bytes(signature[32:], "little")
    assert s + ref.L < (1 << 256)
    malleated = _with_s(signature, s + ref.L)
    assert verify_strict(MESSAGE, signature, public) is True
    assert verify_strict(MESSAGE, malleated, public) is False


# --- gate sanity: nothing outside the derived set is rejected as small-order ---


def test_gate_rejects_only_the_derived_small_order_set_among_torsion_variants() -> None:
    seed = _seed()
    torsion = ref.torsion_subgroup()
    a_pt = ref.mul(ref.secret_scalar(seed), ref.BASE)
    _seed_, _public, signature = _honest()
    for t in torsion[1:]:
        variant = ref.encode(ref.add(a_pt, t))
        assert variant not in set(SMALL_ORDER)
        assert strict_gate(signature, variant) is True, "a mixed-order key is not small-order"
        assert strict_gate(variant + signature[32:], ref.public_key(seed)) is True


# --- torsion variants: acceptable passes, torsion_free fails; verify accepts (R2 pin) ---


@pytest.mark.parametrize("index", range(1, 8))
def test_torsion_variant_key_is_acceptable_but_not_torsion_free(index: int) -> None:
    seed = _seed()
    torsion = ref.torsion_subgroup()[index]
    key_enc, signature = ref.sign_under_torsion_variant(seed, torsion, MESSAGE)
    assert key_enc != ref.public_key(seed)
    assert acceptable_public_key(key_enc) is True
    assert torsion_free(key_enc) is False
    assert verify_strict(MESSAGE, signature, key_enc) is True, "accepted at verify; host rejects it"
    # No key substitution: the honest signature does not verify under the torsion variant.
    honest_signature = ref.sign_for_encoded_key(seed, ref.public_key(seed), MESSAGE)
    assert verify_strict(MESSAGE, honest_signature, key_enc) is False


def test_prime_order_key_is_acceptable_and_torsion_free() -> None:
    for _ in range(6):
        _seed_, public, _signature = _honest()
        assert acceptable_public_key(public) is True
        assert torsion_free(public) is True


def test_off_curve_key_is_not_acceptable_and_not_torsion_free() -> None:
    off = ref.off_curve_encoding()
    assert ref.decode(off) is None
    assert acceptable_public_key(off) is False
    assert torsion_free(off) is False
    _seed_, _public, signature = _honest()
    assert verify_strict(MESSAGE, signature, off) is False


def test_never_raises_on_arbitrary_input() -> None:
    for junk in (b"", b"\x00", os.urandom(32), os.urandom(64)):
        assert verify_strict(b"m", os.urandom(64), junk) in (True, False)
        assert acceptable_public_key(junk) in (True, False)
        assert torsion_free(junk) in (True, False)


# --- differential property: verify_strict equals the pure reference rule (no table, no backend) ---


def _reference_verdict(message: bytes, signature: bytes, key: bytes) -> bool:
    if len(key) != 32 or len(signature) != 64:
        return False
    a, r = ref.decode(key), ref.decode(signature[:32])
    if a is None or r is None:
        return False
    if ref.mul(8, a) == ref.IDENTITY or ref.mul(8, r) == ref.IDENTITY:
        return False
    return ref.verifies(signature, key, message)


def _differential_inputs() -> list[tuple[bytes, bytes, bytes]]:
    cases: list[tuple[bytes, bytes, bytes]] = []
    torsion = ref.torsion_subgroup()
    for round_number in range(6):
        seed = hashlib.sha256(b"differential" + bytes([round_number])).digest()
        message = MESSAGE + bytes([round_number])
        public = ref.public_key(seed)
        honest = ref.sign_for_encoded_key(seed, public, message)
        s = int.from_bytes(honest[32:], "little")
        cases.append((message, honest, public))
        cases.append((message, _with_s(honest, s + ref.L), public))
        cases.append((message, ref.identity_r_signature(seed, message), public))
        for t in torsion[1:]:
            key_enc, sig = ref.sign_under_torsion_variant(seed, t, message)
            cases.append((message, sig, key_enc))
            cases.append((message, honest, key_enc))
        for weak in SMALL_ORDER:
            cases.append((message, ref.encode(ref.IDENTITY) + bytes(32), weak))
            cases.append((message, weak + honest[32:], public))
        for alias in ALIASES[:12]:
            cases.append((message, honest, alias))
            cases.append((message, alias + honest[32:], public))
    return cases


def test_verify_strict_matches_the_pure_reference_on_a_differential_set() -> None:
    cases = _differential_inputs()
    assert len(cases) > 300
    accepted = 0
    for message, signature, key in cases:
        expected = _reference_verdict(message, signature, key)
        assert verify_strict(message, signature, key) is expected, (key.hex(), signature.hex())
        accepted += expected
    assert 20 < accepted < len(cases), "the set exercises both verdicts"


# --- the fallible set: JWK encode/decode and every public thumbprint function ---


def _okp(raw: bytes) -> OkpPublic:
    return OkpPublic(crv="Ed25519", kty="OKP", x=base64url_encode(raw).decode("ascii"))


def _weak_keys() -> list[bytes]:
    return [*SMALL_ORDER, *ALIASES, ref.off_curve_encoding()]


def test_every_public_key_function_rejects_weak_keys_and_accepts_an_honest_key() -> None:
    _seed_, honest, _signature = _honest()
    # Positive controls: every function works on an honest key.
    assert isinstance(jwk_encode_public(honest), bytes)
    assert jwk_decode_public(jwk_encode_public(honest)).is_ok
    assert len(public_key_thumbprint_raw(honest)) == 32
    assert isinstance(thumbprint(_okp(honest)), str)
    assert len(thumbprint_raw(_okp(honest))) == 32
    assert thumbprint_preimage(_okp(honest)).startswith(b'{"crv":"Ed25519"')
    assert jwk_from_public_key(honest).x

    for weak in _weak_keys():
        with pytest.raises(InvalidError):
            jwk_encode_public(weak)
        text = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": base64url_encode(weak).decode()},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        assert not jwk_decode_public(text).is_ok
        with pytest.raises(InvalidError):
            public_key_thumbprint_raw(weak)
        with pytest.raises(InvalidError):
            jwk_from_public_key(weak)
        with pytest.raises(InvalidError):
            thumbprint(_okp(weak))
        with pytest.raises(InvalidError):
            thumbprint_raw(_okp(weak))
        with pytest.raises(InvalidError):
            thumbprint_preimage(_okp(weak))
        with pytest.raises(InvalidError):
            import_public_key(weak, "fingerprint")


def test_unchecked_thumbprint_is_a_pure_hash_available_for_weak_keys() -> None:
    _seed_, honest, _signature = _honest()
    for raw in (honest, *SMALL_ORDER, ALIASES[0]):
        preimage = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": base64url_encode(raw).decode()},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        assert thumbprint_digest_unchecked(raw) == hashlib.sha256(preimage).digest()
    assert thumbprint_digest_unchecked(honest) == public_key_thumbprint_raw(honest)
    with pytest.raises(InvalidError):
        thumbprint_digest_unchecked(honest[:31])


def test_thumbprint_digest_unchecked_is_never_called_from_src() -> None:
    """It exists for censuses and generators only (finding 10a). No SDK module may call or reference
    it other than its own definition, so no verify or key-import path can silently skip key
    acceptance."""
    src = Path(sdk_jwk.__file__).resolve().parent
    references = []
    for path in sorted(src.glob("*.py")):
        tree = ast.parse(path.read_text())
        defined = {
            id(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "thumbprint_digest_unchecked"
        }
        for node in ast.walk(tree):
            name = (
                node.id if isinstance(node, ast.Name)
                else node.attr if isinstance(node, ast.Attribute)
                else node.name if isinstance(node, ast.alias)
                else None
            )
            if name == "thumbprint_digest_unchecked":
                references.append(f"{path.name}:{getattr(node, 'lineno', 'import')}")
        assert defined or path.name != "jwk.py"
    assert references == [], references
