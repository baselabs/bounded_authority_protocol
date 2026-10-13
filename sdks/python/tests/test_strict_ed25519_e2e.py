"""End-to-end strict-Ed25519 tests: the public verify APIs must reject a forgery under a weak key.

A small-order public key (the identity point, ``01 00..00``) lets anyone forge an Ed25519 signature
without a private key: R = identity, S = 0 satisfies the cofactorless equation for every message.
These tests build the forged artifacts by hand (JSON plus the raw JWS framing), deliberately NOT
through the SDK's own producers, so the setup keeps working after the SDK refuses to produce
artifacts under a weak key, and so a rejection here can only come from the verifier.

Each forged test has a positive control built the same way with a real key, so a failure to build the
artifact cannot masquerade as a rejection.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bounded_authority_verifier import role_attestation as v1_ra
from bounded_authority_verifier import v1, v2
from bounded_authority_verifier.json_alg import JNull

IDENTITY_KEY = bytes([1]) + bytes(31)
FORGED_SIGNATURE = IDENTITY_KEY + bytes(32)  # R = identity, S = 0

ISSUER = "https://issuer.example.test"
AUDIENCE = "https://resource.example.test"
TARGET = "https://resource.example.test/invoke"
INVOCATION = "550e8400-e29b-41d4-a716-446655440000"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jcs(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _compact(header: dict, payload: dict, signature: bytes) -> bytes:
    return f"{_b64(_jcs(header))}.{_b64(_jcs(payload))}.{_b64(signature)}".encode("ascii")


def _signing_input(header: dict, payload: dict) -> bytes:
    return f"{_b64(_jcs(header))}.{_b64(_jcs(payload))}".encode("ascii")


def _okp_thumbprint(raw_key: bytes) -> bytes:
    """RFC 7638 thumbprint of the OKP JWK, hashed here directly so the test needs no SDK helper."""
    return hashlib.sha256(_jcs({"crv": "Ed25519", "kty": "OKP", "x": _b64(raw_key)})).digest()


def _grant_payload(version: int, holder_thumbprint: bytes) -> dict:
    return {
        "aud": [AUDIENCE],
        "cnf": {"jkt": _b64(holder_thumbprint)},
        "exp": 2000,
        "iat": 1000,
        "iss": ISSUER,
        "jti": "urn:example:grant:1",
        "nbf": 1000,
        "operations": [{"name": "read", "selectors": [{"kind": "all"}]}],
        "v": version,
    }


def _grant_header() -> dict:
    return {"alg": "EdDSA", "kid": "issuer", "typ": "ba+cap"}


def _real_key() -> tuple[bytes, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    return private.public_key().public_bytes_raw(), private


def _expected_grant(module):
    return module.ExpectedGrant(
        issuer=ISSUER, audience=AUDIENCE, evaluation_time=1500, clock_skew=60
    )


def _honest_grant(version: int, holder_thumbprint: bytes) -> tuple[bytes, bytes]:
    issuer_pub, issuer_priv = _real_key()
    header, payload = _grant_header(), _grant_payload(version, holder_thumbprint)
    signature = issuer_priv.sign(_signing_input(header, payload))
    return _compact(header, payload, signature), issuer_pub


def test_verify_grant_rejects_identity_key_forgery_with_positive_control() -> None:
    holder_pub, _ = _real_key()
    thumb = _okp_thumbprint(holder_pub)
    honest, issuer_pub = _honest_grant(1, thumb)
    control = v1.verify_grant(
        honest, v1.TrustedIssuer(key_id="issuer", public_key=issuer_pub), _expected_grant(v1)
    )
    assert control.is_ok, "positive control: the honestly signed grant must verify"

    forged = _compact(_grant_header(), _grant_payload(1, thumb), FORGED_SIGNATURE)
    result = v1.verify_grant(
        forged, v1.TrustedIssuer(key_id="issuer", public_key=IDENTITY_KEY), _expected_grant(v1)
    )
    assert not result.is_ok, "a grant forged under the identity issuer key must be rejected"


def test_verify_grant_rejects_identity_key_forgery_second_major_with_positive_control() -> None:
    holder_pub, _ = _real_key()
    thumb = _okp_thumbprint(holder_pub)
    honest, issuer_pub = _honest_grant(2, thumb)
    control = v2.verify_grant(
        honest, v2.TrustedIssuer(key_id="issuer", public_key=issuer_pub), _expected_grant(v2)
    )
    assert control.is_ok, "positive control: the honestly signed v2 grant must verify"

    forged = _compact(_grant_header(), _grant_payload(2, thumb), FORGED_SIGNATURE)
    result = v2.verify_grant(
        forged, v2.TrustedIssuer(key_id="issuer", public_key=IDENTITY_KEY), _expected_grant(v2)
    )
    assert not result.is_ok


def _proof_payload_from_producer(module, grant_compact: bytes, holder_pub: bytes) -> dict:
    """Borrow an honest proof payload from the SDK producer (the payload does not carry the key)."""
    producer = module.ProofProducer(
        holder_public_key=holder_pub,
        proof_id="urn:example:proof:1",
        method="POST",
        target_uri=TARGET,
        issued_at=1400,
        invocation_id=INVOCATION,
        operation="read",
        grant_compact=grant_compact,
        cast_arguments=JNull(),
    )
    signing_input = module.proof_signing_input(producer)
    assert signing_input.is_ok
    payload_segment = signing_input.value.payload_segment.decode("ascii")
    return json.loads(base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4)))


def _expected_request(module, issuer_pub: bytes):
    return module.ExpectedRequest(
        trusted_issuer=module.TrustedIssuer(key_id="issuer", public_key=issuer_pub),
        issuer=ISSUER,
        audience=AUDIENCE,
        method="POST",
        target_uri=TARGET,
        invocation_id=INVOCATION,
        operation="read",
        cast_arguments=JNull(),
        evaluation_time=1500,
        clock_skew=60,
        proof_max_age=300,
        nonce=module.NonceNotRequired(),
    )


def _envelope_with_holder_signature(module, version: int, holder_key: bytes, signer):
    """A grant bound to ``holder_key`` plus a proof whose header carries that key's JWK."""
    grant_compact, issuer_pub = _honest_grant(version, _okp_thumbprint(holder_key))
    honest_holder_pub, _ = _real_key()
    payload = _proof_payload_from_producer(module, grant_compact, honest_holder_pub)
    header = {
        "alg": "EdDSA",
        "jwk": {"crv": "Ed25519", "kty": "OKP", "x": _b64(holder_key)},
        "typ": "dpop+jwt",
    }
    signature = signer(_signing_input(header, payload))
    return grant_compact, _compact(header, payload, signature), issuer_pub


def test_check_envelope_rejects_identity_holder_key_forgery_with_positive_control() -> None:
    holder_pub, holder_priv = _real_key()
    grant, proof, issuer_pub = _envelope_with_holder_signature(v1, 1, holder_pub, holder_priv.sign)
    control = v1.check_envelope(grant, proof, _expected_request(v1, issuer_pub))
    assert control.is_ok, "positive control: the honest envelope must verify"

    grant, proof, issuer_pub = _envelope_with_holder_signature(
        v1, 1, IDENTITY_KEY, lambda _message: FORGED_SIGNATURE
    )
    result = v1.check_envelope(grant, proof, _expected_request(v1, issuer_pub))
    assert not result.is_ok, "a proof forged under the identity holder key must be rejected"


def test_check_envelope_rejects_identity_holder_key_forgery_second_major_with_positive_control() -> None:
    holder_pub, holder_priv = _real_key()
    grant, proof, issuer_pub = _envelope_with_holder_signature(v2, 2, holder_pub, holder_priv.sign)
    control = v2.check_envelope(grant, proof, _expected_request(v2, issuer_pub))
    assert control.is_ok, "positive control: the honest v2 envelope must verify"

    grant, proof, issuer_pub = _envelope_with_holder_signature(
        v2, 2, IDENTITY_KEY, lambda _message: FORGED_SIGNATURE
    )
    result = v2.check_envelope(grant, proof, _expected_request(v2, issuer_pub))
    assert not result.is_ok


# --- role attestation (RA1): the attestor key, and the subject key carried in the payload ---

ATTESTOR_KID = "attestor-ra-1"
NOW = 1735691000


def _ra_header() -> dict:
    return {"alg": "EdDSA", "kid": ATTESTOR_KID, "typ": "ba+role-attestation"}


def _ra_payload(subject_key: bytes) -> dict:
    return {
        "exp": 1735693200,
        "jti": "urn:example:attestation:ra-1",
        "key_id": "subject-key-1",
        "nbf": 1735689600,
        "public_key": _b64(subject_key),
        "role": "issuer",
        "v": 1,
    }


def _ra_expected(attestor_key: bytes, subject_key: bytes):
    return v1_ra.ExpectedAttestation(
        attestor=v1_ra.TrustedAttestor(
            key_id=ATTESTOR_KID, public_key=attestor_key, valid_from=1735689000, valid_before=1735694000
        ),
        subject_key_id="subject-key-1",
        subject_public_key=subject_key,
        now=NOW,
    )


def test_role_attestation_rejects_identity_attestor_forgery_with_positive_control() -> None:
    attestor_pub, attestor_priv = _real_key()
    subject_pub, _ = _real_key()
    header, payload = _ra_header(), _ra_payload(subject_pub)
    honest = _compact(header, payload, attestor_priv.sign(_signing_input(header, payload)))
    assert v1_ra.verify_attestation(honest, _ra_expected(attestor_pub, subject_pub)).is_ok

    forged = _compact(header, payload, FORGED_SIGNATURE)
    assert not v1_ra.verify_attestation(forged, _ra_expected(IDENTITY_KEY, subject_pub)).is_ok


def test_role_attestation_refuses_a_weak_subject_key_in_payload_and_in_the_producer() -> None:
    attestor_pub, attestor_priv = _real_key()
    header = _ra_header()
    for weak in (IDENTITY_KEY, bytes(32), bytes([1] + [0] * 30 + [0x80])):
        payload = _ra_payload(weak)
        compact = _compact(header, payload, attestor_priv.sign(_signing_input(header, payload)))
        assert not v1_ra.decode_attestation(compact).is_ok, weak.hex()
        assert not v1_ra.verify_attestation(compact, _ra_expected(attestor_pub, weak)).is_ok
        producer = v1_ra.AttestationProducer(
            attestor_key_id=ATTESTOR_KID, jti="urn:example:attestation:ra-1", key_id="subject-key-1",
            public_key=weak, role="issuer", nbf=1735689600, exp=1735693200,
        )
        assert not v1_ra.attestation_signing_input(producer).is_ok

    good_pub, _ = _real_key()
    payload = _ra_payload(good_pub)
    compact = _compact(header, payload, attestor_priv.sign(_signing_input(header, payload)))
    assert v1_ra.decode_attestation(compact).is_ok, "positive control: a real subject key decodes"
    producer = v1_ra.AttestationProducer(
        attestor_key_id=ATTESTOR_KID, jti="urn:example:attestation:ra-1", key_id="subject-key-1",
        public_key=good_pub, role="issuer", nbf=1735689600, exp=1735693200,
    )
    assert v1_ra.attestation_signing_input(producer).is_ok


# --- the byte-level gate at the choke point: failures that a key check alone cannot catch ---


def test_verify_grant_rejects_a_key_holder_signature_with_small_order_r() -> None:
    """The issuer key is a REAL key, so key acceptance passes; only the R clause of the gate rejects
    this signature (R = identity, S = k*a). A bare cofactorless backend accepts it."""
    import ed25519_reference as ref

    seed = os.urandom(32)
    issuer_pub = ref.public_key(seed)
    holder_pub, _ = _real_key()
    header, payload = _grant_header(), _grant_payload(1, _okp_thumbprint(holder_pub))
    message = _signing_input(header, payload)
    signature = ref.identity_r_signature(seed, message)
    assert ref.verifies(signature, issuer_pub, message), "the construction satisfies the equation"
    Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(signature, message)

    honest = _compact(header, payload, ref.sign_for_encoded_key(seed, issuer_pub, message))
    trusted = v1.TrustedIssuer(key_id="issuer", public_key=issuer_pub)
    assert v1.verify_grant(honest, trusted, _expected_grant(v1)).is_ok, "positive control"

    forged = _compact(header, payload, signature)
    assert not v1.verify_grant(forged, trusted, _expected_grant(v1)).is_ok


def test_verify_grant_rejects_a_scalar_above_the_group_order() -> None:
    """S + L is congruent to S and a lenient verifier accepts it; the gate rejects it first."""
    import ed25519_reference as ref

    seed = os.urandom(32)
    issuer_pub = ref.public_key(seed)
    holder_pub, _ = _real_key()
    header, payload = _grant_header(), _grant_payload(1, _okp_thumbprint(holder_pub))
    message = _signing_input(header, payload)
    signature = ref.sign_for_encoded_key(seed, issuer_pub, message)
    s = int.from_bytes(signature[32:], "little")
    malleated = signature[:32] + (s + ref.L).to_bytes(32, "little")
    trusted = v1.TrustedIssuer(key_id="issuer", public_key=issuer_pub)
    assert v1.verify_grant(_compact(header, payload, signature), trusted, _expected_grant(v1)).is_ok
    assert not v1.verify_grant(_compact(header, payload, malleated), trusted, _expected_grant(v1)).is_ok
