"""Issue a grant, sign a holder proof for one request, verify both, then show that the same
proof fails for other arguments. The keys come from fixed seeds so the output is stable; in
production the private keys stay with the issuer and the holder, and the verifier receives only
public keys."""

from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from bounded_authority_verifier import (
    Err,
    ExpectedRequest,
    GrantProducer,
    JString,
    NonceNotRequired,
    Ok,
    OperationInput,
    ProofProducer,
    SigningInput,
    TrustedIssuer,
    assemble_compact,
    check_envelope,
    grant_signing_input,
    json_decode,
    jwk_from_public_key,
    proof_signing_input,
    thumbprint,
)

issuer_key = Ed25519PrivateKey.from_private_bytes(bytes(32))
holder_key = Ed25519PrivateKey.from_private_bytes(bytes([1]) + bytes(31))
issuer_public = issuer_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
holder_public = holder_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def signed(signing_input: SigningInput, key: Ed25519PrivateKey) -> bytes:
    """Sign ASCII(base64url(protected) || "." || base64url(payload)) and assemble the compact."""
    message = signing_input.protected_segment + b"." + signing_input.payload_segment
    result = assemble_compact(signing_input, key.sign(message))
    assert isinstance(result, Ok)
    return result.value


# The issuer grants one operation, restricted to one argument value.
grant_input = grant_signing_input(
    GrantProducer(
        key_id="issuer-1",
        issuer="https://issuer.example",
        grant_id="grant-001",
        audiences=["https://docs.example"],
        issued_at=1_800_000_000,
        not_before=1_800_000_000,
        expires_at=1_800_003_600,
        holder_thumbprint=thumbprint(jwk_from_public_key(holder_public)),
        operations=[
            OperationInput(
                name="publish_article",
                selectors=[{"kind": "equals", "path": ["section"], "value": JString(b"science")}],
            )
        ],
    )
)
assert isinstance(grant_input, Ok)
grant = signed(grant_input.value, issuer_key)

# The holder binds one request to the grant.
arguments = json_decode(b'{"section":"science","title":"Tides"}')
proof_input = proof_signing_input(
    ProofProducer(
        holder_public_key=holder_public,
        proof_id="proof-001",
        method="POST",
        target_uri="https://docs.example/articles",
        issued_at=1_800_000_100,
        invocation_id="9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
        operation="publish_article",
        grant_compact=grant,
        cast_arguments=arguments,
    )
)
assert isinstance(proof_input, Ok)
proof = signed(proof_input.value, holder_key)

# The service verifies the raw bytes against what it derived from the request.
expected = ExpectedRequest(
    trusted_issuer=TrustedIssuer(key_id="issuer-1", public_key=issuer_public),
    issuer="https://issuer.example",
    audience="https://docs.example",
    method="POST",
    target_uri="https://docs.example/articles",
    invocation_id="9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
    operation="publish_article",
    cast_arguments=arguments,
    evaluation_time=1_800_000_100,
    clock_skew=60,
    proof_max_age=300,
    nonce=NonceNotRequired(),
)

result = check_envelope(grant, proof, expected)
assert isinstance(result, Ok)
facts = result.value
print(facts.operation, facts.grant_id, facts.authorization)

# The same proof against other arguments fails closed, with no detail.
other = replace(expected, cast_arguments=json_decode(b'{"section":"sports","title":"Tides"}'))
print(isinstance(check_envelope(grant, proof, other), Err))
