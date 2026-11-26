"""Candidate bap-content-assertion-es256/1 facade."""

from __future__ import annotations

from typing import cast

from .bounds import Bounds
from .compact import SigningInput, assemble_segments_es256
from .content_assertion import (
    _ES256,
    _compact_bounds,
    _parse,
    _projected_compact_bounds,
    _signing_input,
    _verify_assertion,
    _verify_successor,
)
from .content_assertion import ContentAssertion as ContentAssertion
from .content_assertion import ExpectedContentAssertion as ExpectedContentAssertion
from .content_assertion import content_digest as content_digest
from .ed25519 import sha256
from .error import Result, _fail, _unwrap
from .facts import Es256ContentAssertionDecoded as ContentAssertionDecoded
from .facts import Es256ContentAssertionFacts as ContentAssertionFacts
from .role_attestation import _closed_shape, _trying
from .v3 import _es256_scalars

CONTENT_ASSERTION_TYP = "ba+content-assertion-es256"
CONTENT_ASSERTION_PROFILE = "bap-content-assertion-es256/1"


@_closed_shape
def assertion_signing_input(
    assertion: ContentAssertion, bounds: Bounds | None = None
) -> Result[SigningInput]:
    """Build the exact ES256 content assertion signing input."""
    return _trying(lambda: _signing_input(assertion, bounds, _ES256))


@_closed_shape
def assemble_compact(
    signing_input: SigningInput, signature: bytes, bounds: Bounds | None = None
) -> Result[bytes]:
    """Assemble and validate a compact with a caller-supplied raw signature."""
    def body() -> bytes:
        b = _compact_bounds(bounds)
        if signing_input.kind != _ES256.kind:
            _fail()
        _projected_compact_bounds(signing_input, b)
        _es256_scalars(signature)
        compact = _unwrap(assemble_segments_es256(signing_input, signature))
        _parse(compact, b, _ES256)
        return compact

    return _trying(body)


@_closed_shape
def decode_assertion(compact: bytes, bounds: Bounds | None = None) -> Result[ContentAssertionDecoded]:
    """Decode structurally valid ES256 assertion claims."""
    return _trying(
        lambda: cast(ContentAssertionDecoded, _parse(compact, _compact_bounds(bounds), _ES256)[1])
    )


@_closed_shape
def verify_assertion(
    compact: bytes, expected: ExpectedContentAssertion
) -> Result[ContentAssertionFacts]:
    """Verify an ES256 assertion against explicit expected inputs."""
    return _trying(lambda: cast(ContentAssertionFacts, _verify_assertion(compact, expected, _ES256)))


@_closed_shape
def assertion_digest(compact: bytes, bounds: Bounds | None = None) -> Result[bytes]:
    """Validate structural framing and hash the exact compact bytes."""
    def body() -> bytes:
        _parse(compact, _compact_bounds(bounds), _ES256)
        return _unwrap(sha256(compact))

    return _trying(body)


@_closed_shape
def verify_successor(
    predecessor: ContentAssertionFacts, successor: ContentAssertionFacts, bounds: Bounds
) -> Result[None]:
    """Check a successor against verified ES256 predecessor facts."""
    return _trying(lambda: _verify_successor(predecessor, successor, bounds))
