"""JWS compact serialization (RFC 7515) — the 3-segment wire shape:
``base64url(protected) || "." || base64url(payload) || "." || base64url(signature)``.

The signing input (REQ1-SIGNING-exact-input) is ``ASCII(base64url(protected) || "." ||
base64url(payload))`` — no signature, no extra bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .error import InvalidError, Ok, Result, err, fail, require

_DOT = 0x2E


@dataclass(frozen=True)
class CompactSegments:
    protected_segment: bytes   # the raw base64url TEXT (not decoded)
    payload_segment: bytes
    signature: bytes           # decoded raw bytes (64 for Ed25519)
    protected_bytes: bytes     # decoded
    payload_bytes: bytes       # decoded
    signing_input: bytes       # ASCII(protected "." payload) text


def parse_compact(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> CompactSegments:
    """Parse + bound a compact input into 3 segments. Validates the segment count, bounds, canonical
    base64url of each segment, and decodes protected + payload (signature kept raw after decode)."""
    if len(data) > bounds_resolve(bounds, "compact_bytes"):
        fail("compact: byte bound")
    if len(data) == 0:
        fail("compact: empty")
    # Split into exactly 3 segments on '.'.
    dots = [i for i, b in enumerate(data) if b == _DOT]
    if len(dots) != 2:
        fail("compact: three segments")
    d0 = dots[0]
    d1 = dots[1]
    if d0 == 0 or d1 == d0 + 1 or d1 == len(data) - 1:
        fail("compact: empty segment")
    protected_text = data[:d0]
    payload_text = data[d0 + 1:d1]
    signature_text = data[d1 + 1:]
    if len(protected_text) > bounds_resolve(bounds, "encoded_segment_bytes"):
        fail("compact: protected segment bound")
    if len(payload_text) > bounds_resolve(bounds, "encoded_segment_bytes"):
        fail("compact: payload segment bound")
    protected_bytes = base64url_decode(protected_text, bounds_resolve(bounds, "decoded_segment_bytes"))
    payload_bytes = base64url_decode(payload_text, bounds_resolve(bounds, "decoded_segment_bytes"))
    signature = base64url_decode(signature_text)
    signing_input = protected_text + bytes([_DOT]) + payload_text
    return CompactSegments(
        protected_segment=protected_text,
        payload_segment=payload_text,
        signature=signature,
        protected_bytes=protected_bytes,
        payload_bytes=payload_bytes,
        signing_input=signing_input,
    )


@dataclass(frozen=True)
class SigningInput:
    kind: str  # "grant" | "proof" | "boundary_anchor" | "key_transition"
    protected_segment: bytes  # base64url text
    payload_segment: bytes    # base64url text


_KINDS = ("grant", "proof", "boundary_anchor", "key_transition")


def assemble_compact(signing_input: SigningInput, signature: bytes) -> Result[bytes]:
    """``assemble_compact``: SigningInput + 64-byte signature → Ok<compact> | Err.

    REQ1-VERIFY-no-signer-callback: takes a signature, never a key. Cross-vendor #21: returns
    Result, mirroring the Elixir ``{:ok, binary} | {:error, :invalid}`` and the other 15 façade
    functions.
    """
    try:
        if signing_input.kind not in _KINDS:
            fail("assemble_compact: kind closed set")
        require(len(signature) == 64, "assemble_compact: signature width 64")
        sig_b64 = base64url_encode(signature)
        return Ok(
            signing_input.protected_segment
            + bytes([_DOT])
            + signing_input.payload_segment
            + bytes([_DOT])
            + sig_b64
        )
    except InvalidError:
        return err()
