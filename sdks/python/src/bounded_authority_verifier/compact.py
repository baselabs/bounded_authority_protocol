"""JWS compact serialization (RFC 7515) — the 3-segment wire shape:
``base64url(protected) || "." || base64url(payload) || "." || base64url(signature)``.

The signing input (REQ1-SIGNING-exact-input) is ``ASCII(base64url(protected) || "." ||
base64url(payload))`` — no signature, no extra bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
from .ed25519 import _signature_gate
from .error import InvalidError, Ok, Result, _fail, _require, _unwrap, err

_DOT = 0x2E


@dataclass(frozen=True)
class CompactSegments:
    protected_segment: bytes   # the raw base64url TEXT (not decoded)
    payload_segment: bytes
    signature: bytes           # decoded raw bytes (64 for Ed25519)
    protected_bytes: bytes     # decoded
    payload_bytes: bytes       # decoded
    signing_input: bytes       # ASCII(protected "." payload) text


def _parse_compact(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> CompactSegments:
    """Parse + bound a compact input into 3 segments. Validates the segment count, bounds, canonical
    base64url of each segment, and decodes protected + payload (signature kept raw after decode)."""
    # Cross-vendor F2: re-validate caller-supplied bounds (a hand-crafted Bounds can widen limits past
    # MAXIMA, bypassing bounds_new). Mirrors the reference's Bounds.coerce on every entry point.
    b = _unwrap(coerce_bounds(bounds))
    if len(data) > _unwrap(bounds_resolve(b, "compact_bytes")):
        _fail("compact: byte bound")
    if len(data) == 0:
        _fail("compact: empty")
    # Split into exactly 3 segments on '.'.
    dots = [i for i, byte in enumerate(data) if byte == _DOT]
    if len(dots) != 2:
        _fail("compact: three segments")
    d0 = dots[0]
    d1 = dots[1]
    if d0 == 0 or d1 == d0 + 1 or d1 == len(data) - 1:
        _fail("compact: empty segment")
    protected_text = data[:d0]
    payload_text = data[d0 + 1:d1]
    signature_text = data[d1 + 1:]
    if len(protected_text) > _unwrap(bounds_resolve(b, "encoded_segment_bytes")):
        _fail("compact: protected segment bound")
    if len(payload_text) > _unwrap(bounds_resolve(b, "encoded_segment_bytes")):
        _fail("compact: payload segment bound")
    protected_bytes = _unwrap(base64url_decode(protected_text, _unwrap(bounds_resolve(b, "decoded_segment_bytes"))))
    payload_bytes = _unwrap(base64url_decode(payload_text, _unwrap(bounds_resolve(b, "decoded_segment_bytes"))))
    signature = _unwrap(base64url_decode(signature_text))
    # spec/bap-v1.md §14 and §16 require the fixed decoded signature width.
    # The hash-only scan checks compact shape and size; decode checks the width.
    if len(signature) != _unwrap(bounds_resolve(b, "signature_bytes")):
        _fail("compact: signature width")
    signing_input = protected_text + bytes([_DOT]) + payload_text
    return CompactSegments(
        protected_segment=protected_text,
        payload_segment=payload_text,
        signature=signature,
        protected_bytes=protected_bytes,
        payload_bytes=payload_bytes,
        signing_input=signing_input,
    )


def _scan_compact(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    """Validate compact shape and size before hashing (spec/bap-v1.md §14).

    Canonical base64url and decoded signature width belong to the full decode
    path. A malformed or oversized compact must be rejected before its hash is used.
    """
    b = _unwrap(coerce_bounds(bounds))
    if len(data) > _unwrap(bounds_resolve(b, "compact_bytes")):
        _fail("compact: byte bound")
    if len(data) == 0:
        _fail("compact: empty")
    dots = [i for i, byte in enumerate(data) if byte == _DOT]
    if len(dots) != 2:
        _fail("compact: three segments")
    d0 = dots[0]
    d1 = dots[1]
    if d0 == 0 or d1 == d0 + 1 or d1 == len(data) - 1:
        _fail("compact: empty segment")
    seg_bytes = _unwrap(bounds_resolve(b, "encoded_segment_bytes"))
    if d0 > seg_bytes:
        _fail("compact: protected segment bound")
    if d1 - d0 - 1 > seg_bytes:
        _fail("compact: payload segment bound")
    if len(data) - d1 - 1 > seg_bytes:
        _fail("compact: signature segment bound")
    # signature dot-free: exactly 2 dots guarantees no dot inside the signature segment.


@dataclass(frozen=True)
class SigningInput:
    kind: str  # Closed profile-specific kind; see _KINDS.
    protected_segment: bytes  # base64url text
    payload_segment: bytes    # base64url text


_KINDS = (
    "grant",
    "proof",
    "local_loopback_http_proof",
    "boundary_anchor",
    "key_transition",
    "role_attestation",
    "content_assertion",
)


def assemble_segments(signing_input: SigningInput, signature: bytes) -> Result[bytes]:
    """Assemble protected.payload.base64url(signature) (spec/bap-v1.md §14).

    This internal byte assembler checks the kind and signature canonicality. Public
    profile producers also reparse the assembled header and payload under §16.
    REQ1-VERIFY-no-signer-callback: it takes a signature, never a key.
    """
    try:
        if signing_input.kind not in _KINDS:
            _fail("assemble_segments: kind closed set")
        _require(len(signature) == 64, "assemble_segments: signature width 64")
        # Erratum 3 (REQ1/REQ2-SIGNING-ed25519-producer-canonical): assembly is a producer
        # surface — it frames a signature and verifies none — so it refuses a signature that
        # fails the keyless part of rule S1 and emits accepted bytes unchanged. Every Ed25519
        # assembler (contract-majors 1 and 2, local loopback, role attestation, content
        # assertion) assembles through this function.
        _require(_signature_gate(signature), "assemble_segments: signature canonicality")
        sig_b64 = _unwrap(base64url_encode(signature))
        return Ok(
            signing_input.protected_segment
            + bytes([_DOT])
            + signing_input.payload_segment
            + bytes([_DOT])
            + sig_b64
        )
    except InvalidError:
        return err()


def assemble_segments_es256(signing_input: SigningInput, signature: bytes) -> Result[bytes]:
    """The ES256 counterpart of ``assemble_segments`` (mirrors the reference's separate
    V3.CompactJws assembler: the standard kind closed set + 64-byte width, then the same byte
    assembly). The canonical-signature gate is the v3 façade's, as it is the reference
    runtime's: a raw r || s is big-endian and low-S, never little-endian R || S.

    REQ1-VERIFY-no-signer-callback: takes a signature, never a key.
    """
    try:
        if signing_input.kind not in ("grant", "proof", "boundary_anchor", "key_transition"):
            _fail("assemble_segments: kind closed set")
        _require(len(signature) == 64, "assemble_segments: signature width 64")
        sig_b64 = _unwrap(base64url_encode(signature))
        return Ok(
            signing_input.protected_segment
            + bytes([_DOT])
            + signing_input.payload_segment
            + bytes([_DOT])
            + sig_b64
        )
    except InvalidError:
        return err()
