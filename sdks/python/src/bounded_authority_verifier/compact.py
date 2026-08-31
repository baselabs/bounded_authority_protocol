"""JWS compact serialization (RFC 7515) — the 3-segment wire shape:
``base64url(protected) || "." || base64url(payload) || "." || base64url(signature)``.

The signing input (REQ1-SIGNING-exact-input) is ``ASCII(base64url(protected) || "." ||
base64url(payload))`` — no signature, no extra bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
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
    # Cross-vendor F2: re-validate caller-supplied bounds (a hand-crafted Bounds can widen limits past
    # MAXIMA, bypassing bounds_new). Mirrors the reference's Bounds.coerce on every entry point.
    b = coerce_bounds(bounds)
    if len(data) > bounds_resolve(b, "compact_bytes"):
        fail("compact: byte bound")
    if len(data) == 0:
        fail("compact: empty")
    # Split into exactly 3 segments on '.'.
    dots = [i for i, byte in enumerate(data) if byte == _DOT]
    if len(dots) != 2:
        fail("compact: three segments")
    d0 = dots[0]
    d1 = dots[1]
    if d0 == 0 or d1 == d0 + 1 or d1 == len(data) - 1:
        fail("compact: empty segment")
    protected_text = data[:d0]
    payload_text = data[d0 + 1:d1]
    signature_text = data[d1 + 1:]
    if len(protected_text) > bounds_resolve(b, "encoded_segment_bytes"):
        fail("compact: protected segment bound")
    if len(payload_text) > bounds_resolve(b, "encoded_segment_bytes"):
        fail("compact: payload segment bound")
    protected_bytes = base64url_decode(protected_text, bounds_resolve(b, "decoded_segment_bytes"))
    payload_bytes = base64url_decode(payload_text, bounds_resolve(b, "decoded_segment_bytes"))
    signature = base64url_decode(signature_text)
    # Decoded signature-width gate (runtime.ex:237 parse_grant, :259 parse_proof,
    # boundary_anchor_codec.ex:88, key_transition_codec.ex:120 all enforce byte_size(signature) ==
    # signature_bytes). scan_compact (the ath/hash gate) intentionally does NOT — it mirrors
    # CompactJws.scan (shape+size only); the decoded-width check belongs to the decode path.
    if len(signature) != bounds_resolve(b, "signature_bytes"):
        fail("compact: signature width")
    signing_input = protected_text + bytes([_DOT]) + payload_text
    return CompactSegments(
        protected_segment=protected_text,
        payload_segment=payload_text,
        signature=signature,
        protected_bytes=protected_bytes,
        payload_bytes=payload_bytes,
        signing_input=signing_input,
    )


def scan_compact(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    """Faithful port of the reference ``CompactJws.scan`` (compact_jws.ex:16-27): the shape+size gate
    that ``ath``/``hash`` run BEFORE hashing a compact. Validates structure + bounds only — NOT
    base64url canonicity (canonicity is the full verify path's job via parse_compact). The producer
    ath (proof signing input) and the verify grant-hash both gate on this so a non-compact grant
    (wrong segment count, oversized, dotted signature) is rejected rather than hashed. Mirrors the
    Rust scan_compact gate added in the BAP-15 closeout.
    """
    b = coerce_bounds(bounds)
    if len(data) > bounds_resolve(b, "compact_bytes"):
        fail("compact: byte bound")
    if len(data) == 0:
        fail("compact: empty")
    dots = [i for i, byte in enumerate(data) if byte == _DOT]
    if len(dots) != 2:
        fail("compact: three segments")
    d0 = dots[0]
    d1 = dots[1]
    if d0 == 0 or d1 == d0 + 1 or d1 == len(data) - 1:
        fail("compact: empty segment")
    seg_bytes = bounds_resolve(b, "encoded_segment_bytes")
    if d0 > seg_bytes:
        fail("compact: protected segment bound")
    if d1 - d0 - 1 > seg_bytes:
        fail("compact: payload segment bound")
    if len(data) - d1 - 1 > seg_bytes:
        fail("compact: signature segment bound")
    # signature dot-free: exactly 2 dots guarantees no dot inside the signature segment.


@dataclass(frozen=True)
class SigningInput:
    kind: str  # "grant" | "proof" | "local_loopback_http_proof" | "boundary_anchor" | "key_transition"
    protected_segment: bytes  # base64url text
    payload_segment: bytes    # base64url text


_KINDS = ("grant", "proof", "local_loopback_http_proof", "boundary_anchor", "key_transition")


def assemble_segments(signing_input: SigningInput, signature: bytes) -> Result[bytes]:
    """``assemble_segments``: the LOW-LEVEL compact assembler (mirrors CompactJws.assemble's byte
    assembly, compact_jws.ex:41-43). Validates only the kind closed-set + 64-byte signature width,
    then concatenates protected.payload.base64url(signature). It does NOT validate the signing-input
    header/payload content — that is the v1.py ``assemble_compact`` FAÇADE's job (re-parse per kind,
    runtime.ex:151 validate_assembled_compact). Test helpers and conformance use this to build
    compacts freely; the public contract is the façade (assemble_compact in v1.py).

    REQ1-VERIFY-no-signer-callback: takes a signature, never a key. Returns Result, mirroring the
    Elixir ``{:ok, binary} | {:error, :invalid}``.
    """
    try:
        if signing_input.kind not in _KINDS:
            fail("assemble_segments: kind closed set")
        require(len(signature) == 64, "assemble_segments: signature width 64")
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
