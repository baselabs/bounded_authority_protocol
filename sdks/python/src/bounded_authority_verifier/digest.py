"""The request digest (protocol-v1.md § Signing and digest inputs, L238-264)::

    base64url(SHA-256("BAP1-REQUEST\\0" || JCS([operation, typed(cast_arguments)])))

The prefix is exact ASCII including its final zero byte (REQ1-SIGNING-digest-prefix). ``typed()``
projects the tagged JSON algebra to the closed ``["tag", value]`` JSON form before JCS, preserving the
int/float distinction (REQ1-SELECTOR-semantic-identity depends on it).
"""

from __future__ import annotations

from .base64url import base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .ed25519 import sha256
from .error import InvalidError, Ok, Result, err, fail, invalid_error
from .jcs import jcs_encode
from .json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString, Tagged, str_utf8

REQUEST_PREFIX = b"BAP1-REQUEST\x00"
"""The 13-byte ASCII prefix including its final zero byte (REQ1-SIGNING-digest-prefix)."""


def typed_project(value: Tagged) -> Tagged:
    """``typed()`` projection: tagged value → ``["tag", value]`` JSON array (protocol-v1.md:247-256).

    - ``null`` → ``["null"]``; ``bool`` → ``["boolean", v]``; ``int`` → ``["integer", v]``;
      ``float`` → ``["float", v]``; ``string`` → ``["string", v]``;
    - ``array`` → ``["array", [typed(v)...]]``; ``object`` → ``["object", {k: typed(v)...}]``
    """
    if isinstance(value, JNull):
        return JArray((JString(str_utf8("null")),))
    if isinstance(value, JBool):
        return JArray((JString(str_utf8("boolean")), JBool(value.v)))
    if isinstance(value, JInt):
        return JArray((JString(str_utf8("integer")), JInt(value.v)))
    if isinstance(value, JFloat):
        return JArray((JString(str_utf8("float")), JFloat(value.v)))
    if isinstance(value, JString):
        return JArray((JString(str_utf8("string")), JString(value.v)))
    if isinstance(value, JArray):
        return JArray((JString(str_utf8("array")), JArray(tuple(typed_project(i) for i in value.v))))
    if isinstance(value, JObject):
        out = {k: typed_project(v) for k, v in value.v.items()}
        return JArray((JString(str_utf8("object")), JObject(out)))
    raise invalid_error("typed: unknown tag")  # unreachable — the algebra is closed


def request_digest(operation: str, cast_arguments: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> bytes:
    """``request_digest(operation, cast_arguments, bounds?)``. Returns the raw 32-byte digest.

    ``operation`` is validated printable ASCII 1..128.
    """
    op_bytes = str_utf8(operation)
    if not (1 <= len(op_bytes) <= bounds_resolve(bounds, "operation_bytes")):
        fail("request_digest: operation bound")
    for b in op_bytes:
        if b < 0x20 or b > 0x7E:
            fail("request_digest: operation printable ASCII")
    # The projection: [operation_string, typed(cast_arguments)].
    projected = typed_project(cast_arguments)
    array: Tagged = JArray((JString(op_bytes), projected))
    # Per-node bounds on the TYPED projection (not the raw args): `typed` deepens/triples the tree, so
    # the depth boundary is ~15 (not 32) and total_nodes is reachable inline.
    if not _within_tagged_bounds(array, 0, bounds):
        fail("request_digest: cast_arguments bounds")
    if _count_tagged_nodes(array) > bounds_resolve(bounds, "total_nodes"):
        fail("request_digest: total_nodes")
    jcs = jcs_encode(array, bounds)
    if len(jcs) > bounds_resolve(bounds, "jcs_bytes"):
        fail("request_digest: jcs_bytes")
    return sha256(REQUEST_PREFIX, jcs)


def _within_tagged_bounds(v: Tagged, level: int, bounds: Bounds) -> bool:
    """Per-node-type bounds gate over the tagged algebra (mirrors the official Jcs.encode per-node gate)."""
    if isinstance(v, (JNull, JBool)):
        return level <= bounds_resolve(bounds, "depth")
    if isinstance(v, JInt):
        return level <= bounds_resolve(bounds, "depth") and abs(v.v) <= bounds_resolve(
            bounds, "integer_magnitude"
        )
    if isinstance(v, JFloat):
        return (
            level <= bounds_resolve(bounds, "depth")
            and v.v == v.v  # not NaN
            and v.v not in (float("inf"), float("-inf"))
            and abs(v.v) <= bounds_resolve(bounds, "float_magnitude")
        )
    if isinstance(v, JString):
        return level <= bounds_resolve(bounds, "depth") and len(v.v) <= bounds_resolve(
            bounds, "string_bytes"
        )
    if isinstance(v, JArray):
        return (
            level < bounds_resolve(bounds, "depth")
            and len(v.v) <= bounds_resolve(bounds, "array_items")
            and all(_within_tagged_bounds(item, level + 1, bounds) for item in v.v)
        )
    if isinstance(v, JObject):
        return (
            level < bounds_resolve(bounds, "depth")
            and len(v.v) <= bounds_resolve(bounds, "object_members")
            and all(_within_tagged_bounds(val, level + 1, bounds) for val in v.v.values())
        )
    return False  # type: ignore[unreachable] # unreachable — the algebra is closed


def _count_tagged_nodes(v: Tagged) -> int:
    """Node count: one node per value (scalar OR container); object keys are not nodes."""
    if isinstance(v, JArray):
        return 1 + sum(_count_tagged_nodes(item) for item in v.v)
    if isinstance(v, JObject):
        return 1 + sum(_count_tagged_nodes(val) for val in v.v.values())
    return 1


def request_digest_b64url(operation: str, cast_arguments: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[str]:
    """base64url-encoded form (for comparison against proof.ba_req which is base64url).

    Returns Ok<str> | Err (cross-vendor #21 + the bounds-ignored note: bounds threaded into the digest).
    """
    try:
        raw = request_digest(operation, cast_arguments, bounds)
        return Ok(base64url_encode(raw).decode("ascii"))
    except InvalidError:
        return err()
