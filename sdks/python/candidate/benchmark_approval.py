"""CI performance gate for complete candidate approval verification."""

from __future__ import annotations

import math
import platform
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib.metadata import distribution
from pathlib import Path
from time import perf_counter_ns

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from bounded_authority_verifier import HistoricalPublicKey, content_assertion, content_assertion_es256, v3
from bounded_authority_verifier.action_approval import (
    ApprovalContext,
    Diagnostic,
    Suite,
    TrustEntry,
    TrustSnapshot,
    VerifiedApprovalFacts,
    _snapshot,
    verify_approval_eddsa,
    verify_approval_es256,
)
from bounded_authority_verifier.approval_record import (
    PROFILE,
    PROFILE_DIGEST,
    ApprovalRecord,
    RecordBounds,
    encode_record,
)
from bounded_authority_verifier.error import _unwrap

WARMUP = 30
SAMPLES = 200
P99_LIMIT_NS = 5_000_000


@dataclass(frozen=True)
class Case:
    wire: bytes
    compact: bytes
    context: ApprovalContext


def build_case(suite: Suite, ordinal: int, *, at_cap: bool) -> Case:
    limit = RecordBounds().record_bytes
    width = 124 if at_cap else 64
    resources = tuple(f'{index:04d}/"\\\n' + "x" * (width - 8) for index in range(500))
    assert all(len(resource.encode("utf-8")) == width for resource in resources)
    request_id = f"request-{ordinal}"
    revision = ordinal.to_bytes(32, "big")
    record = ApprovalRecord("image-indexer", "index", request_id, "image-review", resources, revision)
    wire = _unwrap(encode_record(record))
    if at_cap:
        resources = (*resources[:-1], resources[-1] + "x" * (limit - len(wire)))
        record = ApprovalRecord("image-indexer", "index", request_id, "image-review", resources, revision)
        wire = _unwrap(encode_record(record))
        assert len(wire) == limit
    kid = f"key-{ordinal}"
    claims = content_assertion.ContentAssertion(
        kid, f"event-{ordinal}", "reviewer", "image-host", request_id, PROFILE, PROFILE_DIGEST,
        _unwrap(content_assertion.content_digest(wire)), 1, bytes(32), 10, 10, 60,
    )
    if suite is Suite.EDDSA:
        signer = ed25519.Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes_raw()
        signing = _unwrap(content_assertion.assertion_signing_input(claims))
        signature = signer.sign(signing.protected_segment + b"." + signing.payload_segment)
        compact = _unwrap(content_assertion.assemble_content_assertion_compact(signing, signature))
    else:
        p256 = ec.generate_private_key(ec.SECP256R1())
        public = p256.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
        )
        signing = _unwrap(content_assertion_es256.assertion_signing_input(claims))
        r, s = decode_dss_signature(p256.sign(
            signing.protected_segment + b"." + signing.payload_segment, ec.ECDSA(hashes.SHA256()),
        ))
        signature = r.to_bytes(32, "big") + min(s, v3.P256_N - s).to_bytes(32, "big")
        compact = _unwrap(content_assertion_es256.assemble_compact(signing, signature))
    entry = TrustEntry("reviewer", HistoricalPublicKey(kid, public, 0, 60), ("image-review",))
    snapshot = TrustSnapshot(suite, "image-index", "local configuration", 15, (entry,))
    context = ApprovalContext(
        "image-index", "image-host", request_id, revision, "image-indexer", "index",
        resources, ("image-review",), 20, 5, 50, snapshot,
    )
    return Case(wire, compact, context)


def p99(samples: Sequence[int]) -> int:
    return sorted(samples)[math.ceil(len(samples) * 0.99) - 1]


def benchmark(suite: Suite, *, at_cap: bool) -> bool:
    count = WARMUP + SAMPLES
    offset = (int(suite is Suite.ES256) * 2 + int(at_cap)) * count
    cases = tuple(build_case(suite, i, at_cap=at_cap) for i in range(offset, offset + count))
    verify: Callable[[bytes, bytes, ApprovalContext], VerifiedApprovalFacts | Diagnostic]
    verify = verify_approval_eddsa if suite is Suite.EDDSA else verify_approval_es256
    admitted_ns: list[int] = []
    predicate_ns: list[int] = []
    verification_ns: list[int] = []
    revoked_keys = frozenset({("old-key", bytes(32))})
    observed_events = frozenset({("image-index", "reviewer", "previous-event")})

    def is_revoked(entry: TrustEntry, fingerprint: bytes) -> bool:
        return (entry.key.key_id, fingerprint) in revoked_keys

    def is_replayed(domain: str, issuer: str, event: str) -> bool:
        return (domain, issuer, event) in observed_events

    for index, case in enumerate(cases):
        ctx = case.context
        start = perf_counter_ns()
        result = verify(case.wire, case.compact, ctx)
        full = perf_counter_ns() - start
        assert isinstance(result, VerifiedApprovalFacts), result

        start = perf_counter_ns()
        entries = _snapshot(ctx.snapshot, suite, ctx.trust_domain, ctx.bounds, ctx.record_bounds)
        admitted = perf_counter_ns() - start
        entry, fingerprint = entries[result.assertion.attestor_key_id]
        identity = result.trust_domain, result.assertion.iss, result.assertion.jti
        start = perf_counter_ns()
        revoked = is_revoked(entry, fingerprint)
        replayed = is_replayed(*identity)
        predicates = perf_counter_ns() - start
        assert not revoked and not replayed
        if index >= WARMUP:
            verification_ns.append(full)
            admitted_ns.append(admitted)
            predicate_ns.append(predicates)

    full_p99 = p99(verification_ns)
    label = "encoded-cap" if at_cap else "500x64"
    sizes = [len(case.wire) for case in cases]
    print(
        f"{suite.value} {label} record_bytes_min={min(sizes)} record_bytes_max={max(sizes)} "
        f"verification_p99_ms={full_p99 / 1e6:.3f} "
        f"snapshot_admission_p99_ms={p99(admitted_ns) / 1e6:.3f} "
        f"host_predicates_p99_ms={p99(predicate_ns) / 1e6:.3f}",
        flush=True,
    )
    return full_p99 <= P99_LIMIT_NS


def main() -> None:
    if sys.version_info[:2] not in {(3, 11), (3, 12)}:
        raise SystemExit("Run the approval performance gate on Python 3.11 or 3.12")
    cpu = next(
        line.partition(":")[2].strip()
        for line in Path("/proc/cpuinfo").read_text().splitlines()
        if line.startswith("model name")
    )
    crypto = distribution("cryptography")
    wheel = crypto.read_text("WHEEL")
    assert wheel is not None
    print(f"runner={platform.platform()} cpu={cpu} python={platform.python_version()}")
    print(f"cryptography={crypto.version} openssl={backend.openssl_version_text()}\n{wheel.rstrip()}")
    print(f"warmup={WARMUP} samples={SAMPLES} quantile=nearest-rank-p99 ceiling_ms={P99_LIMIT_NS / 1e6:g}")
    outcomes = [benchmark(suite, at_cap=at_cap) for suite in Suite for at_cap in (False, True)]
    if not all(outcomes):
        raise SystemExit("Approval verification exceeded the p99 ceiling")


if __name__ == "__main__":
    main()
