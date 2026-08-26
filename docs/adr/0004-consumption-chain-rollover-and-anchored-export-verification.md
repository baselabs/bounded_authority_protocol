# ADR 0004: Consumption-chain rollover and anchored-export verification

- Status: accepted (superseded as the NORMATIVE home of the byte definitions — see below)
- Date: 2026-07-28

> **Supersession note (2026-08-26).** The consumption row, boundary-anchor, key-transition,
> and archive-framing byte definitions this ADR froze are now NORMATIVE in
> `spec/bap-v1.md` (sections "Consumption chain and anchored export"),
> machine-extracted and drift-gated by the spec-facts machinery. This ADR remains the accepted
> decision record for WHY those formats are shaped as they are; where the two documents could
> ever disagree, the spec is the authority and the disagreement is a gate-red defect.

## Context

BAP-04 must let an offline caller verify an exact range of consumption commitments, its signed
boundary anchors, an authenticated historical Ed25519 key path, and the complete bytes and
out-of-band version of an archived object. The public package cannot discover keys, read storage,
infer caller expectations from the archive, certify deletion, or turn cryptographic facts into
operational authority.

Chain self-consistency alone cannot detect a validly relinked omission or a consistently shortened
range. A current key alone cannot authenticate an old anchor after rollover. A stored digest
alone cannot prove that the caller retrieved the intended object generation.

## Decision

### Consumption rows

<!-- facts:archive-framing -->
One row is the closed JCS object:

```json
{"chain_id":"<StringOrURI>","commitment":"<base64url-32>","previous":"<base64url-32>","sequence":1,"v":1}
```

Its raw hash is `SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)`. Sequence one requires the
all-zero predecessor. Verification accepts a nonempty proper list of raw row binaries and an
`ExpectedChain`; it requires exact canonical bytes, chain identity, consecutive sequence,
predecessor links, row count, first/last sequence, caller predecessor, and caller head.

### Boundary anchors

A boundary anchor is standard compact JWS with exact protected header
`{"alg":"EdDSA","kid":"...","typ":"ba+chain-anchor"}` and a closed JCS payload binding protocol
version, anchor identity and time, chain identity, sequence, chain hash, and the RFC 7638
fingerprint derived from the raw Ed25519 public key. Sequence zero requires the all-zero hash.

The caller supplies one exact `HistoricalPublicKey` and `ExpectedAnchor`. Verification requires
the signed values, key ID, derived fingerprint, Ed25519 signature, and
`valid_from <= anchored_at < valid_before`; `:unbounded` is the only open upper interval.

### Authenticated key transitions

A transition is standard compact JWS with exact protected type `ba+key-transition`. Its closed
payload binds transition and chain identities, effective time, current fingerprint, next key ID,
and next fingerprint. The current key signs it. Current and next public keys/fingerprints must
differ, while their key IDs may be equal; the effective time must lie in both historical
intervals.

An anchored export advances through the caller-supplied ordered key list positionally. Transition
times strictly increase, fingerprints cannot cycle, the start anchor precedes every transition,
and the end anchor is at or after the last transition, including exactly at its effective time.
Equal start/end times are permitted only for the no-transition same-key case.

### Anchored export

The archive is the exact binary concatenation:

```text
"BAP1-ARCHIVE\0EXPORT\0"
frame(canonical_header)
frame(start_anchor_compact)
frame(each ordered transition_compact)
frame(each canonical row)
frame(end_anchor_compact)
EOF
```

Every frame is `UINT32_BE(nonzero_length) || bytes`. The closed header binds chain identity,
first/last sequence, row count, transition count, predecessor, head, and version one. Verification
scans a bounded nonempty proper flat chunk list incrementally, requires exact EOF, hashes every
raw byte, and compares the raw SHA-256 digest in constant time. It also requires exact equality
between the observed object-store version and caller-supplied expected version. The version is
out-of-band context; it is not embedded in the archive.

The verifier authenticates both anchors and every transition, checks all rows again, and requires
the authenticated start/end tuples to equal the caller's chain boundaries. Producer results and
facts are not accepted as stored objects or credentials.

### Results and authority

`ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`, and `AnchoredExportFacts` are closed,
value-bearing, fixed-redacted, and non-authorizing. They implement no generic encoder, string,
enumeration, collection, or access protocol. Every result carries `trust: :not_evaluated`;
anchored-export results additionally carry `authorization: :not_evaluated`.

Every public failure is exactly `{:error, :invalid}`. The library performs no trust lookup, clock
read, network or storage I/O, key custody, signing, callback, state mutation, archive removal,
retention decision, witness submission, or business authorization.

### Bounds

The immutable maxima are 4,096 bytes per row, 65,536 rows, 8,192 bytes per anchor/transition,
8,192 header bytes, 256 transitions, 65,796 chunks, 270,820,384 archive bytes, and 512 object
version bytes. The archive-byte ceiling is exactly:

```text
20 + 8,196 + 2 × 8,196 + 256 × 8,196 + 65,536 × 4,100
```

Callers may only tighten resource ceilings. Ed25519 public-key/signature and SHA-256 digest widths
are immutable protocol constants and cannot be tightened.

## Consequences

- A valid chain proves consistency with caller-supplied boundaries, not completeness by itself.
- Validly signed shortened and relinked archives remain valid under their own boundaries and fail
  the original boundaries; callers must retain or derive the intended boundary context.
- Authenticated transitions let callers advance historical trust without network lookup or
  current-key fallback.
- Exact object-version comparison binds verification to the retrieved object generation.
- BAP-05 generalizes the public corpus and CLI. It does not supply BAP-04's first independent
  implementation proof, which is already required here.
