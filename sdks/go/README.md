# `bounded-authority-protocol-go`

Typed, provider-neutral **verifier** library that reimplements the BAP v1 verification profile from the
published spec ([`spec/bap-v1.md`](../../spec/bap-v1.md)), the governing ADRs, and the published
conformance corpus ([`priv/conformance/v1/corpus/`](../../priv/conformance/v1/corpus/)) — authored from spec +
corpus **alone** with no code-level derivation from the Elixir reference or the sibling SDKs
([ADR 0014](../../docs/adr/0014-cross-language-verifier-sdks.md) D5).

This is a **verifier, not an authority runtime**: a successful result proves only that caller-supplied bytes
satisfy caller-supplied trusted inputs. It never selects keys, reserves replay, or grants execution.

The module also exposes the byte-distinct local-development profile through
`LocalLoopbackHTTPUriNormalize`, `LocalLoopbackHTTPProofSigningInput`,
`AssembleLocalLoopbackHTTPCompact`, `DecodeLocalLoopbackHTTPProof`, and
`CheckLocalLoopbackHTTPEnvelope`. It accepts only literal `127.0.0.1`/`[::1]` HTTP targets and a
mandatory nonce; standard `dpop+jwt` APIs reject its bytes.

## Status

Not yet published to a Go module proxy. Per the [SDK graduation model](../../docs/adr/0015-sdk-graduation-and-publish-topology.md),
this SDK graduates to its own repository (`bounded_authority_protocol_go`) on first publication — never from
this monorepo. The module path `github.com/baselabs/bounded_authority_protocol_go` is the reserved identifier
recorded for the graduated publish.

- Go floor: **1.25** (`go.mod`); the CI job installs exactly 1.25 so the floor is the tested floor.
- Runtime dependencies: **zero** — stdlib only (`crypto/ed25519`, `crypto/sha256`, and pure stdlib
  parsing/formatting packages). Verified by [`tools/license_check.sh`](tools/license_check.sh).
- Platform floor: **64-bit** — the bounds fields hold 9,007,199,254,740,991 as `int` (compile-time
  overflow on 32-bit targets; fail-closed, but unsupported).

## Conformance

Passes all **283** published conformance vectors, recomputed from scratch, and SHA-binds the vendored corpus
`index.json` at startup (`TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs`) — a mismatched vendored corpus fails
closed rather than drifting silently. Every case file is verified against the index's per-file SHA-256, and
the two-boundary key census is asserted per run (observed import-boundary thumbprints ==
`index.json` `public_key_fingerprints`, both directions; at authoring: `agreed=283 disagreed=0 census=11`).

```bash
go test ./conformance/   # agreed=283 disagreed=0 + census
```

## The public façade

The 17-function v1 verification contract (see `spec/bap-v1.md` § Public verification contract) plus the
versioned primitives, translated to Go idioms:

- **Producers**: `GrantSigningInput`, `ProofSigningInput`, `BoundaryAnchorSigningInput`,
  `KeyTransitionSigningInput`, `AssembleCompact` (nil bounds = profile maximum; a `*Bounds` threads the
  caller's tightening-only limits through the assemble gates — [ADR 0018](../../docs/adr/0018-sdk-bounds-contract.md) D4),
  `EncodeConsumptionEntry`, `EncodeAnchoredExport`, `RequestDigest`.
- **Decoders / locator**: `DecodeGrant`, `DecodeProof`, `UntrustedKeyLocator`.
- **Verifiers**: `VerifyGrant`, `CheckEnvelope`, `VerifyHistoricalAnchor`, `VerifyKeyTransition`, `CheckChain`,
  `VerifyAnchoredExport`.
- **Versioned primitives**: `JsonDecode` / `JcsEncode` (the tagged JSON algebra), `Base64urlDecode` /
  `Base64urlEncode`, `UriNormalize`, the `Jwk*` thumbprint family, `BoundsMaximum` / `BoundsNew`.

Every fallible function returns `(T, error)` where the error is either `nil` or exactly `ErrInvalid`;
infallible constructors and encoders return their value directly. The facts structs (`GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`,
`KeyTransitionFacts`, `AnchoredExportFacts`) are value-bearing and redacted by construction: they contain only
their documented fields and carry `AuthorizationNotEvaluated` / `TrustNotEvaluated`. There is no
`Authorized`/`Allowed`/decision surface.

## Permissiveness battery (no F1 debt)

Beyond the corpus, the SDK ships a per-clause red-capable battery
([`tests/permissiveness_test.go`](tests/permissiveness_test.go) + the white-box legs in
[`permissiveness_internal_test.go`](permissiveness_internal_test.go)). Every closure and gate is pinned by a
leg that goes **RED when the gate is mechanically removed** — all proven at authoring, unlike the shipped-SDK
round-12..17 pin debt ([ADR 0017](../../docs/adr/0017-inter-sdk-behavioral-contract.md) honest limit, which
BAP-16 was required not to repeat):

- duplicate-rejecting decoder (any depth), raw-lexeme 64-byte ceiling, single-value + trailing rejection,
  int/float tag distinction, source-order preservation, base64url canonicality (pad bits);
- per-node JCS encode-bounds closure (depth/nodes/members/items/string/name bytes, magnitude, duplicate keys);
- ADR 0017 clause 1 — closed Result surface: no panic escapes any façade (recover guard + panic-through leg
  through the public `VerifyAnchoredExport`);
- ADR 0017 clause 3 — pre-digest expected-context hoist with a **zero-hash work pin** (Go's work-observation
  channel is the internal `archiveDigest` seam — the Python-monkeypatch equivalent without monkeypatching);
- ADR 0017 clause 4 — signature width gated at decode; canonical byte-equality for anchor/transition
  segments. The canonical gate's macro-path verdict is **subsumed** (verify: by Ed25519; encode: by the
  archive digest) — the ADR 0017 subsumption pattern — so its red-capable pin is the unit-level
  `TestCanonicalGateUnit`;
- ADR 0017 clause 5 — role-bounded frame reads (`anchor_bytes`, `chain_row_bytes`);
- skew / proof-max-age ceilings (a misconfigured caller is rejected, never silently widened);
- overflow fail-closure on extreme sequence values;
- ADR 0018 bounds threading at every ceiling (chain, anchor, assemble, json, archive) and the D2
  nested-pins identity semantics on the export expected struct.

## What this SDK does NOT do

No I/O, filesystem, clock, RNG, network, environment, or process-spawn in the library path
([`tools/purity_check.sh`](tools/purity_check.sh) enforces it, import allowlist included). No trust discovery,
key custody, signing, replay reservation, revocation state, issuance, or business authorization — those belong
to the host. No registry-publish infrastructure (ADR 0015; the `sdk-publish-guard` hook and CI job reject it).

## Development

```bash
gofmt -l . && go vet ./...
go test ./...                            # library + battery + conformance (283 + census)
sh tools/purity_check.sh && sh tools/license_check.sh
```

The library path is built from `spec/bap-v1.md` + the ADRs + RFCs + the conformance corpus **only**
(ADR 0014 D5: no derivation from the Elixir reference or a sibling SDK).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
