# `bounded-authority-protocol` (Rust)

Typed, provider-neutral **verifier** library that reimplements the BAP v1 verification profile from the
published spec ([`docs/protocol-v1.md`](../../docs/protocol-v1.md)) and the published conformance corpus
([`priv/conformance/v1/corpus/`](../../priv/conformance/v1/corpus/)). Authored from the spec + corpus
**alone** with no code-level derivation from the Elixir reference ([ADR 0014](../../docs/adr/0014-cross-language-verifier-sdks.md)).

This is a **verifier, not an authority runtime**: a successful result proves only that caller-supplied
bytes satisfy caller-supplied trusted inputs. It never selects keys, reserves replay, or grants execution.

## Status

Not yet published to crates.io. Per the [SDK graduation model](../../docs/adr/0015-sdk-graduation-and-publish-topology.md),
each SDK graduates to its own per-SDK repository (`bounded_authority_protocol_rust`) on first publication —
never from this monorepo. The crate name `bounded-authority-protocol` is a reserved identifier recorded for
the graduated publish.

- MSRV: **1.81** (`rust-toolchain.toml`).
- Runtime dependencies: `ed25519-dalek` (default-features = false), `sha2`, `ryu-js` — see
  [Deployment](../../docs/deployment/rust-sdk.md) for the supply-chain and sandbox posture.
- `#![forbid(unsafe_code)]` covers this crate (transitive `unsafe` in the crypto backend remains; see the
  deployment guide).

## Conformance

Passes all **283** published conformance vectors, recomputed from scratch (not cached verdicts), and
SHA-binds the vendored corpus `index.json` at startup — a mismatched vendored corpus fails closed rather
than drifting silently. The two-boundary key census is asserted per-run (observed import-boundary keys ==
`index.json` `public_key_fingerprints`, both directions).

```bash
cargo test --test conformance   # agreed=283 disagreed=0 + census
```

Beyond the frozen corpus, the crate ships a **per-language permissiveness mutation-gate battery**
([`tests/permissiveness.rs`](tests/permissiveness.rs)): for every host-runtime closure (duplicate-rejecting
decoder, source-order preservation, raw-lexeme scan, single-value, int/float tag distinction, and the
`(d)`-class per-node encode-bounds in `jcs_encode`), a red-capable test that constructs the host-specific
defect the closure defeats and proves it goes RED when the closure is removed. The base64url non-canonical
pad-bits rejection (corpus-blind) is covered there too, as is the decode-path conformance
class (decoded signature width at decode + anchor/transition canonical-form byte-equality,
including the pinning legs that guard the grant/proof canonical EXCLUSION the reference
imposes nowhere).

```bash
cargo test --test permissiveness   # 19 tests: closures + conformance legs + exclusion pins, each red-capable
```

## The public façade

The 17-function v1 verification contract (see [`docs/protocol-v1.md`](../../docs/protocol-v1.md) § Public
verification contract) plus the versioned primitives:

- **Producers**: `grant_signing_input`, `proof_signing_input`, `boundary_anchor_signing_input`,
  `key_transition_signing_input`, `assemble_compact`, `encode_consumption_entry`, `encode_anchored_export`,
  `request_digest`.
- **Decoders / locator**: `decode_grant`, `decode_proof`, `untrusted_key_locator`.
- **Verifiers**: `verify_grant`, `check_envelope`, `verify_historical_anchor`, `verify_key_transition`,
  `check_chain`, `verify_anchored_export`.
- **Versioned primitives**: `json_decode`, `jcs_encode`, `base64url_decode`/`base64url_encode`, `uri_normalize`,
  the `jwk_*` thumbprint family, `Bounds`.

Every function returns `Result<T>` (`Ok<T>` | `Err(Invalid)`) — exactly one value-free error shape. The
facts structs (`GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`,
`AnchoredExportFacts`) are value-bearing, redacted by construction, derive `Debug` only (no `Serialize`/
`Display` — they cannot be serialized into a credential), and carry `authorization: NotEvaluated` (or
`trust: NotEvaluated` for the chain/anchor/transition/export facts).

## What this SDK does NOT do

No I/O, filesystem, clock, RNG, network, environment, or process-spawn in the library path
([`tools/purity_check.sh`](tools/purity_check.sh) enforces it). No trust discovery, key custody, signing,
replay reservation, revocation state, issuance, or business authorization — those belong to the host.
There is no `authorized?`/`allowed?`/`decision` surface.

## Development

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
cargo test                                   # lib + permissiveness + conformance
sh tools/purity_check.sh && sh tools/license_check.sh
```

The library path is built from `docs/protocol-v1.md` + the ADRs + RFCs + the conformance corpus **only**
(ADR 0014 D5: no derivation from the Elixir reference or a sibling SDK).

## Deployment

See [`docs/deployment/rust-sdk.md`](../../docs/deployment/rust-sdk.md) for AWS Lambda (`provided.al2023`)
and PostgreSQL `plrust` binding guidance, including the plrust-trusted-mode incompatibility.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
