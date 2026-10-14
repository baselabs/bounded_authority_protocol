# Bounded Authority Protocol verifier for Rust

A pure, deterministic Rust implementation of the Bounded Authority Protocol (BAP) verification
profiles: contract-majors 1 and 2 (Ed25519) and 3 (ES256), the local-loopback HTTP proof
profile, and the role-attestation and content-assertion profiles, with strict Ed25519
verification on every Ed25519 surface.

It checks the exact bytes of a grant, a holder proof, or an evidence object against public keys
and expected context that you supply, and returns redacted facts or the single error `Invalid`.
It is a **verifier, not an authority**: it never selects trusted keys, reserves replay, checks
revocation, or decides whether a request may run. Those stay in your service.

Its behavior is defined by the specifications ([v1](../../spec/bap-v1.md),
[v2](../../spec/bap-v2.md), [v3](../../spec/bap-v3.md), and the sibling profiles under
[`spec/`](../../spec/)) and the certified conformance corpora; source comments cross-reference
the Elixir reference implementation for traceability.

## Status

**Not published.** The crate is not on crates.io; the name `bounded-authority-protocol` is the
one it will use. It moves to its own repository when it is first published
([ADR 0015](../../docs/adr/0015-sdk-graduation-and-publish-topology.md)). Until then, depend on
a checkout of this repository.

- Rust **1.81** or later (`rust-version` in `Cargo.toml`; `rust-toolchain.toml` pins 1.81 for
  development and CI).
- Runtime dependencies: `ed25519-dalek` 2.2 (default features off), `p256` 0.13 (ECDSA only, for
  contract-major 3), `sha2` 0.10, `ryu-js` 1.0, and `zeroize` pinned to exactly 1.8.1 (a
  dependency of `p256`; later 1.x releases need Rust 1.85). See the
  [deployment notes](../../docs/deployment/rust-sdk.md) for the full tree and its `unsafe` use.
- `#![forbid(unsafe_code)]` covers this crate's own source.
- **Erratum 3 (producer canonicality) is not yet implemented.** `assemble_compact` and
  `encode_anchored_export` (and their `v2` and `v3` forms) check the signature width but not its
  value, so they can assemble an Ed25519 signature with `S >= L` or a non-canonical or
  small-order `R`, or an ES256 signature that is out of range or high-S. Every verifier, this
  one included, rejects such a credential. Until this crate implements erratum 3, check a
  signature from an external signer before assembly (for ES256, normalize to low S).

## Install from a checkout

```toml
[dependencies]
bounded-authority-protocol = { path = "../bounded_authority_protocol/sdks/rust" }
```

or pin a commit of the repository:

```toml
[dependencies]
bounded-authority-protocol = { git = "https://github.com/baselabs/bounded_authority_protocol", rev = "<commit>" }
```

## Quickstart

`cargo test` runs this block as a doctest. It signs with `ed25519-dalek` keys from fixed seeds;
in production the private keys stay with the issuer and the holder, and the verifier receives
only public keys.

```rust
use bounded_authority_protocol::types::{
    Credentials, ExpectedRequest, GrantInput, GrantOperation, NonceMode, ProofInput,
    ProducedSigningInput, SigningInput, SigningKind, TrustedIssuer,
};
use bounded_authority_protocol::{
    assemble_compact, check_envelope, grant_signing_input, json_decode, proof_signing_input,
    public_key_thumbprint_raw, Bounds, Invalid,
};
use ed25519_dalek::{Signer, SigningKey};

// assemble_compact takes the two encoded segments and the kind; sign `message`.
fn for_assembly(kind: SigningKind, produced: &ProducedSigningInput) -> SigningInput {
    SigningInput {
        kind,
        protected_segment: produced.protected_segment.clone(),
        payload_segment: produced.payload_segment.clone(),
    }
}

fn main() -> Result<(), Invalid> {
    let bounds = Bounds::maximum();
    let issuer_key = SigningKey::from_bytes(&[0u8; 32]);
    let holder_key = SigningKey::from_bytes(&[1u8; 32]);
    let issuer_public = issuer_key.verifying_key().to_bytes();
    let holder_public = holder_key.verifying_key().to_bytes();

    // The issuer grants one operation, restricted to one argument value.
    let grant_input = grant_signing_input(
        &GrantInput {
            issuer: "https://issuer.example".into(),
            grant_id: "grant-001".into(),
            key_id: "issuer-1".into(),
            holder_thumbprint: public_key_thumbprint_raw(&holder_public)?,
            issued_at: 1_800_000_000,
            not_before: 1_800_000_000,
            expires_at: 1_800_003_600,
            audiences: vec!["https://docs.example".into()],
            operations: vec![GrantOperation {
                name: "publish_article".into(),
                selectors: vec![json_decode(
                    br#"{"kind":"equals","path":["section"],"value":"science"}"#,
                    &bounds,
                )?],
            }],
        },
        &bounds,
    )?;
    let grant_signature = issuer_key.sign(&grant_input.message).to_bytes();
    let grant = assemble_compact(&for_assembly(SigningKind::Grant, &grant_input), &grant_signature, None)?;

    // The holder binds one request to the grant.
    let arguments = json_decode(br#"{"section":"science","title":"Tides"}"#, &bounds)?;
    let proof_input = proof_signing_input(
        &ProofInput {
            proof_id: "proof-001".into(),
            method: "POST".into(),
            target_uri: "https://docs.example/articles".into(),
            invocation_id: "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80".into(),
            operation: "publish_article".into(),
            cast_arguments: arguments.clone(),
            grant_compact: grant.clone(),
            holder_public_key: holder_public,
            issued_at: 1_800_000_100,
        },
        &bounds,
    )?;
    let proof_signature = holder_key.sign(&proof_input.message).to_bytes();
    let proof = assemble_compact(&for_assembly(SigningKind::Proof, &proof_input), &proof_signature, None)?;

    // The service verifies the raw bytes against what it derived from the request.
    let mut expected = ExpectedRequest {
        issuer: "https://issuer.example".into(),
        audience: "https://docs.example".into(),
        evaluation_time: 1_800_000_100,
        skew: 60,
        bounds: bounds.clone(),
        method: "POST".into(),
        target_uri: "https://docs.example/articles".into(),
        invocation_id: "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80".into(),
        operation: "publish_article".into(),
        cast_arguments: arguments,
        proof_max_age: 300,
        nonce_mode: NonceMode::NotRequired,
        trusted_issuer: TrustedIssuer { key_id: "issuer-1".into(), public_key: issuer_public },
    };
    let credentials = Credentials { grant, proof };

    let facts = check_envelope(&credentials, &expected)?;
    assert_eq!(facts.operation, "publish_article");
    assert_eq!(facts.grant.grant_id, "grant-001");

    // The same proof against other arguments fails closed, with no detail.
    expected.cast_arguments = json_decode(br#"{"section":"sports","title":"Tides"}"#, &bounds)?;
    assert_eq!(check_envelope(&credentials, &expected), Err(Invalid));
    Ok(())
}
```

## API

Contract-major 1 functions are re-exported at the crate root (they also live in `v1`).
Contract-major 2 and 3 functions live in the `v2` and `v3` modules under the same names, because
each major has its own byte-distinct contract: `v2` adds the `lte` and `gte` range selectors,
and `v3` uses ES256 with 65-byte uncompressed SEC1 keys and 64-byte raw `r || s` signatures (it
also has its own EC JWK and thumbprint functions). Each major rejects the others' bytes.

| Group | Functions |
|---|---|
| Producers | `grant_signing_input`, `proof_signing_input`, `boundary_anchor_signing_input`, `key_transition_signing_input`, `assemble_compact`, `encode_consumption_entry`, `encode_anchored_export`, `request_digest` |
| Decoders (no signature check) | `decode_grant`, `decode_proof`, `untrusted_key_locator` |
| Verifiers | `verify_grant`, `check_envelope`, `check_chain`, `verify_historical_anchor`, `verify_key_transition`, `verify_anchored_export` |
| Local-loopback HTTP proofs | `local_loopback_http_uri_normalize`, `local_loopback_http_proof_signing_input`, `assemble_local_loopback_http_compact`, `decode_local_loopback_http_proof`, `check_local_loopback_http_envelope` |
| Role attestations | `attestation_signing_input`, `assemble_attestation_compact`, `decode_attestation`, `verify_attestation` |
| Content assertions | `assertion_signing_input`, `assemble_content_assertion_compact`, `decode_content_assertion`, `verify_content_assertion`, `content_digest`, `assertion_digest`, `verify_content_assertion_successor` |
| Strict Ed25519 | `verify_strict`, `acceptable_public_key`, `torsion_free` |
| Primitives | `json_decode`, `jcs_encode`, `base64url_decode`, `base64url_encode`, `uri_normalize`, `jwk_decode_public`, `jwk_encode_public`, `thumbprint_preimage`, `thumbprint`, `thumbprint_raw`, `public_key_thumbprint_raw`, `Bounds::maximum`, `Bounds::new`, `resolve_bounds`, `require_bounds_equal` |

The argument and result structs are in `types` and `facts`.

**Errors.** Fallible functions return `Result<T>`, which is `std::result::Result<T, Invalid>`;
`Invalid` carries no reason. Some functions cannot fail and return plain values:
`verify_strict`, `acceptable_public_key`, and `torsion_free` return `bool`, `base64url_encode`
returns `Vec<u8>`, `resolve_bounds` returns `Bounds`, and `Bounds::maximum` returns `Bounds`.

**Facts.** `GrantFacts`, `EnvelopeFacts` (which embeds the re-verified `GrantFacts` as `grant`),
`ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`, `AnchoredExportFacts`, `AttestationFacts`,
and `ContentAssertionFacts` hold identifiers, digests, times, and counts, never raw signatures,
keys, nonces, or arguments. `GrantFacts` and `EnvelopeFacts` carry
`authorization: NotEvaluated`; `ChainFacts`, `AnchorFacts`, and `KeyTransitionFacts` carry
`trust: NotEvaluated`; `AnchoredExportFacts` carries both; `AttestationFacts` and
`ContentAssertionFacts` carry `verification: SignatureAndWindow` and `trust: NotEvaluated`.
Every facts type derives `Debug`, `Clone`, and `PartialEq` (`ContentAssertionFacts` also `Eq`),
and none implements `Display` or `Serialize`. The derived `Debug` prints every field; the
fixed redacted rendering the specification calls for is not implemented yet, so log the fields
you need by name.

## Strict Ed25519

Every Ed25519 signature check goes through one function (`ed25519::verify`, internal) that
applies rule S1 of [ADR 0040](../../docs/adr/0040-strict-ed25519-soundness-erratum.md) before
the `ed25519-dalek` backend: exact widths, canonical `A` and `R`, neither of small order,
`S < L`, then the cofactorless equation (dalek's `verify`, not its `verify_strict`).
`acceptable_public_key` is the key-entry check (canonical, not small order, on the curve), and
the JWK and thumbprint functions return `Err(Invalid)` for a key that fails it. `torsion_free`
adds `[L]A = O`; call it at key enrollment, at trust install, and before any deny-list or
revocation comparison, never on the verification path.

## Conformance

`cargo test --locked` runs everything: the unit tests, this README's quickstart, the
vendored v1 (283 cases), v2 (268), v3 (292), and strict-Ed25519 (2,410) corpus snapshots with
their `index.json` SHA-256 asserted at load and a key census per run, the local-loopback,
role-attestation, and content-assertion corpora read from `priv/conformance/`, and the
permissiveness battery (`tests/permissiveness.rs`, 83 tests), which builds each defect a parser
closure exists to reject and proves the closure catches it.

```bash
cargo test --locked
cargo test --locked --test conformance          # v1: agreed=283 disagreed=0 + census
cargo test --locked --test conformance_strict   # 2,410 strict-Ed25519 cases
cargo test --locked --test content_assertion    # 131 + 9 + 14 cases
```

The producer-canonicality corpus (erratum 3) is not run yet; see Status.

## What this SDK does not do

No I/O, filesystem, clock, randomness, network, environment, or process access in the library
(`tools/purity_check.sh` enforces it for `src/`). No trust discovery, key custody, signing,
replay reservation, revocation state, issuance, or authorization decisions. No registry-publish
setup: a pre-commit hook and a CI job reject it here (ADR 0015).

## Development

```bash
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
sh tools/purity_check.sh && sh tools/license_check.sh
```

Deployment notes, including AWS Lambda and PostgreSQL: see
[`docs/deployment/rust-sdk.md`](../../docs/deployment/rust-sdk.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
