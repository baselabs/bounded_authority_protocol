# Bounded Authority Protocol verifier for Rust

A pure, deterministic Rust implementation of the Bounded Authority Protocol (BAP) verification
profiles: contract-majors 1 and 2 (Ed25519) and 3 (ES256), the local-loopback HTTP proof
profile, and the role-attestation and content-assertion profiles, with strict Ed25519
verification on every Ed25519 surface.

It checks the exact bytes of a grant, a holder proof, or an evidence object against public keys
and expected context that you supply, and returns facts or the single error `Invalid`.
Facts exclude raw credentials and secrets; the logging notes below describe their display limitations.
It is a **verifier, not an authority**: it never selects trusted keys, reserves replay, checks
revocation, or decides whether a request may run. Those stay in your service.

Already-trusted public keys, expected context, and time are explicit inputs. The SDK has no
private-key access or custody and reads no clock.

Its behavior is defined by the specifications ([v1](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md),
[v2](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v2.md), [v3](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md), and the sibling profiles under
[`spec/`](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/)) and the certified conformance corpora; source comments cite
the tracked normative specifications and independent conformance corpora.

## Status

**Not published.** The crate is not on crates.io; the name `bounded-authority-protocol` is the
one it will use, and any crate of that name there is not ours until this page says otherwise. It moves to its own repository when it is first published
with its self-contained tests and corpus inputs. Until then, depend on
a checkout of this repository.

- Rust **1.88** or later (`rust-version` in `Cargo.toml`; `rust-toolchain.toml` pins 1.88.0 for
  development and CI).
- Runtime dependencies: `ed25519-dalek` 3.0 (default features off), `p256` 0.14 (ECDSA only, for
  contract-major 3), `sha2` 0.11 and `ryu-js` 1.0. `zeroize` is a transitive dependency. See the
  [deployment notes](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/rust-sdk.md) for the full tree and its `unsafe` use.
- `#![forbid(unsafe_code)]` covers this crate's own source.
- **Erratum 3 (producer canonicality) is implemented.** Compact assembly and anchored-export encoding for every profile refuse a signature no
  conforming signer emits under spec/bap-v1.md §16 and spec/bap-v3.md §3.2. The certified
  `bap-producer-canonicality/1` corpus (75 cases) runs with this SDK's conformance suite.
- **Erratum 6 (selector float zero) is implemented.** Grant decode on every contract-major
  rejects an `equals` value or `one_of` member holding a float-tagged zero at any depth, of any
  sign or spelling (range bounds and inert `all` members are unchanged), and the grant producer
  refuses any float-tagged integral selector value (spec/bap-v1.md §12,
  REQ1-SIGNING-integral-float-selector; spec/bap-v2.md §4; spec/bap-v3.md §4). The certified `bap-selector-float-zero/1` corpus (161 cases) runs with this SDK's
  conformance suite.

The unpublished SDK ships the committed `Cargo.lock`; CI audits that exact resolved set.
The dependency MSRVs top out at Rust 1.88 (`sha2` 0.11.1). Use `--locked` when building or
testing this checkout. A consuming application maintains and audits its own lockfile.

## Install from a checkout

Start from an empty directory and choose either the [complete path manifest or the
complete Git manifest](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/rust-sdk.md#not-published-yet), both pinned to a
selected full source commit. CI executes both installs as independent consumer projects.

## Quickstart

Save the following as `src/main.rs` in either consumer, then run `cargo generate-lockfile`
and `cargo run --locked`. The manifests include `ed25519-dalek` for this demonstration's
caller-owned signer. `cargo test` also executes this block as a native doctest.

The example signs with keys from fixed demonstration seeds. Production private keys stay with
the issuer and holder; the verifier receives public keys only.

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

Contract-major 1 functions are re-exported at the crate root from the `v1` module, except
`request_digest`, which the root re-exports from an internal module.
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

The argument structs are in `types`, the facts in `facts`, and the content-assertion structs
(`ContentAssertionInput`, `ExpectedContentAssertion`, `DecodedContentAssertion`,
`ContentAssertionFacts`) in `content_assertion`, also re-exported at the root.

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
Every facts type derives `Clone` and `PartialEq` (`ContentAssertionFacts` also `Eq`),
and none implements `Display` or `Serialize`. `Debug` matches the specified diagnostic rendering (for example,
`#BoundedAuthorityProtocol.V1.GrantFacts<redacted>`), including alternate formatting and
nested Results. Each contract-major retains its `V1`, `V2`, or `V3` namespace; sibling facts
use `RoleAttestation.V1` and `ContentAssertion.V1`.
Read individual fields explicitly when needed.

## Strict Ed25519

Every Ed25519 signature check goes through one function (`ed25519::verify`, internal) that
applies rule S1 of [erratum 2](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md) before
the `ed25519-dalek` backend: exact widths, canonical `A` and `R`, neither of small order,
`S < L`, then the cofactorless equation (dalek's `verify`, not its `verify_strict`).
`acceptable_public_key` is the key-entry check (canonical, not small order, on the curve), and
the JWK and thumbprint functions return `Err(Invalid)` for a key that fails it. `torsion_free`
adds `[L]A = O`; call it at key enrollment, at trust install, and before any deny-list or
revocation comparison, never on the verification path.

## Conformance

`conformance/priv/conformance/` is a complete, byte-identical snapshot of the Hex package built
from this commit's `priv/conformance/` tree. It includes all nine certified corpora, schemas, focused vectors,
and `verdict-digests.json`. Every test input is inside this SDK root; copying this directory
alone is sufficient to run the suite.
The manifest was introduced in 1.1.0.

| Corpus | Cases |
|---|---:|
| v1 / v2 / v3 | 283 / 268 / 292 |
| Local-loopback HTTP | 44 (36 URI, 8 proof) |
| Role attestation | 40 |
| Content assertion | 154 (131 assertion, 9 digest, 14 successor) |
| Producer canonicality | 75 |
| Selector float zero | 161 |
| Strict Ed25519 | 2,410 |

Each runner pins its index, hashes every indexed file, including `.raw` inputs, and rejects
extra or missing files, duplicate IDs, and skipped cases. It records computed outcomes,
orders them by the index's file and case order, and checks their JCS/SHA-256 verdict digest
against the vendored manifest. Expected-value comparison cannot substitute for this check.
Outcome projections and index ordering are specified in the
[verdict digest contract](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/corpus-verdict-digests.md).
The contract-major runners also retain their public-key import censuses.

Run from this SDK directory:

```bash
cargo test --locked
```

The crate archive includes its tests and the complete input tree, including `.raw` sidecars.
CI runs `cargo package`, unpacks the archive, and runs the full suite from the unpacked crate.

The monorepo's distribution job copies only this SDK root into a temporary directory,
runs its full suite, checks its package, and removes the temporary artifacts afterward.
A corpus update replaces the entire snapshot from the verified Hex unpack in one change;
individual case edits are not a supported update path. These checks do not publish the SDK.

## What this SDK does not do

No I/O, filesystem, clock, randomness, network, environment, or process access in the library
(`tools/purity_check.sh` enforces it for `src/`). No trust discovery, key custody, signing,
replay reservation, revocation state, issuance, or authorization decisions. No registry-publish
setup: a pre-commit hook and a CI job reject it here.

## Development

```bash
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash tools/purity_check.sh && bash tools/license_check.sh
```

Deployment notes, including AWS Lambda and PostgreSQL: see
[`docs/deployment/rust-sdk.md`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/rust-sdk.md).

## Migration from earlier source snapshots

These SDKs are unpublished at version 0.1.0; there is no earlier supported registry major.
When moving from an older source commit, apply these changes recorded in the monorepo
[CHANGELOG](https://github.com/baselabs/bounded_authority_protocol/blob/main/CHANGELOG.md). The quickstart uses the current forms.

| Earlier usage | Current usage |
|---|---|
| Construct chain, anchor, transition or export facts without a major | Set `version` explicitly in direct struct construction. Verifiers populate it automatically. |
| Match `#GrantFacts<redacted>` | Match the full namespace, for example `#BoundedAuthorityProtocol.V1.GrantFacts<redacted>`. Sibling profiles retain their own namespaces. |
| Construct decoded grants without operations | Include `operations`; decoded proofs also require `version` and `holder_public_key`. Prefer obtaining diagnostics from decoding. |
| Log a decoded proof's nonce through generic debugging | Use its specified diagnostic rendering, which redacts the nonce; read named fields only for explicit host logic. |

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Decoded diagnostics match the specified inspection notation. `GrantDecoded` includes ordered
`operations`; `ProofDecoded` includes `version` and `holder_public_key` and redacts its optional
nonce in `Debug`. `DecodedContentAssertion` renders fully redacted. No decoded type implements
serde serialization. Read named fields explicitly.
