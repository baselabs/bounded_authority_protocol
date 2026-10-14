# Rust verifier SDK: deployment notes

The Rust verifier SDK (`sdks/rust/`, crate `bounded-authority-protocol`) is a pure,
deterministic implementation of the BAP verification profiles: contract-majors 1, 2, and 3 plus
the local-loopback, role-attestation, and content-assertion sibling profiles. It is a
**verifier**: it returns redacted facts or `Invalid`, never an authorization decision. The
[SDK README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/rust/README.md)
has the quickstart and the full API list.

## Not published yet

The crate is not on crates.io. It moves to its own repository when it is first published
([ADR 0015](../adr/0015-sdk-graduation-and-publish-topology.md)). Until then, depend on this
repository by path or by Git commit:

```toml
[dependencies]
bounded-authority-protocol = { path = "../bounded_authority_protocol/sdks/rust" }
# or
bounded-authority-protocol = { git = "https://github.com/baselabs/bounded_authority_protocol", rev = "<commit>" }
```

The path form expects this repository cloned next to your crate. Pin a commit: without a
published version, the commit is the identity of what you deployed.

Erratum 3 (producer canonicality) is not implemented in this crate yet: `assemble_compact`,
`encode_anchored_export` (and their `v2` and `v3` forms), `assemble_local_loopback_http_compact`,
`assemble_attestation_compact`, and `assemble_content_assertion_compact` do not refuse a
non-canonical signature. Verification is unaffected. See the SDK README.

## Local-loopback application profile

The crate exposes `local_loopback_http_uri_normalize`,
`local_loopback_http_proof_signing_input`, `assemble_local_loopback_http_compact`,
`decode_local_loopback_http_proof`, and `check_local_loopback_http_envelope` for direct local
development listeners. Select them explicitly, admit only literal `127.0.0.1`/`[::1]` HTTP
targets, require the server nonce, and never infer or retry the standard profile.

## Strict Ed25519 verification

Every Ed25519 verification in the SDK applies rule S1 of
[ADR 0040](../adr/0040-strict-ed25519-soundness-erratum.md) at its single Ed25519 verification
point: canonical point encodings, no small-order key or `R`, a scalar below the group order, and
the cofactorless equation. Key import, JWK encode and decode, and thumbprint functions refuse a
key that fails key acceptance. Call `torsion_free` at key enrollment, at trust install, and
before any deny-list or revocation comparison. A vendored snapshot of the strict-Ed25519 corpus
under `conformance/corpus-strict/` runs through `conformance/run_strict.rs` with its index
SHA-256 pinned.

## Supply chain

Runtime dependencies (`sdks/rust/tools/license_check.sh` checks the license of every crate in the runtime tree):

| Crate | License | Role |
|---|---|---|
| `ed25519-dalek` 2.2 (default features off) | BSD-3-Clause | Ed25519 verification |
| `curve25519-dalek` 4.1 (transitive) | BSD-3-Clause | curve arithmetic |
| `p256` 0.13 (default features off, `ecdsa`) | Apache-2.0 OR MIT | ECDSA P-256 verification for contract-major 3 |
| `zeroize` =1.8.1 (transitive of `p256`, pinned exactly because later 1.x releases need Rust 1.85) | Apache-2.0 OR MIT | memory zeroing |
| `sha2` 0.10 | MIT OR Apache-2.0 | SHA-256 |
| `ryu-js` 1.0 | Apache-2.0 OR BSL-1.0 | ECMAScript float formatting (JCS) |
| `subtle`, `digest`, `generic-array`, `typenum`, `elliptic-curve`, `crypto-bigint`, and others | MIT, Apache-2.0, or BSD-3-Clause | transitive cryptographic support |

**Backend selection.** `default-features = false` on `ed25519-dalek` does not choose the
`curve25519-dalek` backend. `curve25519-dalek` picks it in its build script: on 64-bit
`x86_64` it compiles in the `simd` backend and uses AVX2 when the CPU has it, falling back to
`serial` at run time (its AVX-512 code needs a nightly compiler); on other targets, such as
`aarch64`, it builds only the portable `serial` backend. To compile only `serial` on `x86_64`,
build with `RUSTFLAGS='--cfg curve25519_dalek_backend="serial"'`.

**Unsafe code.** `#![forbid(unsafe_code)]` covers this crate's own source only. A source scan
of the locked dependency versions (October 14, 2026) finds `unsafe` blocks, functions, or
impls in `curve25519-dalek`, `sha2`, `generic-array`, `cpufeatures`, `libc` (pulled in by
`cpufeatures` on some targets), `crypto-bigint`, `subtle`, `zeroize`, `block-buffer`,
`base16ct`, `rand_core`, and `ryu-js`. `p256`, `ecdsa`, `elliptic-curve`, `primeorder`, `sec1`,
`der`, `ff`, `ed25519`, and `ed25519-dalek` declare `#![forbid(unsafe_code)]`. Using vetted
cryptographic implementations is the reason for that trade.

## AWS Lambda (`provided.al2023`)

Lambda's `provided.al2023` runtime runs a `bootstrap` executable directly, so the transitive
`unsafe` above is ordinary native code there. The crate is a library: build your own binary
crate (the Lambda handler) that depends on it, then build that binary for a static `musl`
target and ship it as `bootstrap`:

```bash
rustup target add aarch64-unknown-linux-musl   # or x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl   # in your handler crate
# rename the binary to `bootstrap`, zip it, and deploy it as an arm64 function
```

This repository does not build or test a `musl` target or a Lambda handler; verify the build in
your own pipeline. The handler wraps a verifier call in your request format (the SDK does no
I/O) and keeps the trusted inputs explicit: the trusted public key, the expected audience, the
evaluation time, and the bounds.

## PostgreSQL (`plrust`)

[`plrust`](https://plrust.io/) runs Rust functions inside PostgreSQL. Its trusted mode restricts
what a function's code and dependencies may do, and the transitive `unsafe` listed above may
keep this crate from building there. This repository does not test a `plrust` build, so check
against the documentation and dependency policy of the `plrust` version you run before relying
on it. Two postures avoid the question:

1. **Verify outside the database.** Keep PostgreSQL for storage and verify in a service, a
   worker, or a Lambda function (the binary above), then store the redacted facts.
2. **Use an untrusted language mode**, if your database operator allows it. It runs the code
   without the trusted-mode restrictions, so weigh that against your database's threat model.

## What to deploy, and what to leave to the host

The SDK verifies caller-supplied bytes against caller-supplied trusted inputs and returns
redacted facts. Keep these out of the verifier:

- trusted-key discovery and custody,
- replay reservation and live revocation state,
- the operational authorization decision,
- evidence and consumption writes, and archive removal.

A verifier result is one input to that decision, never the decision itself
([protocol charter](../design/protocol-charter.md)).
