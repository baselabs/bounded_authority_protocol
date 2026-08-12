# Rust verifier SDK — deployment guide

The Rust verifier SDK (`sdks/rust/`, crate `bounded-authority-protocol`) is a pure, deterministic,
fail-closed reimplementation of the BAP v1 profile. It is a **verifier**: it returns redacted, value-bearing
facts or `Invalid`, never an authorization decision. This guide covers the two serverless/edge deployment
targets named in the BAP-15 acceptance bar: AWS Lambda (`provided.al2023`) and PostgreSQL (`plrust`).

See [`docs/protocol-v1.md`](../protocol-v1.md) for the verification contract and
[`../adr/0014-cross-language-verifier-sdks.md`](../adr/0014-cross-language-verifier-sdks.md) for the
packaging and derivation-hygiene decisions.

## Supply-chain posture

Runtime dependencies (the consumer-facing closure, audited by `sdks/rust/tools/license_check.sh`):

| crate | license | role |
|---|---|---|
| `ed25519-dalek` 2.2 (default-features = false) | BSD-3-Clause | Ed25519 verify (serial backend) |
| `curve25519-dalek` 4.1 (transitive) | BSD-3-Clause | curve arithmetic |
| `sha2` 0.10 | MIT OR Apache-2.0 | SHA-256 |
| `ryu-js` 1.0 | Apache-2.0 OR BSL-1.0 | ECMAScript float formatting (JCS) |
| `subtle`, `digest`, `generic-array`, `typenum`, … | MIT / BSD-3-Clause | transitive crypto/plumbing |

Every runtime dependency is permissively licensed. `default-features = false` on `ed25519-dalek` selects the
serial verify backend (no SIMD/assembly). The crate carries `#![forbid(unsafe_code)]` over **its own**
source; the crypto backend (`curve25519-dalek`, `cpufeatures`, `libc`, `generic-array`) compiles `unsafe`
transitively — that is the documented, reviewed trade for a vetted Ed25519 implementation.

## AWS Lambda — `provided.al2023`

Lambda's `provided.al2023` runtime executes a static `bootstrap` binary directly. There is no
trusted-language sandbox, so the transitive `unsafe` in the crypto backend is unproblematic here — it is
normal native code on a normal Linux runtime.

Build a fully static binary against the `musl` target and ship it as `bootstrap`:

```bash
rustup target add aarch64-unknown-linux-musl   # or x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
# zip the renamed binary as `bootstrap` and upload as a Lambda function (arch: arm64)
```

A minimal handler wraps a verifier call behind whatever wire format your platform uses (the SDK itself does
no I/O). Keep the caller-supplied trusted inputs (already-trusted public key, expected audience/instance,
evaluation time, bounds) explicit — the SDK never discovers trust.

## PostgreSQL — `plrust`

[`plrust`](https://plrust.io/) is a trusted-language extension that runs Rust inside PostgreSQL under a
sandboxed, allowlisted toolchain (the plrust trusted build). **ed25519-dalek-based verification is NOT
plrust-trusted-mode-compatible as built**: `curve25519-dalek`'s static initialization, plus `generic-array`,
`cpufeatures`, `libc`, and `ryu-js`, compile `unsafe` regardless of this crate's
`default-features = false` / `#![forbid(unsafe_code)]` (those govern only OUR source, not the transitive
backend). plrust's trusted-mode allowlist rejects crates that compile `unsafe`.

Three viable postures (choose per your PostgreSQL operator policy):

1. **Verify against your plrust version's allowlist.** plrust's trusted toolchain pins an allowlist of
   permitted crates; check whether the pinned `curve25519-dalek`/`ed25519-dalek` versions are admitted before
   attempting a trusted build. The version matrix moves with plrust releases.
2. **Run verification in a sidecar.** Keep PostgreSQL for storage and perform verification in a Lambda,
   a small service, or a worker — the same static binary described above — returning the redacted facts to
   the database layer. This keeps the crypto stack off the database host entirely.
3. **Use plrust *untrusted* mode.** plrust can run functions in an untrusted mode with a broader crate
   surface; verify the security implications against your database's threat model first (untrusted-mode
   plrust is not the hardened posture trusted mode is).

The SDK's purity (`#![forbid(unsafe_code)]` + the `tools/purity_check.sh` lib-path gate) is necessary but
NOT sufficient for plrust trusted mode — the transitive backend `unsafe` is the blocker, not this crate's
own code. The Lambda path is unaffected.

## What to deploy, and what to leave to the host

The SDK verifies caller-supplied bytes against caller-supplied trusted inputs and returns redacted facts.
Deployment must keep the **private-runtime responsibilities** out of the verifier:

- trusted-key discovery and custody,
- replay reservation and live revocation state,
- the operational authorization decision,
- evidence/consumption writes and archive removal.

A verifier result is one input to that decision; it is never the decision itself
([`docs/design/protocol-charter.md`](../design/protocol-charter.md), AGENTS rule 1).
