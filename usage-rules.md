# Usage rules

1. Treat verifier success as a cryptographic result, not an authorization decision.
2. Supply only already-trusted public keys selected outside this library.
3. Derive method, URI, operation, and cast arguments on the server; never trust caller-selected
   expected context.
4. Enforce live revocation, replay reservation, execution claims, host policy, and effect
   authorization in a stateful authority runtime.
5. Use the published bounds and reject unknown versions or extensions.
6. Never pass private keys, secrets, raw user values, or production credentials into fixtures,
   logs, errors, or telemetry.
7. Pin released major versions and run the conformance vectors before accepting a new release.
8. Treat `untrusted_key_locator/2` output only as a case-sensitive lookup hint with
   `trust: :not_evaluated`; it does not parse claims, verify bytes, select trust, or authorize.
9. Pass only raw compact credentials to verification boundaries. Decoded values and verified
   facts are evidence outputs, never reusable credentials.
10. Supply chain/archive verification with the intended predecessor/head, both expected anchors,
    the complete ordered historical-key path, raw archive digest, and exact object-store version.
    Do not infer those expectations from the archive being verified.
11. Treat chain consistency as consistency only. It cannot by itself prove that a validly
    shortened or relinked history omitted nothing.
12. Keep commitment preimages private. The public row carries only a fixed-width commitment.
13. Consume the published Hex release (`{:bounded_authority_protocol, "~> 0.3.0"}`) only after the
    registry exposes that immutable archive. A Git tag or mutable checkout is not a package
    identity. The standard v1 verification surface stays byte- and verdict-identical; the
    local-loopback application profile is selected only through its separately named API.
14. Run the verifier CLI with an explicit `--corpus DIR` pointing at the packaged corpus
    (`deps/bounded_authority_protocol/priv/conformance/v1/corpus` from a consumer). Never rely on
    a default corpus path. Treat exit 0 as conformance evidence only — it does not authorize.
15. For local-loopback HTTP, admit only literal `127.0.0.1` or `[::1]`, require the server nonce,
    derive the exact target from the direct listener, and reject proxy/forwarding-header authority.
    Never retry the standard profile after a local-profile rejection or vice versa.
