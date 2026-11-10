# Usage rules

The rules a host follows around verification. Each is short; the
[troubleshooting checklist](docs/guides/troubleshooting.md) and the [recipes](docs/guides/recipes.md)
show them in code.

1. Treat verifier success as a cryptographic result, not an authorization decision.
2. Supply only already-trusted public keys selected outside this library.
3. Derive method, URI, operation, and cast arguments on the server; never trust caller-selected
   expected context.
4. Enforce live revocation, replay reservation, execution claims, host policy, and effect
   authorization in a stateful authority runtime.
5. Use the published bounds and reject unknown versions or extensions.
6. Never pass private keys, secrets, raw user values, or production credentials into fixtures,
   logs, errors, or telemetry.
7. Pin a package release line and run the packaged conformance corpora before accepting a new
   release.
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
13. Depend on the published Hex release (`{:bounded_authority_protocol, "~> 1.0"}`), never on a
    source tag or a mutable checkout. Select one profile per boundary through its named
    namespace: the contract-major surfaces stay byte- and verdict-identical, and each sibling
    profile is reached only through its own API.
14. Run the verifier CLI with an explicit `--corpus DIR` pointing at a packaged corpus: install it
    with `mix escript.install hex bounded_authority_protocol 1.0.0` and run
    `bounded_authority_conformance --corpus deps/bounded_authority_protocol/priv/conformance/v1/corpus`,
    or call `BoundedAuthorityProtocol.Conformance.Cli.run/1` from Elixir. Never rely on a default
    corpus path. Treat exit 0 as conformance evidence only; it does not authorize.
15. For local-loopback HTTP, admit only literal `127.0.0.1` or `[::1]`, require the server nonce,
    derive the exact target from the direct listener, and reject proxy/forwarding-header authority.
    Never retry the standard profile after a local-profile rejection or vice versa.
16. For content assertions, hash the exact retained content bytes with `content_digest/2` and
    pass that digest, the pinned profile digest, every expected identifier, one caller-selected
    attestor key and window, and `now` to `verify_assertion/2`. Verified facts prove signature,
    context, and window only. Keep durable per-subject generation and digest state to refuse
    replay, regression, and forks; `verify_successor/3` compares two facts values and nothing more.
17. Call `BoundedAuthorityProtocol.Ed25519.torsion_free?/1` on every Ed25519 key at enrollment, at
    trust install, and before any deny-list or revocation comparison, and reject a key that fails
    it. Verification applies the strict rule itself and accepts mixed-order keys by design; the
    torsion-free check is what makes one secret map to exactly one key and thumbprint. Scan keys
    you stored before adopting the package, and archived key chains, with
    `acceptable_public_key?/1` and `torsion_free?/1`, and treat any failure as a compromise.
18. Hand compact assembly only a signature a conforming signer emits. For ES256 that is the raw
    64-byte `r || s` with low S: convert a DER signature from an HSM, KMS, or secret store with
    `BoundedAuthorityProtocol.Es256.der_to_raw/1`, then `normalize_low_s/1`, before assembly.
    Assembly never normalizes; it refuses a high-S or out-of-range signature.
19. Tag each selector value by what it is: an integral number is `{:integer, n}`, never
    `{:float, n.0}`. Producers refuse a float-tagged integral selector value on every
    contract-major, and verification rejects a float zero in an `equals` value or a `one_of`
    member.
20. When verification returns `{:error, :invalid}`, diagnose from your own inputs with the
    [troubleshooting checklist](docs/guides/troubleshooting.md). Never retry with loosened
    expectations or under another profile.
