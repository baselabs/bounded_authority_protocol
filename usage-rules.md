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
9. Treat the current 0.1.0 package as unpublished. BAP-02 decoding is available, but
   cryptographic verification and public release are not.
