# Contributing

Contributions must preserve the pure deterministic verifier boundary, closed versioned formats,
fixed value-free errors, and independent conformance requirements in [`AGENTS.md`](AGENTS.md).

Before a pull request:

1. use Forge for protocol, cryptography, canonicalization, or conformance changes;
2. add allow, deny, malformed-input, and mutation-red tests;
3. update normative vectors and obtain independent exact-byte verification when wire bytes change;
4. run the complete quality and conformance gates documented by the current roadmap;
5. update the changelog and every affected contract document.

Do not submit secrets, production credentials, private key fixtures, customer data, proprietary
consumer code, or QorPay/Beamline product vocabulary.

By contributing, you agree that your contribution is licensed under Apache License 2.0. No
contributor license agreement or DCO sign-off is currently required.
