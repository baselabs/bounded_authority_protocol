# Contributing

Contributions must preserve the pure deterministic verifier boundary, closed versioned formats,
fixed value-free errors, and independent conformance requirements in [`AGENTS.md`](AGENTS.md).

Before a pull request:

1. use Forge for protocol, cryptography, canonicalization, or conformance changes;
2. add allow, deny, malformed-input, and mutation-red tests;
3. update normative vectors and obtain independent exact-byte verification when wire bytes change;
4. run `mix deps.get` and `mix quality`;
5. update the changelog and every affected contract document.

The package supports Elixir 1.18/OTP 27, Elixir 1.19/OTP 28, and Elixir 1.20/OTP 29. Focused
boundary commands are `mix architecture`, `mix audit`, `mix package.check`, and
`mix sbom.generate`. The architecture and archive allowlists must be expanded only with a reviewed
public protocol requirement and matching red-capable tests.

Do not submit secrets, production credentials, private key fixtures, customer data, or proprietary
consumer code. Runtime code, public APIs, wire formats, and conformance artifacts must remain
provider-neutral; boundary documentation may name consumers only to state exclusions and
dependency direction.

By contributing, you agree that your contribution is licensed under Apache License 2.0. No
contributor license agreement or DCO sign-off is currently required.
