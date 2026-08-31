# Contributing

Contributions must preserve the pure deterministic verifier boundary, closed versioned formats,
fixed value-free errors, and independent conformance requirements in the
[protocol charter](docs/design/protocol-charter.md) and [governance policy](docs/governance.md).

Before a pull request:

1. open a design discussion before protocol, cryptography, canonicalization, or conformance changes;
2. add allow, deny, malformed-input, and mutation-red tests;
3. update normative vectors and obtain independent exact-byte verification when wire bytes change;
4. run `mix deps.get` and `mix quality`;
5. update the changelog and every affected contract document.

Application-profile changes also update their normative specification, certified corpus and digest,
all five implementations, README/guides/Livebook, and the cross-profile rejection proofs. Run
`mix local_loopback_http.verify` to exercise real IPv4 and IPv6 listeners with ephemeral keys; a
self-round-trip or canned HTTP response is not interoperability or transport evidence.

The package supports Elixir 1.18/OTP 27, Elixir 1.19/OTP 28, and Elixir 1.20/OTP 29. Focused
boundary commands are `mix architecture`, `mix audit`, `mix package.check`, and
`mix sbom.generate`. The architecture and archive allowlists must be expanded only with a reviewed
public protocol requirement and matching red-capable tests.

## SDK publish topology

Cross-language verifier SDKs under `sdks/` are authored in this repository but **do not publish
from it**. Each SDK graduates to its own per-SDK repository (`bounded_authority_protocol_<lang>`)
on first publication; see [ADR 0015](docs/adr/0015-sdk-graduation-and-publish-topology.md). A
local pre-commit hook (`sh scripts/install-hooks.sh`) and a CI job on `main` reject SDK publish
infrastructure (registry-publish steps, `prepublishOnly`/`prepack` scripts, `publishConfig`)
committed to this repository. The deliberate-admin bypass is `git commit --no-verify`, documented
here as the sanctioned escape hatch. Neither layer catches a literal ad-hoc publish command run
against a working tree — that is a runtime act no commit gate sees; CI on `main` is the hard gate
for committed infrastructure.

Do not submit secrets, production credentials, private key fixtures, customer data, or proprietary
consumer code. Runtime code, public APIs, wire formats, and conformance artifacts must remain
provider-neutral; boundary documentation may name consumers only to state exclusions and
dependency direction.

By contributing, you agree that your contribution is licensed under Apache License 2.0. No
contributor license agreement or DCO sign-off is currently required.

## Code of Conduct

By participating in this project you agree to uphold the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md) (v2.1).
