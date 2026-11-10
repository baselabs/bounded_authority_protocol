# Contributing

Contributions must preserve the pure deterministic verifier boundary, closed versioned formats,
fixed value-free errors, and independent conformance requirements in the
[protocol charter](docs/design/protocol-charter.md) and [governance policy](docs/governance.md).

Report security vulnerabilities privately, never in an issue or pull request: see
[SECURITY.md](SECURITY.md).

Before a pull request:

1. open a design discussion before protocol, cryptography, canonicalization, or conformance changes;
2. add allow, deny, malformed-input, and mutation-red tests;
3. update normative vectors and obtain independent exact-byte verification when wire bytes change;
4. run `mix deps.get` and `mix quality`;
5. update the changelog and every affected contract document.

Application-profile changes also update their normative specification, certified corpus and digest,
every implementation (Elixir, the three SDKs here, and the TypeScript verifier in its own
repository), README/guides/Livebook, and the cross-profile rejection proofs. Run
`mix local_loopback_http.verify` to exercise real IPv4 and IPv6 listeners with ephemeral keys; a
self-round-trip or canned HTTP response is not interoperability or transport evidence.

The declared Elixir range is `~> 1.18` (1.18/1.19/1.20) and the supported Erlang/OTP majors are
**27, 28, 29** — floor-limited by the stdlib `:json` module (OTP 27+) and enforced by
`config/config.exs` at config load, before anything compiles; the assert is not shipped in the Hex
package, so consumers enforce their own. The mix.exs range, the config set, `.tool-versions`, and
the CI lanes move together in one commit. The clone →
`deps.get` → compile → test contract must hold on macOS and Linux as a developer-setup
property, proven on a developer machine; CI runs on Linux only, one lane per supported
Erlang/OTP major plus the complete-quality lane. Windows developers use WSL2 (clone
inside the WSL filesystem, not under `/mnt/c`), which is the Linux path; no native-Windows developer
path is maintained. The full quality battery is
POSIX-only tooling. Focused boundary commands are
`mix architecture`, `mix audit`, `mix package.check`, and
`mix sbom.generate`. The architecture and archive allowlists must be expanded only with a reviewed
public protocol requirement and matching red-capable tests.

The local quality gate requires Gitleaks 8.30.1. `gitleaks version` must print `8.30.1` exactly.
On Linux x86_64, install the checksum-verified official binary with
`scripts/install_gitleaks.sh "$HOME/.local/bin"` and ensure that directory is on `PATH`. On other
platforms, install version 8.30.1 from the official Gitleaks release. Run `mix secrets` for the
merge-aware history, staged-index, and tracked-working-tree scans; `mix quality` runs the same gate.

## SDK publish topology

Cross-language verifier SDKs under `sdks/` are authored in this repository but **do not publish
from it**. Each SDK graduates to its own per-SDK repository (`bounded_authority_protocol_<lang>`)
on first publication, because a registry publication is irreversible and each SDK's release
cadence and credentials belong to its own repository. A
local pre-commit hook (`sh scripts/install-hooks.sh`) and a CI job on `main` reject SDK publish
infrastructure (registry-publish steps, `prepublishOnly`/`prepack` scripts, `publishConfig`)
committed to this repository. Contributor hook installation works without any local policy;
maintainer checks activate only where a maintainer has set one up. The deliberate-admin bypass is `git commit --no-verify`, documented
here as the sanctioned escape hatch. Neither layer catches a literal ad-hoc publish command run
against a working tree — that is a runtime act no commit gate sees; CI on `main` is the hard gate
for committed infrastructure.

## Maintainer checks

Maintainers also run local confidential-term checks through the same hooks; contributors do not
need them, and the hooks print an inactive notice without the local policy. The repository's
[maintainer notes](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/reference/maintainer-checks.md)
describe them.

Do not submit secrets, production credentials, private key fixtures, customer data, or proprietary
consumer code. Runtime code, public APIs, wire formats, and conformance artifacts must remain
provider-neutral; boundary documentation may name consumers only to state exclusions and
dependency direction.

By contributing, you agree that your contribution is licensed under Apache License 2.0. No
contributor license agreement or DCO sign-off is currently required.

## Code of Conduct

By participating in this project you agree to uphold the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md) (v2.1).
