# ADR 0031: Self-enforcing toolchain and the tri-platform build bar

- Status: accepted (the per-push Windows CI lane element is superseded by
  [ADR 0033](0033-developer-portability-ci-scope.md); the toolchain and pinning elements stand)
- Date: 2026-09-16
- Governs: the declared Elixir range, the supported Erlang/OTP major set, their
  enforcement point, and the platform portability bar for the library contract

## Context

Before this ADR, toolchain identity lived outside the repository. The declared Elixir
range (`~> 1.18`) carried no rationale binding it to anything; the CI compatibility
lanes were hand-picked with nothing tying them to a discovered set; and nothing in
the repository refused a build on an unsupported Erlang/OTP major — a host PATH, a
personal install, or an out-of-band version manager alone could drive a build.

Two probes settle the supported set for the declared line (Elixir 1.18/1.19/1.20):

- Precompiled build availability (asdf `list all`, the official `library/elixir`
  docker tags, both channels agreeing): Elixir 1.18 has OTP 25–28 builds, 1.19 has
  26–28, 1.20 has 27–29. Build availability alone would admit {25..29}.
- The package's own stdlib floor: `lib/bounded_authority_protocol/v1/json.ex`
  decodes through the `:json` module, which enters the Erlang stdlib in OTP 27
  (there is no JSON fallback dependency). OTP 25 and 26 cannot run the codecs even
  though images exist for them; the sibling `bounded_authority_report_adapter`
  audit probed the same wall independently from the consumed Hex package
  (`:json.decode/1` UndefinedFunctionError on OTP 25/26).

Separately, the owner ruled on 2026-09-16 that the library contract — `git clone`,
`deps.get`, `compile`, `test` — must hold on macOS, Linux, and Windows ("if this
cannot be cloned on a Windows machine it is a failed project"). A default
Git-for-Windows clone (`core.autocrlf=true`) would have checked every tracked text
file out with CRLF — byte-mangling the certified corpora whose index SHA-256 is
pinned at load — and the test path carried POSIX-only mechanisms (shell-shim
`System.cmd` targets, `/tmp` literals, `mktemp`, `sh -c`, chmod-based failure
injection).

## Decision

1. The supported-OTP set is **{27, 28, 29}**: the probe-derived build set for the
   declared line, intersected with the package's own OTP 27 stdlib floor. This is
   the set's rationale, not a change to the declared Elixir range, which stays
   `~> 1.18`.
2. `config/config.exs` raises at config-load time — before any compilation, for
   every Mix invocation in this repository — when the running OTP major is outside
   the set. The file is **not** shipped: `files:` in mix.exs excludes `config/`,
   so consumers of the published package never inherit this assert; each consuming
   repository enforces its own toolchain.
3. Lockstep rule: the mix.exs Elixir range, the config supported-OTP set,
   `.tool-versions`, and the CI compatibility lanes move together in **one commit**.
   A supported major without a CI lane is a defect; a lane outside the set is a
   defect.
4. Tri-platform build bar: the library contract must hold on macOS, Linux, and
   Windows. `.gitattributes` forces LF checkout everywhere (`* text=auto eol=lf`)
   and marks the byte-exact conformance trees `-text`. The test path contains no
   POSIX-only mechanism: `mix`/`elixir`/`escript` subprocesses route through one
   portable wrapper (`test_support/portable.ex`, `cmd /c` on win32), scratch paths
   use `System.tmp_dir!()`, and the two mechanisms with no Windows equivalent
   (chmod-based unreadability, the POSIX-shell publish guard) carry compile-time
   carve-outs naming the POSIX lanes that still cover them. A `windows-2025` CI
   lane proves the contract continuously. The full `mix quality` battery remains
   POSIX-only tooling (shell gates, Gitleaks, ProVerif, kramdown) and runs on the
   Linux lanes or WSL.

## Consequences

- Refusals are value-free and pre-compilation. Proof legs (throwaway source copy,
  official docker images): Elixir 1.17.3/OTP 27 is refused by Mix with the declared
  range error; Elixir 1.19.6/OTP 26 and Elixir 1.18.4/OTP 25 are refused at config
  load with the assert message (`supports Erlang/OTP 27/28/29; running 26` / `25`);
  Elixir 1.18.4/OTP 27 compiles green under `MIX_ENV=test`. The dev lane
  (`.tool-versions`, Elixir 1.20.2-otp-29 / Erlang 29.0.3) compiles green.
- The Windows surface is gated and observed green: the `windows-2025` lane proved
  checkout, `deps.get`, `compile --warnings-as-errors`, and `mix test` (445/445) on
  its first completed run (2026-09-17) and re-proves it on every push. The checkout-bytes claim is
  enforced by the eol policy (a default `core.autocrlf` clone would otherwise
  CRLF-convert the digest-pinned corpora); the POSIX-only test mechanisms (chmod-based
  unreadability, symlink-privilege cases, Win32-unrepresentable path components, the
  POSIX-shell publish guard) are carved out with the POSIX lanes named as their
  coverage at each site.
- Hex consumers see no new behavior: the assert never ships, and published-package
  bytes do not change.
