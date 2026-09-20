# ADR 0033: Developer portability, not a per-push tri-OS CI matrix

- Status: accepted (owner directive 2026-09-20; supersedes the per-push Windows CI lane
  element of [ADR 0031](0031-self-enforcing-toolchain-and-tri-platform-build-bar.md))
- Date: 2026-09-20
- Track: T2

## Context

ADR 0031's tri-platform build bar added a per-push `windows-2025` CI lane proving the
clone → `deps.get` → compile → test contract on Windows, next to the Linux lanes (macOS was
never a CI lane in this repository). The owner clarified the standing directive on
2026-09-20: the goal was always **developer portability** — a contributor on Windows, macOS,
or Linux can clone this repository and work on it — not continuous CI proof that the protocol
builds and tests on three operating systems. The per-push Windows lane bills paid runner
minutes against a contract the owner did not intend to prove on every push.

## Decision

1. The per-push Windows CI lane is removed. CI runs on Linux only: the three Elixir/OTP
   compatibility lanes, the complete-quality lane, and the informative lanes. No macOS lane
   is added.
2. The developer-portability contract stays and remains enforced in-repo, at zero runner
   cost: portable test support with Windows-aware branches, the LF-forcing `.gitattributes`
   discipline (a default-autocrlf checkout must not CRLF-mangle the certified corpora), no
   POSIX shell inside declared gates, and `cmd /c` routing where a process must spawn on
   Windows. ADR 0031's toolchain and pinning elements are unaffected by this ADR.
3. A Windows or macOS lane may be run ad hoc — `workflow_dispatch`, a throwaway branch, or a
   developer machine — when a platform-specific defect is actually suspected. Documentation
   claims exactly what CI proves: Linux lanes only.

## Consequences

- Per-push runner spend drops to Linux-only; the repo's single non-Linux runner lane is gone.
- README's development section states the developer-portability contract and the Linux-only
  CI scope; the hygiene and architecture tests keep their Windows-aware branches (dormant on
  Linux CI, correct for local Windows development).
- ADR 0031's header records the partial supersession.

## Alternatives considered

- **Keep the lane on a schedule instead of every push.** Rejected: still spends paid runner
  minutes continuously proving a contract the owner did not ask to prove; ad hoc on
  suspicion covers the diagnostic need.
- **Drop the in-repo portability machinery as well.** Rejected: that machinery IS the owner's
  directive — any-OS contributors — and it costs no runner minutes.
