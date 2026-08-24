# ADR 0022: Durable contract identities

- Status: accepted
- Date: 2026-08-24

## Context

The public protocol intentionally carries a contract major in its namespace,
wire fields, requirement identifiers, suite name, conformance corpus, SDK
facades, and package tag. A broad ban on every version token classified those
accepted public identities as implementation genealogy, leaving the repository
scanner permanently red.

## Decision

Project versioning is enabled at the kimosabe policy boundary, then narrowed by
the tracked architecture gate to the current accepted contract families:

- the `BoundedAuthorityProtocol.V1` namespace and the exact current-major source,
  test, corpus, SDK, and normative-document paths;
- wire field `v: 1`;
- suite `BAP1-Ed25519-SHA256` and the five current `BAP1-*` domain separators;
- `REQ1-*` identifiers only when present in the independent tracked requirement
  fixture, with exact equality against the normative requirement map; and
- `source_ref: "v#{@version}"` only at the `mix.exs` package boundary.

Path, identifier kind, major, and family are load-bearing. Contract identities
are accepted only on their enumerated source or normative-content path classes.
`V2`, `REQ2`,
`BAP2-*`, or another normative profile path remains rejected until a separately
accepted successor-major contract enumerates it. Modules, functions, queues,
events, config keys, tests, and implementation paths may not derive their names
from roadmap rows, tasks, review labels, or package chronology.

## Decision protocol

Initial recommendation: enable project versioning and rely on the universal
lifecycle-name scanner. The strongest counterargument was that this would admit
internal names such as `decode_v2` and an unaccepted `V2` facade. The initial
choice was revised: the binary project policy only disables its false-positive
version sweep, while a repository-owned multi-language scanner retains the
narrower allowlist and proves both accepted and rejected fixtures.

## Consequences

Contract-major identity remains explicit and independently testable. A new
major cannot enter accidentally through a filename or helper name. The
canonical kimosabe sweep continues to reject generic phase, task, slice,
sprint, step, and work-order names.
