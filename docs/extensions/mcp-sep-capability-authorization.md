# SEP-DRAFT: Capability-Authorization Extension

**Type:** Extensions Track · **Status:** draft (pre-submission; not yet filed as a SEP in the
`modelcontextprotocol/modelcontextprotocol` repository) · **Target venue:** MCP experimental-extension
track ([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Experimental Extensions),
with the official `ext-auth` track as a gated follow-on.

> This is a project-tracked draft from the
> [Bounded Authority Protocol](https://github.com/baselabs/bounded_authority_protocol). It is not a
> submitted SEP. Filing it as an Extensions-Track SEP in the main MCP repository is gated on the
> external dependencies in § Reference Implementation and § Submission gates.

## Preamble

- **SEP:** (to be numbered on submission)
- **Title:** Capability-Authorization Extension
- **Extension identifier:** `io.boundedauthority/capability-authorization`
- **Author(s):** Russ Palermo, BaseLabs
- **Sponsor:** None (seeking sponsor)
- **Working Group:** (to be identified — `ext-auth` authorization working group)
- **Extension Maintainers:** (to be identified)

## Abstract

This SEP proposes an OPTIONAL, additive capability-authorization extension for the Model Context
Protocol. An issuer grants a holder a cryptographically bounded capability over a set of MCP
operations and their arguments; the holder proves possession per invocation; a verifier checks the
capability against the invocation under a closed, fail-closed profile. The mechanism is the
already-normative [Bounded Authority Protocol v1 profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/protocol-v1.md);
this SEP documents it for the MCP venue. The capability-authorization *mechanism* (grant, proof,
selector algebra, verification) introduces nothing normative outside that profile; the extension's
negotiation, transport-binding, and graceful-degradation surfaces are normative requirements this
extension defines for MCP per [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions), not
restatements of the v1 profile. The
extension composes with — does not replace — the OAuth-scope authorization the existing `ext-auth`
extensions assume.

## Motivation

MCP's existing authorization model (the `ext-auth` extensions) is OAuth-scope-based: a client
presents a scoped access token, and the server decides whether the scope permits the invocation.
Scopes are coarse, string-based, and delegated entirely to the authorization server; they do not
cryptographically bind *which arguments* an operation may be invoked with, nor bind a specific
invocation to a specific holder proof. For agent-driven invocations — where an autonomous agent
calls tools on a user's behalf, and the consequences of an over-broad capability are real — a
finer-grained, cryptographically bound capability model closes a gap that scopes leave open: the
*object-level* authority ("this agent may call `transfer_funds` only for account A, only until
time T") is provable per-invocation, not merely asserted by a scope string. (The v1 selector
algebra expresses exact-value and enumerated-set argument bounds — `equals`/`one_of` — plus
operation, time, and audience bounds; it does not express inequality/range bounds like "up to
amount N," which remain a server-side policy check.)

The Bounded Authority Protocol already specifies this mechanism — bounded proof-of-possession grants
with a conjunctive selector algebra over invocation arguments, holder proofs that bind the request
operation and digest, and a closed, fail-closed verification profile. This SEP proposes documenting
it as an MCP extension so MCP implementers can adopt it without re-deriving the design.

## Specification

The normative specification of the mechanism is the
[Bounded Authority Protocol v1 profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/protocol-v1.md)
and its [registries](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/registries.md).
The extension-document restatement is
[`capability-authorization.mdx`](./capability-authorization.mdx), which carries the full conformance
language (BCP 14 / RFC 2119 / RFC 8174) required by
[SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Official Extensions. Conformance
to this extension REQUIRES conformance to the v1 profile's grant, proof, selector, header, and
verification surfaces; the extension's negotiation/transport/fallback surfaces (defined per
[SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions)) are the additional normative
requirements this extension introduces for MCP.

- **Extension identifier:** `io.boundedauthority/capability-authorization` (the
  `io.boundedauthority` prefix is a reversed-DNS name the extension author controls).
- **Capability negotiation:** via `capabilities.extensions["io.boundedauthority/capability-authorization"]`
  with a settings object identifying the accepted suite and contract-major
  ([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Negotiation).
- **Graceful degradation:** revert to core MCP authorization (OAuth scopes) when a peer does not
  support the extension ([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Graceful
  Degradation); a server MAY reject for a tool/resource that requires capability-auth.

## Rationale

The capability model is additive and composable with scope-auth: a capability grant narrows what
scopes permit, so deployments that already use scopes can layer capability-auth on top without
replacing their authorization server. The closed, fail-closed profile (reject every unlisted member)
is the structural defense against the `alg:"none"` / `crit`-confusion / permissive-compatibility
classes; it is non-negotiable and inherited from the v1 profile. The conjunctive selector algebra is
chosen over an open-ended caveat DSL (Macaroons/biscuits) deliberately: the closed algebra is the
attenuation language, mechanically checkable without interpretation.

## Backward compatibility

This extension is purely additive to the core protocol; it does not modify core MCP behavior.
Breaking changes to the extension (per [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions)
§ Definition) would require a new extension identifier (e.g. `...-v2`). The Bounded Authority
Protocol's own evolution contract (parallel contract-majors with published deprecation windows)
governs changes to the underlying mechanism.

## Security implications

See [`capability-authorization.mdx`](./capability-authorization.mdx) § Security considerations. The
load-bearing posture: **verification is not authority** — a verified grant + proof proves only that
the bytes satisfy caller-supplied trusted inputs; replay reservation, revocation state, and the
authorization decision are the MCP server's responsibility. The closed profile structurally rejects
the algorithm-confusion and permissive-parsing classes.

## Reference implementation

[SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Creation requires that an
extension SEP "MUST have at least one reference implementation in an official SDK prior to review."
This draft is **pre-submission**: no reference implementation in an official MCP SDK exists yet.
[SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § SDK Implementation states that
"SDK maintainers are under no obligation to implement any extension or accept contributed
implementations," so the reference implementation is a negotiation with the
`modelcontextprotocol` SDK maintainers (e.g. the TypeScript or Python MCP SDKs), not a repository the
extension author provisions. This SEP is not filed until that reference implementation exists;
filing is gated on it.

## Submission gates (external, recorded honestly)

Per [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions), official acceptance of this
extension requires — none of which this draft performs:

1. A reference implementation in an official MCP SDK (negotiated with the SDK maintainers).
2. A Working Group + sponsor identified in this SEP's Preamble.
3. Extensions-Track SEP review and acceptance by the MCP Core Maintainers.
4. IANA registration of the `ba_*` / `ba+*` names (coordinated with the Bounded Authority Protocol's
   BAP-12 roadmap row; the names are currently reserved under the `ba_` / `ba+` collision-avoidance
   prefix, unregistered).
5. On acceptance, a PR adding the `.mdx` to `modelcontextprotocol/ext-auth`.

Until these gates close, this draft targets the **experimental-extension** track
([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Experimental Extensions), which
is the sanctioned incubation path and does not require the reference-SDK implementation.
