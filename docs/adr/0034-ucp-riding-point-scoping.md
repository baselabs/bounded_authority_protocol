# ADR 0034: UCP riding-point scoping

- Status: accepted
- Date: 2026-09-21
- Track: T2
- Closes: the UCP open question recorded by the [A2A capability-binding
  profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/a2a-capability-binding-profile.md) §12 and the [AP2 interop
  profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/ap2-interop-profile.md) §6 (owner direction 2026-09-21: resolve, do not
  park).

## Context

The AP2 interop profile (§6) recorded BAP's UCP riding point as undesigned, and the A2A
capability-binding profile (§12) carried it forward as "a separately-owned open question whose
precondition is pinning and reading a UCP source first." The owner directed resolution
2026-09-21. That precondition is now discharged: the UCP specification was read first-hand at
pinned commit `d3ccb55c43d0d801f4f8616e877599e2bd12c6ae`
([Universal-Commerce-Protocol/ucp](https://github.com/Universal-Commerce-Protocol/ucp),
Apache-2.0; `docs/specification/overview/index.md`, `docs/specification/signatures.md`,
`docs/specification/shopping/checkout/{index,rest,a2a}.md`,
`docs/specification/embedded-protocol.md`, `docs/documentation/ucp-and-ap2.md`,
`docs/versioning.md`; the payment tree's structure including
`payment/extensions/ap2-mandates.md`). All OBSERVED.

What UCP is (facts load-bearing for the decision):

1. **UCP is a multi-transport commerce protocol.** A service (e.g. `dev.ucp.shopping`) is
   declared per transport in a profile document at `/.well-known/ucp`: REST (OpenAPI), MCP
   (OpenRPC over streamable HTTP), A2A (Agent Card), and Embedded (OpenRPC over
   `postMessage` between an embedded iframe/webview and its host — not an HTTP transport).
   The checkout capability exposes five first-class REST operations (create / get / update /
   complete / cancel checkout) over HTTPS.
2. **UCP's authentication menu lists RFC 9421 HTTP Message Signatures as one of four
   SHOULD-level mechanisms** (with API keys, OAuth 2.0, and mTLS; businesses SHOULD
   authenticate platforms, and only business-to-platform webhooks MUST be signed). Where used,
   RFC 9421 applies to the HTTP transports: ES256 the universal baseline, RFC 9530
   `Content-Digest` over raw body bytes, keys published as a JWK Set in the profile, an
   optional Web Bot Auth dual-audience shape, replay via the business-layer `Idempotency-Key`.
   UCP defines no signature coverage for its A2A or Embedded bindings. AP2 is UCP's payment
   trust layer (checkout mandates bound to checkout hashes, via
   `payment/extensions/ap2-mandates.md`).
3. **UCP-over-A2A is an A2A extension — at an older A2A shape.** UCP declares an extension URI
   in the business's Agent Card, checkout data rides A2A `DataPart`s keyed `a2a.ucp.checkout`,
   and the platform's profile rides the `UCP-Agent` header. But UCP's A2A binding names
   `X-A2A-Extensions` in its required-headers table, and its examples use the `message/send`
   method — 0.3-era shapes against A2A 1.0's `A2A-Extensions` and `SendMessage`. Reconciliation
   is UCP's; until it lands, a deployment following UCP's published A2A binding does not speak
   the A2A this repository's binding profile targets.
4. **UCP governance is namespace-native.** Capability names are reverse-domain
   (`{reverse-domain}.{service}.{capability}`), authority-bound to the host serving the
   capability's `schema`; versions are date-based with long-lived `release/YYYY-MM-DD`
   branches; the `dev.ucp.*` namespace is reserved to the UCP governing body and vendors MUST
   use their own reverse-domain namespace. This is a venue-native negotiation surface any
   third-party binding can use without a central registry.

## Decision

**The UCP riding point is transport-composed; UCP introduces no new BAP layer, wire mechanism,
or binding fork.** The composition decision taken for A2A (recorded by the [A2A
capability-binding profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/a2a-capability-binding-profile.md) §3) applies per UCP
transport:

1. **UCP over the A2A transport is covered, as-is, by the [A2A capability-binding
   profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/a2a-capability-binding-profile.md) — for a deployment speaking A2A
   1.0.** A UCP business's agent endpoint is an A2A endpoint: the extension declaration,
   `BA-Grant` / `BA-Proof` carriage, the `ba_op` spelling, and the bounded per-operation
   projection all apply unchanged, and UCP checkout content inside `DataPart`s is bound by the
   profile's per-part digests (with the recorded boundary: selectors cannot reach into parts).
   A deployment following UCP's current published A2A binding (`X-A2A-Extensions`,
   `message/send`) does not trigger the profile's opt-in — its `BA-*` carriage would be
   ignored under the profile's undeclared-carriage rule — so this path is covered in design and
   uncovered in practice until UCP reconciles to A2A 1.0.
2. **UCP over the MCP transport is inside the BAP-08 MCP extension's scope**
   ([`docs/extensions/capability-authorization.mdx`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/extensions/capability-authorization.mdx)),
   whose open §4.2 transport binding is the owning surface for that path. UCP's MCP transport
   is JSON-RPC over streamable HTTP — the same surface that draft targets.
3. **UCP over the REST transport has a named follow-on design, not a new layer question:** a
   UCP-REST binding profile defining the five checkout operations' `ba_op` vocabulary under
   the project's own reverse-domain prefix (`io.bounded-authority/…`, per the A2A profile §7
   precedent; UCP reserves `dev.ucp.*` to its governing body), keyed to UCP's governed
   capability names, plus their bounded request projections — using the A2A profile as the
   template and UCP's profile documents as the venue-native negotiation surface, carrying the
   A2A profile's empty-`params` posture (publishing accepted contract-majors and suites stays
   deferred to the reserved verifier discovery document).
4. **UCP over the Embedded transport is out of scope** (no per-request HTTP target; an
   ADR 0027-class sibling profile would be the mechanism if ever needed).

**Composition doctrine (extends the AP2 profile §6 separation).** On UCP's HTTP transports
(REST, MCP): UCP's RFC 9421 signature, where a deployment uses it, binds transport identity
(who sent these bytes, covering `ucp-agent`); a BAP grant + proof binds invocation authority
(which holder may invoke which operation under which argument bounds, per request); AP2 binds
payment authorization (mandates bound to checkout hashes). The three surfaces are disjoint and
none covers another — a deployment composes them and must not assume any one substitutes for
another. On the A2A and Embedded bindings UCP defines no transport signature at all, so there
the transport-identity layer is the deployment's own and the same disjointness holds between
whatever it deploys and the BAP and AP2 layers.

## Alternatives considered

- **Design the full UCP-REST binding profile now.** Rejected on load-bearing sequencing: the
  A2A profile was designed first because AP2, UCP, and the payment cohort highlight the A2A
  integration path — it was the composition the program's whole interop arc pointed at. No
  adopting cohort yet names the REST path; Decision 3 records it as this program's follow-on
  with its precondition (an adopting deployment cohort) explicit, so it is a sequenced
  decision rather than a parked one.
- **Register a UCP venue capability (`io.bounded-authority.*`) now.** Rejected: using UCP's
  namespace governance for a third-party binding capability is venue strategy — publication
  under the project's domain is implied by any future UCP-REST profile, and each such
  publication is the owner's call. Nothing here publishes or promises publication.
- **Declare UCP permanently out of scope.** Rejected: the first-hand reads show real, direct
  composition (Decision 1 requires no new design for A2A-1.0-speaking deployments), and the
  AP2 profile's recorded host-protocol question deserves the answer the sources now support.

## Consequences

- The UCP open question recorded by the graduated design profiles and the ROADMAP is closed by
  this decision; those surfaces carry a pointer to this ADR from its landing.
- No BAP wire change, no new proof profile, no registry activation, and no reserved mechanism
  is designed or touched (the disclosure gate holds; delegation-shaped UCP requirements route
  to the successor-major program exactly as the A2A profile §12 routes them).
- The UCP pin `d3ccb55…` is this ADR's evidence anchor; a newer pin requires re-deriving the
  four transport facts before relying on them.
- Follow-on work owned by this program, each with its named precondition: the UCP-REST binding
  profile (adopting cohort); projection and `htu` conformance vectors plus real-substrate A2A
  drills (an implementing surface — the ES256 suite cohort's TypeScript signer and kiosk demo
  sweep is the natural first one).
