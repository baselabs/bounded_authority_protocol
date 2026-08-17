# Offline authorization — protocol requirements (BAP side)

**Status:** requirement inputs consumed by the closed BAP-17 row (owner-set, 2026-08-02; the
roadmap row is closed — see [ADR 0016](../adr/0016-offline-eligible-grant-claims.md): the
`ba_offline` claim name is reserved in the registries and the activating-major mechanism is
specified; the offline arc itself is successor-major-gated). Nothing here changes protocol v1 — offline eligibility is a strictly
additive capability, and until it ships, every conforming verifier's existing behavior
(deny on unknown claims) already produces the correct result. Keywords
MUST/SHOULD/MUST NOT read per RFC 2119 intent.
**Origin:** unattended endpoints on connectivity windows (kiosk / EV charging /
vending fleets) that must answer "what happens when the authority service is
unreachable?" **Precedent:** EMV offline authorization — offline data authentication
plus issuer-set floor limits and deferred clearing. The runtime-side half lives in the
private repo: `bounded_authority/docs/design/offline-authorization-requirements.md`.

## Requirements

- **R-BAP-1 · Offline-eligibility claims, closed shape.** Define first-class grant
  claims expressing offline floor limits — at minimum: maximum value with explicit
  currency, maximum offline use count, and an offline time window. Closed shape,
  canonical encoding, no free-form extension field. Absence of these claims MUST mean
  online-only; the spec MUST state that default explicitly.
- **R-BAP-2 · Legacy verifiers stay correct by construction.** Protocol v1's
  unknown-claim rule (deny) MUST be preserved: a verifier that predates offline
  eligibility MUST deny a grant carrying these claims. This is the intended
  compatibility story — offline-eligible grants verify only where the claims are
  understood — and the spec MUST name it as intended behavior, not a migration bug.
- **R-BAP-3 · Offline consumption record.** Define a canonical, holder-signed record
  of an offline acceptance — grant ID, invocation ID, operation, amount, device/holder
  identity, monotonic sequence and device timestamp — deterministically encoded so any
  party can verify it independently, and self-contained so it can ride third-party
  journal/batch transports unmodified (the record is data to a carrier, protocol to a
  verifier). This record is the deferred-clearing artifact the runtime reconciles.
- **R-BAP-4 · Verifier facts, not decisions.** The verifier's offline-path output
  remains non-authorizing facts: signatures valid, bounds satisfied, "offline-eligible
  within stated limits: yes/no, limits: {…}". The acceptance decision belongs to the
  endpoint under its operator's policy; the authorization/effect split is unchanged.
- **R-BAP-5 · Conformance vectors.** Vectors MUST cover at minimum: accept-within-
  limits; deny-beyond-each-limit (value, count, window — boundary and beyond-boundary
  cases per the no-boundary-exact-span discipline); legacy-verifier denial of an
  offline-eligible grant; tampered floor-limit bytes failing signature verification;
  and consumption-record verification, including a tampered record.
- **R-BAP-6 · Threat analysis rides the spec.** The offline window is a deliberate,
  issuer-priced risk acceptance. The spec section MUST carry its threat analysis —
  double-spend across devices inside the window, clock skew on device timestamps,
  replayed consumption records — with the mitigation each limit provides, so adopters
  price the knob the way EMV adopters price floor limits.

## Non-goals

Offline issuance; consumption transfer between holders; any relaxation of
proof-of-possession or the no-bearer rule under any connectivity condition.
