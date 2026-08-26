# The successor-major (v2) charter — consolidated scope

**Status:** design-only. This charter consolidates everything a successor contract-major is
charted to standardize, from the accepted ADRs that carry each mechanism. It activates
nothing: every name and mechanism below is reserved-and-rejected in the closed v1 profile
(the 283-green conformance corpus proves the rejection mechanically), and activation follows
the successor-major process (complete closed profile, corpus, cross-suite evidence rules).

## The absolute constants (unchanged across majors)

These do not move — they are the protocol's identity, not its features:

- The public verifier is pure, deterministic, and stateless. It never gains revocation state,
  replay reservation, trust selection, or an authorization decision (critical rules 1 and 4).
- Facts stay value-bearing, redacted, and non-authorizing.
- The closed-rejection invariant: unknown members, values, encodings, and extensions fail
  closed with the single error value.
- Suite succession under `BAP<contract-major>-<signature>-<digest>` naming with
  `BAP<contract-major>-*` domain separators; v1 never downgrades inside itself.

## Successor-major scope

### 1. Delegation with attenuation (ADR 0010)

The `ba_dlg` parent-grant-hash claim and the `ba+cap-delegated` typ with header-`jwk`
parent-holder key binding; the four-part attenuation relation (set-containment on distinct
tuples over the existing selector algebra, proven decidable); the depth-bounded
chain-verification algorithm. Portable holder-signed delegation is successor-major; the
current v1 wire rejects both names.

### 2. Offline-eligible floor limits (ADR 0016)

The reserved `ba_offline` claim: the closed `{cnt, cur, max, win}` nested object (maximum
value with explicit currency, maximum offline use count, offline-window expiry), the
non-authorizing facts contract, the `max × cnt` ceiling, and the `ba_dlg` attenuation
interaction. Absence means online-only. The endpoint honors floor limits at its own risk
within the window; the runtime reconciles deferred consumption and surfaces over-consumption
as a first-class event.

### 3. Suite succession and cross-suite evidence (ADR 0009 + ADR 0026)

The `BAP2-*` ML-DSA candidate family (RFC 9964's JOSE mapping; ML-DSA-65 baseline,
ML-DSA-87 tier); the hybrid-composite posture option (draft-ietf-jose-pq-composite-sigs,
decided at definition time); the content-covering `ba+suite-attestation` / `ba_sut`
countersignature that keeps v1 evidence verifiable after a classical break; the re-anchoring
procedure for long-lived chain/archive evidence.

### 4. The revocation and freshness posture (consolidated; amended 2026-08-26)

What a successor major MAY standardize AT THE INTERFACE — claim shapes and verifier-side
semantics only:

- **Freshness-bearing claim shapes.** Window-semantics claims (e.g. a short-lived
  status-assertion bound to the grant, in the family of the reserved status-check profile)
  whose VALIDITY the verifier can check statelessly: signed windows, monotone counters where
  the counter source is itself a signed artifact, and nonce-window semantics with exact
  bounds. The design bar: a verifier must be able to reject a stale freshness artifact from
  bytes and caller context alone.
- **What stays runtime-private, permanently.** Live revocation lookup, replay reservation,
  key-state trust selection, and per-invocation accounting are operational state; they are
  NOT standardizable as verifier interface because a stateless verifier cannot own them. A
  successor major standardizes the ARTIFACT SHAPES a runtime uses (status documents, replay
  witnesses) so deployments interoperate, never the verdict "this credential is currently
  trusted."
- **Baseline posture today (unchanged guidance).** Short-lived grants plus server-issued
  nonces for high-consequence operations; replay accounting and per-invocation audit from
  the consumption chain (`ba_inv` chained into append-only evidence); the status-check
  profile for long-lived grants defined once so deployments do not improvise; offline floor
  limits per ADR 0016 for connectivity-window fleets.

### 5. Selector expressiveness (owner decision, 2026-08-26)

The v1 selector algebra binds exact-value (`equals`) and enumerated-set (`one_of`) arguments.
Successor-major scope, decided deliberately rather than parked:

- **Per-request range constraints** — amount floor/ceiling, execution-date windows, and the
  like — are pure inequality selector kinds: a stateless verifier checks them from the grant
  bytes and the typed arguments alone. These are the natural successor-major extension of
  the selector algebra (the payments-vertical "spend up to X per request" mandate shape) and
  BELONG in the successor major's selector design.
- **Cumulative budgets** — "up to $500/day" — are NOT stateless: no verifier can check a
  cumulative bound from bytes and context alone. A naive `budget` selector kind would be a
  silent false security property. Budget enforcement routes to the freshness/revocation
  posture's runtime-private territory: issuer attestation (a re-issued grant or a signed
  budget-window assertion the verifier can check statelessly) or runtime-side accounting
  over the consumption chain. The successor major may standardize the ATTESTATION SHAPES;
  it must not standardize a bare cumulative selector.

This decision supersedes the parked fork in the AP2 mandate-mapping document, which now
points here.

## Activation checklist (per successor major)

1. Complete closed profile + spec revision under its own major.
2. Conformance corpus with its own certified identity.
3. Cross-suite evidence rules for prior-major artifacts.
4. Registries: reserved names flip to active by ADR.
5. The v1 profile's availability follows the governance document's deprecation policy.
