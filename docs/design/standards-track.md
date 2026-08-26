# Standards track charter

## Objective

The Bounded Authority Protocol aims to become the industry standard for cryptographically bounded,
argument-level agent capability verification and attestation. A standard is more than a correct
library: it is consistent, persistent, and survives upgrades and enhancements. This charter defines
the evolution, cryptographic-agility, conformance, registration, governance, and delegation
posture that make those properties true — designed now, before first publication, because every
item here is cheap to define before third parties implement the profile and nearly impossible to
retrofit after.

This document is the standing authority for standards-track decisions. The
[protocol charter](protocol-charter.md) defines what the verifier does; the
`normative profile` freezes the current contract-major's bytes; the
[conformance contract](conformance-contract.md) defines how conformance is proven. This charter
defines how all three survive time.

Normative keywords in this charter (MUST, MUST NOT, MAY) carry the meanings defined in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as carried by the
`normative profile`. Evolution-contract requirements use the stable identifier
scheme of [ADR 0007](../adr/0007-normative-requirement-identifiers.md) under the `REQ1-EVO-*`
prefix and are traced to conformance cells in the requirement map
[requirement map](requirement-map.md).

## The evolution contract

The wire profile is closed: a conforming verifier rejects every unlisted member, value, encoding,
or extension. That posture is permanent (`REQ1-EVO-closed-format-permanent`). It is what
structurally kills the `alg:"none"`, `crit`-confusion, and permissive-compatibility class that
destroyed the security reputation of prior token formats, and no evolution need weakens it.
Evolution therefore happens **above** the wire format, through parallel contract-majors, never
through in-place extension of an open format (`REQ1-EVO-evolution-above-wire`).

### Self-declaration and negotiation

Every artifact already declares its contract-major mechanically: the `v` claim, the `typ` header,
and the version-bound domain separators (`BAP1-REQUEST\0` and siblings). A verifier detects the
major of any artifact from its bytes alone. Negotiation is therefore discovery, not handshake:

- A verifying deployment publishes the set of contract-majors it accepts (the discovery-document
  shape is defined at first external submission; its name is reserved in the
  [registries](registries.md)).
- An issuer chooses the emission major per audience capability. A holder presents artifacts of one
  major end-to-end: a proof's contract-major MUST equal its grant's contract-major
  (`REQ1-EVO-proof-major-equals-grant`). Mixed-major envelopes are invalid by construction
  (`REQ1-EVO-mixed-major-invalid`).
- Acceptance of an older major never weakens a newer one: each accepted major is verified under its
  own complete closed profile. There is no cross-major fallback, no downgrade path, and no
  best-effort parsing (`REQ1-EVO-no-downgrade`).

### Parallel-version support and deprecation

Successor contract-majors overlap rather than flag-day:

- A contract-major enters deprecation only after its successor has a published normative profile, a
  published conformance corpus, and at least two independent implementations passing that corpus
  (`REQ1-EVO-deprecation-prerequisites`).
- The deprecation window is published at announcement and is never shorter than twelve months
  (`REQ1-EVO-deprecation-window-minimum`), except for a security contract-major, whose accelerated
  overlap window is governed by the security-policy rule under § Governance. During the window,
  conforming verifier deployments support both majors in parallel
  (`REQ1-EVO-parallel-support-during-window`).
- Sunset of a major is a deployment decision after the published window, never a silent library
  change (`REQ1-EVO-sunset-is-deployment-decision`).
- Errata never change verification behavior. An erratum may clarify prose, correct non-normative
  text, or add conformance cases; **no erratum may flip a corpus verdict**
  (`REQ1-EVO-no-verdict-flip`). Any change that would alter an accept/reject outcome is by
  definition a contract-major change. The errata registry lives at [docs/errata.md](../errata.md).

### Registries

Two things genuinely vary within the protocol's lifetime and are governed by
[registries](registries.md) rather than by code: **operation-name conventions** and **selector
kinds**. The registries also carry reserved claim names, `typ` values, and cryptographic suite
identifiers. Reservation is cheap and immediate; activation of reserved semantics arrives only
with a contract-major. This is how the closed wire format and forward compatibility coexist: names
are coordinated ahead of time so independent implementers never collide, while the bytes of the
current major never widen.

## Cryptographic suite identity

The current profile is not "the" algorithm set; it is a **named suite**:
`BAP1-Ed25519-SHA256` — EdDSA over Ed25519, SHA-256 digests, RFC 8785 JCS canonical bytes, and the
`BAP1-*` domain separators. Every current artifact carries this suite identity implicitly through
its domain separators, `alg` values, and fixed widths. The suite registry names it explicitly.

Suite succession follows the naming scheme `BAP<contract-major>-<signature>-<digest>`. A successor
suite binds new domain separators, new `alg` values, and new fixed widths under its own
contract-major — the same closed posture, different constants. The `kid`/thumbprint indirection at
the key-locator boundary is already key-type independent, so trusted-key resolution survives suite
succession unchanged.

The successor candidate family is the `BAP2-*` ML-DSA family (FIPS 204, JOSE mapping per
RFC 9964), with a hybrid Ed25519+ML-DSA composite posture reserved per
draft-ietf-jose-pq-composite-sigs — the concrete names, parameter sets, quantum-readiness
statement, and revisit triggers are recorded in `docs/adr/0026-pq-successor-suite.md`.
Post-quantum migration is a decade-scale industry program already underway; this charter's
commitment is that the migration is a suite succession, not a redesign.

### Evidence longevity and cross-suite attestation

BAP-04 anchored exports and historical-key rollover exist so evidence verifies years later.
Long-retention evidence under a frozen signature algorithm means the evidence's trustworthiness
would expire before its retention period — a design problem, not a hypothetical. The committed
design direction, specified now and activated in a successor contract-major (carried to ADR
quality in [ADR 0009](../adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md)):

- **Cross-suite content-covering countersignature.** A boundary anchor of a current suite
  countersigns an archive whose rows and anchors were produced under an earlier suite, attesting
  "verified complete under suite A at time T" by signing the archive's CONTENT DIGEST (not merely
  chaining key/suite identity — a content-covering signature is required so trust survives the
  original suite's cryptanalytic break, since the original signatures are forgeable under break).
- Verification of aged evidence then has two parts: the archive verifies under its original suite's
  complete rules, and an authenticated content-covering countersignature from a currently trusted
  suite re-attests the archive's content. Trust freshness comes from the newest countersignature,
  not from the original signature surviving cryptanalysis.
- The archive's existing SHA-256 content digest (BAP-04, computed over every raw byte) is the
  binding target; suite succession reuses the anchored-export digest mechanism rather than
  inventing a parallel one.

## Conformance language

The normative profile currently expresses requirements as declarative prose. Before the
release-candidate contract (BAP-06), the profile is rewritten with RFC 2119 / RFC 8174 conformance
keywords, and every requirement receives a stable requirement identifier. The acceptance bar is
mechanical and unique to this project's method: **every MUST maps to at least one conformance-
corpus applicability cell (surface × class) or to a named, falsifiable gap** — requirement-to-
corpus traceability, so a standards reviewer can walk from any normative keyword to the executable
cases that prove it both directions. Prose that cannot be mapped is either not a requirement or a
missing corpus case, and the mapping exposes which.

## Registrations

The protocol's claim names (`ba_inv`, `ba_op`, `ba_req`) and `typ` values (`ba+cap`,
`ba+chain-anchor`, `ba+key-transition`) are currently unregistered. For the standards track they
are registered with IANA — the JWT Claims registry and the media-type suffix conventions
respectively — both for collision safety and because registration is the visible signal of a
standards posture rather than a vendor format. Registration templates are prepared as their own
roadmap row and filed at first external submission. Until filing, the `ba_` and `ba+` prefixes are
the collision-avoidance namespace, and the [registries](registries.md) document is authoritative
for every name this protocol uses or reserves.

## Delegation with attenuation

Multi-agent topologies sub-delegate: a planner spawns workers, each needing a narrower capability
than its parent. The current contract-major binds one holder per grant, deliberately. The
delegation design is **specified now** so the successor contract-major implements an
already-decided shape rather than opening a design debate after external adoption:

- **Chained attenuated grants.** A delegation link is itself a signed grant whose issuer is the
  parent grant's holder, bound to the parent by a parent-grant-hash claim (the reserved `ba_dlg`
  registry entry) exactly as `ath` binds a proof to its grant. The chain roots at a trusted issuer.
- **Attenuation is the only direction, and it is mechanically checkable.** A child grant's
  operations are a subset of the parent's by name; a child operation's selectors are the parent's
  selectors PLUS additional conjunctive selectors; the child validity window and audience set lie
  within the parent's. Because the existing selector algebra is conjunctive, adding selectors can
  only narrow — the subset relation is decidable without any new language.
- **No caveat interpreter.** Macaroons and biscuits demonstrated attenuation's value and its cost:
  an open-ended caveat DSL is exactly the extension surface this protocol's closed posture forbids.
  Here the closed selector algebra IS the attenuation language. Nothing is interpreted; everything
  is compared.
- Verification walks the chain from the trusted root, depth-bounded, verifying each link's
  signature and subset relation under the same closed rules; the holder proof binds the leaf grant.

The names this design needs (`ba_dlg`, a delegated-capability `typ`) are reserved in the
registries now. The full mechanism — the `ba_dlg` claim schema, the `ba+cap-delegated` typ with
its parent-holder key binding, the depth-bounded chain-verification algorithm, and the attenuation
subset rules proven decidable against the existing selector algebra — is specified in
[ADR 0010](../adr/0010-delegation-with-attenuation.md).

## Revocation and freshness

The verifier library is pure and stateless by charter, and stays so. But a standard that says
nothing about revocation gets implemented inconsistently, so the standards track ships deployment
guidance with normative force at submission time:

- Baseline freshness comes from bounded validity windows and the nonce challenge already in the
  profile: short-lived grants plus server-issued nonces for high-consequence operations are the
  default posture, not an optional hardening.
- Replay accounting and per-invocation audit come from the consumption chain (`ba_inv` bound into
  the signed proof, chained into append-only evidence).
- For long-lived grants, a status-check profile (issuer-published revocation status, exact shape
  defined once at submission; name reserved in the registries) prevents each deployment from
  improvising its own. The library still never performs I/O; the deployment requirement sits at
  the layer that already owns key resolution and replay state.
- **Offline-eligible floor limits.** For endpoints that must answer during a connectivity window
  (kiosk / EV-charging / vending fleets), an issuer MAY price an offline risk acceptance into a
  grant via floor-limit claims (the reserved `ba_offline`): maximum value with explicit currency,
  maximum offline use count, and an offline-window expiry. The endpoint honors these at its own
  risk within the window; the runtime (in the private `bounded_authority`) reconciles deferred
  consumption and surfaces over-consumption as a first-class event. The closed claim shape, the
  non-authorizing facts contract, the `ba_dlg` attenuation composition, and the successor-major
  activation are specified in [ADR 0016](../adr/0016-offline-eligible-grant-claims.md); the
  requirements are [R-BAP-1..6](offline-authorization-requirements.md). The closed v1 profile
  rejects the reserved name today; activation arrives with a successor contract-major.

## Principal binding

Regulatory direction is converging on binding agent actions to the human or organizational
principal who authorized them. `ba_inv` plus the consumption chain gives invocation-level
attribution; what is missing is an explicit, issuer-asserted on-behalf-of claim. The registry
reserves `ba_obo` — an issuer-asserted principal identifier (StringOrURI), verified as exact
expected context like every other bound claim — with semantics activated in a successor
contract-major. Reserving it now means independent implementations never squat the name and the
audit story has a designed home.

## Governance

Published now, while the project is single-maintainer, because publishing the policy is the
credibility step and the policy is what makes single-maintainer tolerable to adopters:

- **Change classes.** Editorial (errata; never verdict-changing) · clarifying (minor version;
  additive docs/cases only) · wire or verification behavior (contract-major only, with a public
  ADR).
- **Change control.** Every product-shaping decision lands as a numbered public ADR. Once at least
  two independent external implementations pass the conformance corpus, contract-major ADRs gain a
  published comment window of no fewer than thirty days and a change-control group with implementer
  representation. The hand-off criterion to a formal standards body is adoption, not ceremony:
  when a venue (see below) accepts the work, that venue's process supersedes this one.
- **Errata channel.** [docs/errata.md](../errata.md) is the numbered errata registry; each entry
  names affected versions and its corpus impact, and the no-verdict-flip invariant is checked at
  review.
- **Deprecation policy.** As defined in the evolution contract above; the policy text there is the
  authoritative one.
- **Security policy.** SECURITY.md governs vulnerability intake; a vulnerability whose fix would
  change a verdict is handled as a contract-major security release with an accelerated overlap
  window — published at announcement and set proportional to the vulnerability's severity, exempt
  from the twelve-month deprecation minimum above (§ The evolution contract), yet still a published,
  deployment-decided sunset, not a flag-day — never as a silent verdict change.

The governance policy is also published as a standalone normative project document at
[docs/governance.md](../governance.md); this charter section remains its authoritative source.

## Venue strategy

- **First:** the MCP `ext-auth` extensions repository (roadmap row BAP-08) — fast, targeted, and
  aimed at exactly the agentic-invocation audience this protocol serves. The extension documents
  the already-normative profile; nothing normative is introduced outside it.
- **Durable home:** IETF (OAuth/GNAP working-group orbit) if and when external traction warrants —
  the registries, RFC 2119 profile, and IANA templates in this charter are built to that
  submission bar from the start.
- **ISO:** treated as a design checklist (consistency, testability, conformity assessment,
  persistence), not a destination. ISO is the wrong venue for a wire protocol; its principles are
  the right lens for auditing one.

## Sequencing

Ordered, and wired into the repository roadmap (`docs/ROADMAP.md`, repository-internal) as
dependencies of the first public release — BAP-07 does not publish without the items that cannot
be retrofitted:

1. **Evolution contract + registries + RFC 2119 normative pass** (row BAP-10) — the one item that
   becomes impossible after third parties implement.
2. **Cryptographic suite identity + evidence longevity design** (row BAP-11) — cheap now,
   expensive later; the domain separators and key indirection already carry the bones.
3. **IANA registration templates** (row BAP-12) and **published governance** (row BAP-13) —
   mechanical, disproportionate credibility.
4. **Delegation-with-attenuation contract design** (row BAP-14) — decided above; the row carries
   the full design to ADR quality so the successor contract-major starts from a specification.

The venue decision is made (this charter); BAP-08 executes it.
