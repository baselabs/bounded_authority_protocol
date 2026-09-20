# AP2 mandate-mapping note — Agent Payments Protocol ↔ Bounded Authority Protocol

**Status:** pre-submission draft (BAP-08). **Not a compatibility claim.** This note maps
*structural* correspondences between the [Agent Payments Protocol (AP2)](https://ap2-protocol.org/)
mandate model and the Bounded Authority Protocol's grant/proof model. Runtime compatibility — an
AP2-conforming agent actually consuming a Bounded Authority Protocol grant + proof end-to-end — is
**not verified** by this note and is **not claimed**. It is a future connected-verification concern.

## What AP2 is

[AP2 (Agent Payments Protocol)](https://ap2-protocol.org/) is the Google-originated, FIDO-donated
specification (current version v0.2; standardization continuing within the FIDO Alliance's Agentic
Authentication and Payments Technical Working Groups) for how an AI agent cryptographically proves to
a merchant or payment network that a real user authorized a specific purchase. Its mandate layer is
built on **Verifiable Digital Credentials (VDCs)** — tamper-evident, cryptographically signed digital
objects. Two mandate kinds:

- **Checkout Mandate** — captures the reference to the specific items and purchase details negotiated
  between the agent and the merchant.
- **Payment Mandate** — authorizes a payment against a specific payment instrument.

Mandates are created through a delegation ceremony on a **Trusted Surface** (a user-consent surface
guaranteed by a User Credential issuer or a Trusted Agent Provider), and they form a
**cryptographically verifiable chain** from an **Open** state (constraint-bearing, bound to the
agent's key) to a **Closed** state (bound to one transaction by the agent's proof-of-possession); a
closed Checkout Mandate plus a closed Payment Mandate together form the non-repudiable proof of user
authorization for a specific transaction. Its overview describes AP2 as
"an extension for emerging agent-to-agent (A2A), model-context protocols (MCP), and Universal
Commerce Protocol (UCP)" (AP2 v0.2 `docs/overview.md`) — so it targets **A2A, MCP, and UCP** as host
protocols.

**Positioning.** The Bounded Authority Protocol is a different answer at the same layer as AP2's
agent authorization framework — composable with it, not nested under it. Both bind an issuer-signed
permission to a holder key with per-presentation proof-of-possession; they differ in constraint
language, verifier state, proof binding surface, output, and signature suite, as mapped below.

## The structural correspondence

Both AP2 and the Bounded Authority Protocol encode *issuer-signed authorization credentials that a
holder proves possession of per transaction*. The table maps the credential-model correspondence.

| AP2 v0.2 concept | Bounded Authority Protocol correspondence | Relationship |
|---|---|---|
| **Open Mandate** — user-approved via a Trusted Surface (`docs/ap2/agent_authorization.md` § Mandate Delegation), issuer-signed SD-JWT VDC carrying `constraints` and a `cnf` key binding to the agent (§ Mandate Structure) | BAP grant (issuer-signed compact JWS over operations + selectors, bound to the holder key) | structural: both are issuer-signed, constraint-bearing, holder-key-bound authorization credentials. This — not the closed mandate — is the grant's analog |
| **Closed Mandate + Key Binding JWT** — the agent binds the mandate to a specific transaction by signing with the key endorsed in the open mandate's `cnf` | BAP `dpop+jwt` holder proof (binds the grant via `ath` + the request via `ba_req` + the invocation via `ba_inv`/`ba_op`) | structural: both are the per-transaction proof-of-possession hop |
| Mandate chain — each open mandate's constraints are checked against the closed mandate content by the verifier walking the chain | BAP selector evaluation — every selector is evaluated against the typed request arguments the proof binds | structural but partial: AP2's narrowing-to-this-transaction lives inside a second credential (the closed mandate); BAP's narrowing lives at proof verification (server-derived typed arguments), with no second credential |
| Verifier-signed Mandate Receipt — `result: "success"\|"error"` plus `reference` (a hash over the final SD-JWT in the chain, calculated in the same manner as `sd_hash`) | **no correspondence, by design**: public verification returns value-bearing facts marked `not_evaluated`; the protocol has no decision and no receipt | structural difference, not a gap: AP2's verifier issues a signed decision; a Bounded Authority Protocol verifier never does — the operational decision belongs to a stateful authority runtime |

The mandate-kind split (Checkout vs Payment) has no one-to-one counterpart: the Bounded Authority
Protocol has one grant kind, and the payment-versus-checkout distinction rides in the grant's
operations and selectors rather than in the credential type.

## Constraint-language correspondence

AP2's constraint model is an **open type registry**: a new constraint type specifies a unique
`type`, a schema (which may mark fields selectively disclosable), and its own evaluation
algorithm (`docs/ap2/specification.md` § Extension Points). New mandate types and new constraint
types MAY be defined, with collision-resistant naming RECOMMENDED
(`docs/ap2/agent_authorization.md` § Mandates using SD-JWT VCs). Unknown constraint types **fail
evaluation** — the verifier treats them as failing
(`docs/ap2/agent_authorization.md` § Verification and Processing Rules). The Bounded Authority
Protocol's selector algebra is a **closed kind set** — contract-major 1 recognizes `all`, `equals`,
and `one_of`; contract-major 2 adds the per-request range kinds `lte` and `gte`
([`spec/bap-v2.md`](../../spec/bap-v2.md); [ADR 0028](../adr/0028-range-selector-kinds.md); activated
by [ADR 0030](../adr/0030-v2-contract-major-activation.md), released in 0.4.0) — and unknown kinds,
members, and encodings fail closed. Both protocols fail closed on the unrecognized; they differ in
who may extend the recognized set (anyone, via a new AP2 constraint type; only a new BAP
contract-major).

For the Payment Mandate constraints specifically (`docs/ap2/payment_mandate.md`):

- **Allowed Payee / Allowed Payment Instrument / Allowed PISP** (set membership) ↔ `one_of`
  selectors.
- **`payment.amount_range`** (min/max/currency) and execution-date ranges (per-request inequality
  bounds) ↔ the contract-major 2 `lte`/`gte` range selectors — statelessly verifiable, same-tag
  numeric operands, inclusive comparison. Range bounds are expressible since contract-major 2; they
  are no longer a selector-expressiveness gap.
- **`payment.budget` and `payment.agent_recurrence`** ↔ deliberately **no selector correspondence in
  any major**. AP2 defines their evaluation over verifier state — the accumulated total of
  previously closed Payment Mandates, or the timing and count of previous presentations — and the
  Bounded Authority Protocol's public verifier is stateless by construction: no verifier can check a
  cumulative bound from grant bytes and request context alone. Budget enforcement routes to the
  issuer-attestation / runtime-accounting posture
  ([successor-major charter](../design/successor-major-charter.md) § Selector expressiveness;
  [ADR 0029](../adr/0029-budget-window-posture.md)). This is a real structural disagreement between
  the two protocols, recorded on purpose rather than papered over.

## Other structural differences a reviewer will meet

- **Signature suites.** AP2 requires the merchant-signed Checkout JWT to use a digital signature
  scheme such as ECDSA and forbids deterministic signatures such as Ed25519 there
  (`docs/ap2/specification.md` § Payment Mandate); on the holder side, AP2's agent key material is
  profiled as EC P-256 with ES256 throughout — the open mandate's `cnf.jwk` and the SD-JWT /
  key-binding algorithm values (`docs/ap2/agent_authorization.md`) — while every Bounded Authority
  Protocol suite to date is Ed25519 (`BAP1-`/`BAP2-Ed25519-SHA256`). One holder key therefore
  cannot serve both sides today, and credential-level byte interoperability is not claimed. The
  suite difference is a composition seam, named here so a reviewer does not have to find it.
- **Proof binding surface.** AP2's key-binding hop binds the mandate content, `aud`, `nonce`,
  `iat`, and a hash of the preceding SD-JWT (`sd_hash`, or `issuer_jwt_hash` in the SDK's
  delegation chain) — no DPoP / RFC 9421-style binding of an HTTP method, URI, or request body
  exists anywhere in AP2 v0.2. A Bounded Authority Protocol proof binds `htm`, `htu`, `ba_inv`,
  and `ba_op` over server-derived typed request arguments. A composition must not assume either
  binding surface enforces the other's.
- **Selective disclosure.** AP2 mandates are SD-JWT VCs: constraint content may be hidden behind
  disclosure hashes and revealed per presentation, with the agent choosing disclosures to maximize
  user privacy. Bounded Authority Protocol grants are plaintext JSON by design
  ([`spec/bap-v1.md`](../../spec/bap-v1.md) — authenticity and integrity, not confidentiality), and
  every selector is evaluated on every verification. A composition inherits AP2's partial-disclosure
  semantics on the AP2 side only.

## The host-protocol question (open)

AP2 targets A2A, MCP, and UCP as host protocols, so the capability-authorization extension's
mandate correspondence is relevant at multiple layers. The Bounded Authority Protocol's charter
venue strategy names the MCP `ext-auth` repository as its first venue — and MCP is one of AP2's
named hosts — so an MCP-layer correspondence (BAP grants presented at MCP tool/resource invocations,
AP2 mandates securing the payment/checkout step an MCP tool triggers) is directly in scope. The
A2A and UCP layers are additional correspondences (BAP grants carried in A2A agent delegations; AP2
mandates composed with UCP checkout flows), not mutually exclusive with the MCP one.

Resolving the primary target is a content decision for the extension's eventual submission, shaped
by where adoption is real; this note maps the correspondences without prejudging the venue split.
The structural mapping above holds at whichever host layer an adopter composes AP2 with BAP.

## Honesty line

Every correspondence above is a **structural** mapping of the published Bounded Authority Protocol
mechanism (contract-majors 1 and 2) to AP2's VDC mandate model (v0.2). This note does **not** claim:

- that an AP2-conforming agent can consume a BAP grant + proof (unverified);
- that either protocol's verifier accepts the other's credential or proof bytes (the signature-suite
  difference above is one reason it does not);
- that Bounded Authority Protocol verification yields an authorization decision or receipt — it
  yields facts marked `not_evaluated`, by design;
- that the host-protocol question (which host layer among A2A, MCP, and UCP is primary) is resolved.

This is the same no-round-trip-claims discipline the Bounded Authority Protocol applies to its
independent conformance verifier: a structural correspondence is a hypothesis about credential-model
alignment, not a verified runtime guarantee.
