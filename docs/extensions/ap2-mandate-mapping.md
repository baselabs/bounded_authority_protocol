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

VDCs chain from an **Open** state (capturing user constraints) to a **Closed** state (capturing
finalized authorization); a closed Checkout Mandate plus a closed Payment Mandate together form the
non-repudiable proof of user authorization for a specific transaction. AP2 is described on its public
site as "an extension for [Agent2Agent (A2A)](https://a2aproject.dev/) and [UCP](https://www.universalcommerce.org/)"
— it is **not MCP-native**.

## The structural correspondence

Both AP2 and the Bounded Authority Protocol encode *issuer-signed authorization credentials that a
holder proves possession of per transaction*. The table maps the credential-model correspondence.

| AP2 v0.2 concept | Bounded Authority Protocol correspondence | Relationship |
|---|---|---|
| AP2 Checkout Mandate (signed authorization for the negotiated items/purchase details) | BAP `ba+cap` grant (issuer-signed capability over operations + selectors) | structural: both are issuer-signed authorization credentials binding *what* is authorized |
| AP2 Payment Mandate (signed authorization against a payment instrument, bound to a finalized checkout) | BAP grant with selector narrowing binding the payment scope + a `ba_req` request binding | structural: both additionally bind the *scope/target* of the authorization |
| AP2 closed-mandate proof (agent presents the closed VDC chain) | BAP `dpop+jwt` holder proof (binds the grant via `ath` + the request via `ba_req` + the invocation via `ba_inv`/`ba_op`) | structural: both prove holder possession of the authorization and bind it to the specific invocation |
| AP2 VDC credential model (signed, tamper-evident, chain Open→Closed) | BAP compact-JWS grant + DPoP proof (RFC 7515 / RFC 9449) | structural at the credential-model level |

The exact AP2 VDC wire format and field-level structure is defined in the AP2 v0.2 specification
under its `docs/` and `schemas/` directories; the field-level mandate↔grant mapping is an
execution-time read of those schemas, not asserted here.

## The host-protocol question (open)

AP2 is **A2A/UCP-native**, not MCP-native. The Bounded Authority Protocol's charter venue strategy
names the MCP `ext-auth` repository as its first venue. So a real design question for the
capability-authorization extension's target is: does the mandate correspondence operate at the
**MCP** layer (BAP grants presented at MCP tool/resource invocations — the charter-named venue) or
the **A2A** layer (BAP grants presented at A2A agent-to-agent delegations — where AP2 actually
lives)?

This note maps both correspondences and records that AP2's native host is A2A, while not prejudging
the eventual venue. The two are not mutually exclusive: a BAP capability grant could bind an MCP
tool invocation *and* be carried in an A2A delegation that AP2 secures. Resolving the primary target
is a content decision for the extension's eventual submission, shaped by where adoption is real.

## Honesty line

Every correspondence above is a **structural** mapping of the published Bounded Authority Protocol
v1 mechanism to AP2's VDC mandate model. This note does **not** claim:

- that an AP2-conforming agent can consume a BAP grant + proof (unverified);
- that AP2's VDC format is identical to or interoperable with BAP's compact-JWS grant (the exact VDC
  wire format is an execution-time read);
- that the host-protocol question (MCP vs A2A) is resolved.

This is the same no-round-trip-claims discipline the Bounded Authority Protocol applies to its
independent conformance verifier: a structural correspondence is a hypothesis about credential-model
alignment, not a verified runtime guarantee.
