# Consumer seam note — application report path (non-normative)

Date: 2026-08-02 · Status: informative. This note registers a consuming pattern. It is
**not** part of the normative protocol surface (`protocol-v1.md`, `protocol-charter.md`,
`conformance-contract.md`, `threat-model.md`) and changes no wire format, limit, or
verification rule.

## The seam

The private_consumer platform (owner's private verifier) plans to carry this protocol on
its **application report path**: a customer-side edge agent — built from the application transport
libraries (`transport component`, `transport component`) — reports materializations, checkpoints, and events
over the wire into the platform. Decision record: `bounded_authority/docs/adr/0002`.

Pattern, mapped to the public API:

- **Holder = the edge agent.** It holds its own holder key and assembles proof
  signatures locally (external signature assembly). Each report is an invocation
  carrying a grant + a proof envelope; the platform verifies with
  `verify_grant/3` + `check_envelope/2` and gets redacted, non-authorizing facts.
- **No verification service, no signing service.** Verification is embedded in every
  party via this package; signing is local to the holder. The stateful runtime
  (`bounded_authority`) participates only at issuance/renewal and
  revocation/replay-sensitive decisions.
- **Checkpoint-ack authentication (exploratory).** The platform's durable-commit
  confirmation back to the edge agent (the checkpoint-after-persist ack) can be a
  signed **boundary anchor** the agent verifies before advancing its transport
  checkpoint — authenticating the effect-once loop end-to-end with existing protocol
  objects. If this hardens into a requirement the protocol cannot express, that gap
  returns here as a proposed protocol change through the normal ADR path — never as a
  consumer-side fork of protocol semantics.

## Why record it here

The conformance thesis ("any language implements against the spec and vectors") is kept
honest by real consumers. This seam is an early first-party consumer whose topology —
embedded verification, local signing, wire-crossing reports — exercises exactly the
boundary this package was split out to serve. Transport libraries themselves stay free
of protocol code; the envelope lives in a separate composable report-path adapter.
