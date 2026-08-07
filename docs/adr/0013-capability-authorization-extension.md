# ADR 0013: Capability-authorization extension proposal

- Status: accepted
- Date: 2026-08-07
- Track: T2
- Refines: [ADR 0001](0001-public-protocol-verifier-boundary.md) (the public verifier boundary — the
  extension documents, does not change, it)

## Context

[ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §8 and the
[standards track charter](../design/standards-track.md) § Venue strategy name the MCP
`modelcontextprotocol/ext-auth` repository as the Bounded Authority Protocol's first external venue.
ROADMAP row BAP-08 carries that decision: draft a capability-authorization extension for that venue
plus an AP2 mandate-mapping note, documenting the already-normative v1 protocol. This ADR records
the decisions BAP-08 makes — it refines ADR 0001's public-protocol scope (the extension is a
public-facing document of that surface) without superseding it.

The MCP submission bar is [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) (Final,
Standards Track), verified live during BAP-08. It defines **three tracks** with rising gates:
(1) *unofficial* — published outside MCP governance under the author's own prefix, zero MCP gate;
(2) *experimental* — an `experimental-ext-` repo under the MCP org, associated with a working group,
the sanctioned **incubation path before SEP submission** (no reference-SDK requirement); (3)
*official* — the full bar: Extensions-Track SEP accepted by Core Maintainers, "MUST have at least
one reference implementation in an official SDK prior to review," working group + Extension
Maintainers + sponsor, `.mdx` lands in `ext-auth`. [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § SDK
Implementation adds that "Maintainers are under no obligation to implement any extension or
accept contributed implementations," so the reference implementation is a negotiation with the
`modelcontextprotocol` SDK maintainers, not a repository this project provisions.

## Decision

1. **BAP-08 targets the experimental track (track 2), with the official and unofficial tracks as
   recorded alternatives.** The official track's reference-SDK requirement is unreachable from this
   repository (an "official SDK" is an MCP-org SDK; this project's BAP-09 verifier SDKs verify *this*
   protocol, they are not implementations *in* an MCP SDK). The experimental track is the sanctioned
   pre-SEP incubation path with no reference-SDK requirement — though reaching it still requires an
   MCP maintainer to create the `experimental-ext-*` repository and a Working Group / Interest Group
   association ([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Experimental
   Extensions), i.e. an engagement with the MCP `ext-auth` working group, not a repository this
   project provisions. BAP-08 delivers a conforming pre-submission draft package for that track;
   official submission is gated on the external dependencies in Decision 5.

2. **The extension identifier is `io.bounded-authority/capability-authorization`.** The
   `io.modelcontextprotocol` prefix is reserved for official extensions
   ([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Official Extensions); this is
   a third-party proposal, so it uses the author's own reversed-DNS prefix. The project owns the
   `bounded-authority.io` domain (user-confirmed 2026-08-07), satisfying
   [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § Definition's reversed-domain
   rule. (An earlier draft asserted this ownership without verifying it; the design-adversarial
   review caught it, and ownership is now confirmed.)

3. **"AP2" in the ROADMAP row denotes the Agent Payments Protocol** (Google-originated, now
   FIDO-donated; [ap2-protocol.org](https://ap2-protocol.org/)). The abbreviation was undefined
   anywhere in the repository; the design-adversarial review caught that the "AP2 mandate-mapping
   note" deliverable rested on an undefined term. AP2 is the mandate layer (holder-signed
   authorization credentials — Verifiable Digital Credentials: Checkout Mandate, Payment Mandate)
   that this protocol's grant/proof model structurally corresponds to. The mandate-mapping note
   (`docs/extensions/ap2-mandate-mapping.md`) cites the AP2 v0.2 spec as its mapping target and
   makes **no runtime compatibility claim** — the correspondences are structural, and AP2
   self-describes as an extension for A2A, MCP, and UCP (the host-protocol question — at which layer
   an adopter composes AP2 with BAP — is recorded in the note).

4. **The extension documents, and does not change, the v1 *mechanism*; its MCP-spec surfaces are
   new normative requirements defined per SEP-2133.** `git diff -- lib/ test/ priv/conformance/
   mix.lock` is empty at closeout; the conformance corpus is unchanged at `agreed=259`. The
   capability-authorization *mechanism* (grant, proof, selector algebra, verification) restates the
   v1 surfaces in MCP vocabulary, citing the v1 profile per claim, and introduces nothing normative
   outside [`protocol-v1.md`](../protocol-v1.md). The extension's negotiation and graceful-degradation
   surfaces are normative requirements this extension defines for MCP per
   [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions); its transport binding is scoped
   to streamable-HTTP for this draft with the per-message binding left open (see the `.mdx` § 4.2) —
   not restatements of v1. The
   fidelity check (every restated mechanism value cites its v1 source) is a manual closeout
   discipline, not an automated gate — the extension documents do not ship in the Hex package
   (Decision 6), so ExDoc does not run against them.

5. **Official submission is gated on external dependencies, recorded as preconditions (not BAP-08
   closeout gates):** (a) a reference implementation in an official MCP SDK, negotiated with the
   `modelcontextprotocol` SDK maintainers; (b) a working group + Extension Maintainers + sponsor; (c) Extensions-Track SEP
   acceptance by the MCP Core Maintainers; (d) IANA registration of the `ba_*` / `ba+*` names,
   coordinated with the Bounded Authority Protocol's BAP-12 roadmap row (the names are currently
   reserved under the `ba_` / `ba+` collision-avoidance prefix, unregistered — the extension `.mdx`
   carries a registration-status note). BAP-08 drafts; it does not submit. **No new repository is
   required for BAP-08** — the official-SDK implementation is a future maintainer negotiation, not a
   repo this project provisions.

6. **The extension documents are repo-tracked under `docs/extensions/`, excluded from the Hex package
   census, and covered by the repository's Apache-2.0 license.** They are pre-submission drafts, not
   a consumer-facing capability of this package; shipping them in the Hex archive would publish a
   draft-as-final to package consumers. The README points to them as "pre-submission MCP extension
   drafts" (audience: the project + future submission, not package consumers).

## Alternatives considered

- **Target the official `ext-auth` track directly.** Rejected: the reference-SDK requirement is
  unreachable from this repository, and [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions)
  § SDK Implementation makes acceptance contingent on maintainer discretion the project cannot force.
  The experimental track is the honest reachable target.
- **Provision a new BaseLabs SDK repository to satisfy the reference-SDK requirement.** Rejected: an
  "official SDK" is an MCP-org SDK; a BaseLabs repo would not satisfy the term, and
  [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) § SDK Implementation is explicit
  that the official-SDK path runs through the `modelcontextprotocol` SDK maintainers.
- **Ship the extension documents in the Hex package.** Rejected: pre-submission drafts are not a
  consumer-facing package capability; shipping would misrepresent draft-as-final. They are
  repo-tracked + LICENSE-covered + README-pointed instead.
- **Claim AP2/BAP runtime compatibility in the mandate-mapping note.** Rejected: the BAP-08
  acceptance bar explicitly forbids "claiming compatibility not yet verified," and the
  no-round-trip-claims discipline (BAP-05) applies. The note maps structural correspondences and
  states compatibility is unverified.
- **Amend ADR 0001 in place rather than record a new ADR.** Rejected: ADR 0001 spans the whole
  public/private boundary; the extension is one execution decision (draft for a venue) that does not
  change the boundary, so a narrow ADR is more traceable (same split as ADR 0011/0012).

## Consequences

- The capability-authorization extension is drafted for the MCP experimental track as a
  pre-submission package (`.mdx` + SEP + AP2 mandate-mapping note), repo-tracked under
  `docs/extensions/`.
- Official submission to MCP `ext-auth` is gated on the external dependencies in Decision 5; until
  they close, the draft targets the experimental track. No new repository is owed from this project
  for BAP-08.
- No wire byte, bound, or verdict change; the design-only invariant
  (`git diff -- lib/ test/ priv/conformance/ mix.lock` empty) holds, and the conformance corpus is
  unchanged at `agreed=259`.
- The `ba_*` / `ba+*` names remain unregistered pending BAP-12 (filed at submission); the extension
  `.mdx` records this registration status.
