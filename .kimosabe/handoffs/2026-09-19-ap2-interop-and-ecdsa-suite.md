# Handoff: AP2 interop profile, mapping-note corrections, and an ECDSA signature suite

Written September 19, 2026 by a session that had read access to this repository and to the
`bounded_authority_report_adapter` repository but wrote to neither. Adopt this file into
`.kimosabe/handoffs/` of `bounded_authority_protocol` in that repository's own commit; it was authored
outside the tree because the authoring session was not permitted to write here.

Audience: engineer — a fresh agent session opened in `bounded_authority_protocol`, later one opened in
`bounded_authority_report_adapter` — and the owner. Register: technical detail, precise, no marketing language.

Evidence classes: **OBSERVED** (a file, command or page read first-hand by the party named), **DERIVED**
(read by a research agent on September 19, 2026 and restated here; the author of this handoff did not open
the file), **INFERRED** (reasoning), **REPORTED** (a third party's statement).

## 0. READ THESE FIRST — source provenance

External contracts apply. Read the normative source for any surface before implementing it; a line number
below is a pointer to verify, not a fact.

- **AP2 (Google Agentic Commerce), the counterparty contract for the interop profile.** Repository
  `google-agentic-commerce/AP2`, `main` = `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (April 29, 2026,
  "fix: remove uvlock (#246)"); tag `v0.2.0` = `b4587ac1d055…` (April 28, 2026). No commit has landed on
  `main` since (DERIVED: `git log --since=2026-04-29` on a fresh clone returned 0; known-positive control
  `gh pr list --state merged --search merged:>=2026-04-28` returned #233, #238, #239, #240, #246). Files that
  carry the contract: `docs/ap2/agent_authorization.md`, `docs/ap2/specification.md`,
  `docs/ap2/payment_mandate.md`, `docs/ap2/checkout_mandate.md`, `docs/ap2/flows.md`,
  `docs/ap2/security_and_privacy_considerations.md`, `docs/ap2/implementation_considerations.md`,
  `code/sdk/schemas/ap2/*.json`, `code/sdk/python/ap2/sdk/constraints.py`, `sdjwt/chain.py`,
  `sdjwt/kb_sd_jwt.py`. Re-clone at that commit before designing; do not work from the rendered site.
- **This repository, at HEAD `4ac276a` (September 18, 2026; Hex `bounded_authority_protocol` 0.4.1).**
  `spec/bap-v1.md`, `spec/bap-v2.md`, `docs/extensions/ap2-mandate-mapping.md`,
  `docs/extensions/capability-authorization.mdx`, `docs/design/successor-major-charter.md`,
  `docs/design/registries.md`, `docs/adr/0010`, `0013`, `0026`, `0028`, `0030`, `docs/standards/submissions.md`.
  All DERIVED for this handoff's author; every line number cited below was reported against that HEAD.
- **`bounded_authority_report_adapter` at 0.6.3**, `mix.exs` exact pin `{:bounded_authority_protocol, "== 0.4.1"}`
  (DERIVED). Key-shape assumptions live in `lib/bounded_authority_report_adapter.ex` and
  `lib/mix/tasks/bounded_authority_report_adapter.doctor.ex` and `.install.ex` (DERIVED, see §4 B2).
- **Normative references for the suite work:** RFC 7515 (JWS), RFC 7518 §3.4 (ES256: raw `r || s`, 64 bytes),
  RFC 7638 (JWK thumbprint; for an EC key the members are `crv`, `kty`, `x`, `y`), RFC 9449 (DPoP), RFC 8785
  (JCS), FIPS 186-5 / SEC 1 (P-256 encodings), RFC 9901 (SD-JWT, the AP2 side). Read these first-hand.
- **Disclosure gate (owner-held; its record lives outside this repository).** Nothing beyond the currently
  published specification text enters this repository until the owner lifts the gate. In particular no
  successor-major mechanism from the private design — delegation with attenuation (`ba_dlg`), on-behalf-of
  (`ba_obo`), offline floors (`ba_offline`), cross-suite attestation (`ba_sut`), any detached profile — may be
  activated, documented beyond its existing reserved registry rows, or shipped. The gate is about **content,
  not timing**: an ECDSA signature suite discloses no gated mechanism and is not itself gated (owner decision,
  September 19, 2026).

## 1. Worst open item

`docs/extensions/ap2-mandate-mapping.md` is public text that is false at HEAD: it says the selector algebra
does not express inequality or range bounds, and that range kinds are successor-major scope. v2 `lte`/`gte`
are active (`spec/bap-v2.md` lines 77–78; ADR 0030 accepted September 13, 2026; shipped in 0.4.0 on
September 14, 2026 per `CHANGELOG.md` lines 82–92 — all DERIVED). A standards reviewer who knows AP2 will read
this note first. Next evidence: open the note and `spec/bap-v2.md` side by side, confirm each cited line, and
correct the note (§4 A1) before any other item.

## 2. Status

**Goal.** Position the Bounded Authority Protocol as composable with AP2, with the published text telling the
truth about both: (a) correct the stale AP2 mapping note and the matching paragraph in the capability
authorization extension; (b) design an AP2 interop profile; (c) add an ECDSA (ES256 / P-256) signature suite as
a contract-major so a BAP holder key can be the same key AP2 binds in an open mandate's `cnf`; (d) bring the
report adapter along.

**Decisions accepted by the owner on September 19, 2026, binding on this work.**

1. Compose with AP2; do not position against it. The framing sentence: the Charter Agreement Protocol and
   the Agent Blueprint Protocol are additional layers AP2 does not have; the Bounded Authority Protocol is "a
   different answer at the same layer as AP2's agent authorization framework, composable with it." The sentence
   never to be written: "a deeper layer under AP2 with no overlap."
2. The mapping-note correction is blocking for any standards material that leaves this repository.
3. The ECDSA suite is a contract-major under the `BAP<contract-major>-<signature>-<digest>` naming with its own
   domain separators (`docs/design/successor-major-charter.md` lines 18–19, DERIVED). It may start now; the
   disclosure gate in §0 governs its content.
4. The report adapter follows the suite; it is not touched for tranche A.
5. Apache-2.0 stays on the protocol packages. Nothing is submitted to any body: `docs/standards/submissions.md`
   reads "Nothing has been submitted" (DERIVED).

**Whole-outcome coverage.** Implementation: none started. Verification: none run. Delivery: none. This handoff
transfers design intent and verified-by-research facts only.

**Why the layers are as stated (DERIVED from the AP2 texts at `e1ea56d` and the specs at `4ac276a`).**
AP2's agent authorization framework and BAP's grant→proof both bind an issuer-signed permission to a holder key
with per-presentation proof-of-possession and typed constraints. They disagree on: verifier state (AP2 requires
it for `payment.budget` and `payment.agent_recurrence`, `payment_mandate.md` lines 58–63 and 204–209; BAP refuses
budgets as selectors, `successor-major-charter.md` lines 81–87); constraint language (AP2 open type registry,
each type with its own evaluation algorithm, `specification.md` lines 371–379, unknown types fail,
`agent_authorization.md` line 465; BAP closed five-kind algebra); what the proof binds (AP2: mandate content,
`aud`, `nonce`, `sd_hash`, nothing binding method, URI or body — zero hits for DPoP or RFC 9421 across AP2 docs
and SDK, known-positive `budget` 7 hits; BAP: `htm`, `htu`, `ba_inv`, `ba_op`, `ba_req` over server-derived
typed arguments); evaluation completeness (AP2 selective disclosure is mandatory and evaluation is
presence-driven, AP2 issue #339 closed "Intended Behavior"; BAP grants are plaintext and every selector is
evaluated); output (AP2 verifier-signed receipt = a decision; BAP facts marked `not_evaluated`); signature
suite (AP2 ES256, Ed25519 forbidden for the checkout JWT, `specification.md` lines 155–157; BAP Ed25519 only).

## 3. Done (verified)

Nothing in this repository or in the report adapter was changed by the authoring session, and no command was
executed in either tree by it. The only verified work is reading: two research passes on September 19, 2026,
one over the Visa Trusted Agent Protocol and Intelligent Commerce pages, one over AP2 at `e1ea56d` and the three
protocol specifications (DERIVED, as labeled throughout). There is no changed file to account for.

## 4. Open / not done

Everything below is open: nothing has been implemented, authored or executed. Two tranches, ordered by what
the standards material needs first; both are permitted now under the content gate in §0.

**Tranche A — documentation truth and the interop design (start now).**

- **A1. Correct `docs/extensions/ap2-mandate-mapping.md`** (authored August 7, 2026 `a8d4c4f`; last touched
  August 26, 2026 `b20f580`, which changed only the selector-gap paragraph — DERIVED). Sentences reported false
  or imprecise at HEAD: lines 47–50 (the algebra "does **not** express" range bounds — v2 does); lines 52–54
  (range kinds "DECIDED successor-major scope" — shipped); line 36's table maps the *closed* checkout mandate to
  a `ba+cap` grant, when the grant's analog is the *open* mandate (issuer-signed, `cnf`-bound,
  constraint-bearing; `agent_authorization.md` lines 396–400 and 441–443) and the closed mandate in the
  autonomous mode is the agent's key-binding hop, which line 38 already and correctly maps to the BAP proof —
  the table double-counts; lines 41–43 defer a field-level mandate↔grant read that has since been done and
  never carried back. Also add what the note never mentions: open→closed key binding, mandate chains,
  verifier receipts, the fail-closed unknown-constraint rule, the Trusted Surface. Reason: public, false,
  reviewer-facing. Next action: verify each line first-hand, then rewrite the note against the two sources in §0.
- **A2. Correct `docs/extensions/capability-authorization.mdx` §5, lines 194–199** — "does **not** include
  inequality or range selectors … Range bounds are the deployment's responsibility" is true of v1 only
  (DERIVED). Next action: scope the sentence to v1 and point at v2.
- **A3. Write the AP2 interop profile as a spec first** — `.kimosabe/specs/` per the project's placement rule,
  graduating to `docs/design/` when settled. It must specify, at minimum: (1) the signature-suite bridge
  (AP2 `cnf.jwk` is a full EC P-256 JWK, `agent_authorization.md` line 337; BAP `cnf.jkt` is an RFC 7638
  thumbprint of an Ed25519 OKP key, `spec/bap-v1.md` line 262 — these do not compose today; the ES256 suite in
  tranche B is the chosen bridge); (2) a digest-spelling map (AP2 bare base64url over the final SD-JWT; BAP raw
  32 bytes for `ath`; the Charter Agreement Protocol's `sha-256:` tag); (3) the typed projection of AP2 closed
  mandate content into BAP cast arguments, deciding integer-versus-float explicitly because AP2 leaves
  `budget.max` untyped (`open_payment_mandate.json` lines 260–262) and its `amount_range` schema (integer minor
  units) contradicts its own document example (`100.50`, `payment_mandate.md` line 186; AP2 PR #340 open);
  (4) where a BAP proof rides in A2A and UCP — BAP has no A2A binding (the only A2A mentions are ADR 0013, the
  mapping note and `ROADMAP.md`), and the MCP message binding is "an open design question"
  (`capability-authorization.mdx` lines 157–167); (5) the receipt correspondence — an AP2 receipt's `reference`
  and a Charter Agreement Protocol receipt's `grant_digest` decode to the same 32 bytes, so a `grant.scheme`
  of `"ap2"` is the natural join, but that lives in the CAP repository and is noted here only; (6) cross-vectors
  on both sides — AP2 ships none in-tree (0 vector, conformance or golden files against 22 test files;
  external vector offers sit in AP2 PRs and issues #265, #279, #303, #307). Composition seams to write down with
  field names: a BAP grant beside an AP2 open mandate governing the agent's tool calls while AP2 governs the
  presentation of consent; example selectors `{kind: "equals", path: ["open_mandate_hash"], value: <sd_hash>}`
  and `{kind: "lte", path: ["payment_amount", "amount"], value: 20000}` paired with an `equals` on the currency
  member (INFERRED; unverified at runtime — the note's own no-round-trip discipline applies).
- **A4. Decide the A2A binding for BAP.** Reuse the Agent Blueprint Protocol's federation envelope lane
  (`Task.metadata` / MCP `_meta`) or define a BAP-specific `DataPart` key alongside AP2's `ap2.mandates.*`
  (AP2 `X-A2A-Extensions` URI `…/ap2/v1`, DERIVED). This is a design decision; run it through the project's
  design method, not a quick pick.
- **A5. ADR 0029 (`ba+budget-window`) is unwritten** — `docs/adr/` holds 0028 and 0030 and no 0029 (DERIVED:
  `ls docs/adr | grep -c 0029` = 0). The AP2 comparison rests on BAP's stated budget posture ("route to the
  issuer-attestation/runtime-accounting posture"). Either write the ADR or record an explicit deferral so the
  interop profile can cite a settled position.

**Tranche B — the ECDSA suite and the adapter (permitted now; content-gated per §0).**

- **B1. ES256 suite as a contract-major.** Open decisions the ADR must settle: the suite name and contract-major
  number under `BAP<n>-<sig>-<digest>` and whether a parallel suite in the current major is admissible (the
  charter says v1 never downgrades inside itself; read `successor-major-charter.md` and ADR 0026, the
  post-quantum successor-suite statement, for the precedent); fixed-width encodings (P-256 public key: choose
  compressed 33-byte or uncompressed 65-byte and fix it; signature: raw `r || s` 64 bytes per RFC 7518 §3.4;
  decide and document low-S normalization and reject non-canonical encodings the way v1 rejects malformed
  Ed25519 points); `cnf.jkt` over the EC JWK per RFC 7638; domain separators for the new major; the full
  corpus for the suite with mutation gates that go red (tampered `r`, tampered `s`, wrong curve, high-S if
  normalized, thumbprint over the wrong member set); SDK parity — Elixir reference, Python, Rust, Go, and the
  TypeScript verifier on npm — each re-derived from specification and corpus; `CHANGELOG.md`; the registries.
  Red-before-green: author one corpus vector signed with P-256 and watch the current Ed25519-only verifier
  refuse it before writing any suite code.
- **B2. Report adapter.** Every key path assumes Ed25519: `public_key/1` "must return a 32-byte Ed25519 public
  key" (`lib/mix/tasks/bounded_authority_report_adapter.doctor.ex` lines 13 and 127), the signing tail returns
  "the raw 64-byte Ed25519 signature" (`lib/bounded_authority_report_adapter.ex` line 1038), `next_public_key`
  is "a raw 32-byte Ed25519 public key" (line 962), key identity carries "its 32-byte raw Ed25519 public key"
  (lines 1057 and 1070), and the install template's example custody shape is Ed25519 (`.install.ex` line 76) —
  all DERIVED. Next action after B1 lands: extend the key-handle callback contract with a key-type discriminator,
  update the doctor and install tasks, run the conformance round-trip against the new corpus, bump the exact pin.
- **B3. Cross-vectors with AP2.** AP2 has none to test against; author BAP-side vectors for the projection in A3
  and offer the AP2 side upstream only if the owner directs it (an upstream contribution requires the Google CLA,
  `CONTRIBUTING.md` lines 11–14, DERIVED — that is the owner's call, not the session's).
- **B4. Charter Agreement Protocol receipt join** (`grant.scheme: "ap2"`) — belongs to that repository; note
  only, no work here.

**Material evidence.** None is retained by this handoff beyond the citations above. The authoring session's two
research transcripts are session scratch, released by the end of that session; nothing here depends on them,
and every fact the next action needs is restated with its source path or identifier.

## 5. Git + environment

- This repository: `main` at `4ac276a`, September 18, 2026 (DERIVED). The authoring session did not inspect
  the working tree; run `git status --short` and `git log --oneline -3` first and adopt any coherent
  predecessor work rather than treating it as conflict.
- Report adapter: 0.6.3, exact pin `== 0.4.1` (DERIVED). Not inspected further.
- No services. Toolchain per each repository's `.tool-versions` and `mix.exs` pins.
- No worker or run identity, no persisted attempt budget: this outcome has not been started.

## 6. Cadence + guardrails

- Owner approval covers exactly: composing with AP2; the framing sentence in §2; fixing the mapping note and
  the extension paragraph; designing the interop profile; starting the ES256 suite as a contract-major; the
  adapter following the suite. It does **not** cover activating any reserved mechanism, changing the licensing
  of any package, submitting anything to any standards body, or contributing to AP2 upstream.
- The disclosure gate in §0 binds every commit.
- Project rules as this repository declares them: commit on `main` with exact pathspecs, US English, real
  substrate (no mocks unless the owner directs one for a named thing), red-before-green for every new gate.
- Placement: spec in `.kimosabe/specs/` first; `docs/design/` when settled; ADRs in `docs/adr/`.
- No concurrent writer is known. Verify with `git status` before the first write.

## 7. Referenced artifacts

- This repository: `spec/bap-v1.md`, `spec/bap-v2.md`, `docs/extensions/ap2-mandate-mapping.md`,
  `docs/extensions/capability-authorization.mdx`, `docs/extensions/mcp-sep-capability-authorization.md`,
  `docs/design/successor-major-charter.md`, `docs/design/registries.md`, `docs/design/standards-track.md`,
  `docs/adr/0010-*`, `0013-*`, `0026-pq-successor-suite.md`, `0028-*`, `0030-v2-contract-major-activation.md`,
  `docs/standards/submissions.md`, `CHANGELOG.md`, `ROADMAP.md`.
- Report adapter: `README.md`, `mix.exs`, `lib/bounded_authority_report_adapter.ex`,
  `lib/mix/tasks/bounded_authority_report_adapter.doctor.ex`, `.install.ex`, `docs/consumer-integration.md`.
- AP2: repository and files in §0; issues #250 (post-quantum proposal), #268 (deterministic-signature
  prohibition contested), #338 (dispute-evidence format), #339 (presence-driven evaluation, closed "Intended
  Behavior"), #340 (budget units, PR open), #346 (one consent redeemable for multiple payments), #353
  (`present()` cannot extend a chain past one hop), #356 (schema `contains` dropped by codegen), #358
  (`checkout_hash` binding not enforced by `CheckoutMandateChain.verify`); PR #305 (TypeScript SDK, unmerged).
- Standardization context (REPORTED from public pages, September 19, 2026): AP2 was donated to the FIDO
  Alliance on April 28, 2026; "Standardization of the specification will continue within the Agentic
  Authentication Technical and Payments Technical Working Groups in FIDO" (AP2 `docs/index.md` line 190).

## 8. Suggested skills + next action

**First action.** In `bounded_authority_protocol`: `git status --short`, then open
`docs/extensions/ap2-mandate-mapping.md` and `spec/bap-v2.md` side by side and confirm or refute each line
cited in A1 against the actual bytes. Record what was confirmed and what was not before editing anything.

**Order after that.** A1 → A2 → A5 (settle or defer the budget-window position) → A3 (the profile spec) → A4
(the A2A binding decision, through the design method) → B1 (suite ADR, then red vector, then implementation and
corpus, then SDK parity) → B2 (adapter) → B3.

**Skills.** `kimosabe` for the lifecycle; `codebase-design` for the suite-naming and A2A-binding decisions;
`tdd` for the red-before-green vector in B1 and every new mutation gate; `research` for first-hand reads of
RFC 7518 §3.4, RFC 7638 and RFC 9901 before B1; `review` before any push.

**Resume prompt for the next session.**
Read this handoff in full. Verify the live anchors it names — HEAD, the working tree, the cited lines in the
mapping note and `spec/bap-v2.md` — before believing any line number. Re-clone AP2 at `e1ea56d` and read
`docs/ap2/agent_authorization.md` first-hand. Then take the first action above. The disclosure gate in §0
binds every commit; nothing reserved is activated in this work.
