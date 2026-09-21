# AP2 interop profile — design specification

Status: accepted — owner approval 2026-09-20, following an independent adversarial review of the
draft (all findings repaired and re-verified). This document changes no wire format, public API,
verifier behavior, or package dependency; it is the composition contract between this protocol's
published contract-majors and AP2 v0.2.

Evidence classes at each load-bearing claim:

- **OBSERVED** — verified first-hand on 2026-09-20 against the AP2 text at pinned commit
  `e1ea56d` ([google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2)),
  this repository at `3994b4f` (v0.4.2), or RFC 9901 fetched from datatracker (§ per claim names
  the source).
- **DERIVED** — restated from a program record or handoff; not re-verified for this document.
- **INFERRED** — a design recommendation of this profile, not verifiable against any source.

## 0. Scope and framing

This profile specifies how the published Bounded Authority Protocol (contract-majors 1 and 2, as
of 0.4.2) composes with the published AP2 text (v0.2 at `e1ea56d`) at the agent-authorization
layer. The framing is the owner's settled sentence: BAP is **"a different answer at the same
layer as AP2's agent authorization framework, composable with it"** — never "a deeper layer
under AP2 with no overlap."

The profile composes with **published specification text only**. It claims structural
correspondence and mechanically decodable relationships between published encodings; it does NOT
claim:

- that an AP2-conforming agent can consume a BAP grant + proof (unverified);
- that either protocol's verifier accepts the other's credential or proof bytes;
- that BAP verification yields an authorization decision, receipt, or any runtime guarantee;
- that any host-protocol riding question (§6) is resolved.

This is the mapping note's honesty discipline
(`docs/extensions/ap2-mandate-mapping.md`, shipped in 0.4.2), extended from the credential-model
layer to the composition layer. The mapping note is the corrected structural map this profile
builds on; it is cited, not restated.

The disclosure gate binds this document: it activates and documents no reserved mechanism
(`ba_dlg`, `ba_obo`, `ba_offline`, `ba_sut`, detached profiles) beyond the existing reserved
registry rows and the published charter text (§10).

## 1. Normative sources

- AP2 at `e1ea56d`, verified first-hand for this document: `docs/ap2/agent_authorization.md`,
  `docs/ap2/specification.md` (§ Payment Mandate, § Extension Points),
  `docs/ap2/payment_mandate.md`, `docs/ap2/checkout_mandate.md`, `docs/ap2/flows.md`,
  `docs/ap2/security_and_privacy_considerations.md`,
  `docs/ap2/implementation_considerations.md`, `code/sdk/schemas/ap2/*.json` (all six plus
  `types/`), and the SDK verification path (`sdjwt/common.py`, `sdjwt/chain.py`,
  `sdjwt/kb_sd_jwt.py`, `constraints.py`, `payment_mandate_chain.py`,
  `checkout_mandate_chain.py`, `receipt_wrapper.py`, `utils.py`). All OBSERVED.
- This repository at `3994b4f`: `spec/bap-v1.md`, `spec/bap-v2.md`,
  `docs/design/successor-major-charter.md`, `docs/adr/0029-budget-window-posture.md`,
  `docs/extensions/ap2-mandate-mapping.md`. All OBSERVED.
- RFC 9901 §4.3/§4.3.1 (`sd_hash`), fetched from datatracker 2026-09-20. OBSERVED. RFCs 7515,
  7518 §3.4, 7638, 8785, 9449 are cited for their published constructions; none was re-derived
  beyond RFC 9901's `sd_hash` text.
- AP2 PR #340 (the integer-versus-float doc contradiction) and AP2 vector offers in
  PRs/issues #265/#279/#303/#307: DERIVED (program record; not probed upstream).

## 2. Terminology: cast-argument projection, not the typed projection

`spec/bap-v1.md` §7 already uses "typed projection" for BAP's internal `typed/1` digest
construction (`["integer", v]` tag arrays fed to JCS). To avoid collision, this profile's
element-3 mapping is named the **cast-argument projection**: the recommended derivation of BAP
proof cast arguments from schema-conformant AP2 closed-mandate content. The two projections are
unrelated mechanisms that happen to share a word; every reference below means the cast-argument
projection unless it cites §7.

## 3. Element 1 — Signature-suite bridge

**Fact base (OBSERVED).** AP2's holder side is profiled EC P-256 with ES256 throughout: the open
mandate's `cnf.jwk` is a full EC P-256 JWK (`agent_authorization.md` ~337; every worked example
in `checkout_mandate.md` and `agent_authorization.md`; SDK `ec_key_to_jwk` emits exactly
`{kty: "EC", crv: "P-256", x, y}`). The SDK chain walk verifies each hop under the previous
hop's `cnf.jwk` (`sdjwt/chain.py`). BAP contract-majors 1 and 2 are Ed25519-only
(`BAP1-Ed25519-SHA256`, `BAP2-Ed25519-SHA256`; the proof JWK is exactly the Ed25519 OKP form,
`spec/bap-v1.md` `REQ1-HEADER-proof-jwk`; `cnf` is `{jkt: thumbprint}`,
`REQ1-HEADER-thumbprint`). One holder key therefore cannot serve both sides today — the mapping
note's stated composition seam.

**The bridge.** An ES256 contract-major suite is the chosen bridge, under the charter's
major-bound naming: `BAP<n>-ES256-SHA256` with `BAP<n>-*` domain separators, where the suite's
own ADR fixes `n`. This profile describes the bridge contract; the suite's ADR, corpus, and
implementation build it. The suite gives BAP:

- ECDSA over P-256 with SHA-256 per RFC 7518 §3.4, over the exact RFC 7515 signing input;
- a proof-key JWK shape `{kty: "EC", crv: "P-256", x, y}` and an RFC 7638 thumbprint over the
  required EC members, so BAP `cnf.jkt` and AP2 `cnf.jwk` are two spellings of one key identity;
- its own certified corpus and cross-major rejection per the charter's activation checklist.

With the suite in place, the **same EC P-256 holder key pair** can be the AP2 agent key (a
`cnf.jwk` value) and the BAP proof key. The owner decision of 2026-09-20 that the TypeScript
signer adopts the ES256 suite makes the bridge two-sided on the producing side as well (DERIVED:
program record).

**Honest bounds of the bridge.** Key-material correspondence is not credential-byte
compatibility: AP2 `cnf` carries the full `jwk` object, BAP `cnf` carries the `jkt` thumbprint;
the AP2 SD-JWT envelope, disclosure structure, and binding claims have no BAP counterpart, and
vice versa. The bridge composes the two protocols over one holder key; it does not merge their
credentials. Note also that AP2's ECDSA requirement on the merchant Checkout JWT exists for
rainbow-table resistance (deterministic signatures leak enumerable content hashes;
`specification.md` § Payment Mandate; `security_and_privacy_considerations.md` § Rainbow Table
Attacks, both OBSERVED) — the ES256 suite choice for BAP is independent of that AP2-internal
rationale and must be justified in its own ADR on BAP's own terms.

**Two suite profiles, one suite name.** The bridge does not make Ed25519 BAP credentials
interoperable with AP2, nor ES256 a requirement for BAP generally: `BAP1-`/`BAP2-Ed25519-SHA256`
remain frozen and complete, and the ES256 suite is an additional contract-major under the
charter's succession discipline (ADR 0009).

## 4. Element 2 — Digest-spelling map

**Fact base (OBSERVED).** Three digest spellings appear across the composed stack:

1. **AP2: bare unpadded base64url over ASCII token bytes.** RFC 9901 §4.3.1 defines `sd_hash` as
   the base64url encoding (unpadded, RFC 7515 §2) of the full digest over the US-ASCII bytes of
   the encoded SD-JWT — issuer-signed JWT, a tilde, and zero or more disclosures each followed by
   a tilde — excluding the KB-JWT; the algorithm is the disclosure algorithm (`_sd_alg`,
   default sha-256). The AP2 SDK implements exactly this (`sdjwt/common.py` `compute_sd_hash`;
   `b64url_encode` strips padding). The same spelling carries every AP2 digest surface:
   `issuer_jwt_hash` (over the issuer JWT alone), `checkout_hash` and `transaction_id`
   (base64url hash of the `checkout_jwt` value, `_sd_alg`-matched, default sha-256 —
   `checkout_mandate.json`, `payment_mandate.json`), and the Mandate Receipt `reference`
   ("calculated in the same manner as `sd_hash`" over the final SD-JWT in the chain —
   `agent_authorization.md` Mandate Receipt).
2. **BAP: unpadded base64url on the wire, raw 32 bytes inside.** BAP wire digests are canonical
   unpadded base64url: proof `ath` (SHA-256 over the ASCII bytes of the complete received grant
   compact value, `REQ1-CLAIM-ath`), `ba_req` (SHA-256 over
   `"BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])`, where `typed/1` is v1 §7's
   internal typed projection of the runtime's cast arguments), and `cnf.jkt` thumbprints.
   BAP-internal digests are raw 32-byte binaries: verified facts carry the raw 32-byte digest
   (`REQ1-HEADER-digest-width`), and chain rows hash and link as raw binaries
   (`SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)`; verification accepts raw row binaries).
   (For precision: v1's `ath` is base64url-spelled on the wire; the raw-32-byte spelling is the
   facts/chain-row internal one — `spec/bap-v1.md` §11 and §10.)
3. **CAP: the `sha-256:` tagged spelling.** DERIVED (program record); the Charter Agreement
   Protocol repository owns that spelling and any change to it.

**The map.** All three spellings encode the same 32 bytes (for the SHA-256 default both protocols
share); they differ in textual wrapping only:

| from \ to | bare base64url (AP2) | raw 32 bytes (BAP internal) | `sha-256:` tagged (CAP) |
|---|---|---|---|
| bare base64url | — | base64url-decode, verify 32 bytes | prefix the bare string with `sha-256:` |
| raw 32 bytes | unpadded base64url-encode | — | base64url-encode, then prefix `sha-256:` |
| tagged | strip the `sha-256:` prefix — the remainder is the bare base64url string | strip prefix, base64url-decode | — |

Every cell is a lossless byte-level conversion; no re-hashing occurs in any direction.

**Honest bounds.** The map governs spelling only. No two digest VALUES coincide across the
protocols: AP2's `sd_hash` and BAP's `ath` hash different constructions over different inputs,
and nothing in this profile implies equal digests. The one value-coincidence relationship in the
program — receipt `reference` vs CAP `grant_digest` (§7) — lives in the CAP repository and is
not asserted here as verified.

## 5. Element 3 — Cast-argument projection, and the integer decision

### 5.1 The integer-versus-float decision

**Decision: the cast-argument projection is defined over integer minor units only.** The
load-bearing AP2 fields project as BAP integer-tagged values; float-tagged money content has no
projection.

The evidence chain (all OBSERVED first-hand unless noted):

1. The AP2 schema types the projection's inputs as integers in minor units:
   `open_payment_mandate.json` `$defs.amount_range` types `max` and `min` as `"integer"`
   ("Maximum allowed amount in minor (cents) unit of currency"), and `types/amount.json` types
   `amount` as `"integer"` ("Amount in minor units, according to the ISO-4217 spec") —
   `payment_mandate.json` and `open_payment_mandate.json` both reference it for
   `payment_amount`.
2. The AP2 SDK enforces the schema types: the generated pydantic models reject a non-integral
   float for an integer field, and `constraints.py` `AmountRangeEvaluator` compares
   integer-typed operands.
3. The float spelling exists only in `payment_mandate.md`'s prose examples — `"max": 100.50,
   "min": 10.00` (amount_range) and `"max": 1000.00` (budget) — contradicting the schema; AP2
   PR #340 tracks the contradiction upstream (DERIVED). The normative sources (schema, SDK,
   evaluator) are integer; the contradictory example is not normative text.
4. BAP contract-major 2 range kinds are same-tag numeric (`spec/bap-v2.md`
   `REQ2-SELECTOR-range-same-tag`): an integer-tagged value never matches a float-tagged bound,
   and vice versa. A float projection would therefore make every range selector unsatisfiable
   against schema-conformant integer-tagged mandate content — a dead projection, silently.
   V2's own text closes the escape: an integral-valued float canonicalizes back integer-tagged
   ("float-tagged bounds are wire-distinguishable only when non-integral"), so the only stable
   operand domain for money is integer.
5. The sole float-permissive money field, `budget.max` (typed `"number"`), is deliberately
   outside the projection anyway: budgets have no selector correspondence in any major (ADR
   0029, the citable posture). Notably the SDK reads `budget.max` as MAJOR units —
   `int(self.constraint.max * 100)` in `constraints.py` — a different unit and type from
   `amount_range`'s integer minor units, which independently confirms that budget content must
   never be projected onto the amount paths.

**Failure boundary.** The projection is total over schema-conformant closed-mandate content and
undefined elsewhere: float-spelled money content is schema-invalid on AP2's own terms — in
`payment_amount` for `mandate.payment.1` (closed), and for `mandate.payment.open.1` (open) both
in the `amount_range` constraint and in a pre-set `payment_amount` (the open schema references
the same integer-typed `types/amount.json`) — failing the schema and the SDK's model validation
before any BAP composition, and this profile adds no coercion, no tolerance, and no permissive
compatibility path (the repository's critical rules 3 and 8; v1's no-tag-collapse invariant).
If AP2 revises the schemas to floats, that revision ships as a new `vct` suffix under AP2's own
mandate-versioning rule (`specification.md` § Mandate Versioning, OBSERVED), and this profile's
projection for `.1` content stays integer; a projection for a `.2` mandate kind would be a
profile revision, fail-closed in the interim.

The merchant Checkout object (`checkout_jwt` payload) may carry float prices (`"price": 199.0`
in `checkout_mandate.md`'s worked example, OBSERVED) — that content is outside AP2's own schema
scope and enters BAP composition only as an opaque digest input (`checkout_hash` /
`transaction_id`); it is never projected, so its float spelling is immaterial here.

### 5.2 The projection

Cast arguments are server-derived (`spec/bap-v1.md` §12: selectors apply to "the server-derived
tagged arguments"); the runtime owns derivation. **Evidence class: the cast-argument member
names, tagged types, and selector rows below are INFERRED — design recommendations of this
profile, not verifiable against any source. The AP2 source column, the matcher keying, and the
preset-check semantics they build on are OBSERVED** (`payment_mandate.json`,
`open_payment_mandate.json`, `types/*.json`, and `constraints.py`, all first-hand).

This profile fixes the recommended member names and types so grant selectors are writable
against a stable shape, projected from schema-conformant closed Payment Mandate content
(`payment_mandate.json`):

| AP2 source member (closed Payment Mandate) | Cast-argument member | Tagged type |
|---|---|---|
| `payment_amount.amount` | `payment_amount.amount` | integer (minor units) |
| `payment_amount.currency` | `payment_amount.currency` | string (ISO 4217 alpha-3) |
| `payee` (Merchant object) | `payee` | object (members `id` required, `name` required, `website` optional) |
| `payment_instrument` | `payment_instrument` | object (members `id`, `type` required; `description` optional) |
| `pisp` | `pisp` | object (members `legal_name`, `brand_name`, `domain_name`, all required) |
| `transaction_id` | `transaction_id` | string (bare base64url digest) |
| — (chain context: the digest of the associated open Checkout Mandate — AP2's `payment.reference.conditional_transaction_id`, REQUIRED in every open payment mandate; the runtime derives it from the presented checkout-side chain, spelled per §4's AP2 column) | `open_checkout_mandate_hash` | string (bare base64url digest) |
| `execution_date` (optional, ISO8601 string) | `execution_date` | string (ISO8601, as-is) |
| — (runtime normalization of `execution_date`, only when a range selector is wanted on it) | `execution_date_epoch` | integer (Unix seconds) |

`risk_data`, `vct`, `iat`, `exp` have no cast-argument projection (timestamps are BAP proof
claims already; `vct` selects the AP2 profile, not an invocation argument).

Selector correspondence, per constraint kind of the open mandate. **AP2's allowlist and payee
matchers key on identifier members, not whole objects** (`constraints.py`, OBSERVED): merchants
match by `id` when both sides carry one, else by `name` + `website`; payment instruments match by
`id` only. BAP selector identity is whole-value (`REQ1-SELECTOR-semantic-identity` compares
objects as unordered key/value sets), so a `one_of`/`equals` over a whole projected object is
STRICTER than AP2's matcher — an optional member (`website`, `description`) present on one side
and absent on the other fails closed on content AP2 itself accepts. The faithful correspondence
addresses the identifier members; whole-object selectors on `payee` or `payment_instrument` are
not the correspondence. (`pisp` is the exception: its schema requires exactly the three members
the evaluator compares, so whole-object identity is equivalent there.)

| Open-mandate constraint | BAP selectors on the projected arguments |
|---|---|
| `payment.amount_range` `{min?, max, currency}` | conjunctive `{kind: "gte", path: ["payment_amount","amount"], value: min}` (when `min` present) + `{kind: "lte", path: ["payment_amount","amount"], value: max}` + `{kind: "equals", path: ["payment_amount","currency"], value: currency}` — v2 §4's interval composition and unit-member guidance, verbatim |
| `payment.allowed_payees` | `{kind: "one_of", path: ["payee","id"], values: [...]}` (id-keyed, matching `merchant_matches`). An id-less composition has no single-member correspondence; a runtime supporting AP2's `name`+`website` fallback expresses it as conjunctive `equals` on `payee.name` + `payee.website` |
| `payment.allowed_payment_instruments` | `{kind: "one_of", path: ["payment_instrument","id"], values: [...]}` (the evaluator compares `id` only) |
| `payment.allowed_pisps` | `one_of` on `pisp` (whole object — equivalent, see above), or conjunctive `equals` on its three members |
| pre-set `payment_amount` (AP2 checks exact object equality — `constraints.py` `check_preset_payment_claims`, OBSERVED) | conjunctive `equals` on `payment_amount.amount` + `payment_amount.currency` |
| pre-set `payee` (checked with `merchant_matches`, id-keyed) | `equals` on `payee.id` (fallback as for `allowed_payees`) |
| pre-set `payment_instrument` / `execution_date` (checked by exact equality) | `equals` on the projected value — the whole `payment_instrument` object, or `execution_date` as-is |
| `payment.reference` (REQUIRED in every open payment mandate per the schema's `contains` — OBSERVED) | `{kind: "equals", path: ["open_checkout_mandate_hash"], value: <conditional_transaction_id digest of the associated open Checkout Mandate>}` — the constraint binds the payment to the open CHECKOUT mandate, not to the open payment mandate |
| `payment.execution_date` | range selectors only after runtime normalization to `execution_date_epoch` (`gte` from `not_before`, `lte` from `not_after`); AP2's own evaluation compares ISO8601 strings on the AP2 side and is not replaced. INFERRED pending runtime design |
| `payment.budget`, `payment.agent_recurrence` | **no projection, deliberately** — ADR 0029; stateful evaluation belongs to the AP2 verifier or the composing runtime |

Worked examples, verified against the actual selector shapes (`spec/bap-v1.md` §12,
`spec/bap-v2.md` §4 — member sets, path shape, `one_of` spelling, numeric-bound tags all
checked against the published algebra):

```json
{"kind": "equals", "path": ["open_checkout_mandate_hash"], "value": "<bare-base64url digest of the associated open Checkout Mandate>"}
{"kind": "lte", "path": ["payment_amount", "amount"], "value": 20000}
{"kind": "equals", "path": ["payment_amount", "currency"], "value": "USD"}
```

Range selectors require a contract-major 2 grant (v1 grants carry no `lte`/`gte`; the mapping
note states the same for the constraint correspondence). A v1-only composition can express the
`equals`/`one_of` rows but not the amount-range row.

## 6. Element 4 — Where a BAP proof rides in A2A and UCP

**Open by design.** BAP has no A2A binding today, and this profile does not create one: whether
and how a BAP grant + proof rides in A2A agent delegations is a separate design decision, to be
taken through the project's design method. The dependency is recorded here so that decision
inherits a settled base and no unstated assumption.

What this profile can state structurally (all OBSERVED or cited-to-published):

- AP2 names A2A, MCP, and UCP as its host protocols (mapping note, citing AP2 `overview.md`);
  the MCP-layer correspondence is the capability-authorization extension's scope (BAP-08), not
  this profile's.
- The two protocols bind different request surfaces: an AP2 key-binding hop binds mandate
  content, `aud`, `nonce`, `iat`, and the preceding credential's digest (`sd_hash`); a BAP proof
  binds `htm`, `htu`, `ba_inv`, `ba_op`, and the request digest `ba_req` over typed cast
  arguments. Neither binding surface enforces the other's (mapping note, "Proof binding
  surface"). Any A2A/UCP riding design must therefore say explicitly which surface binds which
  step; the composition must not assume AP2's credential-level binding covers a BAP
  request-level binding or the reverse.
- In UCP terms, AP2's own composition point is the Checkout object (the merchant-signed
  `checkout_jwt` MUST be the UCP Checkout when used with UCP — `checkout_mandate.md`, OBSERVED).
  A BAP proof's UCP riding point is not designed anywhere in this repository's published text.

**Element-4 output:** a recorded dependency and open question for the A2A-binding decision,
plus the binding-surface separation above as the constraint any answer must respect. Nothing
here settles that question. Both have since been settled: the A2A binding by the [A2A
capability-binding profile](a2a-capability-binding-profile.md), and BAP's UCP riding point by
[ADR 0034](../adr/0034-ucp-riding-point-scoping.md) (transport-composed; this profile's §6
separation is the constraint both respected).

## 7. Element 5 — Receipt correspondence

**Fact base (OBSERVED).** AP2's verifier-signed Mandate Receipt carries `result` (`success` /
`error`) and `reference` — the base64url hash of the received mandate, "calculated in the same
manner as `sd_hash`" over the final SD-JWT in the chain, `_sd_alg`-matched with sha-256 default
(`agent_authorization.md` Mandate Receipt). The Payment and Checkout Receipt schemas both carry
`reference` as "the hash of the closed Mandate that this receipt is binding to." BAP's verifier
issues no receipt at all: public verification returns value-bearing facts marked `not_evaluated`,
and the operational decision belongs to a stateful authority runtime (repository critical rule 1;
mapping note's fourth table row).

**The join, noted only.** An AP2 receipt's `reference` and a CAP receipt's `grant_digest` decode
to the same 32 bytes (both are bare-base64url SHA-256 spellings per §4's map), so
`grant.scheme: "ap2"` is the natural join key at the evidence-archive layer (DERIVED: program
record; the join is the CAP repository's to define and verify — no work here, no claim here
that it is verified). The layer separation bears repeating: BAP never issues, verifies, or
consumes AP2 receipts; the correspondence lives entirely in CAP's archive joins.

## 8. Element 6 — Cross-vectors posture

**Fact base.** AP2 at `e1ea56d` ships no in-tree conformance or golden vectors: a
filename-and-content probe across the tree (vector/conformance/golden/fixture patterns over
names and JSON content) returned zero hits, with a working positive control (the same instrument
returns the 22 schema JSON files). OBSERVED. Upstream vector offers sit in AP2 PRs/issues
#265/#279/#303/#307 (DERIVED).

**Posture.**

- BAP-side vectors for the cast-argument projection are follow-on certified-corpus work: cases
  pinning the projection table, the integer decision's fail-closed boundary (float-tagged
  content never projects), and the digest-spelling map's conversions.
- No interop claim will rest on self-round-trips (repository workflow rule; the
  no-self-round-trip discipline the mapping note carries). A cross-protocol conformance claim
  would require an independent implementation exercising both sides — impossible until the
  ES256 suite exists and pointless to assert before that.
- Contributing vectors upstream to AP2 requires the Google CLA and is the owner's call; nothing
  in this program assumes it.

## 9. Open questions and dependencies

Questions this profile leaves to their owning decisions:

1. **The A2A binding** (§6); this profile records constraints, not answers.
2. **The ES256 suite** — its ADR fixes the major number, the JWK/thumbprint encodings, corpus
   identity, and the SDK/signer cohort sweep; §3 describes the bridge contract only.
3. **The projection vectors** (§8).
4. **`execution_date_epoch` normalization** (§5.2) — INFERRED until a runtime design owns the
   conversion.

## 10. Disclosure-gate compliance

The gate: nothing beyond published specification text enters this repository until lifted — no
`ba_dlg`/`ba_obo`/`ba_offline`/`ba_sut`/detached-profile activation or documentation beyond
existing reserved registry rows. Compliance read of this document against the accepted bytes,
2026-09-20:

- Reserved mechanism names appear only inside §0 and §10 as the gate's own enumeration — never
  designed, specified, or promised.
- Budget material cites ADR 0029 and the charter's published selector-expressiveness text; no
  `ba+budget-window` shape is designed (the ADR itself defers it).
- The ES256 suite is described in its bridge role only, deferring all design to its own ADR.
  No public announcement is made here beyond what the mapping note already states as fact (the
  suite difference).
- No forward promise of submission, upstream contribution, or runtime compatibility appears
  (§0's honesty list governs the whole document).
