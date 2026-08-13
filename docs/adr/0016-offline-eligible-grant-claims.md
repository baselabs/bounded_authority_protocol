# ADR 0016: Offline-eligible grant claims (floor limits + freshness bound)

- Status: accepted (reserve + specify — activates in a successor contract-major)
- Date: 2026-08-13
- Track: T2

## Context

The offline-authorization surface — endpoints that must answer during a connectivity window
(kiosk / EV-charging / vending fleets) — needs the issuer to price an offline risk acceptance
into a grant, EMV-style: explicit floor limits the endpoint honors at its own risk within an
offline window, with deferred consumption reconciled later. The requirements are settled on
both sides: the protocol-side
[offline requirements](../design/offline-authorization-requirements.md) (R-BAP-1..6) and the
private runtime's [ADR 0014](../../bounded_authority/docs/adr/0014-offline-authorization-surface.md)
+ R-BA-1..7 (the offline DECISION is endpoint-side; the runtime's role is issuance +
reconciliation + distinguishability + freshness).

R-BAP-1 names the floor-limit claims an issuer MUST be able to carry — maximum value with
explicit currency, maximum offline use count, an offline time window — in a closed shape with a
canonical encoding, no free-form extension field, and "absence means online-only." R-BAP-2
requires a verifier that predates the claims to DENY a grant carrying them (intended
compatibility, not a migration bug).

The closed v1 grant payload forbids in-place admission. `@grant_payload_keys`
(`runtime.ex:47`) is an exact-match nine-key set; `closed_map/2` (`runtime.ex:800-807`) requires
the member-name set to equal the allowed set in length and content. Admitting a tenth member
(`ba_offline`) — required or optional — flips a floor-bearing grant from `:invalid` to `:ok`,
which is a verdict change, which the evolution contract defines as a contract-major change
(`standards-track.md:67-69`, `REQ1-EVO-no-verdict-flip`; the governance change-class rule at
`standards-track.md:211-213`: "wire or verification behavior = contract-major only"). The
`closed_map_one_of` mechanism (`runtime.ex:809-816`, the proof-`nonce` precedent at
`runtime.ex:264-267`) is legal *within* a frozen major but widening the v1 grant set after the
freeze is the in-place extension `REQ1-EVO-evolution-above-wire` (`standards-track.md:28-33`)
forbids.

This is exactly the situation [ADR 0010](0010-delegation-with-attenuation.md) resolved for the
`ba_dlg` delegation claim, and ADR 0009 for `ba_sut`: reserve the name now, carry the mechanism
to spec quality, activate only in a successor contract-major. The reserve path was selected as the
activation decision (2026-08-13) over the `v0.1.0`-amend alternative (see Alternatives). This ADR
follows the ADR-0010 division: it specifies the mechanism the activating major implements;
the current major rejects the reserved name and changes no byte, bound, or verdict.

## Decision

### 1. The `ba_offline` claim — a closed nested grant-payload object

`ba_offline` is an OPTIONAL grant payload member. When present it is a closed object with exactly
four members, JCS-sorted (`runtime.ex:387-403` is the alphabetical encode precedent):

```jsonc
"ba_offline": {
  "cnt":  3,            // positive integer — max offline acceptance count
  "cur":  "USD",        // exactly 3 upper-case ASCII letters — currency (ISO-4217)
  "max":  5000,         // positive integer — max value in minor units (here 50.00 USD)
  "win":  1735689600    // integer NumericDate — offline-window expiry; iat < win <= grant exp
}
```

- All four members are REQUIRED when `ba_offline` is present — a closed object (the `cnf`/`["jkt"]`
  discipline at `runtime.ex:294-298`). "Offline-eligible with no value cap" is not a floor-limit
  grant; a sentinel `max` would poison the over-consumption detector (R-BA-5) and the exposure
  figure (R-BA-7).
- Admission, on activation: `closed_map_one_of` over the grant payload admits EITHER the base
  nine-key set OR the base nine + `ba_offline` — mirroring the proof-`nonce` pattern
  (`runtime.ex:264-267`). `ba_offline`'s value is itself a `closed_map` over `["cnt","cur","max","win"]`.
- The offline DECISION is endpoint-side (the private runtime's ADR 0014 d.1; the verifier is a pure
  public library — [ADR 0001](0001-public-protocol-verifier-boundary.md) — never a service, so the
  runtime cannot be reached offline). The runtime's offline role is issuance (BA-20),
  reconciliation (BA-21), distinguishability (BA-22), and carrying the freshness bound.

### 2. Encodings and bounds

- `cur`: exactly three upper-case ASCII letters. The verifier is pure/stateless (the BAP-01
  architecture test), so currency validation is alphabet-only — NOT a runtime ISO-4217 fetch. The
  minor-units EXPONENT is per-currency (JPY 0, BHD/KWD 3) and is issuer/endpoint policy, not a
  verifier concern (EMV terminals know their currency); this ADR states that explicitly rather than
  pinning an exponent table. Whether to pin a snapshot of current ISO-4217 codes is left to the
  activating major.
- `max`, `cnt`: positive integers within `±9007199254740991` (`REQ1-JSON-number-bounds`) PLUS a
  tighten-only ceiling.
- **`max × cnt` wire-layer ceiling.** A successor-major `Bounds` member caps the per-audience
  product `max × cnt` and rejects at decode if exceeded. Rationale: R-BA-7's per-audience exposure
  figure (`max × cnt`, reaching ~8.1e31 at the JSON integer ceiling — sixteen orders beyond it) is
  exactly the value the cross-language SDKs compute in fixed-width integers; the Rust SDK works in
  `i64` and its closeout fixed an analogous fixed-width fail-closed violation (the BAP-15 `i64`
  overflow precedent). A maximal-exposure grant that wraps or panics in a consumer SDK would read as
  a small or negative exposure — silently wrong at exactly the magnitudes where R-BA-7's "visible to
  the issuer" matters most. (The audience multiplier `|audiences|` is bounded by `bounds.audiences`
  — small — so it does not change the overflow class; the ceiling caps `max × cnt`.) The ceiling is
  enforced where every other bound is (the closed profile), before the value reaches any consumer.
  The activating major owns the concrete ceiling value.
- `win`: integer NumericDate; coherence `iat < win ≤ exp`. `win` is a hard expiry the endpoint
  checks against its own clock. It is a DISTINCT knob from `nbf`/`exp` (a grant may be online-valid
  thirty days but offline-eligible twenty-four hours — R-BA-4's issuer-priced risk window). The
  verifier applies NO skew to `win`; skew is endpoint policy (R-BAP-4 — facts, not decisions).
  Because the offline endpoint honors `win` against its OWN clock (ADR 0014 d.1 — the endpoint
  performs the offline verdict at its own risk), clock rollback is an endpoint-compromise scenario,
  not a verifier-enforceable property: it is priced into the floor limits, and the resulting
  over-consumption is surfaced at reconciliation (R-BA-5/BA-21). This is the EMV floor-limit model by
  design — the runtime REPORTS over-consumption, never undoes the endpoint's effect (ADR 0014 d.5).

### 3. The facts contract (R-BAP-4)

The verifier's offline-path output remains non-authorizing facts. ADR 0003 §7 restricts `GrantFacts`
to identifiers, timestamps, and fixed-size fingerprints — value-bearing magnitudes are forbidden.
**R-BAP-4's literal "limits: {…}" output wording is therefore NOT honorably met inside `GrantFacts`
and is amended by this ADR to:** the successor-major facts struct carries an `offline_eligible`
flag and the `win` timestamp only (both §7-eligible: a flag is not value-bearing; `win` is a
timestamp like `exp`). `max`, `cnt`, `cur` are read by the endpoint from the `DecodedGrant` of the
same compact bytes it verified. **There is no API-object-identity invariant binding `DecodedGrant` to
`GrantFacts`: they are independent public returns (`decode_grant/2` at `runtime.ex:159-167` vs
`verify_grant/3` at `runtime.ex:179-196`), and `DecodedGrant` carries `verification:
:not_evaluated`. The integrity binding the endpoint relies on is the ISSUER SIGNATURE — `ba_offline`
is inside the signed payload, so any mutation of `max`/`cnt`/`cur` breaks the signature the endpoint
verified (tamper-evident, like every signed claim); and a correct endpoint reads the magnitudes from
the SAME compact bytes it verified (the authz/effect split — AGENTS.md rule 4 — makes that
composition the host's responsibility, not the verifier's). The earlier "structural binding" wording
overstated this; the binding is signature-integrity + caller procedure, not an enforced object
identity.**

### 4. Malformed ⇒ `:invalid`; "online-only" is the absent default

The closed profile rejects a partially-parsed `ba_offline` (an unknown member inside it, a wrong
type, a missing required member): the whole grant is `{:error, :invalid}`. There is no
drop-the-field-and-continue-online parser — that is exactly the permissive-compatibility posture
the closed profile exists to kill (`standards-track.md:28-33`).

"Online-only" is the ABSENT default (R-BAP-1): a grant with no `ba_offline` member is online-only.
It is NOT a malformation recovery. **[ADR 0014](../../bounded_authority/docs/adr/0014-offline-authorization-surface.md)
d.3's "malformed floor fields → online-only" is an issuance/runtime-layer semantic — the runtime's
nullable Grant columns decode a malformed floor as online-only at ISSUANCE — NOT a codec semantic.**
The BA-repo ADR 0014 amendment (the companion follow-up) re-scopes d.3 to the issuance layer; the
codec rejects malformation outright. (The fail-closed direction is preserved either way: a
whole-grant reject is strictly safer than drop-and-continue; "never an offline acceptance" holds
under both.)

### 5. The floor-limit math is endpoint-side; the exposure figure is audience-multiplied

Amount ≤ `max`, count ≤ `cnt`, `now ≤ win` are the ENDPOINT's offline decision (ADR 0014 d.1). The
verifier never compares an operation's amount to `max` — there is no `allowed?`/`authorized?`/
`decision` in the verifier (AGENTS.md rule 4). `max_offline_exposure/1` (ADR 0014 d.7 / R-BA-7) is a
pure function over the grant's fields. **`max × cnt` (minor units of `cur`) is the PER-AUDIENCE
exposure over `[iat, win]`: a grant may name multiple audiences (`aud` is a list, `runtime.ex:288`
— each verified independently), so each audience's endpoints can accept up to `cnt` uses against
their own local replay state. The grant-wide worst-case exposure computable from the grant is
therefore `max × cnt × |audiences|` (R-BA-7's "computable from the grant"); aggregate
over-consumption ACROSS audiences and devices — the gap between that bound and what the fleet
actually spent — is detected at reconciliation (R-BA-5/BA-21), not bounded by the grant alone.**
The "staleness bound visible to the issuer at grant time" (R-BA-7) is `win`.

### 6. Composition with delegation (`ba_offline` × `ba_dlg`)

`ba_offline` and `ba_dlg` ([ADR 0010](0010-delegation-with-attenuation.md)) are both successor-major
grant claims. ADR 0010's four-part attenuation relation (operations subset §3.1, selector-tuple
containment §3.2, validity-window containment §3.3, audience containment §3.4) says nothing about
`ba_offline`, so without an extension a delegated child could carry a longer `win`, larger `max`, or
higher `cnt` than its parent — WIDENING offline exposure, contradicting "attenuation is the only
direction" (`standards-track.md:150-160`). **It also permits a worse widening: because the relation
only constrains values WHEN THE PARENT HAS THEM, a child of an ONLINE-ONLY parent (no `ba_offline`)
could ADD `ba_offline` — granting itself offline authority the parent never had.** The activating
successor major MUST extend the attenuation relation with BOTH:

1. **Non-additivity (the load-bearing rule):** `ba_offline` is optional but NOT addable. A child
   may carry `ba_offline` ONLY IF the parent does; a child of an online-only parent (no `ba_offline`)
   MUST itself be online-only (no `ba_offline`). Offline-eligibility cannot be delegated into
   existence.
2. **Floor-limit containment (when the parent has `ba_offline`):**

```
win_child ≤ win_parent,  max_child ≤ max_parent,  cnt_child ≤ cnt_parent,  cur_child == cur_parent
```

OR record the interaction as a NAMED GAP that the activating major's attenuation spec closes (the
gap must cover BOTH the non-additivity rule and the containment rule). This ADR records the
obligation; it does not pin which horn (that belongs with the activating major's concrete attenuation
spec, alongside `bounds.delegation_depth`).

### 7. Freshness scoping (R-BA-7)

The grant-carried freshness bound for the short-TTL option IS `win` (≤ `exp`): the grant itself
states the offline window, and `max_offline_exposure` is computable from the grant. On this reading
the planned `[ba-offline-freshness-format]` row is absorbable into the window.

The OTHER two R-BA-7 options are NOT grant payload and are NOT absorbed here: a device-cached
revocation list and a runtime-minted short-TTL freshness token ([ADR 0014](../../bounded_authority/docs/adr/0014-offline-authorization-surface.md)
d.7) are signed artifacts the endpoint verifies offline "using only the public package and pinned
trust anchors" (R-BA-1) — canonical wire formats consumable by the pure verifier, i.e. new
public-package surfaces of the boundary-anchor / key-transition class. **If BA-23 picks either, a
separate public-format row is still owed.** The `[ba-offline-freshness-format]` row name therefore
stays open, conditioned on BA-23's choice; this ADR absorbs only the window option.

### 8. Activation is a successor contract-major

The closed v1 profile rejects `ba_offline` today — proven by the reference-implementation
closed-set tripwire in `test/bounded_authority_protocol/v1/grant_test.exs` (a `ba_offline`-bearing
payload is `{:error, :invalid}`, red-capable at the sole admission choke point `closed_map` at
`runtime.ex:241`). The mechanism-accurate mutation — switching line 241 from `closed_map` to the
`closed_map_one_of` two-alternative form (the `runtime.ex:264-267` nonce precedent) that admits
both the nine-key and ten-key sets — makes the tripwire go RED on exactly the `ba_offline` entry
(ten keys admitted, `decode_grant_fields` at `runtime.ex:278-319` is a known-key extractor that
ignores extras, decode succeeds, the `{:error, :invalid}` assertion breaks). The cruder mutation
widening `@grant_payload_keys` to ten keys also goes red (the cardinality check then rejects the
nine-key fixture too) and is the proof actually run in the closeout; both establish red-capability
at the same choke point. Activation requires the deprecation-prerequisites rule (`standards-track.md` §
Parallel-version support: a published successor profile + corpus + two independent passing
implementations). The activating major owns its own `REQ2-CLAIM-*` range ([ADR 0007](0007-normative-requirement-identifiers.md):50-52,98-100), the concrete `max × cnt` ceiling, the
`ba_dlg` attenuation extension (§6), and the accept-direction conformance vectors (R-BAP-5's
decision-math subset belongs to the consumer arc / endpoint conformance, since the verifier never
compares an amount to `max`).

## Alternatives considered

- **(a) Amend `v0.1.0` in place (the "still unpublished" path).** Fold `ba_offline` into the
  tagged `v0.1.0` codec as a `closed_map_one_of` alternative key-set, extending the ADR-0003
  "still unpublished, frozen before external consumption" justification. Rejected by the activation
  decision (2026-08-13, which chose the reserve path): the `v0.1.0` git tag is public, and three shipped SDK
  implementations (TypeScript, Python, Rust — Go / BAP-16 is authored-not-started) pin the corpus
  `index.json` SHA-256 at startup, so a `v0.1.0` corpus growth cascades to re-vendoring and
  re-verifying those SDKs; the published governance change-class rule
  (`standards-track.md:211-213`) makes wire-change "contract-major only, with a public ADR," so
  amending requires a public ADR creating a pre-first-publication exception; and intra-major
  fragmentation (two verifiers both claiming major `1` and disagreeing on `ba_offline`) breaks "a
  verifier detects the major of any artifact from its bytes alone" (`standards-track.md:37-47`).
  A successor major's `v` claim sidesteps all three.
- **(b) Reframe to dodge new claims.** Express the floor limits via existing v1 claims (the
  validity window, the selector algebra). Rejected: max-value needs a range/cap the selector
  algebra (`equals`/`one_of`, set-membership only — `runtime.ex` selectors) cannot express;
  max-use-count has no existing home (the consumption chain tracks usage server-side, the grant
  carries no cap); the offline window is distinct from `nbf`/`exp`. New grant claims are required.
- **(c) A `REQ1-CLAIM-*` id for the reserved name in the v1 requirement map.** Rejected: a reserved
  name imposes no v1 MUST to map (the BAP-10 §3 bar), and [ADR 0007](0007-normative-requirement-identifiers.md)
  gives the successor major its own `REQ2-*` range. Mirror BAP-11/BAP-14 exactly: registry name +
  ADR prose only, no `REQ` id.

## Consequences

- The reserved `ba_offline` claim is REJECTED by the current major's closed profile. The rejection
  evidence is the reference-implementation tripwire (`grant_test.exs`); per [ADR 0010](0010-delegation-with-attenuation.md):286-289
  the unchanged corpus is not itself the rejection proof for names that live in docs only — the
  cross-implementation `ba_offline`-specific corpus vector lands with the activating major's full
  corpus (the corpus proves the `cnf` sub-object closure and the field-decode boundaries today, not
  the top-level payload key set).
- The current major's wire profile, bounds, and verdicts are UNCHANGED. This is a design-only slice:
  `git diff <base>..HEAD -- lib/ docs/protocol-v1.md priv/conformance/` is empty (mirror BAP-11/BAP-14,
  ROADMAP:290-291 + 318-319).
- The offline runtime arc (private `bounded_authority` BA-20..23) is **successor-major-gated**: BA-20
  (issuance of floor-limited grants) cannot ship against the current v1 codec. The companion BA-repo
  amendment re-scopes [ADR 0014](../../bounded_authority/docs/adr/0014-offline-authorization-surface.md)
  d.2/d.10 to "reserved for a successor major" and d.3 to the issuance layer.
- The activating successor major owns: the concrete `max × cnt` ceiling, the `ba_dlg` attenuation
  extension (§6), its `REQ2-CLAIM-*` ids, the accept-direction conformance vectors, and the decision
  between the two §6 horns. None are pinned here; this ADR specifies the mechanism that constrains them.

## See also

- [ADR 0001](0001-public-protocol-verifier-boundary.md) — the verifier is a public, pure library,
  never a service (the endpoint-side framing's authority: the runtime cannot be reached offline).
- [ADR 0002](0002-normative-v1-parsing-profile.md) — the closed-set admission discipline + d.5 byte
  ceilings that §2's bounds extend.
- [ADR 0003](0003-standard-jws-and-verified-grant-results.md) §7 — the facts contract (§3); and the
  pre-publication amendment precedent (Context) considered in Alternative (a).
- [ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) — evolution above
  the wire; registries reserve names, activation only with a contract-major.
- [ADR 0007](0007-normative-requirement-identifiers.md) — the successor major's `REQ2-*` range.
- [ADR 0009](0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) — the
  `ba_sut` reserve-and-activate precedent.
- [ADR 0010](0010-delegation-with-attenuation.md) — the closest precedent (`ba_dlg`) and the
  composition surface §6 extends.
- [offline requirements](../design/offline-authorization-requirements.md) (R-BAP-1..6); the private
  runtime's ADR 0014 (R-BA-1..7).
