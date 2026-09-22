# ADR 0028: Per-request range selector kinds (`lte` / `gte`)

- Status: accepted (reserve + specify — activates in a successor contract-major)
- Date: 2026-09-03
- Track: T2

## Context

The v1 selector algebra binds exact-value (`equals`) and enumerated-set (`one_of`) argument
constraints only — closed at the `Selector.t` type (`lib/bounded_authority_protocol/v1/selector.ex:11-14`),
the decode kind dispatch (`lib/bounded_authority_protocol/v1/runtime.ex:758-801`: the three
recognized member sets of [ADR 0021](0021-v1-all-selector-recognized-shapes-erratum.md), kind-string
match, fall-through `{:error, :invalid}`), the producer arms (`runtime.ex:698-732`), the
registries selector-kind table, and the spec's `facts:selector-kinds` region. Portable
"spend up to $X per request" and execution-date-window mandates are therefore inexpressible on
the wire; today the private runtime and consumer policy engines enforce them privately.

The successor-major charter settled the scope (§5, owner decision 2026-08-26): per-request range
constraints are pure inequality selector kinds and BELONG in the successor major's selector
design; cumulative budgets ("up to $500/day") are NOT statelessly checkable and route to a
signed budget-window assertion (that half is the companion mechanism of the same program, now
recorded as [ADR 0029](0029-budget-window-posture.md) — the posture consolidated and the
`ba+budget-window` attestation-shape design explicitly deferred). This ADR carries
charter §5's inequality half.

In-place admission is forbidden by the same reasoning [ADR 0016](0016-offline-eligible-grant-claims.md)
recorded for `ba_offline`: admitting `lte`/`gte` in the frozen v1 kind set flips an
lte-bearing grant from `{:error, :invalid}` to `{:ok, _}`, a verdict flip the evolution
contract classes contract-major (`REQ1-EVO-no-verdict-flip`; the governance change-class rule —
"wire or verification behavior = contract-major only"); the published corpus is pinned by four
shipped verifier SDKs; and intra-major fragmentation would break major detection from bytes
alone. The path is the ADR-0010/0016 reserve-and-activate discipline: reserve the names now,
carry the mechanism to spec quality, activate only in a successor contract-major. The design
was decided in the approved BAP-20 spec (scout Stage F, adversarial pass 8/8 CONFIRMED and
reconciled); this ADR writes the mechanism, it does not redesign it.

## Decision

### 1. Kind set: exactly `lte` and `gte` — inclusive, one-sided

Two one-sided INCLUSIVE kinds: `lte` asserts the value at `path` is ≤ `value`; `gte` asserts it
is ≥ `value`. An interval is the CONJUNCTIVE COMPOSITION of two one-sided selectors on the same
path (`{gte, path, lo}` + `{lte, path, hi}`), exactly as any other conjunction composes.
There is no compound `range` kind (see Alternatives). Strict kinds are excluded permanently,
not deferred (§2).

### 2. Operand domain: SAME-TAG numeric only

- The traversed value and the bound must BOTH be integer-tagged or BOTH be float-tagged.
  A cross-tag pair does not match — fail closed. This extends
  `REQ1-SELECTOR-no-tag-collapse` from identity to ordering: `{:integer, 50}` never satisfies
  a bound of `{:float, 50.0}` and vice versa, so a tagged bound retains its identity
  discipline under comparison exactly as under `semantic_equal?/2`.
- Comparison is by NUMERIC VALUE on finite IEEE 754 binary64 — language-independent and
  totally ordered on the finite domain, so every verifier SDK implements the same verdict
  without a profile-defined order derivation. Under IEEE 754 numeric comparison `−0.0 = 0.0`;
  JCS likewise serializes both as `0` (RFC 8785 §3.2.2.3, the `Number::toString` rule), so
  signed zero distinguishes no authority in either dimension.
- Non-finite operands cannot occur: JSON grammar carries no `NaN`/`Infinity` literal, and the
  bounded decoder's numeric domain (`REQ1-JSON-number-bounds`, finite binary64 floats) rejects
  everything else at decode.
- Non-numeric tags (`string`, `boolean`, `null`, `array`, `object`) do not match a range
  selector — fail closed; only same-tag numeric operands can satisfy it. A missing path
  member fails closed exactly as for `equals`/`one_of`.

### 3. Member set: the existing `{kind, path, value}` recognized set

An `lte`/`gte` selector object is exactly `{kind: "lte"|"gte", path: path, value: bound}` —
the second of [ADR 0021](0021-v1-all-selector-recognized-shapes-erratum.md)'s three recognized
member sets, with `value` carrying the numeric bound. NO fourth member set is introduced: the
three-set discipline (exactly `kind`; `kind,path,value`; `kind,path,values`) is unchanged, and
every SDK's member-set matrix extends by two kind strings alone.

### 4. Paths, selector counts, and Bounds: unchanged, with no new ceiling

Path discipline is identical to `equals`/`one_of` (`REQ1-SELECTOR-path-shape`,
`REQ1-SELECTOR-path-required`: 1–32 object-member names, 1–128 UTF-8 bytes each, object
traversal only, never array indexing). 1–64 selectors per operation unchanged. There are NO
new `Bounds` members, and the argument is structural rather than a sizing compromise: a
comparison CONSUMES two decoder-bounded numbers and produces a boolean — it derives no new
magnitude. Both operands are already inside the closed numeric domain (integers within
±9,007,199,254,740,991; floats finite binary64), so no comparison of two individually-bounded
operands can overflow or become undefined. This is deliberately unlike
[ADR 0016](0016-offline-eligible-grant-claims.md) §2's `max × cnt` wire-layer ceiling, which
caps a MULTIPLIED magnitude before it reaches SDK fixed-width arithmetic — here there is no
product to cap. The activating major still owns a concrete bounds review as part of its
complete profile; this ADR records that no new bound is REQUIRED by the mechanism.

### 5. Attenuation: the ADR 0010 §3.2 relation is UNCHANGED

The four-part attenuation relation is not extended. The new kinds are new tuple inhabitants
of the existing selector algebra:

- Narrowing is conjunctive add, as for every kind: a child narrows a parent
  `{lte, path, 100}` by containing the parent tuple AND adding `{lte, path, 50}`; interval
  endpoints tighten independently per side.
- The §3.2 soundness chain runs over `Enum.all?(selectors, &matches?/3)`
  (`selector.ex:23`) and never inspects selector shape or kind — it is kind- and
  domain-agnostic, so it carries the new inhabitants verbatim: a conjunction with added
  conjuncts can only shrink, hence `Accept(S_child) ⊆ Accept(S_parent)` holds for
  `lte`/`gte` tuples exactly as for `equals`/`one_of`/`:all`.
- The tagged-bound identity discipline is restated for ordering: `{:integer, 50}` never
  subsumes `{:float, 50.0}` — the tuples are distinct and neither satisfies the other's
  comparison. A child that adds a cross-tag conjunct (e.g. parent `{gte, path, {:integer, 0}}`
  plus child-added `{lte, path, {:float, 99.0}}`) produces an UNSATISFIABLE conjunction ⇒
  fail closed, never a widening. Attenuation set-containment on distinct tuples remains
  mechanically checkable without interpretation (§3.2 decidability), since the comparison of
  tuple identity never invokes the matcher.

### 6. Facts: no change

Selector matching is verdict-internal — `Selector.match_all/3` runs only inside envelope
proof verification (`verify_proof_parsed/5`, reached from `check_envelope/2`;
`runtime.ex:547`), where the typed cast arguments exist; the standalone `verify_grant/3`
path (`runtime.ex:217` → `verify_grant_parsed/4`) checks signature, issuer, audience, and
times only and never evaluates selectors — a verified grant is not a selector-checked grant.
The match outcome only contributes to the accept/reject verdict. `GrantFacts` and `EnvelopeFacts` shapes are unchanged; in particular a
range bound is a payload magnitude read from the `DecodedGrant` of the same verified bytes
(the [ADR 0016](0016-offline-eligible-grant-claims.md) §3 discipline — value-bearing
magnitudes are never facts), and there is no `allowed?`/`decision` anywhere (critical rule 1).

### 7. Malformed ⇒ `{:error, :invalid}` — fail closed

On activation as today: an unknown kind, a non-recognized member set, a non-numeric bound, a
path violation, an empty path, or an over-limit selector list makes the whole grant
`{:error, :invalid}`. There is no drop-the-selector-and-continue parser — the same
closed-profile posture `REQ1-EVO-evolution-above-wire` mandates. A conjunctive interval whose
endpoints cross (lo > hi) is not a special error: the conjunction is unsatisfiable and simply
never matches (fail closed on every argument), the same semantics a contradictory
`equals` pair has today.

### 8. The current major rejects both names; activation is a successor contract-major

The closed v1 profile rejects `lte` and `gte` today. The rejection evidence is the
reference-implementation tripwire pair landed with this ADR:

- T1 (`test/bounded_authority_protocol/v1/grant_test.exs`): an `lte`/`gte` selector object on
  the recognized `{kind, path, value}` member set in an otherwise-valid grant ⇒
  `{:error, :invalid}`, with the kind dispatch (`runtime.ex:758-801` fall-through) as the
  SOLE rejector (the object passes the member-set check, isolating the choke point); the
  producer mirror rejects `{:lte, _}`/`{:gte, _}` tuples at `grant_signing_input`
  (`runtime.ex:732` fall-through).
- T2 (`test/bounded_authority_protocol/v1/selector_test.exs`): the `matches?` fall-through
  (`selector.ex:81`) rejects `{:lte, _}`/`{:gte, _}` tuples against satisfiable same-tag
  arguments, so the term-level matcher admits no reserved kind either.

Both mutation classes were executed in-ticket (the BAP-17 two-mutation honesty pattern). The
SURGICAL mutation — adding exactly the two kind clauses to the decode dispatch, the producer
arms, and a same-tag-comparison matcher — reddens precisely the reserved entries: T1's decode
assertion breaks on `{:ok, %V1.Grant{... selectors: [{:lte, ["amount"], {:integer, 100}}]}}`,
T1's producer assertion breaks on `{:ok, _signing_input}`, and T2 breaks on `:ok` from
`match_all` (18 tests → 16 passing; the full-suite run's three additional failures are the
architecture purity/package gates, which redden on ANY `lib/` byte change and are not
kind-admission evidence). The CRUDE mutation — dropping the kind-string discrimination in the
two three-member decode arms so any kind string decodes — reddens the T1 decode assertion
alone (17/18): it widens decode only, leaving the producer and matcher fall-throughs closed,
which is exactly why the tripwire set covers all three choke points rather than one.
`lib/` was restored byte-identical after each run (`git diff` empty over `lib/`).

Per [ADR 0010](0010-delegation-with-attenuation.md):286-289, the unchanged corpus is not
itself the rejection proof for names that live in docs only — the cross-implementation
`lte`/`gte` corpus vectors land with the activating major's full corpus. Activation requires
the charter's activation checklist (complete closed profile + spec revision, conformance
corpus with its own certified identity, cross-suite evidence rules, two independent passing
implementations). The activating major owns: its `REQ2-*` requirement-id range
([ADR 0007](0007-normative-requirement-identifiers.md)), the accept-direction and
reject-direction conformance vectors — including the named classes same-tag match/no-match,
cross-tag, `−0.0`/`0.0`, and extreme-magnitude binary64 bounds — and the concrete bounds
review of §4.

## Alternatives considered

- **A compound `range` kind (`{kind, path, lo, hi}`).** Rejected: it adds no expressive power
  over the conjunctive composition of two one-sided selectors on the same path; it requires a
  FOURTH recognized member set, fragmenting the ADR 0021 three-set discipline every SDK's
  shape matrix pins; and it doubles the bound-validation surface (two numeric members with
  one shape rule) where two ordinary tuples reuse everything already proven for
  `{kind, path, value}`. Conjunctive composition is also how attenuation already narrows
  (§5), so the compound form buys nothing on that axis either.
- **Four relation kinds (`lte`/`gte`/`lt`/`gt`) over the same-tag domain.** The adversarial
  pass's strongest-form alternative (challenge C1 named it; the same-tag domain it argued for
  was ADOPTED). The strict kinds are rejected PERMANENTLY, not deferred: the charter §5
  mandate is floor/ceiling-shaped ("spend up to X per request", execution-date windows) —
  inclusive bounds; on integers a strict bound is derivable (`amount < 100` ≡
  `amount ≤ 99`), so strictness is expressible where the mandate names it; no
  authority-named mandate requires strict FLOAT bounds (the ±1 derivation is not available
  there, which is precisely why the exclusion is recorded as permanent rather than parked —
  "add `lt`/`gt` later" would itself be a contract-major and the banned deferral posture);
  and the closed kind set grows only by contract-major in any case. The `lt`-later deferral
  framing was one of the challenge-8 banned reasoning classes and is not revived.
- **An integer-only operand domain.** Rejected as an unproven-limit exclusion (adversarial
  challenge C1): same-tag float comparison is mechanically deterministic within the
  already-bounded finite binary64 domain the v1 decoder admits and `semantic_equal?/2`
  already compares; nothing in the authority chain limits inequality kinds to monetary minor
  units or NumericDates; transitional SDK implementation effort ("Rust i64", cross-SDK glue)
  is not a technical impossibility for a comparison that produces a boolean. The float tag is
  the designed bridge for decimal-facing consumers (the B2 forward-lens bet, recorded in the
  BAP-20 spec's Further Notes).
- **A new member set (e.g. `{kind, path, bound}`).** Rejected: ADR 0021's three-set
  discipline exists so member-set matrices stay closed and testable; `lte`/`gte` fit the
  existing `value` slot with a numeric-domain constraint, so a new set would multiply shapes
  without semantic gain.
- **`REQ1-SELECTOR-*` ids for the reserved names in the v1 requirement map.** Rejected on the
  [ADR 0016](0016-offline-eligible-grant-claims.md) alternative-(c) precedent: a reserved
  name imposes no v1 MUST to map, and the successor major owns its own `REQ2-*` range.
  Registry rows + this ADR's prose carry the reservation.

## Consequences

- The reserved `lte`/`gte` kinds are REJECTED by the current major's closed profile at the
  three wire-profile choke points (decode kind dispatch, producer arm fall-through, matcher
  fall-through), proven by the T1/T2 tripwires and both executed mutation classes above. A
  fourth kind-sensitive site exists outside the wire profile: the conformance corpus
  runner's selector builder (`lib/bounded_authority_protocol/conformance/runner.ex`,
  `build_selector/1`) also fails closed on the reserved names through its catch-all, and the
  activating major extends it alongside its corpus vectors.
- The current major's wire profile, bounds, and verdicts are UNCHANGED — this is a design-only
  slice: `git diff <base>..HEAD -- lib/ docs/protocol-v1.md priv/conformance/ spec/ sdks/` is
  empty over the slice range, and the corpus is untouched.
- `docs/design/registries.md` gains `lte` and `gte` as reserved selector-kind rows; the
  existing "activate only with a contract-major" policy paragraph governs them.
- Issuers cannot express per-request ranges until the successor major activates; the private
  runtime's private enforcement posture is unchanged in the meantime (critical rule 4).
- The activating successor major owes: its `REQ2-*` ids, the named corpus-vector classes
  (same-tag accept/reject, cross-tag, signed zero, extreme magnitudes), the concrete bounds
  review, and the four-SDK re-verification under the charter's activation checklist.

## See also

- [ADR 0010](0010-delegation-with-attenuation.md) — §3.2, the attenuation relation this ADR
  leaves unchanged and restates its soundness over; :286-289, the corpus-deferral rule.
- [ADR 0016](0016-offline-eligible-grant-claims.md) — the reserve-and-activate precedent this
  ADR mirrors, and the `max × cnt` ceiling contrast for why §4 needs no new bound.
- [ADR 0021](0021-v1-all-selector-recognized-shapes-erratum.md) — the three recognized member
  sets the new kinds reuse.
- [ADR 0003](0003-standard-jws-and-verified-grant-results.md) §7 — the facts discipline §6
  restates for range bounds.
- [ADR 0007](0007-normative-requirement-identifiers.md) — the successor major's `REQ2-*` range.
- [ADR 0029](0029-budget-window-posture.md) — the companion mechanism carrying charter §5's
  cumulative half; written 2026-09-19 as the posture consolidation, with the `ba+budget-window`
  attestation-shape design explicitly deferred.
- [successor-major charter](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/successor-major-charter.md) §5 — the owner decision this
  ADR mechanizes; [registries](../design/registries.md) — the selector-kind reservations.
