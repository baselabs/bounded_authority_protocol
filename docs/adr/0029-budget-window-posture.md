# ADR 0029: Cumulative budget posture and the `ba+budget-window` deferral

- Status: accepted (posture consolidation + explicit deferral of the attestation-shape design)
- Date: 2026-09-19
- Track: T2
- Companion: [ADR 0028](0028-range-selector-kinds.md) — the inequality half of the same charter
  program, activated as contract-major 2 by [ADR 0030](0030-v2-contract-major-activation.md)

## Context

The [successor-major charter](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/successor-major-charter.md) settled the selector-scope
split for payment-shaped authority (§ Selector expressiveness, owner decision 2026-08-26):

- **Per-request range constraints** are pure inequality selector kinds and belong in the selector
  algebra. That half shipped: contract-major 2 activates `lte`/`gte`
  ([ADR 0028](0028-range-selector-kinds.md),
  [ADR 0030](0030-v2-contract-major-activation.md); released in 0.4.0).
- **Cumulative budgets** — "up to $500/day" — are not stateless: no verifier can check a
  cumulative bound from grant bytes and request context alone. A naive `budget` selector kind
  would be a silent false security property. The charter names the two enforcement routes —
  issuer attestation (a re-issued grant or a signed budget-window assertion the verifier can
  check statelessly) or runtime-side accounting over the consumption chain — and permits a
  successor major to standardize the attestation shapes while forbidding a bare cumulative
  selector.

[ADR 0028](0028-range-selector-kinds.md)'s context, before this landing, named the attestation
half "the planned ADR 0029, `ba+budget-window`, not yet written, the companion mechanism of the
same program — it lands with or after this ADR" — a forward reference this landing updates to
point here. The roadmap carried the same follow-up. Two things have changed since
that sentence was written:

1. Contract-major 2 shipped (0.4.0, 2026-09-14) carrying only the inequality half, so the
   attestation half is now the program's only open part.
2. The AP2 mandate-mapping note (`docs/extensions/ap2-mandate-mapping.md`, tracked in this
   repository outside the Hex package) now compares
   this protocol's budget posture against AP2's `payment.budget` and `payment.agent_recurrence`
   constraints, whose evaluation algorithms are defined over verifier state — the accumulated
   total of previously closed Payment Mandates, and the timing and count of previous presentations
   (AP2 v0.2 `docs/ap2/payment_mandate.md`). That comparison — and any interop profile built on
   it — needs a citable, settled statement of this protocol's position rather than a
   planned-but-unwritten ADR.

## Decision

1. **The posture is settled and citable here.** No contract-major of this protocol defines a
   cumulative-budget selector kind. Budget enforcement is never a stateless verification claim;
   it belongs to the issuer-attestation or runtime-accounting routes the charter names. This
   re-states the charter's rule — stated there for the successor major — and applies it to every
   future contract-major of this protocol.
2. **The `ba+budget-window` attestation-shape design is explicitly deferred.** This ADR does not
   reserve a wire name (the [registries](../design/registries.md) gain no row), define a claim,
   header member, suite, or payload shape, or constrain the future design beyond the charter's
   own rule (standardize attestation shapes only, never a bare cumulative selector). When that
   design is directed, it lands under its own ADR following the reserve-and-activate discipline
   and the charter's activation checklist, and activates only in a successor contract-major.
3. **No code, corpus, wire, or public-API change.** This ADR is documentation-only; every
   verifier and SDK behaves exactly as before.

## Consequences

- Interop and comparison material (the AP2 mapping note and any future interop profile) cite this
  ADR as the settled budget position instead of pointing at an unwritten companion.
- The structural disagreement with stateful-verifier constraint systems is recorded as a
  deliberate difference, not an open question: this protocol's public verifier is stateless by
  construction, and a composition with a stateful counterpart must place cumulative enforcement
  on the stateful side.
- The roadmap follow-up is discharged to "written (posture + deferral)"; the shape design remains
  future work pending direction and a successor contract-major.

## Alternatives considered

- **Design the budget-window attestation shape now.** Rejected: it is successor-major mechanism
  design, subject to the charter's activation checklist, and nothing in the current comparison
  work needs the shape — only the position.
- **A bare `budget` selector kind.** Rejected permanently by the charter: a stateless verifier
  asked to check a cumulative bound must either track state (breaking statelessness) or silently
  under-enforce (a false security property).
