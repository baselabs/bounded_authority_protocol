# ADR 0007: Normative requirement identifiers

- Status: accepted
- Date: 2026-08-05
- Refines: [ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §3
  (Requirement-to-corpus traceability)
- Implemented by: roadmap row BAP-10

## Context

ADR 0006 §3 commits the protocol, before the release-candidate contract (BAP-06), to a normative
profile rewritten with RFC 2119/RFC 8174 conformance keywords and "stable requirement identifiers,"
with the acceptance bar that every MUST maps to at least one conformance applicability cell or a named
falsifiable gap. ADR 0006 committed to the *concept* of stable requirement identifiers; it did not
specify the *format*. This ADR records the format decision.

The format is not execution detail. A requirement identifier is:

1. **Public and third-party-cited.** Errata (`docs/errata.md`), external implementations, and the
   conformance mapping will reference individual ids (`REQ1-HEADER-alg-eddsa`) the way RFC errata
   reference section numbers. Once third parties implement and cite the profile, an id rename is a
   breaking reference change.
2. **Post-publication-irreversible.** Per ADR 0006 §context's capture-now doctrine — "all of it
   captured as tracked product authority now ... cheap to fix before third parties implement the
   profile and nearly impossible to retrofit after" — a naming decision that cannot be retrofitted
   after publication lands as tracked authority before publication.
3. **Load-bearing under the parallel contract-majors evolution contract.** ADR 0006 §1 and the
   [standards track charter](../design/standards-track.md) § The evolution contract establish that
   successor contract-majors overlap (a deprecation window of at least twelve months during which
   both majors verify under their own complete closed profiles). An id scheme that does not namespace
   by contract-major is ambiguous during that overlap: the same id would refer to potentially
   different rules in major 1 and a successor major.

A fresh-context adversarial design review of the BAP-10 design (2026-08-05) reconstructed the
strongest case for treating the format as an ADR-grade decision and defeated the original "execution
detail" framing; this ADR is the response. The review's load-bearing observations — that the scheme
is irreversible, third-party-cited, and ambiguous under parallel majors without a major namespace —
are the substance of this decision.

## Decision

The requirement-identifier format is:

```text
REQ<contract-major>-<SURFACE>-<short-tag>
```

- **`<contract-major>`** — the artifact's contract-major, matching the `v` claim, the suite scheme
  (`BAP<contract-major>-<signature>-<digest>`, [registries.md](../design/registries.md)), and the
  `BAP1-*` domain separators. The current contract-major is `1`, so every requirement the v1 profile
  carries is `REQ1-*`. A successor contract-major authors its own `REQ2-*` range; the two ranges are
  disjoint by construction during the deprecation overlap.
- **`<SURFACE>`** — the section or public-API surface the requirement governs. The fixed surface
  vocabulary for the v1 profile: `CORE` (profile-wide invariants), `JSON`, `B64`, `SCHEMA`,
  `HEADER`, `CLAIM`, `SELECTOR`, `URI`, `SIGNING`, `VERIFY`, `BOUNDS`, `LOCATOR`, `CHAIN`,
  `EXPORT`, and the reserved `EVO` (evolution-contract requirements that live in
  [standards-track.md](../design/standards-track.md) rather than the normative profile).
- **`<short-tag>`** — a stable kebab-case slug of the requirement's subject (`alg-eddsa`,
  `kid-bytes`, `closed-set`, `no-duplicate`, `v`).

Properties:

- **Major-namespaced** — resolves the parallel-majors ambiguity. `REQ1-HEADER-alg-eddsa` (major 1,
  EdDSA) and `REQ2-HEADER-alg-ml-dsa` (a hypothetical successor major) cannot collide.
- **Stable across editorial rewording within a major** — an id's meaning only changes at a
  contract-major boundary, which is exactly when a new `REQ2-*` range is authored under a new
  normative profile.
- **Surface-namespaced for locality** — a reader or erratum author scanning `REQ1-HEADER-*` finds all
  header requirements together.
- **No per-slice or per-version component** — the id is keyed to the contract-major (a product
  boundary), not to a roadmap slice or a SemVer patch. An erratum adding a requirement within major 1
  slots in as `REQ1-<SURFACE>-<new-tag>` without renumbering.

The closed-rejection profile invariant ("a conforming implementation rejects every unlisted member,
value, encoding, or extension with exactly `{:error, :invalid}`") is stated once as a profile-level
invariant under the `CORE` surface and is the rationale for the per-surface closed-set MUSTs; it is
not itself a single mapping target. Each per-surface closed-set requirement (`REQ1-HEADER-closed-set`,
`REQ1-CLAIM-closed-set`, ...) is its own MUST and maps to the rejection cells of the surface(s) it
governs. This keeps RFC 2119 §6 sparing-use (the principle stated once) consistent with the BAP-10
acceptance bar (every MUST maps to a populated conformance cell).

## Alternatives considered

- **`REQ-<SURFACE>-<tag>` (no major component).** Rejected: ambiguous under the parallel-majors
  evolution contract. The protocol namespaces by major everywhere else it matters (suites, domain
  separators, the `v` claim); the id scheme must follow.
- **`BAP10-001` flat counter.** Rejected: no locality (a reader cannot find neighbors by surface);
  couples to the roadmap slice number (an erratum adding a requirement would need `BAP10-001a` or a
  renumber); and the slice number is an implementation-tracking artifact, not a product boundary.
- **`REQ1-<SURFACE>-<NNN>` numeric per-surface counter.** Rejected in favor of kebab-case short-tags:
  a numeric counter renumbers on insertion (erratum adds a requirement between 003 and 004), while a
  semantic slug (`alg-eddsa`) is insertion-stable. The slug also reads in errata citations.

## Consequences

- The v1 profile's requirement ids all carry the `REQ1-` prefix. The conformance mapping
  [conformance mapping](../design/bap-10-requirement-map.md) references ids in this form.
- A successor contract-major (BAP-14 and beyond) authors a `REQ2-*` range under its own normative
  profile; the two ranges coexist during the deprecation overlap without collision. This is the same
  posture the suite and domain-separator conventions already take.
- Errata cite the major-prefixed id; an erratum against major 1 carries `REQ1-*` references and does
  not silently apply to a successor major — consistent with the no-verdict-flip and per-major-closed
  invariants in ADR 0006 §1 and the charter.
- This ADR refines ADR 0006 §3 by specifying the format; it does not supersede the §3 commitment
  (RFC 2119/8174 keywords + stable ids + the MUST-to-cell acceptance bar), which stands unchanged.
- No wire byte, bound, or verdict changes. The id scheme is documentation and citation authority;
  the verifier code is unchanged.
