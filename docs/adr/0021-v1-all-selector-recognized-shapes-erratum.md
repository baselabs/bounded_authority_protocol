# ADR 0021: v1 `all` selector recognized-shapes erratum

- Status: accepted
- Date: 2026-08-24
- Erratum: 1
- Corrects: the v1 selector table, the standalone selector schema, and the
  selector definition embedded in the grant-payload schema

## Context

The released Elixir decoder, the independent Node implementation, every verifier SDK, and the
normative corpus case `check-envelope-valid-selector-all-with-extra-members` agree that an `all`
selector is accepted on any of the selector algebra's three recognized exact member sets. When the
set is `kind,path,value` or `kind,path,values`, the latter members are inert and `all` matches every
tagged JSON root.

The protocol table and both Draft 2020-12 schemas described only `{kind:"all"}`. Some SDKs also
returned early on `kind:"all"` before checking that the member set was recognized, accepting shapes
the reference and independent runner reject. These were artifact and implementation contradictions,
not an open choice for the frozen profile.

## Decision

1. A selector object has exactly one of three recognized member sets: `kind`; `kind,path,value`; or
   `kind,path,values`. No fourth member and no other combination is accepted.
2. `kind` selects interpretation. `equals` and `one_of` validate their matching three-member form.
   `all` is valid on any recognized set and ignores `path`, `value`, or `values`. Inert values remain
   subject to the enclosing bounded JSON decoder.
3. The protocol prose and both schemas are corrected to the released corpus verdict. SDKs reject
   unrecognized member combinations. The Elixir reference, independent runner, corpus bytes,
   signing inputs, bounds, and released verdicts do not change.
4. A successor contract major may simplify this shape only in its own complete profile and corpus.

## Alternatives considered

Requiring only `{kind:"all"}` was rejected because it would reverse a published valid corpus verdict.
Accepting any object whose `kind` is `all` was rejected because it widens the closed member-set rule
and disagrees with the reference and independent runner.

## Enforcement

The schema test accepts all three recognized `all` forms, including inert values whose types would
be invalid for `equals` or `one_of`, and rejects every other member combination. Each SDK carries the
same matrix. The existing corpus case and independent-runner mutation continue to pin the released
valid verdict.
