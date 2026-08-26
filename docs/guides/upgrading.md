# Upgrading — the published compatibility contract

What a consumer of `bounded_authority_protocol` may rely on across releases, and what each
release kind changes. The locked 0.1.0 release-candidate contract
([ADR 0008](../../docs/adr/0008-release-candidate-contract.md)) remains the HISTORICAL record
of the frozen API surface; THIS document is the living contract consumers read.

## Contract classes

| Release kind | Wire formats | Bounds and verdicts | Public API | Conformance corpus |
|---|---|---|---|---|
| Patch (0.x.y → 0.x.z) | byte-identical | identical | additive bug-fix only; no signature change | identical (corpus revision unchanged) |
| Minor (0.x → 0.x+1) | byte-identical on the v1 profile | identical | additive; existing signatures stable | may grow (corpus revision bumps; new cases only — no verdict flips) |
| Major (successor contract-major) | new closed profile; the v1 profile never downgrades inside it | per its own spec | a new namespace; v1 remains verifiable | new corpus |

## What may never change inside v1

- A single wire byte, bound, or verdict: the profile is closed permanently; evolution happens
  above it through parallel contract-majors.
- The error shape (`{:error, :invalid}`) and the facts contracts (value-bearing, redacted,
  non-authorizing, with their not-evaluated markers).
- The locked public API surface enforced by the architecture gate.

## What a minor release may do

- Add public functions, add corpus cases (corpus revision bump — cited documents update in
  the same change), tighten documentation, and add gates. Consumers who pin the corpus digest
  must rotate the six certified-index-SHA pins in the same change as a corpus-consumer
  upgrade (the repository ships the one-command regeneration script).

## How to check you are unaffected

1. Pin the exact package version; the conformance corpus ships inside the package.
2. Run the packaged verifier CLI against the packaged corpus (exit 0 = your build still
  agrees with the certified corpus).
3. For corpus-consuming minors: rotate the certified digest pins with the shipped script and
  re-run your suite.

## Deprecation policy

Nothing inside v1 deprecates. Successor-majors carry their own complete profiles; the v1
profile's availability follows the repository's governance document (minimum twelve-month
deprecation windows for anything that ever retires, published change-control, and a
security-release policy).
