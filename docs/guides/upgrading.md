# Upgrading — the published compatibility contract

What a consumer of `bounded_authority_protocol` may rely on across releases, and what each
release kind changes. The locked 0.1.0 release-candidate contract
([ADR 0008](../../docs/adr/0008-release-candidate-contract.md)) remains the HISTORICAL record
of the frozen API surface; THIS document is the living contract consumers read.

## 0.2.x to 0.3.0

`0.3.0` adds `bap-application-proof/local-loopback-http/1` as a separately named application
profile. Standard `dpop+jwt` bytes, bounds, public signatures, the 283-case standard corpus, and all
standard verdicts are unchanged. Existing consumers that never select the new profile need only
update the package pin and rerun the standard corpus.

Consumers adopting the new profile must select its five-surface API explicitly, pin its certified
index SHA-256 (`10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4`), require the server nonce,
derive the target from the direct literal-loopback listener, and keep standard/local proof bytes
mutually rejected. Do not adopt from the Git tag alone: wait for the immutable Hex archive and
verify its registry checksum before changing a package dependency.

## Contract classes

| Release kind | Wire formats | Bounds and verdicts | Public API | Conformance corpus |
|---|---|---|---|---|
| Patch (0.x.y → 0.x.z) | byte-identical | identical | additive bug-fix only; no signature change | identical (corpus revision unchanged) |
| Minor (0.x → 0.x+1) | byte-identical on the v1 profile | identical | additive; existing signatures stable | may grow (corpus revision bumps; new cases only — no verdict flips) |
| New application profile (pre-1.0: next 0.x.0) | standard profiles byte-identical; new profile has a distinct `typ` | existing profiles identical; new profile has its own closed verdict contract | separately named APIs; no inference or fallback | separate certified corpus and digest |
| Major (successor contract-major) | new closed profile; the v1 profile never downgrades inside it | per its own spec | a new namespace; v1 remains verifiable | new corpus |

## What may never change inside v1

- A single standard-v1 wire byte, bound, or verdict: the profile is closed permanently. Evolution
  uses parallel contract-majors or separately identified byte-distinct application profiles whose
  APIs, `typ`, specification, and corpus cannot be inferred or used as fallback.
- The error shape (`{:error, :invalid}`) and the facts contracts (value-bearing, redacted,
  non-authorizing, with their not-evaluated markers).
- The locked public API surface enforced by the architecture gate.

## What a minor release may do

- Add public functions, add corpus cases (corpus revision bump — cited documents update in
  the same change), tighten documentation, and add gates. Consumers who pin the corpus digest
  must rotate the six certified-index-SHA pins in the same change as a corpus-consumer
  upgrade (the repository ships the one-command regeneration script).
- A new byte-distinct application profile is a breaking pre-1.0 release (`0.x.0`), never a patch.
  Consumers opt into its separately named API and independently pin its certified corpus index.

## How to check you are unaffected

1. Pin the exact package version; the conformance corpus ships inside the package.
2. Run the packaged verifier CLI against the packaged corpus (exit 0 = your build still
  agrees with the certified corpus).
3. For corpus-consuming minors: rotate the certified digest pins with the shipped script and
   re-run your suite.
4. For a sibling application profile: select its named API explicitly, pin its separate corpus
   index digest, and prove the standard profile still rejects its artifacts (and vice versa).

## Deprecation policy

Nothing inside v1 deprecates. Successor-majors carry their own complete profiles; the v1
profile's availability follows the repository's governance document (minimum twelve-month
deprecation windows for anything that ever retires, published change-control, and a
security-release policy).
