# Upgrading — the published compatibility contract

What a consumer of `bounded_authority_protocol` may rely on across releases, and what each
release kind changes. The locked 0.1.0 release-candidate contract
([ADR 0008](../../docs/adr/0008-release-candidate-contract.md)) remains the HISTORICAL record
of the frozen API surface; THIS document is the living contract consumers read.

## 0.6.0 to 0.6.1

Repair patch: the second independent review family's pass over the role-attestation
landing range confirmed eight
findings (three blocking) in the role-attestation surface — caller-tightened bound
enforcement, producer/decoder limit agreement, closed-error shapes for malformed caller
input, and in-repo SDK alignment. No corpus, pin, or ADR change; no verdict moves on
legal input. Consumers on 0.6.0 holding caller-tightened bounds should upgrade — the
0.6.0 codec ignored a tightened `anchor_bytes` for standalone attestations (the blocking
finding). `~> 0.6.0` picks 0.6.1 up on the next `mix deps.update`.

## 0.5.1 to 0.6.0

Additive sibling-profile release: `0.6.0` ships the first package bearing
`bap-role-attestation/1` (ADR 0036) — the `BoundedAuthorityProtocol.RoleAttestation.V1`
namespace (`attestation_signing_input/2`, `assemble_compact/2,3`, `decode_attestation/2`,
`verify_attestation/2`) and its certified corpus. No contract-major byte or verdict changes:
the v1/v2/v3 profiles, corpora, and certified pins are unchanged, and the only v1/v2-tree
behavior change is a closed-error-shape fix (wrong-width signatures now return exactly
`{:error, :invalid}` instead of a bare `false` — no accept/reject verdict moves). Consumers on
`0.5.x` who never touch the new namespace need no changes; the minor-bounded `~> 0.6.0`
requirement picks it up on the next `mix deps.update`.

## 0.5.0 to 0.5.1

Documentation-truth patch with **no code, wire-format, bound, or public-API change**: the
published doc set is trimmed to implementer-facing content (the IANA pre-filing drafts, the
AP2/A2A interop design profiles, the successor-major activation checklist, and the superseded
0.1.0 release-candidate contract leave the package and hexdocs while remaining tracked in the
repository). Consumers on 0.5.0 need not upgrade; the pin bump is optional.

## 0.4.2 to 0.5.0

Additive contract-major release: `0.5.0` activates the ES256 suite as contract-major 3 under
`BoundedAuthorityProtocol.V3` (`BAP3-ES256-SHA256` — ECDSA P-256/SHA-256, RFC 7518 §3.4 raw
`r || s` signatures with low-S canonicality, EC JWK holder keys, 65-byte uncompressed-SEC1 raw
keys; [ADR 0035](../adr/0035-es256-contract-major-activation.md)) with its certified 292-case
corpus, and ships the spec-facts v2/v3 extraction baselines inside the package. v1 and v2 are
byte-frozen: wire bytes, bounds, public APIs, verdicts, and certified pins are unchanged, so
v1/v2 consumers need only bump the requirement pin. The new namespace is opt-in — nothing that
does not reference `BoundedAuthorityProtocol.V3` changes.

## 0.4.1 to 0.4.2

Documentation-truth patch: the corrected AP2 mandate-mapping note and the capability extension's
selector-scope paragraph, [ADR 0029](../adr/0029-budget-window-posture.md) (the cumulative-budget
posture; the `ba+budget-window` attestation-shape design explicitly deferred), the owner-directed
tracked-authoring-paths exception for the adopted handoff record, and a batched dependency
sweep. **No wire-format or public-API change**; no consumer action.

## 0.4.0 to 0.4.1

No wire-format or public-API change: 0.4.1 lands the self-enforcing toolchain and the
tri-platform build bar ([ADR 0031](../adr/0031-self-enforcing-toolchain-and-tri-platform-build-bar.md))
and the dependency-currency gate ([ADR 0032](../adr/0032-dependency-currency-gate.md)) inside the
repository — the OTP assert is not shipped in the package, so consumer builds are unaffected.
Bump the requirement as convenient; nothing else changes for consumers.

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
