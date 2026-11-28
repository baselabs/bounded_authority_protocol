# Requirement map for holder custody attestations

The [normative profile](../../spec/bap-holder-custody-attestation-v1.md) assigns the
`REQ-HCA1-` range. The table uses that prefix for every ID. Corpus cases run through
the conformance CLI. The independent generator checks the reason for each single-fault
case and produces the signed bytes and expected facts.

| Requirement suffix | Coverage or evidence |
|---|---|
| `CORE-profile-identity`, `CORE-typ` | Exact-byte signing and assembly answer in `profile.json`, `valid-standard`, `wrong-typ` |
| `CORE-cross-profile-reject`, `CORE-no-inference-fallback` | Every row in `custody-separation-cases.json` checks acceptance by the intended decoder and both reciprocal rejections |
| `HEADER-closed-set` | `wrong-alg`, `invalid-kid`, `extra-header`, each `missing-header-*` case |
| `HEADER-signed-identity` | `protected-kid-tamper` binds the changed key ID in the context so that only signature verification can reject |
| `CLAIM-v` | `wrong-version`, `float-version` |
| `CLAIM-jti` | `invalid-jti`, `valid-standard` |
| `CLAIM-key-id`, `CLAIM-public-key` | `invalid-subject-id`, `invalid-subject-key`, `valid-standard` |
| `CLAIM-custody-class-closed-set` | `valid-standard`, `valid-hosted`, `unknown-custody-class`, `numeric-custody-class` |
| `CLAIM-window` | `empty-window`, `reversed-window`, `float-window`, `over-limit-window`, `now-at-nbf`, `now-at-exp` |
| `CLAIM-closed-required` | `extra-claim` and every `missing-claim-*` case |
| `CLAIM-canonical` | `noncanonical-header`, `noncanonical-payload`, `duplicate-header`, `duplicate-claim`; exact RFC 7638 output in both valid class cases |
| `VERIFY-caller-supplied` | `invalid-attestor-key`, `invalid-expected-subject-key`, `invalid-now`, `compact-at-bound`, `compact-over-bound`, `encoded-over-bound`, `decoded-over-bound` |
| `VERIFY-fail-closed`, `VERIFY-closed-sets` | All negative decode and verification outcomes in `attestation-cases.json` |
| `VERIFY-attestor-signature` | `attestor-id-mismatch`, `wrong-signature`, `short-signature`, `noncanonical-scalar`, `small-order-r`, `signed-class-tamper` |
| `VERIFY-subject-binding` | `subject-id-mismatch`, `subject-key-mismatch` |
| `VERIFY-no-self-attestation` | `self-id`, `self-key` with expected context matching the signed artifact |
| `VERIFY-window-containment` | `valid-standard` at both containment equalities, `starts-before-attestor`, `outlives-attestor`, `unbounded-attestor` |
| `VERIFY-now-window` | `now-before-nbf`, `now-at-nbf`, `now-before-exp`, `now-at-exp` |
| `VERIFY-facts`, `VERIFY-facts-non-authorizing` | Exact fact projection from both valid class cases and the rendering test |
| `VERIFY-policy-caller-side` | Both class cases use the same caller context. Host obligations are in §5. |
| `API-complete`, `API-namespace`, `API-return-shape` | Façade export pin, exact signing and assembly answer, decode and verify vectors, closed-failure API test |
| `API-no-signer` | Architecture gate checks the pure producer and verifier surfaces |
| `API-assembly-revalidate`, `API-symmetry` | Assembly acceptance and refusals over the pinned bytes |
| `SECURITY-custody-semantics`, `SECURITY-not-authority`, `SECURITY-holder-semantics` | The closed class set and exact facts in `valid-standard` and `valid-hosted`. Per-grant holder standing remains in the grant. |
| `SECURITY-trust-scope`, `SECURITY-runtime-private` | `attestor-id-mismatch`, `outlives-attestor` and `unbounded-attestor`. Caller obligations are in §5. |
| `CONFORMANCE-complete`, `CONFORMANCE-certified-pin` | The packaged CLI checks the index pin and computes the verdict digest over all 76 cases. |
| `CONFORMANCE-sdks`, `RELEASE-immutable` | Package 1.5.0 corpus inventory and governance release evidence for the shipped SDK |
| `IANA-template` | Active registry row and the media type template comparison in `mix spec.facts` |
