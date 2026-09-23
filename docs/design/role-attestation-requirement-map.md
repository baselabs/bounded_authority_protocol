# Role-attestation profile requirement map

This map traces every normative `REQ-RA1-*` requirement in
[`spec/bap-role-attestation-v1.md`](../../spec/bap-role-attestation-v1.md) to executable
evidence or an explicit downstream/release gate. The certified profile corpus is revision 1
(40 cases) at `priv/conformance/attestation-profiles/role-attestation/v1`, index SHA-256
`be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a`.

| Requirements | Evidence | Status |
|---|---|---|
| `CORE-profile-identity`, `CORE-typ`, `HEADER-closed-set`, `HEADER-signed-identity` | `attestation-cases.json`; exact producer/assembly bytes; the unknown-header-member, wrong-typ, and tamper cases | populated |
| `CORE-cross-profile-reject`, `CORE-no-inference-fallback` | the wrong-typ and cross-profile-grant-rejected cases both directions; the separately named `BoundedAuthorityProtocol.RoleAttestation.V1` namespace; architecture export/import locks | populated |
| `CLAIM-v`, `CLAIM-jti`, `CLAIM-key-id`, `CLAIM-public-key`, `CLAIM-role-closed-set`, `CLAIM-window`, `CLAIM-closed-required`, `CLAIM-canonical` | the missing-member matrix (7 cases), role-outside-closed-set, public-key-wrong-width, inverted/empty window, v-float-lexeme, non-canonical-payload-order, duplicate-member cases | populated |
| `VERIFY-caller-supplied`, `VERIFY-fail-closed` | every corpus case drives `verify_attestation/2` to exactly `{:error, :invalid}` or facts; expected context (attestor, subject binding, now, bounds) is caller-supplied in every case | populated |
| `VERIFY-closed-sets`, `VERIFY-attestor-signature`, `VERIFY-subject-binding` | wrong-attestor-kid, signature-by-other-key, attestor-key-mismatch, subject-key-id-mismatch, subject-key-mismatch cases | populated |
| `VERIFY-no-self-attestation` | self-attestation-same-material and self-attestation-same-key-id cases; key-transition distinct-fingerprint precedent | populated |
| `VERIFY-window-containment` | nbf-before-attestor-window and exp-outliving-attestor-window rejects; nbf-at-attestor-valid-from and exp-at-attestor-valid-before boundary accepts | populated |
| `VERIFY-now-window` | now-at-nbf accept; now-before-window and now-at-exp rejects (half-open `[nbf, exp)`) | populated |
| `VERIFY-facts`, `VERIFY-facts-non-authorizing`, `VERIFY-policy-caller-side` | facts-shape ExUnit assertions (anchor posture, `trust: :not_evaluated`, no `authorization` marker, `Inspect` redaction, RFC 7638 fingerprints); no decision surface exists in the profile API | populated |
| `API-complete`, `API-namespace`, `API-return-shape`, `API-no-signer`, `API-assembly-revalidate`, `API-symmetry` | four separately named public surfaces; corpus producer/assembly/decode/verify checks; external-signature-only assembly | populated |
| `SECURITY-not-authority`, `SECURITY-holder-semantics`, `SECURITY-runtime-private` | normative security section; facts carry no decision; holder-role corpus case verifies without granting per-grant standing; pure-library architecture gate | populated |
| `SECURITY-trust-scope` | containment makes the attestor window the attestation-lifetime ceiling; documented posture (no new bound) | populated |
| `CONFORMANCE-complete` | 40-case certified corpus: both valid roles, missing-member matrix, every rejection family, boundary equalities, both self-attestation discriminating forms (same key id, same key material), outliving window, ES256 confusion, meaningful-byte tampers, cross-profile legs both directions; v1/v2/v3 corpora execute unchanged | populated |
| `CONFORMANCE-certified-pin` | index SHA-256 pinned independently by the ExUnit suite, this map, the profile spec, and every SDK consumer | populated |
| `CONFORMANCE-sdks` | Elixir reference plus in-repo Python/Rust/Go legs (this landing); the graduated TypeScript verifier adopts the surface as a release precondition coordinated at corpus freeze | populated |
| `IANA-template` | exact active registry entry plus machine-readable and rendered RFC 6838 templates; filing remains externally gated | populated |
| `CONFORMANCE-cross-repo-receipts` | The artifact has no public transport; the authority-runtime issuance receipt and the companion-signer consumption receipt are named release preconditions discharged by their own private closeouts before any `0.x.0` release bearing this profile. | release gate |
| `RELEASE-immutable` | Requires the exact reviewed package and corpus identity before adopters consume it; release is the owner's decision, not authorized by design approval. | release gate |

“Populated” means the repository contains executable evidence for the public-library
obligation. It does not claim live revocation, trust selection, replay reservation, or a
business effect; those remain downstream authority-host responsibilities.
