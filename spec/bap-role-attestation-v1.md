---
title: BAP Role Attestation Profile 1
docname: bap-role-attestation-v1
---

# BAP Role Attestation Profile 1

Document status: normative for attestation profile `bap-role-attestation/1`. Document revision:
rev 1. This document defines a standalone sibling attestation profile under
[ADR 0036](../docs/adr/0036-role-attestation-profile.md); it changes no contract-major
profile's bytes or verdicts.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** are to be
interpreted as described in BCP 14 when, and only when, they appear in all capitals.

## 1. Scope and profile identity

This profile defines a role attestation: a compact JWS in which an attestor key binds a
subject key to a role for a bounded window. It single-sources the contract-major 1 primitives
(Ed25519/EdDSA under `BAP1-Ed25519-SHA256`, the bounded JSON/JCS/base64url/JWK machinery) and
is parsed by no contract-major profile (`REQ-RA1-CORE-profile-identity`).

The profile identity is `bap-role-attestation/1`. A conforming attestation MUST carry protected
`typ: "ba+role-attestation"` (`REQ-RA1-CORE-typ`). Every contract-major profile MUST reject this
`typ`, and this profile MUST reject every contract-major `typ`
(`REQ-RA1-CORE-cross-profile-reject`).

The artifact is standalone and grant-unbound: it binds no grant, names no issuer identity,
audience, or scope, and carries no authorization. Profile selection is trusted caller code
expressed through a separately named public API; it MUST NOT be inferred from bytes, context,
environment, or a failed verification, and a caller MUST NOT retry another profile after
failure (`REQ-RA1-CORE-no-inference-fallback`).

## 2. Protected header and payload claims

The protected header has exactly these members:

| Member | Required value |
|---|---|
| `alg` | `EdDSA` |
| `kid` | attestor key id — bounded ASCII `[A-Za-z0-9.-_~]` under the BAP1 `kid` rules; a hint, never a trust selector |
| `typ` | `ba+role-attestation` |

Every unlisted member or value is invalid (`REQ-RA1-HEADER-closed-set`). The header is
protected by the JWS signature; altering any protected byte invalidates the attestation
(`REQ-RA1-HEADER-signed-identity`).

The payload has exactly these members:

| Member | Type | Rule |
|---|---|---|
| `v` | integer | exactly `1` (`REQ-RA1-CLAIM-v`) |
| `jti` | string | non-empty bounded StringOrUri identifier under the BAP1 grant `jti` rules — the audit and revocation-reference handle (`REQ-RA1-CLAIM-jti`) |
| `key_id` | string | the attested subject key id under the BAP1 `kid` rules (`REQ-RA1-CLAIM-key-id`) |
| `public_key` | string | base64url of exactly 32 raw Ed25519 subject public-key bytes (`REQ-RA1-CLAIM-public-key`) |
| `role` | string | exactly `"issuer"` or `"holder"` (`REQ-RA1-CLAIM-role-closed-set`) |
| `nbf` | integer NumericDate | integral; `nbf < exp` (`REQ-RA1-CLAIM-window`) |
| `exp` | integer NumericDate | integral; the acceptance window is the half-open `[nbf, exp)` (`REQ-RA1-CLAIM-window`) |

Every unlisted member is invalid, every listed member is required, and a numeric member
encoded as a float (for example `1.0`) is invalid (`REQ-RA1-CLAIM-closed-required`). Both
segments MUST equal their RFC 8785 canonical re-encoding, duplicate members are invalid, and
fingerprints derived by implementations use the RFC 7638 Ed25519 thumbprint preimage —
`{"crv":"Ed25519","kty":"OKP","x":…}` — never a hash of raw key bytes (`REQ-RA1-CLAIM-canonical`).

## 3. Verification contract

Verification is a pure function from caller-supplied bytes and caller-supplied trusted inputs
and expected context. The expected context carries the attestor key (key id, raw 32-byte
public key, and its own `[valid_from, valid_before)` validity window, `valid_before` possibly
unbounded), the expected subject binding (subject key id and raw 32-byte subject public key),
the caller's `now`, and bounds (`REQ-RA1-VERIFY-caller-supplied`).

Verification MUST prove all of the following, and MUST return exactly `{:error, :invalid}`
when any fails (`REQ-RA1-VERIFY-fail-closed`):

1. the closed header and payload sets and canonical bytes of §2
   (`REQ-RA1-VERIFY-closed-sets`);
2. the header `kid` equals the attestor key id, and the Ed25519 signature verifies under the
   attestor public key (`REQ-RA1-VERIFY-attestor-signature`);
3. the payload subject binding equals the expected subject binding — `key_id` equality and
   raw `public_key` byte-equality (`REQ-RA1-VERIFY-subject-binding`);
4. the attestor and the subject are distinct: the attestor thumbprint MUST NOT equal the
   subject thumbprint, and the attestor key id MUST NOT equal the subject key id
   (`REQ-RA1-VERIFY-no-self-attestation`);
5. window containment: `nbf >= attestor.valid_from` and, when the attestor window is bounded,
   `exp <= attestor.valid_before` (`exp == valid_before` is containment and is valid)
   (`REQ-RA1-VERIFY-window-containment`);
6. the caller-supplied `now` is in `[nbf, exp)` (`REQ-RA1-VERIFY-now-window`).

A successful verification returns closed, value-bearing, redacted, non-authorizing
`AttestationFacts`: the attestor key id and RFC 7638 thumbprint, the subject key id and
thumbprint, the role as a binary, the `jti`, the window, `verification:
:signature_and_window`, and `trust: :not_evaluated` (`REQ-RA1-VERIFY-facts`). Facts carry no
raw key material, no signature, and no decision (`REQ-RA1-VERIFY-facts-non-authorizing`).
Which attestor to trust, which role a consumer requires, what deployment scope is accepted,
and replay reservation are caller obligations; the maximum attestation lifetime is caller
policy through the attestor key window (`REQ-RA1-VERIFY-policy-caller-side`).

## 4. Public verification contract

A language binding MUST expose separately named equivalents of these four surfaces
(`REQ-RA1-API-complete`):

1. attestation signing-input production;
2. compact assembly from signing input and external signature;
3. attestation decoding;
4. attestation verification.

The Elixir reference namespace is `BoundedAuthorityProtocol.RoleAttestation.V1`; the citation
symbol consumers document is `BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2`
(`REQ-RA1-API-namespace`). All four surfaces return the single `{:error, :invalid}` failure
shape (`REQ-RA1-API-return-shape`). The package owns no signer and accepts no private key or
signing callback (`REQ-RA1-API-no-signer`).

Compact assembly MUST revalidate the protected header, payload, member rules, segment bounds,
and signature width under this profile before returning a compact artifact
(`REQ-RA1-API-assembly-revalidate`). Signing-input production, assembly, decoding, and
verification MUST use the same profile semantics (`REQ-RA1-API-symmetry`).

## 5. Security and host obligations

A role attestation is evidence of a binding, not an authorization. It MUST NOT be represented
as granting execution, and a verified attestation MUST NOT be treated as an authorization
decision (`REQ-RA1-SECURITY-not-authority`). An attestation is valid wherever its attestor key
is trusted: deployments scope attestations through their trust configuration, and issuers
SHOULD issue bounded attestor windows — a configured unbounded attestor window admits
unbounded attestation lifetimes by that choice (`REQ-RA1-SECURITY-trust-scope`). A `holder`
attestation is admission control and defense-in-depth only; per-grant holder standing remains
each grant's `cnf.jkt` binding (`REQ-RA1-SECURITY-holder-semantics`). Replay reservation,
revocation state, and live key-state selection are runtime-private and are no part of this
profile (`REQ-RA1-SECURITY-runtime-private`).

## 6. Conformance and release

This profile has a separate language-neutral corpus (`attestation-cases.json`), certified
index digest, monotone revision, requirement applicability map, and independent
implementations. Cases cover both valid roles, the missing-member matrix, every rejection
family of §2–§3, the window boundary equalities, self-attestation, window-outliving-attestor
rejection, an ES256-signed confusion case, meaningful-byte tampers, and cross-profile
rejection in both directions; the complete contract-major corpora execute unchanged
(`REQ-RA1-CONFORMANCE-complete`).

Revision 1's certified `index.json` SHA-256 is
`be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a` (40 cases). Every corpus
consumer MUST pin that digest independently, require the exact two-file set `profile.json`
and `attestation-cases.json`, and require profile identity, revision, and case counts before
trusting the per-file digests (`REQ-RA1-CONFORMANCE-certified-pin`).

Every in-repository verifier SDK implements the four surfaces and passes the certified corpus
before this profile may be released; the graduated TypeScript verifier adopts the surface as a
release precondition coordinated at corpus freeze. A corpus disagreement or any
contract-major byte or verdict change blocks release (`REQ-RA1-CONFORMANCE-sdks`). Release
evidence additionally includes the authority-runtime issuance receipt and the
companion-signer consumption receipt from their own repositories
(`REQ-RA1-CONFORMANCE-cross-repo-receipts`). Release is the owner's decision.

The profile is adopted only from an immutable public package and exact source/corpus
identities, never a path or mutable Git dependency (`REQ-RA1-RELEASE-immutable`).

## 7. IANA considerations

IANA is asked to register `application/ba-role-attestation+jwt` using the RFC 6838 field
template under LIMITED USE. The ready-to-file source and rendered form live in
`docs/design/iana/media-types.json` and `docs/design/iana/media-types.md`. Filing remains
gated on the protocol's first external submission; this profile and its protected
`ba+role-attestation` wire `typ` do not claim an existing registration
(`REQ-RA1-IANA-template`).
