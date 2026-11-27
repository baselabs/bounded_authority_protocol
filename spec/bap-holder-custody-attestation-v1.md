# BAP Holder Custody Attestation Profile 1

Document status: normative source candidate for `bap-holder-custody-attestation/1`.
Document revision: rev 1.
This standalone profile follows [governance § Byte-distinct sibling attestation
profiles](../docs/governance.md#byte-distinct-sibling-attestation-profiles).

The key words **MUST**, **MUST NOT**, and **SHOULD** are interpreted as described in BCP 14
when, and only when, they appear in all capitals.

## 1. Scope and profile identity

An attestor key binds a holder key to a custody class for a bounded window
(`REQ-HCA1-CORE-profile-identity`). The profile uses the contract-major 1 primitives
(Ed25519/EdDSA under `BAP1-Ed25519-SHA256`, bounded JSON, JCS, base64url and JWK).
The compact JWS MUST carry the protected `typ: "ba+holder-custody-attestation"`
(`REQ-HCA1-CORE-typ`). Every contract-major and every existing sibling profile MUST reject
this type. This profile MUST reject all of their types (`REQ-HCA1-CORE-cross-profile-reject`).

The artifact stands alone. It binds no grant and carries no issuer identity, audience, scope
or authorization. The caller MUST select the profile through its named API and MUST NOT
infer the profile from bytes, context or environment, or retry another profile on failure
(`REQ-HCA1-CORE-no-inference-fallback`).

## 2. Protected header and payload claims

The protected header MUST contain exactly these members (`REQ-HCA1-HEADER-closed-set`).

| Member | Required value |
|---|---|
| `alg` | `EdDSA` |
| `kid` | Attestor key identifier under the bounded ASCII BAP1 `kid` rules |
| `typ` | `ba+holder-custody-attestation` |

The attestor signs the exact protected and payload segments under RFC 7515. Altering any
protected byte invalidates the attestation (`REQ-HCA1-HEADER-signed-identity`).

The payload MUST contain exactly these members (`REQ-HCA1-CLAIM-closed-required`).

| Member | Required value |
|---|---|
| `v` | Integer `1` (`REQ-HCA1-CLAIM-v`) |
| `jti` | Nonempty bounded StringOrURI under the BAP1 grant identifier rules (`REQ-HCA1-CLAIM-jti`) |
| `key_id` | Holder key identifier under the BAP1 `kid` rules (`REQ-HCA1-CLAIM-key-id`) |
| `public_key` | The holder's Ed25519 public JWK `x` value, base64url of exactly 32 raw public key bytes. The profile fixes `kty: "OKP"` and `crv: "Ed25519"` (`REQ-HCA1-CLAIM-public-key`). |
| `custody_class` | String `"standard"` or `"hosted"` (`REQ-HCA1-CLAIM-custody-class-closed-set`) |
| `nbf` | Integral NumericDate for the inclusive start, with `nbf < exp` (`REQ-HCA1-CLAIM-window`) |
| `exp` | Integral NumericDate for the exclusive end (`REQ-HCA1-CLAIM-window`) |

Both JSON segments MUST equal their RFC 8785 canonical re-encoding. Duplicate members and
float encodings of integer fields are invalid. Key fingerprints use the RFC 7638 Ed25519
thumbprint preimage `{"crv":"Ed25519","kty":"OKP","x":…}` (`REQ-HCA1-CLAIM-canonical`).

## 3. Verification contract

Verification is pure. The caller supplies the bytes, already-trusted attestor key and
its key id and `[valid_from, valid_before)` validity window, the expected holder key id
and raw 32-byte public key, integer Unix time `now`, and bounds. The attestor window may
have an unbounded end. The BAP1 bounds apply, including the anchor-byte ceiling for this
compact artifact. Caller bounds may only tighten the profile maxima
(`REQ-HCA1-VERIFY-caller-supplied`).

Verification MUST prove all of the following and return exactly `{:error, :invalid}`
when any check fails (`REQ-HCA1-VERIFY-fail-closed`).

1. The header, payload, and canonical bytes satisfy §2 (`REQ-HCA1-VERIFY-closed-sets`).
2. The protected `kid` equals the supplied attestor key id and the signature verifies under
   the supplied attestor public key (`REQ-HCA1-VERIFY-attestor-signature`).
3. The payload's `key_id` and raw `public_key` equal the expected holder binding
   (`REQ-HCA1-VERIFY-subject-binding`).
4. The attestor and holder key identifiers differ and their thumbprints differ
   (`REQ-HCA1-VERIFY-no-self-attestation`).
5. The signed window is contained in the attestor window. `nbf >= valid_from` and, if
   `valid_before` is bounded, `exp <= valid_before` (`REQ-HCA1-VERIFY-window-containment`).
6. The supplied time satisfies `nbf <= now < exp` (`REQ-HCA1-VERIFY-now-window`).

The signature check MUST follow [BAP1's strict Ed25519 rule](bap-v1.md#strict-ed25519)
(`REQ1-SIGNING-ed25519-canonical-point`, `REQ1-SIGNING-ed25519-small-order-reject`,
`REQ1-SIGNING-ed25519-scalar-range`, `REQ1-SIGNING-ed25519-cofactorless`). The attestor
key, encoded holder key, and expected holder key MUST pass BAP1 key acceptance
(`REQ1-KEY-ed25519-acceptable`). Signing-input production also checks the holder key.
The host MUST apply the torsion-free check at attestor trust installation and holder key
enrollment (`REQ1-HOST-ed25519-torsion-free`).

Successful verification returns redacted `AttestationFacts` with the attestor and holder
key IDs and RFC 7638 thumbprints, the custody class as a binary, `jti`, the window,
`verification: :signature_and_window`, and `trust: :not_evaluated`
(`REQ-HCA1-VERIFY-facts`). The facts carry no raw public keys, signature or decision
(`REQ-HCA1-VERIFY-facts-non-authorizing`). The host selects attestors, defines acceptable
custody classes and deployment scope, and bounds the maximum attestation lifetime through
its attestor key window (`REQ-HCA1-VERIFY-policy-caller-side`).

## 4. Public verification contract

A binding MUST expose separately named signing-input production, compact assembly with an
external signature, bounded decoding, and verification (`REQ-HCA1-API-complete`). The Elixir
reference namespace is `BoundedAuthorityProtocol.HolderCustodyAttestation.V1`. The citation
symbol is `BoundedAuthorityProtocol.HolderCustodyAttestation.V1.verify_attestation/2`
(`REQ-HCA1-API-namespace`). All four surfaces return the single `{:error, :invalid}`
failure shape (`REQ-HCA1-API-return-shape`). The package accepts neither private keys
nor signing callbacks (`REQ-HCA1-API-no-signer`).

Assembly MUST revalidate the closed protected header and payload, their bounds, signature
width, and the keyless part of BAP1 signature rule S1. It emits accepted signature bytes
unchanged (`REQ-HCA1-API-assembly-revalidate`). All four surfaces MUST apply the same profile
rules. Assembly and verification both apply the keyless signature rule
(`REQ-HCA1-API-symmetry`). Decode returns unverified claims for diagnosis.

## 5. Security and host obligations

A holder custody attestation describes how the holder key is held. `standard` means the
holder holds its own key. `hosted` means an operator holds the key under a non-exporting
handle and signs on the holder's behalf (`REQ-HCA1-SECURITY-custody-semantics`).
The attestation grants nothing. A verifier MUST NOT treat successful verification as
authorization (`REQ-HCA1-SECURITY-not-authority`). Per-grant holder standing comes from the
grant's `cnf.jkt` binding (`REQ-HCA1-SECURITY-holder-semantics`).

The host scopes the deployment by choosing where it trusts an attestor key. Hosts SHOULD
use bounded attestor windows because an unbounded window places no upper limit on the
attestation lifetime (`REQ-HCA1-SECURITY-trust-scope`). Live key state, revocation, and
replay reservation belong to the host (`REQ-HCA1-SECURITY-runtime-private`).

## 6. Conformance and release

The independent corpus at `priv/conformance/attestation-profiles/holder-custody-attestation/v1`
covers both custody classes, signed single-fault cases, closed API results, and rejection in
both directions against existing profiles. A corpus consumer MUST also execute the existing
corpora with their pinned verdict digests (`REQ-HCA1-CONFORMANCE-complete`).

Revision 1's pinned `index.json` SHA-256 is
`6f9f497792dca8baf7784ba3e76ba0507731e7859986e89d865f5f89a04bcfaa` (76 cases).
Corpus consumers MUST pin that digest, require the exact indexed files, and check the
profile, revision, counts and per-file digests (`REQ-HCA1-CONFORMANCE-certified-pin`).
Fixture `reason` values describe the single fault expected by the independent generator.
Elixir checks the public `{:error, :invalid}` result and the expected phase of rejection.

Every shipped SDK MUST implement the four surfaces and pass the same corpus before the
profile enters a release and its published corpus inventory (`REQ-HCA1-CONFORMANCE-sdks`).
The first publication is a package minor release and MUST have immutable source, package
and corpus identities plus real-substrate evidence (`REQ-HCA1-RELEASE-immutable`).

## 7. IANA considerations

The prepared LIMITED USE template for `application/ba-holder-custody-attestation+jwt` lives
in the [media type registry source](../docs/design/iana/media-types.json) and its
[rendered form](../docs/design/iana/media-types.md). The template is a candidate
(`REQ-HCA1-IANA-template`).
