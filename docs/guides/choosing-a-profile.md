# Choosing a profile

The package carries several closed wire profiles side by side. Each has its own namespace,
specification, and certified corpus, and each rejects every other profile's bytes. A service
picks one per boundary, explicitly, and never infers a profile from the input or retries another
after a rejection.

## The short answer

| You need | Use | Suite |
|---|---|---|
| Grants and proofs with Ed25519 keys and exact-value selectors | Contract-major 1, `BoundedAuthorityProtocol.V1` | `BAP1-Ed25519-SHA256` |
| The same, plus numeric ranges (`lte`, `gte`) in selectors | Contract-major 2, `BoundedAuthorityProtocol.V2` | `BAP2-Ed25519-SHA256` |
| P-256 keys (ES256), for example keys that live in a cloud KMS or an HSM without Ed25519 | Contract-major 3, `BoundedAuthorityProtocol.V3` | `BAP3-ES256-SHA256` |
| Proofs to a development listener on `127.0.0.1` or `[::1]` over plain HTTP | Local-loopback HTTP, `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1` | Ed25519 |
| A signed statement that a key holds the `issuer` or `holder` role | Role attestation, `BoundedAuthorityProtocol.RoleAttestation.V1` | Ed25519 |
| A signed statement binding the digest of exact content bytes to a context and lineage | Content assertion, `BoundedAuthorityProtocol.ContentAssertion.V1` | Ed25519 |

If none of the special cases apply, start with contract-major 1. Move to contract-major 2 when a
grant must cap a number, and to contract-major 3 when your keys must be P-256.

## Contract-majors

A contract-major is a complete, closed wire profile. Contract-majors 1, 2, and 3 share the same
model (a grant, a proof per request, the evidence formats, the bounds, and the facts) and the
same function names; they differ in the suite and the selector kinds.

| | Contract-major 1 | Contract-major 2 | Contract-major 3 |
|---|---|---|---|
| Signature | EdDSA over Ed25519 | EdDSA over Ed25519 | ECDSA over P-256 (ES256), raw `r \|\| s`, low S |
| Public key | 32 bytes | 32 bytes | 65-byte uncompressed point |
| Holder thumbprint | `V1.Jwk.public_key_thumbprint_raw/2` | `V1.Jwk.public_key_thumbprint_raw/2` | `V3.EcJwk.public_key_thumbprint_raw/2` |
| Selector kinds | `equals`, `one_of`, `all` | adds `lte`, `gte` | adds `lte`, `gte` |
| `v` claim | `1` | `2` | `3` |
| Specification | [`bap-v1.md`](../../spec/bap-v1.md) | [`bap-v2.md`](../../spec/bap-v2.md) | [`bap-v3.md`](../../spec/bap-v3.md) |
| Certified corpus | 283 cases | 268 cases | 292 cases |

Every artifact names its contract-major in its signed bytes (the payload `v` claim, and the
domain separators of every digest), so a verifier can tell them apart without guessing. A
grant and its proofs always come from the same contract-major: a contract-major 1 proof never
pairs with a contract-major 3 grant.

Each contract-major is frozen: its accepted bytes and verdicts never change, except through a
soundness repair recorded in the [errata registry](../errata.md). New capabilities arrive as a
new contract-major or a new sibling profile, side by side with the existing ones. A deployment
can accept several contract-majors at once by routing each boundary to one of them, for example
by the route or the client's registration, never by trying each in turn.

## Sibling profiles

A sibling profile reuses the shared building blocks but has its own protected `typ`, its own
API, and its own corpus.

- **Local-loopback HTTP** (`typ: "ba+loopback-proof"`) replaces the standard proof for a
  listener on a literal loopback address. It requires a server nonce, admits only
  `http://127.0.0.1` and `http://[::1]` targets, and pairs with a contract-major 1 grant.
  Loopback HTTP is not TLS and does not isolate one local process from another
  ([spec](../../spec/bap-local-loopback-http-v1.md)).
- **Role attestation** (`typ: "ba+role-attestation"`) is a standalone artifact in which an
  attestor key binds a subject key to the `issuer` or `holder` role for a window inside the
  attestor key's own validity ([spec](../../spec/bap-role-attestation-v1.md)).
- **Content assertion** (`typ: "ba+content-assertion"`) is a standalone artifact that binds the
  SHA-256 digest of exact content bytes to an issuer, audience, lineage subject, semantic
  profile, window, and predecessor ([spec](../../spec/bap-content-assertion-v1.md)).

The attestation profiles are not credentials: a verified attestation or assertion is evidence of
a binding, with `trust: :not_evaluated`. Which attestor to trust and what a role or an assertion
permits stay with you.

## Signature suites

`BoundedAuthorityProtocol.Ed25519` and `BoundedAuthorityProtocol.Es256` own the signature rules
every profile applies. You call them directly at two points: when you admit a key (key
acceptance, and for Ed25519 the torsion-free check at enrollment), and, for ES256, when you turn a
KMS or HSM signature into the wire form (`Es256.der_to_raw/1`, then `Es256.normalize_low_s/1`).
[Recipes](recipes.md#es256-from-a-kms-or-hsm) shows the second.

## Other languages

Verifiers for TypeScript, Python, Rust, and Go implement the same profiles and pass the same
corpora; see [Other languages](other-languages.md).
