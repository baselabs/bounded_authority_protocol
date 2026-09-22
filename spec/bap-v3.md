# Bounded Authority Protocol v3 Wire Profile

Document revision: rev 1 (2026-09-21). Status: normative. Contract-major 3, suite
`BAP3-ES256-SHA256`. This profile is activated by
[ADR 0035](../docs/adr/0035-es256-contract-major-activation.md) under the
[successor-major charter](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/successor-major-charter.md); the signature-suite bridge
it realizes is specified by the [AP2 interop profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/ap2-interop-profile.md) §3.

The v3 profile is a complete closed wire profile parallel to the frozen v1
([bap-v1.md](bap-v1.md)) and v2 ([bap-v2.md](bap-v2.md)) profiles. Conformance language, the
abstract data model, JSON decoding and canonical serialization, base64url, protected-header and
claim closed sets, URI normalization, signing and digest inputs, the consumption chain and
anchored export, the public verification contract, the untrusted key locator, `typ` values, and
security/privacy considerations are INCORPORATED FROM v1 BY REFERENCE with the substitutions of
§2; the selector algebra is INCORPORATED FROM v2 BY REFERENCE (§4). No section of either
incorporated profile is optional, open, or best-effort in v3. Sections 3–7 state the
v3-specific normative rules in full, including the ES256 signature suite.

## 1. Suite identity and major detection {#suite}

<!-- facts:suite-identity -->
The v3 profile's suite is `BAP3-ES256-SHA256`: ECDSA over the NIST P-256 curve with SHA-256
(`ES256`, RFC 7518 §3.4), SHA-256 digests, RFC 8785 JCS canonical bytes, and the `BAP3-*`
domain separators — under the major-bound naming scheme `BAP<contract-major>-<signature>-<digest>`
(ADR 0009 §1) with the signature family changed from EdDSA/Ed25519 to ECDSA/P-256.

Every v3 artifact declares its contract-major mechanically: the payload `v` claim is exactly
integer `3`, the protected `typ` header carries the same closed values as v1, the protected
`alg` header is exactly `ES256`, and the domain separators are version-bound. A conforming v3
verifier detects the profile of any artifact from its bytes alone.

Cross-major rules (`REQ3-CORE-cross-major-reject`): a v3 verifier rejects every artifact whose
payload `v` is not exactly `3` — including all v1 and v2 artifacts — with the single closed
error; the v1 and v2 profiles reject v3 bytes symmetrically through their closed `v` checks.
There is no cross-major fallback, downgrade, or best-effort parsing in any direction. A holder
presents artifacts of one major end-to-end: a v3 proof MUST pair with a v3 grant
(`REQ3-EVO-proof-major-equals-grant`); mixed-major credentials are invalid by construction
(`REQ3-EVO-mixed-major-invalid`). Cross-suite evidence rules for prior-major artifacts remain
the reserved `ba+suite-attestation` mechanism of ADR 0009; this profile activates none of it.

## 2. Substitutions incorporated from v1 {#substitutions}

<!-- facts:domain-separators -->
For every v1 section not restated below, the normative v3 text is the v1 text with exactly
these substitutions (`REQ3-CORE-v1-incorporation`):

| v1 constant | v3 constant |
|---|---|
| `v` claim value `1` (grant, proof, boundary anchor, key transition, chain row, export header) — grants and proofs MUST carry exactly integer `3` (`REQ3-CLAIM-v`, `REQ3-CLAIM-proof-v`); anchors, transitions, rows, and the export header inherit the same substitution | `3` |
| request-digest prefix `BAP1-REQUEST\0` | `BAP3-REQUEST\0` (`REQ3-SIGNING-digest-prefix`) |
| chain-row domain `BAP1-CHAIN\0` | `BAP3-CHAIN\0` |
| archive prefix `BAP1-ARCHIVE\0EXPORT\0` | `BAP3-ARCHIVE\0EXPORT\0` |
| suite name `BAP1-Ed25519-SHA256` | `BAP3-ES256-SHA256` |
| protected `alg` `"EdDSA"` (grant, proof, boundary anchor, key transition) | `"ES256"` (`REQ3-HEADER-alg`) |
| proof JWK `{crv: "Ed25519", kty: "OKP", x}` and its thumbprint preimage | the EC JWK and preimage of §3 |
| selector kind set | `{all, equals, one_of, lte, gte}` — incorporated from v2 (§4) |
| facts and decoded-struct `version` field `1` | `3` |
| normative references RFC 8032/8037 (EdDSA) | RFC 7518 §3.4/§6.2.1 (ES256, EC JWK parameters); SEC 1 v2 (uncompressed EC point form, as profiled by RFC 5480 §2.2) |

All bounds, claim member sets, header member sets, `typ` values (`ba+cap`, `dpop+jwt`,
`ba+chain-anchor`, `ba+key-transition`), and requirement cross-references to the shared
verification semantics are unchanged except where §3 restates the suite's fixed widths. The
local-loopback application proof profile (`bap-application-proof/local-loopback-http/v1`) is
bound to contract-major 1; it pairs with no v3 grant, and the v3 façade exposes no loopback
functions.

## 3. The ES256 signature suite {#suite-rules}

<!-- facts:suite-rules -->
### 3.1 Keys and the proof JWK

The suite's keys are NIST P-256 (`secp256r1`, `prime256v1`) key pairs. The wire form of a
public key is the JWK; the raw-byte form used where v1 uses "the raw 32-byte Ed25519 public
key" (caller-supplied issuer and historical keys, and the decoded holder key) is the
uncompressed SEC1 point — exactly 65 bytes, `0x04 || x || y` (`REQ3-KEY-uncompressed-sec1`).
Compressed points are invalid in this form.

The proof JWK is exactly `{crv: "P-256", kty: "EC", x: X, y: Y}` in any member order
(`REQ3-HEADER-proof-jwk`), where `X` and `Y` are canonical unpadded base64url of exactly 32
bytes each — the fixed-width unsigned big-endian coordinate spelling of RFC 7518 §6.2.1.2 (x) and §6.2.1.3 (y). Every
additional member, including private `d`, is invalid (`REQ3-HEADER-no-private-jwk`). The
decoded coordinates MUST each be less than the field prime `p` and MUST form a point on the
curve (`REQ3-KEY-point-on-curve`); this check is pure arithmetic in the profile (it precedes
the crypto backend, whose off-curve behavior is backend-specific and never load-bearing).

Issuer-key and holder-key fingerprinting (`cnf.jkt` and the facts fingerprint) use the RFC 7638
thumbprint over exactly:

```json
{"crv":"P-256","kty":"EC","x":"<canonical-X>","y":"<canonical-Y>"}
```

(`REQ3-HEADER-thumbprint`) — the required EC members in lexicographic order; the thumbprint is
unpadded base64url SHA-256 of those UTF-8 bytes, and verified facts carry the raw 32-byte
digest (`REQ3-HEADER-digest-width`, incorporated). BAP `cnf.jkt` and AP2 `cnf.jwk` are two
spellings of one key identity (the AP2 interop profile §3 bridge).

### 3.2 Signatures

The wire signature is the RFC 7518 §3.4 raw form: exactly 64 bytes, `r || s`, two fixed-width
32-byte unsigned big-endian integers (`REQ3-SIGNING-raw-rs`). DER is never a v3 wire spelling.

The verifier rejects, as invalid encodings before any backend call (`REQ3-SIGNING-range`):

- `r = 0` or `s = 0`;
- `r ≥ n` or `s ≥ n`, where `n` is the P-256 group order;
- `s > n/2` — the HIGH-S half (low-S required, `REQ3-SIGNING-low-s`).

Low-S makes each signature non-malleable: for a valid ECDSA signature `(r, s)`, the
counterpart `(r, n − s)` also satisfies the verification equation, so a third party observing a
valid signature could otherwise re-spell it into a second, differently-hashing, still-valid
encoding; only the low-S rule admits one of the two. ECDSA signs with a per-signature nonce, so
the same key and message admit many independently generated valid low-S signatures — the rule
selects one encoding per signature, not one signature per message. Producers MUST normalize
(`s ← n − s` when high) — one conditional subtraction. A backend rejection OR exception (an off-curve point, a backend that raises)
returns exactly the profile's closed error value (`REQ3-SIGNING-backend-reject`, incorporated
from `REQ1-SIGNING-backend-reject`).

Verification order follows the v1 bounds-ordering discipline (`REQ3-BOUNDS-ordering`,
incorporated): segment and canonical-base64url checks; JWK member-set, width, `< p`, and
on-curve checks; signature width and integer-range checks; then the backend verification over
the exact RFC 7515 signing input.

### 3.3 Protected headers

The protected headers bind the suite via `alg: "ES256"`; the member sets are v1's exactly:

<!-- facts:header-members -->
| Compact value | Members |
|---|---|
| grant | `alg: "ES256"`, `typ: "ba+cap"`, `kid: key_identifier` |
| proof | `alg: "ES256"`, `typ: "dpop+jwt"`, `jwk: public_EC_JWK` |

`crit`, `b64`, embedded grant keys, unknown algorithms, and every unlisted member are invalid
(`REQ3-HEADER-closed-set`, incorporated). Grant `kid` keeps the v1 byte discipline
(`REQ1-HEADER-kid-bytes` incorporated) and remains an untrusted hint. The boundary-anchor and
key-transition headers substitute `alg: "ES256"` into the v1 forms verbatim.

## 4. Selector algebra {#selectors}

The v3 selector algebra is the v2 algebra unchanged: the closed member-set discipline with the
FIVE kinds — the three v1 kinds `all`, `equals`, `one_of` plus the two range kinds `lte`, `gte`
that contract-major 2 activated — the same-tag/inclusive range rules, the
interval conjunction, and the v2 path/count/verdict-internal rules
(`REQ2-SELECTOR-*` semantics incorporated; v3 carries them as `REQ3-SELECTOR-*`). See
[bap-v2.md](bap-v2.md) §4. Attenuation posture and the no-strict-kinds exclusion carry over
unchanged.

## 5. Hard maxima {#maxima}

<!-- facts:suite-constants -->
Every v1 bound carries over (`REQ3-BOUNDS-inherited`) except the suite fixed widths, restated
for this suite as immutable cryptographic constants (`REQ3-BOUNDS-fixed-widths`):

| Suite constant | Bytes |
|---|---:|
| P-256 coordinate (`x`, `y`) | 32 each |
| raw public key (uncompressed SEC1) | 65 |
| signature (`r \|\| s`) | 64 |
| SHA-256 digest | 32 |

No new magnitude arises: ECDSA verification consumes two range-checked 32-byte integers, a
65-byte point, and the bounded signing input (the ADR 0035 §5 review). Callers tighten
ceilings exactly as in v1; the fixed widths cannot be tightened or widened.

## 6. Requirement identifiers

The v3 profile carries its own `REQ3-*` range per
[ADR 0007](../docs/adr/0007-normative-requirement-identifiers.md); `REQ1-*` and `REQ2-*` ids
remain bound to the v1 and v2 profiles and never apply to v3 behavior. The v3 MUST-to-cell
traceability lives in the [requirement map](../docs/design/requirement-map.md) § v3.

## 7. Conformance corpus

The v3 conformance corpus is a certified artifact with its own identity
(`priv/conformance/v3/corpus`, revision 1). Its certified index SHA-256 is pinned in the
verifier CLI and every SDK runner exactly as the v1 and v2 corpora are (ADR 0014 D4).
Version-neutral primitive surfaces execute the same shared implementations the v1 corpus
certifies, and their cases are carried into the v3 corpus byte-for-byte; the profile-bound
surfaces carry v3-minted fixtures — every applicability cell v1 populates is populated in v3,
and the full range-selector class matrix of [`bap-v2.md`](bap-v2.md) §4's activation corpus
carries over (v1 populates no `lte`/`gte` cell, and the SDKs' only normative evidence for the
range kinds is this corpus) — plus the suite matrices (signature canonicality: tampered `r`, tampered `s`, high-`s`, zero
`r`/`s`, `r ≥ n`, `s ≥ n`; key encodings: wrong `crv`/`kty`, non-canonical or wrong-width
coordinates, extra JWK member, off-curve point; thumbprint over the wrong member set) and the
cross-major rejections (v1 and v2 artifact bytes under v3 verification). Signed fixtures were
minted with ephemeral in-memory P-256 keys; no private material is tracked
(`REQ3-CORPUS-certified-identity`).
