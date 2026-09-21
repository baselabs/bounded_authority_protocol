# ADR 0035: ES256 contract-major activation (`BAP3-ES256-SHA256`)

- Status: accepted (2026-09-21)
- Date: 2026-09-21
- Track: T2
- Activates: the AP2 interop profile §3 signature-suite bridge
  ([ap2-interop-profile.md](../design/ap2-interop-profile.md)) under the
  [successor-major charter](../../docs/design/successor-major-charter.md) activation checklist
- Implements: roadmap row BAP-22 (the ES256 suite slice)
- Owner decisions binding here: ES256 suite is NOT disclosure-gated (2026-09-19); the TypeScript
  signer ADOPTS the suite and its encodings must stay implementable on the TS producing side
  (2026-09-20); the kiosk-demo refresh joins this cohort sweep (2026-09-20); the sweep's A2A
  drill is the named first real-substrate `BA-Grant`/`BA-Proof` evidence — A4 residual R3
  (2026-09-21; R2, the projection/`htu` conformance vectors, remains routed and is named as a
  follow-up under Consequences)

Evidence classes at load-bearing claims: **OBSERVED** (verified first-hand on the recorded
substrates — OTP 29 / `:crypto` 5.9.1 for the verifier side, Node 22.23.1 for the producing
side), **DERIVED** (restated from a program record or a standard's published construction),
**INFERRED** (this ADR's own decisions).

## Context

Contract-majors 1 and 2 are Ed25519-only (`BAP1-`/`BAP2-Ed25519-SHA256`). AP2's holder side is
profiled EC P-256 with ES256 throughout (AP2 interop profile §3, OBSERVED at AP2 `e1ea56d`), so
one holder key pair cannot serve both protocols today — the composition seam the AP2 profile
names. The bridge is an ES256 contract-major suite: ECDSA over P-256 with SHA-256, under the
suite-naming scheme `BAP<contract-major>-<signature>-<digest>` (ADR 0009 §1), so the same
EC P-256 holder key is the AP2 agent key (a `cnf.jwk` value) and the BAP proof key.

The open decisions this ADR must settle, as the roadmap row names them: the major number and
whether a parallel suite inside an existing major is admissible; the fixed-width encodings
(point compression choice; raw `r||s` per RFC 7518 §3.4; low-S normalization and non-canonical
rejection "the way v1 rejects malformed Ed25519 points"); the `cnf.jkt` EC thumbprint; domain
separators; the corpus with red-capable mutation gates; SDK parity including the npm TypeScript
verifier and — per the 2026-09-20 owner decision — the TypeScript signer's producing-side
adoption; the changelog and registries.

Substrate facts this design rests on (all OBSERVED unless noted; OTP probe):

- `:public_key.generate_key({:namedCurve, :secp256r1})` yields a 32-byte private scalar and the
  public key as the uncompressed SEC1 point — exactly 65 bytes, `0x04 || x || y`, coordinates
  32 bytes each.
- `:crypto.sign(:ecdsa, :sha256, msg, [priv, :prime256v1])` emits a DER `ECDSA-Sig-Value`
  (SEQUENCE of two INTEGERs); observed lengths 70–72 bytes (DERIVED as a range: minimal-octet
  INTEGER encoding bounds the length; the probe prints single samples). The raw RFC 7518 §3.4
  form is not a native OTP spelling and is derived by fixed-width integer re-encoding in both
  directions.
- ECDSA signature malleability is live on the substrate: for a valid `(r, s)`, the counterpart
  `(r, n − s)` also verifies (`verify_high_s=true`), and the backend emits high-`s` values about
  half the time across random keys (the retained 20-sample run: 7 low-`s`; the Node probe's
  retained run: 11 — random-sample snapshots, not fixed ratios).
- An off-curve public point makes `:crypto.verify/5` RAISE (ErlangError), not return `false`;
  a zero-`r` signature returns `false` without raising. The v1 rule that a backend rejection or
  exception returns exactly the closed error value (`REQ1-SIGNING-backend-reject`) is therefore
  load-bearing for this suite, not boilerplate.

## Decision

### 1. The suite is contract-major 3: `BAP3-ES256-SHA256`, payload `v: 3`, `BAP3-*` domain separators

A parallel suite inside an existing major is inadmissible: the charter's absolute constants bind
suite succession to `BAP<contract-major>-*` under a major's own closed profile ("v1 never
downgrades inside itself"), ADR 0009 ("Activation of any of this is a successor-contract-major
concern; the current major stays single-suite"), and ADR 0026's family row already assumes the
successor-major vehicle. Major 2 is taken (ADR 0030, at unchanged algorithms), so this activation
takes major 3.

The v3 wire profile is a complete closed profile whose normative base is two incorporations,
recorded explicitly:

- the v1 profile ([bap-v1.md](../../spec/bap-v1.md)) with the substitutions of
  [`spec/bap-v3.md`](../../spec/bap-v3.md) §2 and the v3-specific rules of its §§3 and 5; and
- [`spec/bap-v2.md`](../../spec/bap-v2.md) §4, incorporated by reference, for the selector
  algebra — the three v1 kinds (`all`, `equals`, `one_of`) plus the two range kinds
  (`lte`, `gte`) that contract-major 2 activated.

Depending on a frozen major's normative text is safe under the same no-verdict-flip discipline
that lets v3 single-source v1's version-neutral algebra: v2 is frozen, so its §4 is a static
reference, and the registries' `lte`/`gte` rows are updated by this activation to name the v3
closed profile alongside v2's (§9). The selector kind set is closed at five; no kind is added or
dropped.

Suite-naming reconciliation (the ADR 0030 precedent, applied again): the registries' ML-DSA
anticipated row describes its activation major generically; with majors 2 and 3 now taken, its
anticipated index moves to the next successor major (4). The scheme is unchanged; only the
anticipated index moves. ADR 0026 itself still reads `BAP2-*` for the family index (stale since
ADR 0030); this landing adds a dated reconciliation note to ADR 0026 so the ADR text and the
registries stop contradicting each other.

Cross-major rules (`REQ3-CORE-cross-major-reject`): a v3 verifier rejects every artifact whose
payload `v` is not exactly `3` — including all v1 and v2 artifacts — with the single closed
error. The reverse direction — v1 and v2 rejecting v3 bytes — holds through the prior majors'
existing closed `v` checks; the frozen v1/v2 corpora (which contain no v3 bytes) are regression
evidence only, and the reverse-direction rejection is proven by focused closed-set tests in the
reference implementation and by a red vector recorded before any suite code existed: complete
v3-shaped artifacts (an ES256 grant and proof over an EC JWK holder key, minted with an
ephemeral P-256 key) were presented to `V1.decode_grant/2`, `V1.decode_proof/2`,
`V1.verify_grant/3`, `V2.decode_grant/2`, and `V2.decode_proof/2`, and every one returned
`{:error, :invalid}`; the remaining surfaces are covered by the focused closed-set tests. It is not
corpus-certifiable in the SDKs, which derive from specification and corpus alone. There is no
cross-major fallback, downgrade, or best-effort parsing in any direction. A holder presents
artifacts of one major end-to-end: a v3 proof MUST pair with a v3 grant
(`REQ3-EVO-proof-major-equals-grant`); mixed-major credentials are invalid by construction.

Charter checklist scope, stated plainly: this ADR discharges checklist item 1 (the complete
closed profile + spec revision), item 2 with §6 (the certified corpus), item 4 with §9 (the
registries edits — the suite row activates by this ADR; no reserved name flips), and item 5
with §9 (the deprecation posture). Item 3 — cross-suite evidence rules for prior-major
artifacts — remains the reserved `ba+suite-attestation` / `ba_sut` content-covering
countersignature design of ADR 0009, deferred under the disclosure gate; this ADR activates
none of it.

### 2. Algorithms and headers

The suite is ECDSA over the NIST P-256 curve (`secp256r1`/`prime256v1`) with SHA-256, per
RFC 7518 §3.4 (`alg: "ES256"`), over the exact RFC 7515 signing input
`ASCII(BASE64URL(protected) || "." || BASE64URL(payload))` — unchanged from v1. All four
protected headers substitute `alg: "EdDSA"` → `alg: "ES256"` (`REQ3-HEADER-alg`); the `typ`
values (`ba+cap`, `dpop+jwt`, `ba+chain-anchor`, `ba+key-transition`), member sets, `kid`
discipline, and the no-`crit`/no-`b64` rules carry over from v1 unchanged.

The proof JWK is exactly `{crv: "P-256", kty: "EC", x: X, y: Y}` in any member order
(`REQ3-HEADER-proof-jwk`), where `X`/`Y` are canonical unpadded base64url of exactly 32 bytes
each — the fixed-width unsigned big-endian coordinate spelling of RFC 7518 §6.2.1.2 and
§6.2.1.3 (the public-key coordinate members; the private-key member `d` of §6.2.2 is invalid
here). Every additional member is invalid (`REQ3-HEADER-no-private-jwk` incorporated). The JWK
carries the two coordinates — the uncompressed point by construction; point compression never
appears on the v3 wire.

The `cnf.jkt` thumbprint and issuer/historical-key fingerprinting use RFC 7638 over exactly:

```json
{"crv":"P-256","kty":"EC","x":"<canonical-x>","y":"<canonical-y>"}
```

(`REQ3-HEADER-thumbprint`) — the required EC members in lexicographic order, unpadded base64url
SHA-256 of those UTF-8 bytes, raw 32-byte digest in facts (the v1 digest-width rule
incorporated). BAP `cnf.jkt` and AP2 `cnf.jwk` are thus two spellings of one key identity — the
bridge contract of AP2 interop profile §3, now normative on the BAP side.

### 3. Signature encoding and canonicality (the low-S decision)

The wire signature is the RFC 7518 §3.4 raw `r || s` form: exactly 64 bytes, two fixed-width
32-byte unsigned big-endian integers (`REQ3-SIGNING-raw-rs`). DER is an internal backend
spelling only — the reference and every SDK convert at the crypto boundary; DER never appears on
the wire or in facts.

**Low-S is REQUIRED: `s` MUST satisfy `0 < s ≤ (n−1)/2` where `n` is the P-256 group order**
(`n` is odd, so `(n−1)/2 = n div 2`; `REQ3-SIGNING-low-s`), and `r` MUST satisfy `0 < r < n`
(`REQ3-SIGNING-range`). The verifier rejects high-`s`, zero-`r`/`s`, and `r`/`s ≥ n` as invalid
encodings before cryptography — the same fail-closed posture v1 practices on malformed
Ed25519 encodings, applied to this suite's own non-canonical class. Rationale, stated for the
property ECDSA actually has:

- **Third-party non-malleability.** For any valid ECDSA signature `(r, s)`, the counterpart
  `(r, n − s)` also satisfies the verification equation (OBSERVED on the substrate), so a
  third party who observes a valid signature can derive a second, differently-hashing, still
  valid 64-byte encoding without the key. With low-S enforced at verification, exactly one of
  the two encodings is admissible: an observed valid v3 signature cannot be transformed into a
  second valid encoding. This matters to every surface that digests signature-bearing bytes
  (compacts, archives): without the rule, malleability would let evidence be re-spelled while
  remaining verifiable.
- **What low-S does NOT deliver** (stated to prevent over-reading): ECDSA signs with a
  per-signature nonce, so the same key and message admit many INDEPENDENTLY generated valid
  low-S signatures; low-S selects one encoding per signature, not one signature per message.
  Producer determinism in this protocol is the signing-input property
  (`REQ1-SIGNING-deterministic-produce` incorporated) — the signature is never a deterministic
  function of the message under ES256.
- **Not a JOSE deviation on the wire**: the bytes are the RFC 7518 §3.4 form; the profile
  restricts which of the two malleable encodings it admits, as is its right as a closed
  profile (rule 3) — and as v1 already does with its own suite's canonicality rules.
- **Producing-side cost is one conditional subtraction**: a signer computing a high-`s` value
  emits `n − s` instead (valid for the same key and message); on the TypeScript producing side
  this is a `BigInt` subtraction with no modular inverse — deliberately implementable per the
  owner's 2026-09-20 decision.
- The bridge is unaffected: AP2 binds the same KEY (`cnf`), not BAP signature bytes, so AP2-side
  ES256 (which does not enforce low-S) composes without constraint.

Verification order (the v1 `REQ1-BOUNDS-ordering` discipline incorporated): width and canonical
base64url checks on all JWK members and signature halves precede point validation (coordinates
less than the field prime, on-curve by pure arithmetic — deterministic across backends, never
relying on backend-specific off-curve behavior) and scalar range checks, which precede the
backend call; any backend rejection OR exception (off-curve points raise — OBSERVED) maps to
exactly `{:error, :invalid}` (`REQ3-SIGNING-backend-reject`).

### 4. Raw public-key spelling: uncompressed SEC1, 65 bytes

Where a v1 API takes "the raw 32-byte Ed25519 public key" (issuer keys, historical keys), the v3
API takes the uncompressed SEC1 point `0x04 || x || y` — exactly 65 bytes
(`REQ3-KEY-uncompressed-sec1`). Compressed points (33 bytes) are rejected. Rationale:

- It is the substrate-native form (OBSERVED: the public key octet is born uncompressed) and the
  trivially reconstructable form from the wire JWK's `x`/`y` members — concatenation only.
- Compressed raw keys would force sqrt-mod-p DEcompression — recovering `y` from
  `0x02|0x03 || x` — into every consumer of the raw-key API (each verifier, and any producer
  holding a compressed key that must emit the JWK), for zero wire effect: the wire already
  carries `x` and `y`. Uncompressed keeps every such path to concatenation, per the owner's
  TS-implementability decision. (Compression itself is a parity bit plus a copy; the field
  arithmetic is all on the decompression side.)

### 5. Hard maxima and bounds

Every v1 bound carries over (`REQ3-BOUNDS-inherited`) with ONE recorded exception: the suite
fixed widths. The v1 bounds row "Ed25519 public key / signature bytes | 32 / 64" does not carry;
v3's immutable suite constants are (`REQ3-BOUNDS-fixed-widths`): P-256 coordinate 32 bytes
each, raw public key (uncompressed SEC1) 65 bytes, signature (`r || s`) 64 bytes, SHA-256
digest 32 bytes.

Where those widths live, decided: they are suite constants in the v3 modules (and each SDK's v3
path), exactly as v1's own `Jwk` and `CompactJws` carry their width constants — NOT members of
the shared `V1.Bounds`, whose `public_key_bytes: 32` is a fixed-width key that mechanically
rejects 65 and therefore stays inert for v3 (no v3 code reads it). This keeps the shared
version-neutral algebra single-sourceable without a per-major Bounds fork. ADR 0018's
threading contract ("the contract is the threading, not the value") is honored through its own
fixed-width carve-out — the same one ADR 0018 grants `signature_bytes`: a fixed-width key
admits only the identity value, so no caller lever exists and the inert field is the
documented exception, not a silent breach. The ADR 0028 §4-style
review found no new magnitude either way: ECDSA verification consumes two range-checked
32-byte integers, a 65-byte point, and the bounded signing input.

### 6. The conformance corpus (checklist item 2)

`priv/conformance/v3/corpus` — a certified artifact with its own identity, revision 1, minted
with ephemeral in-memory P-256 keys (no private material tracked; throwaway mint script,
generator re-derivation via `build_corpus.mjs --major 3`). Composition mirrors ADR 0030 §4 in
full, including the part a five-kind algebra requires:

- version-neutral primitive cases carried byte-for-byte from the certified v1 corpus;
- v3-minted profile-bound cases covering every applicability cell v1 populates (per ADR 0030's
  v2 precedent);
- the full range-selector class matrix carried from ADR 0030's v2 corpus composition —
  same-tag accept and reject, boundary-equal on both kinds and both endpoints, cross-tag in
  both directions, non-numeric operand and non-numeric bound, missing path, over-maxima,
  integer and float extremes, interval conjunction, crossed endpoints, equals-still-enforced —
  because v1 populates no `lte`/`gte` cell, and the SDKs (re-derived from specification and
  corpus alone, ADR 0014 Decision 5) have no other normative evidence for the range kinds;
- the suite-specific matrices: signature canonicality (tampered `r`, tampered `s`, high-`s`,
  zero-`r`, zero-`s`, `r ≥ n`, `s ≥ n`), key encodings (wrong `crv`/`kty`, non-canonical or
  wrong-width coordinates, extra JWK member, off-curve point, coordinate ≥ field prime),
  thumbprint over the wrong member set (missing `y`; OKP-member preimage), and the cross-major
  rejections (v1 and v2 grant/proof/rows/anchor/transition/archive bytes under v3
  verification).

Mutation-battery entries executed RED with proofs recorded in the requirement map § v3:
`v3-signature-low-s-removed` (accept high-S), `v3-selector-range-cross-tag-accepted` (both range kinds compare across numeric tags),
`v3-jwk-curve-accepted` (accept `crv` ≠ P-256), `v3-thumbprint-member-set-wrong` (thumbprint
without `y`), `v3-cross-major-grant-header-and-v-accepted` (grant decode accepts the EdDSA header and `v:1`/`v:2` — v3 cross-major rejection is pinned at BOTH the alg and the v claim, so the entry relaxes both; battery-adjudicated: the v-only variant survives because the alg pin alone still catches every cross-major corpus case),
`v3-request-digest-prefix-downgraded` (BAP3→BAP1 prefix), plus the signature-tamper corpus legs
(tampered `r`, tampered `s`) asserted red-capable through the existing tamper-audit machinery.
Range-check adjudication (battery-executed): the drafted entry
`v3-signature-range-removed` (accept `r`/`s` ≥ n) SURVIVED the battery — the backend
independently rejects out-of-range scalars mathematically, so no corpus verdict isolates the
`0 < r < n` check. The check stays (defense in depth for a backend that might not); its
load-bearing proof is unit-level (`valid_raw_signature?` property tests), and the corpus
cells prove the rejections without proving sole rejection. Disclosed in the requirement map
§ v3's `REQ3-SIGNING-range` row; the battery ships the six verdict-provable entries.

Requirement identities carry the `REQ3-*` range (ADR 0007) with its own MUST-to-cell rows in
the requirement map § v3. Surface tokens: v3 adds `KEY` to ADR 0007's surface vocabulary for
`REQ3-KEY-uncompressed-sec1` (the raw-key API shape is neither a header nor a bound), and
declares the `CORPUS` token v2's `REQ2-CORPUS-certified-identity` already used undeclared.

### 7. Elixir surface

`BoundedAuthorityProtocol.V3` mirrors the v2 module set: the version-bound modules re-authored
(Runtime, Selector, RequestDigest, ConsumptionChain, BoundaryAnchorCodec, KeyTransitionCodec,
AnchoredExportCodec, the version-bearing structs and facts) plus the modules this suite
requires — the EC JWK codec (`EcJwk`: decode/thumbprint/fingerprint over the EC member set,
with the pure-arithmetic on-curve check; v1's `Jwk` is Ed25519-OKP-only and frozen), the ES256
verification module (`Es256`: raw-signature range and low-S checks, the DER conversion, the
exception-rescued backend verify), and `CompactJws` (its Ed25519 `alg`/JWK/width semantics are
suite-bound). The untrusted-key-locator walk is also re-authored in the v3 façade: the v1
locator hard-matches `alg: "EdDSA"` — suite-bound, not major-neutral — so the v3 façade carries
its own `ES256` walk (v2 could share v1's only because both majors are EdDSA; v2's docstring
claim of major-neutrality is accurate for the majors it serves and is left untouched here —
the empty v2 diff is this landing's evidence convention, and a future slice that legally
touches v2 may revisit the docstring). Version-neutral algebra (Json, Jcs, Base64Url, Uri, StringOrUri, Bounds per
§5's inert-width decision, FixedBytes, SigningInput, the carrier structs) single-sources from
`V1` exactly as `V2` does (the no-verdict-flip doctrine of ADR 0030 §2). The v1 and v2 lib
trees are byte-unchanged (git diff over `lib/bounded_authority_protocol/v1*`, `v2*`,
`priv/conformance/v1`, `priv/conformance/v2` is empty; both certified pins unchanged). The
architecture gate pins the V3 export allowances and dynamic-call counts; the
durable-identifier scanner enumerates the accepted v3 families (namespace, paths, `v: 3` wire
field, `BAP3-*` separators, suite, `REQ3-*`), with V4 the new rejected frontier. The
local-loopback application proof profile stays contract-major-1-bound; the v3 façade exposes no
loopback functions.

### 8. The SDK cohort (checklist item 2 across implementations)

- **In-repo SDKs (Python, Rust, Go)**: each gains a v3 namespace re-derived from
  `spec/bap-v3.md` + the certified corpus alone (ADR 0014 Decision 5; ADR 0017's five clauses
  and ADR 0018's bounds threading adopted at authoring), a v3 corpus runner with the certified
  index SHA-256 asserted at load, and per-language permissiveness mutation gates for the new
  closure classes (low-S acceptance, `r`/`s` range, EC JWK member set, coordinate width and
  canonicality, off-curve point) — each red-capable, mechanically broken and reverted at
  authoring. The corpus-sync gate covers the new vendored snapshots; the digest-pin rotation
  script covers v3's pins — the rotation becomes fifteen pins, five per major (four single-line
  pins plus the Rust two-line pin); the TypeScript pin lives in the graduated repository and
  rotates there.
- **npm TypeScript verifier** (`baselabs/bounded_authority_protocol_typescript`): a corpus
  snapshot-bump commit in its own repository at corpus freeze (ADR 0015 graduation topology),
  carrying the v3 profile and runner. Publication is owner-gated two-stage npm publishing — NOT
  part of this landing.
- **TypeScript signer** (`baselabs/bounded_authority_signer_typescript`, owner decision
  2026-09-20): ADOPTS the suite — v3 producing-side support (ES256 signing with low-S
  normalization, the v3 signing-input composers, uncompressed-SEC1 public-key handling). This
  repository's design keeps the encodings implementable there, and the producing side is probed
  first-hand (OBSERVED, Node probe with retained output): Node's
  `crypto.sign("SHA256", data, { key, dsaEncoding: "ieee-p1363" })` emits exactly the 64-byte
  raw `r || s` form; the JWK export is exactly `{crv, kty, x, y}` with 32-byte coordinates; the
  SEC1 raw form is `0x04 || x || y` concatenation; Node's OpenSSL, like OTP's, emits high-`s`
  about half the time — so the signer's normalization is load-bearing, not decorative.
- **Kiosk demo** ("Agent at the Kiosk", private runtime evidence tree): refresh pass joins this
  sweep per the 2026-09-20 decision — the demo moves its slip/request signing onto the signer's
  v3 public API (retiring the verifier-producer workaround recorded in project memory) and
  re-runs its self-test.
- **A2A drill (A4 residual R3)**: the sweep is the first real-substrate A2A binding evidence —
  an actual A2A server receiving `BA-Grant`/`BA-Proof` carriage per
  [a2a-capability-binding-profile.md](../../docs/design/a2a-capability-binding-profile.md) §5
  and verifying a v3 proof against the profile's binding rules (§6 `htm`/`htu`, §7 `ba_op`, §8
  projection), run against the pinned A2A source's own SDK/server surface (A2A at commit
  `afda8316`). No mock peer; no self-round-trip interop claim —
  the drill's claim is carriage-and-verification evidence under the graduated profile, recorded
  in this repository's work record and the demo's evidence tree, not an A2A-conformance claim
  (the profile's §0 non-claims govern). This resolves R3 (runtime evidence); R2 (the
  projection/`htu` conformance vectors) remains routed to its owning slice.

### 9. Registries and repo currency (charter checklist items 4–5)

- `registries.md`: the suite table gains `BAP3-ES256-SHA256` (active — the complete
  contract-major 3 profile per this ADR); the `lte`/`gte` selector rows' profile scope gains
  the v3 closed profile alongside v2's (the rows currently read "the contract-major 2 closed
  profile … (the v1 profile rejects the kind)", which this activation makes incomplete); the
  ML-DSA anticipated row's index moves to the next successor major. No claim name, `typ`
  value, or selector kind flips reserved→active in this activation — the five selector kinds
  are already active, and no reserved mechanism is activated (disclosure gate; the compliance
  section below).
- `spec/bap-v3.md` carries the suite's normative-reference substitution row (RFC 7518 §3.4 and
  §6.2.1; SEC 1 v2's uncompressed point form as profiled by RFC 5480 §2.2) alongside the
  constants table.
- Corpus tooling: `conformance/generators/build_corpus.mjs` gains the major-3 format family
  (`FORMATS_BY_MAJOR[3]` with the three `…-v3-conformance-*` format strings),
  `curated-inputs-v3.json` (n_a cell reasons + the v3 public-key fingerprint census), and the
  `--major` allowlist admits 3.
- Digest-pin rotation: `scripts/regen_corpus_digests.exs` grows the v3 pins (`@majors [1, 2, 3]`
  and the per-major pin lists — fifteen pins, five per major, after this landing) and its stale
  header comment ("rewrite all twelve constants") is corrected in the same change; the rotation
  lands in ONE commit with the certified digest (ADR 0019's atomic-landing template). The
  TypeScript runner's v3 pin rotates in the graduated repository's snapshot-bump commit.
- Repo currency: ROADMAP gains row BAP-22 with its acceptance bar and closeout evidence;
  CHANGELOG carries the entry; `mix.exs` package files and docs extras wire `spec/bap-v3.md`,
  ADR 0035, and the v3 corpus; `scripts/check_package.exs` and the hygiene-test `@roots`
  mirror the package boundary; the architecture gate pins the V3 allowances; the
  durable-identifier scanner enumerates the v3 families. The v1 and v2 profiles are NOT
  deprecated (governance deprecation policy; v1's posture is unchanged since ADR 0030 §7, and
  v2's deprecation clock depends on publication and external-implementation events this
  landing does not consume).

## Alternatives considered

- **A parallel `BAP1-ES256-SHA256`-style suite inside major 1 or 2.** Rejected: the charter,
  ADR 0009, and ADR 0026 all bind suite succession to a new contract-major; a major that
  accepted two signature algorithms would reopen algorithm substitution inside a closed profile
  (the v1 `alg` closed set exists precisely to prevent that), and ADR 0030's no-verdict-flip
  discipline forbids touching frozen majors.
- **Compressed (33-byte) raw public keys.** Rejected: compression itself is a parity bit plus a
  copy, but compressed raw keys force sqrt-mod-p DEcompression onto every consumer of the
  raw-key API for no wire effect (the wire JWK carries `x`/`y` regardless), violating the
  TS-implementability decision's spirit; the substrate's native form is uncompressed
  (OBSERVED).
- **High-S permitted (JOSE-default verification).** Rejected: leaves every valid signature
  malleable (OBSERVED: the `(r, n − s)` counterpart verifies), so observed evidence could be
  re-spelled into a second still-valid, differently-hashing encoding — breaking the
  canonical-bytes contract for every surface that digests signature-bearing bytes. The
  producing-side cost of low-S is one subtraction.
- **DER signatures on the wire.** Rejected: RFC 7518 §3.4 fixes the JWS ES256 signature as raw
  `r||s`; DER would deviate from JOSE interoperability and add a variable-length encoding the
  fixed-widths discipline would have to bound separately.
- **P-384/P-521 or Ed448 suites now.** Rejected for this activation: the bridge target is
  AP2's P-256 profile (OBSERVED); additional suites are future contract-majors under the same
  scheme — nothing here designs them.
- **Deferring the signer/kiosk/A2A cohort to a post-B1 slice.** Rejected: the owner's
  2026-09-20/2026-09-21 decisions bind them to this sweep, and the A2A drill is the named
  resolution of A4 residual R3.

## Consequences

- Contract-major 3 exists in-tree after this landing: Elixir reference (`V3` namespace),
  normative spec (`spec/bap-v3.md`), certified corpus, CLI major-keyed certification, in-repo
  SDKs' v3 namespaces, requirement map § v3, registries, changelog, and this ADR land together;
  the TS verifier's snapshot-bump and the signer/kiosk/A2A cohort land in their own repositories
  as named commits of this sweep, coordinated at corpus freeze.
- v1 and v2 are byte-frozen and proven unchanged: empty git diff over their lib/corpus trees;
  their certified pins still verify their corpora.
- An EC P-256 holder key pair can now be both the AP2 agent key and the BAP proof key — the
  §3 bridge of the AP2 interop profile is normative on the BAP side. Key-material
  correspondence is still not credential-byte compatibility (the profile's own honest bound).
- The ML-DSA anticipated index moves to successor major 4; ADR 0026 gains a dated
  reconciliation note for its stale `BAP2-*` family index; the PQ posture is otherwise
  unchanged.
- Named follow-ups (not blocking): v3 corpus depth growth beyond the v1-populated cells; the
  `spec.facts` v2 AND v3 extraction baselines (the v2 deferral is still open from ADR 0030; v3
  rides the same corpus-integrity + certified-pin + SDK-census machinery until a combined
  extraction lands); the A2A projection/`htu` conformance vectors (A4 residual R2) remain
  routed to their owning slice; the report adapter's key-type
  discriminator (B2) follows this suite; SDK publications and any v3-bearing Hex release are owner
  decisions outside this landing.

## Disclosure-gate compliance

The gate (owner-held, record outside this repository): nothing beyond published specification
text enters this repository until lifted — no `ba_dlg`/`ba_obo`/`ba_offline`/`ba_sut`/
detached-profile activation or documentation beyond existing reserved rows. This ADR complies:
the ES256 suite is not gated (owner decision 2026-09-19); reserved mechanism names appear only
in §1 and this section as the gate's own enumeration; `ba+budget-window` stays deferred exactly
as ADR 0029 records it; no reserved purpose is realized, designed, or promised here.

## See also

- [AP2 interop profile](../../docs/design/ap2-interop-profile.md) §3 — the bridge contract this
  suite realizes.
- [ADR 0009](0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) — suite
  succession and the naming scheme.
- [ADR 0030](0030-v2-contract-major-activation.md) — the contract-major activation precedent
  this landing mirrors (composition, reconciliation, wiring).
- ADR 0026 — the PQ successor statement whose anticipated index
  this activation advances.
- [ADR 0007](0007-normative-requirement-identifiers.md) — the requirement-identifier scheme
  whose surface vocabulary §6 extends.
- [ADR 0014](0014-cross-language-verifier-sdks.md)/[0015](0015-sdk-graduation-and-publish-topology.md)/
  [0017](0017-inter-sdk-behavioral-contract.md)/[0018](0018-sdk-bounds-contract.md)/
  [0019](0019-corpus-artifact-distribution.md) — the SDK contracts the cohort work satisfies.
- [successor-major charter](../../docs/design/successor-major-charter.md) — the activation
  checklist.
