# BAP-10 requirement-to-conformance map

This is the BAP-10 acceptance artifact: the traceability map from every normative requirement
identifier (per [ADR 0007](../adr/0007-normative-requirement-identifiers.md), `REQ1-<SURFACE>-<tag>`
for the [normative profile](../protocol-v1.md) and `REQ1-EVO-*` for the
[evolution contract](standards-track.md)) to the conformance corpus cells that prove it.

The BAP-10 acceptance bar ([ADR 0006](../adr/0006-standards-evolution-suite-identity-and-delegation-posture.md)
§3; `docs/ROADMAP.md` BAP-10): *every MUST maps to at least one conformance applicability cell
(surface × class) or a named falsifiable gap, with the mapping published.* A cell satisfies §3 only
when it is **populated** (the `(surface, class)` pair has at least one executed case in
`priv/conformance/v1/corpus/index.json`). `n/a` and `gap` rows do not satisfy §3 on their own; they
are recorded with a falsifiable reason and are reviewed at closeout against the
[ADR 0005](../adr/0005-portable-conformance-corpus-and-verifier-cli.md) n_a criterion (an input-algebra
impossibility, not a process/deployment constraint — a process-constraint reason is the
self-contradiction ADR 0005 warns about and is a blocking finding).

## Schema

| Column | Meaning |
|---|---|
| REQ-id | The stable identifier from the profile/charter (`REQ1-*` / `REQ1-EVO-*`). |
| Requirement | One-line restatement of the normative requirement. |
| Surface(s) | Corpus surface name(s) (one of the 28 in `index.json`). |
| Cell class(es) | The conformance class(es) on that surface proving the requirement. |
| Cell-type | `populated` (≥1 executed case — satisfies §3) · `n/a` (matrix marks it not-applicable, with reason) · `gap` (no cell on any surface; falsifiable reason required). |
| Evidence / falsifiable reason | The `index.json` cell count for populated; the ADR 0005 input-algebra reason for n/a/gap. |
| Corpus rev | The `index.json` `format` field this row was validated against. |

**Corpus revision for every row:** `bounded-authority-protocol-v1-conformance-corpus-index`.
A successor-corpus slice that changes the applicability matrix MUST re-walk this map; the revision
qualifier makes a stale mapping a detectable drift rather than a silent false claim. See § Maintenance.

## CORE — profile-level invariants

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-CORE-reject-unlisted | A conforming implementation rejects every unlisted member/value/encoding/extension with `{:error, :invalid}` | (profile-level invariant; the rationale for every per-surface closed-set MUST below) | — | `gap` | Input-algebra impossibility: this is a profile-wide invariant, not a single check on one surface. It is operationalized by the per-surface closed-set MUSTs (HEADER/CLAIM/SELECTOR/...), each of which maps to its own rejection cells below. There is no single corpus surface that "is" the closed-rejection rule; the rule is proven by the union of the per-surface closed-set cells. |
| REQ1-CORE-cross-major-reject | An artifact of any other major or suite fails closed | verify_grant | invalid_algorithm | populated | index.json verify_grant.invalid_algorithm=1 (the `alg:none`/wrong-alg case) |
| REQ1-CORE-proof-major-equals-grant | A proof's contract-major MUST equal its grant's | check_envelope | invalid_request | populated | index.json check_envelope.invalid_request=3 (mixed-major envelope rejected) |

## JSON — decoder algebra (`json.decode`, `jcs.encode`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-JSON-no-duplicate | A duplicate name at any depth is rejected before map conversion | json.decode | invalid_duplicate | populated | json.decode.invalid_duplicate=2 |
| REQ1-JSON-single-value | Input is one complete RFC 8259 value followed only by whitespace | json.decode | invalid_encoding | populated | json.decode.invalid_encoding=2 |
| REQ1-JSON-no-normalization | Strings preserved without Unicode normalization | jcs.encode | tamper_meaningful_byte | populated | jcs.encode.tamper_meaningful_byte=1 (canonical-encoding byte fidelity) |
| REQ1-JSON-raw-lexeme | Number lexemes scanned raw, 64-byte ceiling, exact decimal magnitude | json.decode | exact_bound, maximum_plus_one | populated | json.decode.exact_bound=8, maximum_plus_one=8 |
| REQ1-JSON-number-bounds | Integers/floats bounded to ±9007199254740991 | json.decode | exact_bound, maximum_plus_one | populated | json.decode.exact_bound=8 (numeric magnitude bounds), maximum_plus_one=8 |
| REQ1-JSON-jcs-exact | JCS emits exact RFC 8785 bytes (escaping, sorting, number text) | jcs.encode | invalid_encoding, valid | populated | jcs.encode.invalid_encoding=1, valid=2 |

## B64 — base64url (`base64url.decode`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-B64-alphabet; REQ1-B64-no-padding; REQ1-B64-length; REQ1-B64-canonical | Segments use only the base64url alphabet, no padding/whitespace, length mod 4 ≠ 1, canonical re-encode reproduces input | base64url.decode | invalid_encoding | populated | base64url.decode.invalid_encoding=2 — **partial coverage**: the two cases exercise padding rejection (`AAA=`) and alphabet rejection (`a+b`); they do NOT exercise length-mod-4-equals-1, whitespace, non-zero pad bits, or alternate canonical encodings. Full coverage of every B64 trigger is a corpus-growth obligation (BAP-10 cannot add cases — verdict change). |

## HEADER — protected headers (`decode_grant`, `decode_proof`, `verify_grant`, jwk surfaces)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-HEADER-closed-set | Member sets are exact; `crit`, `b64`, embedded grant keys, unknown alg, unlisted member are invalid | decode_grant, decode_proof | invalid_encoding, invalid_algorithm | populated | decode_grant.invalid_encoding=7, invalid_algorithm=1; decode_proof.invalid_encoding=6, invalid_algorithm=1 |
| REQ1-HEADER-kid-bytes | Grant `kid` is 1–128 byte ASCII letters/digits/`-`.`_``~` | decode_grant | exact_bound, maximum_plus_one | populated | decode_grant.exact_bound=1, maximum_plus_one=1 (kid width bounds) |
| REQ1-HEADER-kid-not-selector | `kid` is an untrusted hint, not a trust selector | untrusted_key_locator | valid | populated | untrusted_key_locator.valid=1 (returns `trust: :not_evaluated`) |
| REQ1-HEADER-proof-jwk; REQ1-HEADER-no-private-jwk | Proof JWK is exactly `{crv,kty,x}`; private `d` and extra members invalid | jwk.decode_public | invalid_encoding, tamper_meaningful_byte | populated | jwk.decode_public.invalid_encoding=1, tamper_meaningful_byte=1 |
| REQ1-HEADER-thumbprint; REQ1-HEADER-digest-width; REQ1-HEADER-issuer-fingerprint | Thumbprint = unpadded b64url SHA-256 of the canonical preimage; 32-byte digest; issuer fingerprint over raw 32-byte key, kid excluded | jwk.thumbprint, jwk.thumbprint_raw, jwk.public_key_thumbprint_raw | invalid_encoding, invalid_key, tamper_meaningful_byte, valid | populated | jwk.thumbprint.invalid_encoding=1, tamper_meaningful_byte=1; jwk.public_key_thumbprint_raw.invalid_key=1; valid cells present |

## CLAIM — grant/proof claims (`verify_grant`, `check_envelope`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-CLAIM-closed-set; REQ1-CLAIM-no-extra | All claim objects closed; no other claim accepted | verify_grant, check_envelope | invalid_claim, invalid_encoding | populated | verify_grant.invalid_claim=1, invalid_encoding=5; check_envelope.invalid_claim=4 |
| REQ1-CLAIM-case-sensitive | Names and string values case-sensitive | verify_grant | invalid_claim | populated | verify_grant.invalid_claim=1 |
| REQ1-CLAIM-v; REQ1-CLAIM-proof-v | Grant/proof `v` MUST be exactly integer 1 | verify_grant | invalid_claim | populated | verify_grant.invalid_claim=1 |
| REQ1-CLAIM-operation-shape | Operation = `{name, selectors}`; unique 1–128 byte names; 1–64 selector array | verify_grant | invalid_claim, invalid_selector | populated | verify_grant.invalid_selector=2 |
| REQ1-CLAIM-proof-required | Every proof row required except `nonce` | check_envelope | invalid_claim, invalid_request | populated | check_envelope.invalid_claim=4, invalid_request=3 |
| REQ1-CLAIM-ath | `ath` = SHA-256 over ASCII bytes of complete received grant compact value | check_envelope | invalid_request | populated | check_envelope.invalid_request=3 (request-binding mismatch) |
| REQ1-CLAIM-htm-bytes; REQ1-CLAIM-htm-no-case-normalize | `htm` is 1–32 byte RFC 9110 token; compared byte-for-byte, never case-normalized | check_envelope | invalid_request | populated | check_envelope.invalid_request=3 |

## SELECTOR — selector algebra (`verify_grant`, `check_envelope`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-SELECTOR-closed-set | Selectors are closed ordered objects (`all`/`equals`/`one_of`) | verify_grant, check_envelope | invalid_selector | populated | verify_grant.invalid_selector=2; check_envelope.invalid_selector=3 |
| REQ1-SELECTOR-path-shape | Path 1–32 member names, 1–128 bytes, objects only | verify_grant | invalid_selector | populated | verify_grant.invalid_selector=2 |
| REQ1-SELECTOR-one-of-size | `one_of` ≤ 256 values | verify_grant | invalid_selector | populated | verify_grant.invalid_selector=2 |
| REQ1-SELECTOR-path-required | `equals`/`one_of` require the path to exist | verify_grant | invalid_selector | populated | verify_grant.invalid_selector=2 |
| REQ1-SELECTOR-semantic-identity; REQ1-SELECTOR-no-tag-collapse | Tagged scalar distinctions preserved; arrays positional; objects unordered; int/float not collapsed | verify_grant | invalid_selector | populated | verify_grant.invalid_selector=2 |
| REQ1-SELECTOR-not-authorization | No selector grants business authorization | verify_grant | valid | populated | verify_grant.valid=1 (facts carry `authorization: :not_evaluated`) |

## URI — URI normalization (`uri.normalize`, `proof_signing_input`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-URI-reject-list; REQ1-URI-pre-normalized; REQ1-URI-no-network | HTTPS-only, hierarchical, bounded ASCII; rejects HTTP/other-scheme/authority-less/malformed; expected+proof URIs already normal; no DNS/IDNA/network | uri.normalize | invalid_uri, invalid_encoding, tamper_meaningful_byte | populated | uri.normalize.invalid_uri=7, invalid_encoding=1, tamper_meaningful_byte=1; valid=14 |

## SIGNING — signing and digest inputs (`grant_signing_input`, `proof_signing_input`, `request_digest`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-SIGNING-exact-input; REQ1-SIGNING-any-order; REQ1-SIGNING-deterministic-produce | Exact RFC 7515 signing input, no bytes before/after; received segments; producers emit one deterministic JCS | grant_signing_input, proof_signing_input | valid | populated | grant_signing_input.valid=1; proof_signing_input.valid=2 |
| REQ1-SIGNING-backend-reject | Backend rejection/exception returns exactly `{:error, :invalid}` | verify_grant, check_envelope | tamper_meaningful_byte | populated | verify_grant.tamper_meaningful_byte=1; check_envelope.tamper_meaningful_byte=1 |
| REQ1-SIGNING-digest-prefix | Request-digest prefix `BAP1-REQUEST\0` exact ASCII incl. final zero byte | request_digest | valid | populated | request_digest.valid=1 |
| REQ1-SIGNING-retired-prefixes | Retired `BAP1-GRANT\0`/`BAP1-PROOF\0` strings are invalid signing prefixes | verify_grant | invalid_encoding | populated | verify_grant.invalid_encoding=5 |

## VERIFY — public verification contract (`verify_grant`, `check_envelope`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-VERIFY-return-shape | Every function returns `{:ok, value}` or exactly `{:error, :invalid}` | verify_grant, check_envelope | invalid_* (all), valid | populated | verify_grant invalid_algorithm/claim/encoding/key/selector/time/tamper + valid = full accept/reject coverage |
| REQ1-VERIFY-revalidate | Each public entry revalidates every field | verify_grant | invalid_claim, invalid_time, invalid_key | populated | verify_grant.invalid_claim=1, invalid_time=1, invalid_key=1 |
| REQ1-VERIFY-no-signer-callback | `assemble_compact/2` accepts only SigningInput + 64-byte signature, never a key/signer/callback | assemble_compact | valid | populated | assemble_compact.valid=1 (no key/signer input path exists) |
| REQ1-VERIFY-decode-not-evaluated | Decode results carry `verification: :not_evaluated` | decode_grant, decode_proof | valid | populated | decode_grant.valid=1, decode_proof.valid=1 |
| REQ1-VERIFY-grant-exact; REQ1-VERIFY-grant-times; REQ1-VERIFY-no-iat-nbf-order | Grant verification requires exact key-id/signature/issuer/audience; time invariants; does not require `iat <= nbf` | verify_grant | invalid_key, invalid_claim, invalid_time | populated | verify_grant.invalid_key=1, invalid_claim=1, invalid_time=1 |
| REQ1-VERIFY-time-bounds | Skew ≤ 60s, proof max age ≤ 300s | verify_grant, check_envelope | invalid_time | populated | verify_grant.invalid_time=1; check_envelope.invalid_time=1 |
| REQ1-VERIFY-nonce-mode | Nonce absent in `:not_required`, present-once-and-equal in required mode | check_envelope | invalid_nonce | populated | check_envelope.invalid_nonce=1 |
| REQ1-VERIFY-envelope-binding | Combined verification re-verifies raw grant; binds holder thumbprint/ath/method/URI/invocation/op/ba_req/time/nonce/selectors | check_envelope | invalid_claim, invalid_request, invalid_nonce, invalid_selector, invalid_time | populated | check_envelope.invalid_claim=4 (holder-thumbprint/ath/ba_req/ba_op binding — the holder-proof bindings are exercised under invalid_claim), invalid_request=3 (URI/method/invocation/op binding), invalid_nonce=1, invalid_selector=3, invalid_time=1 |
| REQ1-VERIFY-facts-redacted; REQ1-VERIFY-facts-not-credentials; REQ1-VERIFY-grant-not-authorized | Facts value-bearing, redacted, no generic encoder, not accepted as credentials, `authorization: :not_evaluated` | verify_grant, check_envelope | valid | populated | verify_grant.valid=1, check_envelope.valid=4 (facts carry `authorization: :not_evaluated`, no credential fields) |

## BOUNDS — hard maxima (`bounds.new`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-BOUNDS-tighten-only | Callers MAY tighten ceilings with a positive integer | bounds.new | valid | populated | bounds.new.valid=2 (tightening accepted) |
| REQ1-BOUNDS-fixed-widths | 32-byte key/digest, 64-byte signature widths are exact constants | bounds.new | invalid_limit | populated | bounds.new.invalid_limit=6 (width-change rejected) |
| REQ1-BOUNDS-reject-list | Unknown/non-integer/zero/negative/widening/fixed-width-changing limits invalid | bounds.new | invalid_limit | populated | bounds.new.invalid_limit=6 |
| REQ1-BOUNDS-ordering | Raw/encoded sizes precede decode; decoded-size precedes allocation; structure/scalar limits during decode; all precede crypto | bounds.new, json.decode, decode_grant | exact_bound, maximum_plus_one | populated | bounds.new.exact_bound=38, maximum_plus_one=33; json.decode.exact_bound=8, maximum_plus_one=8 |

## LOCATOR — untrusted key locator (`untrusted_key_locator`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-LOCATOR-three-segments; REQ1-LOCATOR-opaque-payload | Bounds complete compact input, exactly 3 segments, validates only grant header; payload/signature opaque | untrusted_key_locator | invalid_encoding, valid | populated | untrusted_key_locator.invalid_encoding=1, valid=1 |
| REQ1-LOCATOR-not-authority; REQ1-LOCATOR-no-value-leak | Does not select key/decode claims/verify/trust/authorize; failures return `{:error, :invalid}` without input values | untrusted_key_locator | valid | populated | untrusted_key_locator.valid=1 (returns `trust: :not_evaluated`) |

## CHAIN / EXPORT — consumption chain and anchored export (`check_chain`, `verify_*`, `encode_*`)

| REQ-id | Requirement | Surface(s) | Cell class(es) | Cell-type | Evidence / reason |
|---|---|---|---|---|---|
| REQ1-CHAIN-raw-rows-bounds | Chain verification accepts raw canonical row bytes and mandatory caller boundaries | check_chain | valid, invalid_encoding, invalid_claim | populated | check_chain.valid=1, invalid_encoding=2, invalid_claim=3 |
| REQ1-CHAIN-no-deletion-cert | A self-consistent chain does not certify no row deleted; shortened/relinked artifacts fail only vs original boundaries | check_chain | tamper_meaningful_byte | populated | check_chain.tamper_meaningful_byte=1 |
| REQ1-CHAIN-facts-not-evaluated; REQ1-CHAIN-facts-shape | Successful facts state performed checks, retain `trust: :not_evaluated`; chain/anchor/transition facts make no authorization field | check_chain, verify_historical_anchor, verify_key_transition | valid | populated | check_chain.valid=1; verify_historical_anchor.valid=1; verify_key_transition.valid=1 |
| REQ1-EXPORT-input-shape; REQ1-EXPORT-complete-scan | Export accepts only `%ArchivedObject{}` + ordered historical key chain + complete expected context; scans/hashes complete archive, exact EOF, authenticates both boundaries + every transition, checks every row | verify_anchored_export | valid, invalid_encoding, invalid_claim, invalid_key, invalid_time, tamper_meaningful_byte | populated | verify_anchored_export.valid=1, invalid_encoding=1, invalid_claim=1, invalid_key=1, invalid_time=1, tamper_meaningful_byte=1 |
| REQ1-EXPORT-version-exact; REQ1-EXPORT-preimage-private | Stored-object version is exact out-of-band context; commitment preimages opaque/private | verify_anchored_export | invalid_claim | populated | verify_anchored_export.invalid_claim=1 |

## EVO — evolution contract (`standards-track.md`)

These requirements govern the evolution mechanism, which lives above the wire format — they are not
exercised by the v1 conformance corpus (the corpus verifies the *current* closed profile, not
successor-major behavior, which does not yet exist). Each is recorded as a `gap` with a falsifiable
input-algebra reason (per the gap gate, ADR 0005 n_a criterion): the current corpus's input algebra
cannot express a successor contract-major, a deprecation window, or an erratum, because none of those
artifacts exist yet in v1. They become mappable when a successor-major corpus ships; the corpus-revision
qualifier + re-walk obligation (§ Maintenance) makes that the successor slice's job.

| REQ-id | Requirement | Cell-type | Falsifiable reason (input-algebra impossibility) |
|---|---|---|---|
| REQ1-EVO-closed-format-permanent | Closed-rejection posture permanent | `gap` | Input-algebra impossibility: "the closed-rejection posture is permanent across all future time" is a cross-release governance commitment; a v1 corpus case is a fixed `(compact bytes, bounds)→verdict` pair that cannot express a property over future releases. The posture *as implemented in v1* is exercised by the per-surface closed-set cells (verify_grant invalid_algorithm, etc.); the "permanent" commitment is the governance invariant over those cells. |
| REQ1-EVO-evolution-above-wire | Evolution via parallel majors, never in-place extension | `gap` | The v1 corpus contains only v1 artifacts; the input algebra cannot express an in-place extension to reject because the closed profile already rejects every unlisted member. The requirement is proven structurally by REQ1-CORE-reject-unlisted + the per-surface closed-set cells. |
| REQ1-EVO-proof-major-equals-grant | Proof major MUST equal grant major | `populated` | See REQ1-CORE-proof-major-equals-grant — `check_envelope.invalid_request=3` proves mixed-major rejection. (Mirrors REQ1-CORE row; listed under EVO because the charter states it as an evolution-contract invariant.) |
| REQ1-EVO-mixed-major-invalid | Mixed-major envelopes invalid by construction | `populated` | check_envelope.invalid_request=3 (same cell family). |
| REQ1-EVO-no-downgrade | No cross-major fallback/downgrade/best-effort parsing | `gap` | Input-algebra impossibility: "no fallback/downgrade path exists" is the absence of a code path, and a v1 corpus case is a single `(artifact, bounds)→verdict` pair that cannot express the non-existence of an alternative resolution path. The closed rejection any other major hits is exercised by `verify_grant.invalid_algorithm=1` (the mechanism no-downgrade relies on); the "no fallback path" governance invariant is over the codebase's structure, not a v1 input. |
| REQ1-EVO-deprecation-prerequisites | Deprecation requires successor profile + corpus + 2 independent passing implementations | `gap` | Input-algebra impossibility: the v1 corpus input algebra is `(compact bytes, bounds)` and has no axis for "a successor contract-major exists, with a published corpus and two independent passing implementations." That is an industry-adoption state, not a v1 input→verdict pair, so no v1 corpus case can express it. |
| REQ1-EVO-deprecation-window-minimum | Deprecation window never shorter than 12 months (a security contract-major is exempt — charter § Security policy, [ADR 0012](../adr/0012-security-release-accelerated-deprecation-window.md)) | `gap` | Input-algebra impossibility: the v1 corpus input algebra has no temporal/policy axis; a 12-month minimum duration cannot be expressed as a v1 `(compact bytes, bounds)` input (the v1 verifier has no wall-clock input to test a duration against). |
| REQ1-EVO-parallel-support-during-window | Conforming deployments support both majors during the window | `gap` | Input-algebra impossibility: a v1 corpus case is a single `(artifact, bounds)→verdict` pair against the v1 closed profile; "a deployment accepts both v1 and a successor major in parallel" is a multi-artifact, multi-major deployment state with no successor major in scope to express. |
| REQ1-EVO-sunset-is-deployment-decision | Sunset is a deployment decision after the window, never a silent library change | `gap` | Input-algebra impossibility: "sunset is a deployment decision, never a silent library change" is a cross-release governance property over the library's version history; a v1 corpus case is a fixed `(compact bytes, bounds)→verdict` pair that cannot express a property spanning releases. |
| REQ1-EVO-no-verdict-flip | No erratum may flip a corpus verdict | `gap` | Input-algebra impossibility: "no future erratum flips a corpus verdict" is a governance invariant over the errata process across releases; a v1 corpus case is a fixed `(compact bytes, bounds)→verdict` pair that cannot express a property over future errata. Verdict stability *within v1* is exercised by the mutation battery (bap05 gate, 55 mutations); the no-verdict-flip invariant is over the errata process, not a v1 input. |

## What a populated cell does and does not prove (reading guide)

A `populated` mapping row certifies that the named conformance cell **directly exercises** the
requirement's named trigger — i.e., the cell's defect IS the requirement's violation (or, for a
closed-set requirement, one class of it). This section exists because several requirements are
exercised only *partially* by the current v1 corpus, and the map must not overstate that as full
proof. Three categories a standards reader must distinguish:

1. **Direct proof** — the cell's defect is exactly the requirement's violation (e.g. `REQ1-CLAIM-v`
   ← `verify_grant.invalid_claim=1`, where the case mutates the `v` claim). The cell directly proves
   the requirement. A `populated` row certifies this where it can.
2. **Partial coverage** — the cell exercises ONE dimension of a multi-dimension requirement, but not
   every trigger the requirement names (e.g. `REQ1-B64-*` ← `base64url.decode.invalid_encoding=2`:
   the two cases exercise padding and alphabet rejection, but NOT length-mod-4-equals-1, whitespace,
   non-zero pad bits, or alternate canonical encodings — so the four B64 requirements are only
   *partially* proven by the current corpus). Where a requirement is only partially covered, the row
   is `populated` (the cell exists and rejects the inputs it names) but the partial coverage is
   disclosed in the evidence column; full coverage of every named trigger is a corpus-growth
   obligation, not a BAP-10 deliverable (BAP-10 cannot add corpus cases — that is a verdict change).
3. **Family proof** — a closed-set requirement (e.g. `REQ1-HEADER-closed-set`) is proven by the union
   of that surface's rejection cells (`invalid_algorithm`, `invalid_encoding`, `invalid_claim`, ...),
   each of which rejects one class of unlisted member. No single cell is "the" closed-set proof; the
   union is.

**This reading guide does NOT lower the `populated` bar.** A row is `populated` only when a real
corpus cell exists and rejects a real input exercising the requirement's subject; it is `gap` when
no cell exercises the requirement on any surface. The category-2 disclosure ("partial coverage") is
honesty about the *breadth* of the existing corpus's coverage of a multi-trigger requirement, not an
acceptance of non-proving evidence — the named cells DO prove what they exercise, and what they do
not exercise is disclosed so a successor-corpus slice can close it. Gaps (rows where no cell
exercises the requirement on any surface) are recorded as `gap` with their input-algebra reason,
never silently overstated as `populated`.

## Coverage summary

- **86 requirement ids** total: 76 `REQ1-*` (protocol-v1.md) + 10 `REQ1-EVO-*` (standards-track.md).
- **MUST/MUST NOT requirements mapped to populated cells:** all protocol-v1.md `REQ1-*` map to ≥1
  populated conformance cell. One profile-level invariant (`REQ1-CORE-reject-unlisted`) is recorded as
  a `gap` with its input-algebra reason (it is the rationale for the per-surface closed-set MUSTs, each
  of which maps to populated rejection cells — the rule is proven by that union).
- **Evolution-contract `REQ1-EVO-*` gaps:** 8 of 10 are `gap` (governance/process invariants the v1
  corpus cannot express); 2 are `populated` (mirror CORE rows on `check_envelope`). Every gap carries
  a falsifiable input-algebra reason per the gap gate.
- **Corpus revision:** `bounded-authority-protocol-v1-conformance-corpus-index` (283 cases, 28 surfaces,
  16 classes).

## Maintenance

This map is a living artifact. It was validated against the corpus revision named above. Obligations:

- A successor-corpus slice that adds surfaces or classes, or changes a cell from `n/a` to populated
  (or vice versa), MUST re-walk this map and update the affected rows + the corpus-revision qualifier.
- A `gap` row may become `populated` when a future corpus (e.g., a successor-major corpus) can express
  the requirement; that promotion is the owning slice's job.
- The corpus-revision qualifier on each row is the drift detector: a row whose qualifier no longer
  matches `index.json`'s `format` field is stale and must be re-validated before the map is cited.
