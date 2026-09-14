# Bounded Authority Protocol v2 Wire Profile

Document revision: rev 1 (2026-09-13). Status: normative. Contract-major 2, suite
`BAP2-Ed25519-SHA256`. This profile is activated by
[ADR 0030](../docs/adr/0030-v2-contract-major-activation.md) under the
[successor-major charter](../docs/design/successor-major-charter.md); the selector
mechanism it activates is specified by [ADR 0028](../docs/adr/0028-range-selector-kinds.md).

The v2 profile is a complete closed wire profile parallel to the frozen v1 profile
([bap-v1.md](bap-v1.md)). Conformance language, the abstract data model, JSON decoding and
canonical serialization, base64url, protected headers, claims, URI normalization, signing and
digest inputs, the consumption chain and anchored export, the public verification contract, hard
maxima, the untrusted key locator, `typ` values, and security/privacy considerations are
INCORPORATED FROM v1 BY REFERENCE with the substitutions of §2 — every such section is normative
for v2 exactly as for v1, with the named constants replaced. No section of the v1 profile is
optional, open, or best-effort in v2. Sections 3–6 state the v2-specific normative rules in
full, including the selector algebra with the two range kinds.

## 1. Suite identity and major detection {#suite}

The v2 profile's suite is `BAP2-Ed25519-SHA256`: EdDSA over Ed25519, SHA-256 digests, RFC 8785
JCS canonical bytes, and the `BAP2-*` domain separators — the same closed posture and algorithms
as `BAP1-Ed25519-SHA256` under the major-bound naming scheme `BAP<contract-major>-<signature>-<digest>`.

Every v2 artifact declares its contract-major mechanically: the payload `v` claim is exactly
integer `2`, the protected `typ` header carries the same closed values as v1, and the domain
separators are version-bound. A conforming v2 verifier detects the profile of any artifact from
its bytes alone.

Cross-major rules (`REQ2-CORE-cross-major-reject`): a v2 verifier rejects every artifact whose
payload `v` is not exactly `2` — including all v1 artifacts — with the single closed error; the
v1 profile rejects all v2 bytes symmetrically. There is no cross-major fallback, downgrade, or
best-effort parsing in either direction. A holder presents artifacts of one major end-to-end: a
v2 proof MUST pair with a v2 grant (`REQ2-EVO-proof-major-equals-grant`); mixed-major
credentials are invalid by construction (`REQ2-EVO-mixed-major-invalid`).

## 2. Substitutions incorporated from v1 {#substitutions}

For every v1 section not restated below, the normative v2 text is the v1 text with exactly
these substitutions (`REQ2-CORE-v1-incorporation`):

| v1 constant | v2 constant |
|---|---|
| `v` claim value `1` (grant, proof, boundary anchor, key transition, chain row, export header) — grants and proofs MUST carry exactly integer `2` (`REQ2-CLAIM-v`, `REQ2-CLAIM-proof-v`); anchors, transitions, rows, and the export header inherit the same substitution | `2` |
| request-digest prefix `BAP1-REQUEST\0` | `BAP2-REQUEST\0` (`REQ2-SIGNING-digest-prefix`) |
| chain-row domain `BAP1-CHAIN\0` | `BAP2-CHAIN\0` |
| archive prefix `BAP1-ARCHIVE\0EXPORT\0` | `BAP2-ARCHIVE\0EXPORT\0` |
| suite name `BAP1-Ed25519-SHA256` | `BAP2-Ed25519-SHA256` |
| selector kind set `{all, equals, one_of}` | `{all, equals, one_of, lte, gte}` (§4) |
| facts and decoded-struct `version` field `1` | `2` |

All bounds, key widths, claim member sets, header member sets, `typ` values (`ba+cap`,
`dpop+jwt`, `ba+chain-anchor`, `ba+key-transition`), and requirement cross-references to the
shared verification semantics are unchanged. The local-loopback application proof profile
(`bap-application-proof/local-loopback-http/v1`) is bound to contract-major 1; it pairs with no
v2 grant, and the v2 façade exposes no loopback functions.

## 3. Hard maxima {#maxima}

The v2 profile inherits every v1 bound unchanged (`REQ2-BOUNDS-inherited`): the ADR 0028 §4
review found that a range comparison consumes two decoder-bounded numbers and produces a boolean
— it derives no new magnitude, so no new `Bounds` member is required. The complete bound set is
the v1 §17 table, including the selector maxima restated in §5 below.

## 4. Selector algebra {#selectors}

Selectors are closed ordered objects with exactly one of three recognized member sets:
`{kind}`, `{kind,path,value}`, or `{kind,path,values}` … the member-set discipline is v1 §12
verbatim (`REQ2-SELECTOR-closed-set`), with the `kind` selecting among FIVE kinds:

<!-- facts:selector-kinds -->
| Kind | Recognized members and interpretation |
|---|---|
| all | Any recognized member set; `path`, `value`, and `values` are inert when present |
| equals | Exactly `{kind: "equals", path: path, value: JSON_value}` |
| one-of | Exactly `{kind: "one_of", path: path, values: non_empty_JSON_array}` |
| lte | Exactly `{kind: "lte", path: path, value: numeric_bound}` — the value at `path` must be same-tag numeric and numerically ≤ `bound` (inclusive) |
| gte | Exactly `{kind: "gte", path: path, value: numeric_bound}` — the value at `path` must be same-tag numeric and numerically ≥ `bound` (inclusive) |

Range-kind rules (`REQ2-SELECTOR-range-same-tag`, `REQ2-SELECTOR-range-inclusive`,
`REQ2-SELECTOR-range-numeric`):

- Both operands — the traversed value at `path` and the bound in `value` — MUST carry the same
  numeric tag: both integer-tagged or both float-tagged. A cross-tag pair does not match; it
  fails closed exactly as `equals` never collapses tags. This extends the v1
  no-tag-collapse invariant from identity to ordering.
- Comparison is by numeric value on the closed numeric domain the bounded decoder admits
  (integers and floats within ±9007199254740991). Under IEEE 754 numeric comparison −0.0 = 0.0;
  because RFC 8785 serializes both as `0` (the ECMAScript `Number::toString` rule), signed zero
  distinguishes no authority in either the comparison or the canonical bytes, and a zero-valued
  operand re-derives from the wire with the integer tag (`REQ2-SELECTOR-range-signed-zero`).
- By the same serialization rule, an integral-valued float bound (e.g. `10.0`) canonicalizes to
  `10` and decodes back integer-tagged: float-tagged bounds are wire-distinguishable only when
  non-integral. Issuers therefore express integer bounds as integers; the tag carries the
  operand domain, not a unit.
- Non-numeric operands fail closed: a `string`, `boolean`, `null`, `array`, or `object` value at
  the path never satisfies a range selector, and a non-numeric `value` member makes the whole
  grant `{:error, :invalid}` at decode (`REQ2-SELECTOR-range-numeric`). A missing path
  member fails closed exactly as for `equals`/`one_of`
  (`REQ2-SELECTOR-range-path-required`).
- An interval is the CONJUNCTIVE COMPOSITION of two one-sided selectors on the same path
  (`{gte, path, lo}` + `{lte, path, hi}`), exactly as any other conjunction composes. There is
  no compound `range` kind. Crossed endpoints (lo > hi) are not a special error: the
  conjunction is unsatisfiable and never matches (`REQ2-SELECTOR-range-interval`).
- Strict kinds (`lt`, `gt`) do not exist and are excluded permanently
  (`REQ2-SELECTOR-no-strict-kinds`): on integers a strict bound is derivable (`amount < 100` ≡
  `amount ≤ 99`), and no authority-named mandate requires a strict float bound.

Path discipline is identical to `equals`/`one_of` (`REQ2-SELECTOR-path-shape`): 1–32
object-member names, 1–128 UTF-8 bytes each, object traversal only, never array indexing. An
operation carries 1–64 selectors unchanged (`REQ2-SELECTOR-count`). Selector matching is
verdict-internal: the standalone grant verification checks signature, issuer, audience, and
times only, and never evaluates selectors (`REQ2-SELECTOR-verdict-internal`). Facts are
unchanged — a range bound is a payload magnitude read from the decoded grant of the same
verified bytes, never a fact, and no selector grants business authorization
(`REQ2-SELECTOR-not-authorization`).

Attenuation (when a successor major activates delegation) composes conjunctively over selector
tuples and never inspects kind; the new kinds are new tuple inhabitants of the existing algebra,
and a child that adds a cross-tag conjunct produces an unsatisfiable conjunction — fail closed,
never a widening (`REQ2-SELECTOR-attenuation-unchanged`).

## 5. Requirement identifiers

The v2 profile carries its own `REQ2-*` range per
[ADR 0007](../docs/adr/0007-normative-requirement-identifiers.md); `REQ1-*` ids remain bound to
the v1 profile and never apply to v2 behavior. The v2 MUST-to-cell traceability lives in the
[requirement map](../docs/design/requirement-map.md) § v2.

## 6. Conformance corpus

The v2 conformance corpus is a certified artifact with its own identity
(`priv/conformance/v2/corpus`, 268 cases across the 28 surfaces, 16 classes, revision 1). Its
certified index SHA-256 is pinned in the verifier CLI and every SDK runner exactly as the v1
corpus is (ADR 0014 D4). Version-neutral primitive surfaces (JSON/JCS/base64url/JWK/URI/bounds)
execute the same shared implementations the v1 corpus certifies, and their cases are carried
into the v2 corpus byte-for-byte; the profile-bound surfaces carry v2-minted fixtures, the full
range-selector applicability classes, and cross-major rejection vectors. Signed fixtures were
minted with ephemeral in-memory Ed25519 keys; no private material is tracked
(`REQ2-CORPUS-certified-identity`).
