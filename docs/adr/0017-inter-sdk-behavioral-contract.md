# ADR 0017: Inter-SDK behavioral contract — fail-closure, type strictness, pre-hash validation

- Status: accepted
- Date: 2026-08-17
- Track: T2
- Refines: [ADR 0014](0014-cross-language-verifier-sdks.md) (the SDK surface this contract governs),
  [ADR 0005](0005-portable-conformance-corpus-and-verifier-cli.md) (the corpus + permissiveness
  discipline this contract extends), [ADR 0003](0003-standard-jws-and-verified-grant-results.md)
  (the standard-JWS baseline the canonical-form clauses enforce)

## Context

[ADR 0014](0014-cross-language-verifier-sdks.md) defined what a verifier SDK is — packaging, support
surface, derivation hygiene, and a per-language permissiveness mutation-gate for the host-runtime
closure class (duplicate-rejecting decode, null-prototype containers, raw-lexeme scan, single-value,
int/float tags). That ADR's contract ended at "passes the corpus + the permissiveness gates."

The BAP-15 hardening arc exposed a class that contract did not cover. The Rust SDK's bounds-parity
landing (`b4ca616`) was followed by **17 dispatched cross-vendor review rounds (codex + claude peers)
plus delta-reviews between fix clusters** (`3e8524a..226e847`, 28 commits). The rounds surfaced
roughly 25 byte-level behavioral divergences between the three SDKs (and from the Elixir reference)
on surfaces the corpus had no cases for — escapes out of the closed Result API, host-type coercions,
hashing before validation, unbounded frame reads. Every named finding was fixed in-slice; the
falsifiers live in the per-SDK permissiveness batteries. Until this ADR, the shared semantics those
rounds converged on were documented only as a ROADMAP evidence amendment (#3) and CHANGELOG rows —
an ADR-grade contract with no ADR.

The primary sources this contract enforces were read first-hand for this ADR: RFC 7515 (JWS — the
signing-input definition §2/§5.1, the compact serialization §7.1, and the validation MUSTs: §5.2
step 10 "the JWS MUST be considered invalid," §10.12 "MUST be rejected in their entirety" for
trailing characters, §4 duplicate header names) and RFC 8785 (JCS — §3.2.2.2 exact string
serialization with U+007F emitted raw, §3.2.2.3 number serialization delegating to ECMA-262
§7.1.12.1, NaN/Infinity termination). [`protocol-v1.md`](../protocol-v1.md) transcribes the JCS
rules into the spec (the float thresholds, `-0` → `0`, raw DEL); the corpus pins 283 cases over 28
surfaces. Neither pins the clauses below on the SDK *input* surface — that is the gap this ADR
closes.

## Decision

The inter-SDK behavioral contract is the definition of "conformant SDK" **beyond** the corpus: it is
normative for every current SDK (Rust, TypeScript, Python) and every future SDK (Go, BAP-16) adopts
it at authoring. Conformance is claimed for the clauses as the hardening arc closed them, **with two
named exceptions this ADR's own authoring review surfaced and verified live (2026-08-17)** — both
routed as SDK-code fixes and disclosed under Honest limit below; this ADR does not certify the
exceptions away. Five clauses:

1. **Closed Result surface — no escape hatches.** Every path where a caller-supplied value could
   raise out of the SDK's closed `Ok<Facts>` / `Err(Invalid)` API fails closed instead. A host
   exception, an implicit encoding replacement, or a silent fallback is a contract breach even when
   the eventual verdict would have been `Invalid`: the closed surface IS the product (AGENTS rule 3
   fail-closed, rule 1 no execution credential). Closed in the arc: Python's `UnicodeEncodeError`
   escape on ill-formed identifier strings; TypeScript's silent U+FFFD replacement.

2. **Type strictness — no host coercion into protocol types.** Caller-supplied context is checked
   against the protocol's type shape before use, never coerced by host semantics: Boolean values in
   integer positions are rejected (`True == 1` no longer verifies — TypeScript's strict equality and
   Rust's typing already rejected them); non-string identifiers, non-integer chain values, and
   non-bytes chunk elements are gated before any arithmetic or encoding consumes them.

3. **Pre-hash validation — shape before digest.** The caller-context shape is validated BEFORE the
   digest is computed, so malformed metadata fails closed without forcing maximum-sized hashing:
   object versions (string, non-empty, UTF-8 ≤ 512 bytes, well-formed, equal across expected and
   input), the key chain (exact count; key-id in the ASCII-unreserved class with width bounds), key
   windows (integral endpoints, symmetric magnitude bounds, `valid_before > valid_from` ordering),
   chain identifier well-formedness, and — per the reference's
   `validate_expected_anchored_export` → `ContextValidation.expected_anchor`
   (`anchored_export_codec.ex:92/:356-358`) — the expected-anchor identity fields
   (`anchor_id`, `anchored_at`, `chain_id`, `key_id`). This is the DoS-shaped clause: the
   reference's bounds exist so that rejection cost never scales with attacker-controlled magnitude
   (RFC 7515's own rejection posture — §5.2/§10.12 — is total, but this protocol bounds the work to
   get there).

4. **Canonical-form byte equality + signature-width gates.** A compact JWS segment is accepted only
   if its bytes equal the exact canonical re-encoding of its decoded value — for the protected
   header and payload of boundary-anchor and key-transition compacts, per RFC 8785 §3.2.2.2/.3 (a
   reordered or non-canonical member order is rejected, not normalized). Decoded signatures are
   width-gated (`len(signature) == declared width`) at decode. The signing input is the exact
   RFC 7515 construction — `ASCII(BASE64URL(protected) || '.' || BASE64URL(payload))` — with no
   domain prefix ([ADR 0003](0003-standard-jws-and-verified-grant-results.md)).

5. **Role-bounded frame reads.** Frame reads are bounded by their role's ceiling
   (`chain_row_bytes` / `anchor_bytes`) before any walk, and key-window magnitude/ordering gates run
   before hashing. An unbounded read before a later rejection is a contract breach even if the
   verdict is `Invalid`.

**Where each clause is pinned.** The corpus pins what it has cases for; the per-SDK permissiveness
mutation-gates pin the host-specific constructions; **this ADR is the contract of record** — the
document a new SDK implements against and a reviewer diffs against, independent of whether a case
exists yet. The three-layer order is deliberate: corpus (exact bytes) > mutation-gate (host defect)
> ADR (the semantics both must eventually express).

**Honest limit, carried from the arc's terminal state.** The clauses introduced in rounds 12–17 ship
without per-clause red-capable battery legs: every gate is proven load-bearing (the arc's delta-4
mutation probe shows each round-15 defect re-emerging when its gate is removed), but a full revert
of the gate cluster still passes the SDK battery green. The per-leg pins are owed follow-up work
(maintainer-directed). This ADR records the contract; it does not claim the pin debt is paid.

**Two verified exceptions, surfaced by this ADR's own authoring review (cross-vendor, 2026-08-17)
and routed as SDK-code fixes — the ADR does not certify them away:**

1. **Python closed-Result escape (clause 1).** A non-string `request_digest` operation (or
   `ConsumptionEntry.chain_id`) raises `AttributeError` out of the public façade — the `_trying`
   wrapper catches only `InvalidError`, and `str_utf8` is a bare `s.encode("utf-8")`
   (`sdks/python/src/bounded_authority_verifier/v1.py:693-698`, `json_alg.py:532`; live-probed:
   `request_digest(123, …)` → `AttributeError`). Rust excludes the class by typing; TypeScript
   excludes it for TS callers by compile-time types (an untyped JS caller gets host string coercion
   at the `TextEncoder` boundary — a disclosed margin, not an exception escape).
2. **Expected-anchor identity validated post-digest (clause 3, all three SDKs).** The reference
   validates `anchor_id`/`anchored_at`/`key_id` pre-digest (clause 3 above); all three SDKs verify
   the anchor fields only inside the post-digest anchor-compact checks. The bounded-work property
   still holds — chunk-shape gates bound every digest — but the ordering diverges from the
   reference's pre-digest discipline.

**Resolution of exception 1 (2026-08-18, maintainer-authorized fix).** Closed in both dynamic SDKs
by a closed-Result shape gate on every façade, after a mechanical family sweep (2026-08-18, the
alignment-audit session) proved the class total rather than two-instance. Python: 31 of 34
parameter sites and every caller-supplied struct field escaped as `AttributeError`/`TypeError`
(`_trying` catches only `InvalidError`); fixed by the annotation-driven `_closed_shape` decorator
on all 17 façades (`sdks/python/src/bounded_authority_verifier/v1.py`) — each argument is validated
recursively through its dataclass fields against the declared shape (`bool` is not `int`, per
clause 2) and returns `Err` before any attribute deref, `len()`, or encode runs. TypeScript: the
"disclosed margin" above was in fact a live clause-2 breach, not a margin — an untyped caller's
`requestDigest(123/true/null/{})` was silently coerced at the `TextEncoder` boundary and returned
`Ok` with the digest of the coerced text, and 109 parameter positions threw `TypeError` past
`trying()` on null/undefined/array/object arguments; fixed by the `closedShape` gate on all 17
façades (`sdks/typescript/src/v1.ts`) — argument shapes (bytes = real `Uint8Array`, struct =
non-null object with the consumed fields, str = `typeof string`) checked before the body runs.
Rust remains excluded by static typing. Red-capable evidence: the per-SDK family-sweep batteries
(`sdks/python/tests/test_permissiveness.py`, `sdks/typescript/test/permissiveness.ts`) ARE the
pre-fix red run (Python: 237 param + 516 field probe findings; TS: 109 sweep escapes + the
coercion set), and both are mutation-proven — removing any single façade's gate reddens exactly
that façade's cases. Exception 2 below remained open at that landing; its resolution follows.

**Resolution of exception 2 (2026-08-18, maintainer-authorized fix).** Closed in all three
SDKs by hoisting the expected-struct well-formedness suite — chain (identifier, positive
range, count, hash widths, genesis), both anchors (identity: anchor_id/anchored_at/chain_id/
key_id; binding: sequence range, chain_hash/key_fingerprint widths, genesis zero-hash), and
transitions (identifiers, effective_at magnitude, key-id class, fingerprint widths +
distinctness) — to BEFORE the archive digest, mirroring the reference's
`validate_expected_anchored_export` → `ContextValidation` sequence
(`anchored_export_codec.ex:88-104`). The change is VERDICT-INVARIANT by subsumption (the
post-digest equality checks against bounded parsed values reject every malformed expected
either way) — what it fixes is the clause-3 WORK ordering: malformed caller metadata now
rejects without hashing the archive. Verification honors that invariance honestly: the
Python battery carries the behavioral proof (a monkeypatched sha256 counter asserts ZERO
hash calls on each malformed-expected rejection — pre-fix it counted 1+, mutation-proven),
while the TS and Rust batteries pin the gate ordering structurally (the hoist block must
precede the digest call site — mutation-proven in both) plus verdict-matrix regression
legs; ESM bindings and static calls give those hosts no runtime work-observation channel.

## Alternatives considered

- **Leave the contract in the ROADMAP amendment.** Rejected: an evidence amendment records what a
  slice did; it is not the artifact a future SDK author or external reviewer is sent to. Contracts
  that govern future implementations live with the other contracts, in the ADR series.
- **Grow the corpus instead — every clause becomes a case.** Partially adopted, insufficient alone:
  the corpus pins wire-level behavior on fixture inputs, but clauses 1–3 are about the SDK's
  *caller-context* surface (host types, host exceptions), which is per-language by nature — exactly
  the class ADR 0005's permissiveness discipline assigns to mutation-gates, not corpus cases.
- **Per-SDK contracts (one ADR per language).** Rejected: the semantics are shared by design; three
  documents would drift. The per-language residue is already owned by the per-SDK mutation-gates.

## Consequences

- "SDK conformance" now means: the 283-case corpus green, the per-SDK permissiveness gates green,
  AND the five clauses of this ADR holding on the caller-context surface.
- The Go SDK (BAP-16) adopts this contract at authoring rather than rediscovering it through its own
  hardening arc; its acceptance bar cites this ADR.
- A future corpus amendment may absorb cases that pin clauses of this ADR more tightly (exact-byte
  rejections); the ADR is then the semantics of record and the corpus the evidence, in the layer
  order above.
- The round-12–17 per-clause pin debt is now visible in two places (ROADMAP amendment #3's named
  residual, this ADR's honest limit) — deliberately, because it gates how much of this contract is
  mechanically falsified today versus contractually asserted.
