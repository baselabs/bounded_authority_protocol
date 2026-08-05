# ADR 0010: Delegation with attenuation

- Status: accepted
- Date: 2026-08-05
- Track: T2

## Context

The current contract-major binds one holder per grant, deliberately
([protocol-v1.md](../protocol-v1.md) § Claims; `cnf.jkt` is a single holder thumbprint).
Multi-agent topologies sub-delegate — a planner spawns workers, each needing a narrower
capability than its parent. [ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md)
§5 decided the delegation SHAPE in charter prose:

> The successor contract-major's delegation shape is chained attenuated grants: each link a
> signed grant issued by the parent's holder, bound by parent-grant hash (`ba_dlg`),
> attenuation-only and mechanically checkable (operations subset, conjunctive selector
> narrowing, window/audience containment), no caveat DSL — the closed selector algebra is the
> attenuation language. The current major remains single-holder.

ADR 0006 §5 committed to the DIRECTION and reserved the names (`ba_dlg`, `ba+cap-delegated`,
[ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §4); this ADR
carries the MECHANISM to spec quality — claim schema, chain-verification algorithm with depth
bounds, and the attenuation subset rules, with attenuation proven decidable against the existing
selector algebra. This is the same division as [ADR 0009](0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md),
which carried ADR 0006 §2's suite-succession direction to ADR-quality mechanism.

Activation of any of this is a successor-contract-major concern; the current major stays
single-holder and the closed profile rejects every reserved name this ADR references. The
[standards track charter](../design/standards-track.md) § Delegation with attenuation is the
charter statement; this ADR is its specification.

## Decision

### 1. The `ba_dlg` claim — parent-grant-hash binding

A delegation link is bound to its parent by `ba_dlg`, a grant payload claim carrying the SHA-256
hash of the PARENT grant's complete compact-JWS bytes, encoded as canonical unpadded base64url
(the same encoding/type `ath` uses, [protocol-v1.md](../protocol-v1.md) § Claims — the
`ath, ba_req | canonical unpadded base64url SHA-256` row). The
construction mirrors `ath` exactly: `ath` binds a proof to its grant by hashing the grant's
compact bytes ([protocol-v1.md](../protocol-v1.md) § Claims — the "`ath` is SHA-256 over the
ASCII bytes of the complete received grant compact value" sentence); `ba_dlg` binds a child
grant to its parent by hashing the parent's compact bytes.

- `ba_dlg` is REQUIRED exactly once on `ba+cap-delegated` grants.
- `ba_dlg` MUST be absent on `ba+cap` roots (a root has no parent).

Verification re-derives the parent's hash and compares it to the child's `ba_dlg`. The comparison
is RAW-to-RAW: the verifier base64url-decodes `ba_dlg` to 32 raw bytes and compares against the
raw SHA-256 of the parent's compact bytes (computed by the raw-digest variant,
`CompactJws.hash/2` at `compact_jws.ex:61-66`), in constant time. This mirrors how today's `ath`
check compares raw-to-raw (`runtime.ex:482-484`: the proof decodes `ath` from base64url to raw at
`runtime.ex:342-343`, re-derives the raw grant hash, and `secure_equal?`s them). The base64url
*encoding* of the claim value is the wire shape; the *comparison* is over raw bytes, never
raw-vs-encoded. (A draft of this design compared a decoded raw `ba_dlg` against `CompactJws.ath/2`,
which returns base64url — a type incoherence that would always fail closed. It was caught in the
BAP-14 design-adversarial review and corrected to the raw-digest variant.)

### 2. The `ba+cap-delegated` typ and the parent-holder key binding

The successor-major's `ba+cap-delegated` typ (reserved now in
[registries.md](../design/registries.md)) is the compact-JWS `typ` for a delegated (attenuated)
grant. A delegation link's signer is the PARENT grant's holder, so the child grant must carry
its signing key for the chain to verify.

The current grant carries the holder only as a THUMBPRINT: `cnf.jkt` is a 32-byte SHA-256 digest
over the holder's JWK preimage (`runtime.ex:296-298`), NOT a public key, and `Grant.t()`
(`grant.ex:6-17`) carries no holder public key and no holder principal identifier (`iss` is the
issuer). Today's verifier recovers the holder key from the PROOF `jwk` header (`runtime.ex:324`)
and binds proof→grant-holder by checking `thumbprint(proof.jwk) == grant.cnf.jkt`. A signature
cannot be verified "under a thumbprint" — Ed25519 verify requires the 32-byte public key.

The successor-major `ba+cap-delegated` grant therefore carries its issuer (= parent-holder)
public key in its PROTECTED HEADER `jwk`, mirroring exactly how today's `dpop+jwt` proof carries
its holder key in its protected header `jwk` (`runtime.ex:324`). The closed `ba+cap` grant header
is exactly `{alg, kid, typ}` with no `jwk` (`runtime.ex:279-281`); only `ba+cap-delegated`, which
is reserved-and-rejected today, gains the header `jwk` in the successor major. The verifier binds
the link:

```text
Jwk.thumbprint_raw(G_i.header.jwk) == G_{i-1}.payload.cnf.jkt   # the parent named THIS holder
ed25519_verify(G_i.signature, G_i.signing_input, G_i.header.jwk.public_key)
```

A holder PRINCIPAL identifier is NOT carried by the current grant and is NOT invented here. Link
identity is established by the cryptographic key binding above; any `ba_obo`/principal binding is
the separately-reserved successor surface ([standards-track.md](../design/standards-track.md) §
Principal binding).

### 3. The attenuation relation (the acceptance bar)

`attenuate(child, parent)` holds iff ALL FOUR sub-relations hold. Each is decidable by closed-
algebra comparison — no selector interpretation, no caveat DSL.

**3.1 Operations subset by name.** The child's operation-name set is a subset of the parent's
(set membership on 1–128-byte printable ASCII names, [protocol-v1.md](../protocol-v1.md) § Claims
— the "Names are unique within the grant and contain 1–128 printable ASCII bytes" sentence). The
child may drop operations; it may not add, rename, or duplicate them. For each operation name in
BOTH, the selector relation (3.2) must hold.

**3.2 Conjunctive selector narrowing — set containment (the load-bearing rule).** For each
operation `name` present in both child and parent, every DISTINCT selector tuple in
`parent.selectors(name)` appears IDENTICALLY (same kind, same path, same value(s)) AT LEAST ONCE
in `child.selectors(name)`, plus zero or more additional conjunctive selectors, in any order.

This is SET containment of the distinct closed-selector tuples, NOT a verbatim-PREFIX
requirement and NOT a counted-multiset requirement. Order independence is forced by the matcher:
`match_all/3` applies `Enum.all?(selectors, &matches?/3)` (`selector.ex:23`), which is blind to
list order. Multiplicity is IGNORED because the conjunction is idempotent — `Enum.all?([S, S])`
accepts exactly the same arguments as `Enum.all?([S])` (the matcher's own behavior: a duplicate
conjunct adds no restriction), so `Accept([S, S]) = Accept([S])`. (An earlier draft used
counted-MULTISET containment "because the algebra permits repeated selectors." That was rejected
in cross-vendor review: it would reject an equality-preserving delegation `parent [S, S] → child
[S]` even though `Accept([S]) = Accept([S, S])` — i.e. a non-widening the rule should accept. Set
containment on the distinct tuples is the right relation for THIS algebra, where duplicates carry
no acceptance semantics. An even earlier draft required a verbatim PREFIX; that was rejected in
the design-adversarial review as order-sensitive. Set containment is sound and complete without
either brittleness.)

**Soundness** against `match_all/3` (`selector.ex:19-28`):

```text
match_all(S_child, args)
  = Enum.all?(S_child, &matches?/3)               # selector.ex:23
  = Enum.all?(S_parent ∪ S_extra, &matches?/3)    # S_child contains all parent tuples + extras
  ⟹ Enum.all?(S_parent, &matches?/3)              # a conjunction with added conjuncts can only shrink
  = match_all(S_parent, args)
```

(The first `=` abbreviates `match_all/3` to its `Enum.all?` conjunct. `match_all/3` also gates
on `nonempty_bounded?(selectors)` and `Jcs.encode(arguments)` (selector.ex:21-22); both are
well-formedness predicates independent of which selector list is conjuncted — the first is a
property each valid grant's selector list satisfies on its own, the second depends only on
`arguments` — so they are invariant under the parent/child comparison and the dominance of the
`Enum.all?` conjunct carries the conclusion.) Every argument set the child accepts, the parent
accepts: `Accept(S_child) ⊆ Accept(S_parent)`. Attenuation holds.

**Decidability.** The relation is set membership on distinct closed-selector tuples — for each
distinct parent tuple (kind/path/value(s)), check for an identical occurrence in the child list;
never invoke `matches?/3`. Nothing is interpreted; everything is compared ([standards-track.md](../design/standards-track.md)
§ Delegation). This is the closed-algebra discipline that makes attenuation mechanically
checkable without a caveat interpreter. (Multiplicity is ignored at the comparison step because
it is ignored by the matcher — idempotence of conjunction — so deduplicating each list before the
membership check changes no verdict.)

**Acceptance-set completeness (why this is not a capability loss).** In-place value refinement on
a shared path is expressible as a conjunctive ADD, because the conjunction intersects. A parent
`{:one_of, path, [a,b,c]}` narrowed to `{a,b}` is the child CONTAINING the parent's `one_of` AND
ADDING `{:one_of, path, [a,b]}` — the conjunction of {a,b,c} and {a,b} accepts exactly {a,b}. A
parent `{:equals, path, v}` can only be narrowed to the empty set (add a contradictory
`{:equals, path, v'}`), which is correct — `equals` is a singleton. `:all` is narrowed by adding
any selector. So at the level of ACCEPTED ARGUMENT SETS, set containment (on distinct tuples)
is sound AND
expressively complete for every narrowing a general selector-implication rule could express,
without paying for an implication decision procedure (which would require re-implementing the
matcher — i.e. interpretation, forbidden by ADR 0006 §5). This completeness is stated at the
acceptance-set level only.

**3.3 Validity-window containment.** `parent.not_before <= child.not_before` and
`child.expires_at <= parent.expires_at` (integer NumericDate comparison). The child window is a
sub-interval of the parent's; within each grant the existing coherence invariants hold
(`iat < exp`, `nbf < exp`, [protocol-v1.md](../protocol-v1.md) § Verification).

**3.4 Audience containment.** The child's audience set is a subset of the parent's (set
membership on 1–64 StringOrURI each, [protocol-v1.md](../protocol-v1.md) § Claims — the `aud`
row). The
child may narrow who it is for; it cannot widen.

**Not attenuated (recorded honestly).** `grant_id`, `jti`, `iat`, `iss`, `holder_thumbprint`,
`key_id` are per-link identities, not inherited — each link has its own. The cryptographic binding
between child and parent is `thumbprint_raw(G_i.header.jwk) == G_{i-1}.cnf.jkt` (§2), NOT an
`iss`-principal match. Selectors are never rewritten or re-typed — only contained (as a set of
distinct tuples) plus extra conjuncts appended.

### 4. Chain-verification algorithm

`verify_chain(grants, trusted_issuer, expected, bounds)` walks root → leaf, depth-bounded. The
caller supplies `G_0`'s trusted issuer (as today) and the ordered chain bytes `[G_0, …, G_n]`.

1. **Root.** `G_0` verifies under the CURRENT `verify_grant` rules against a caller-trusted
   issuer (`typ = ba+cap`, no `ba_dlg`, header `{alg, kid, typ}` with no `jwk`). Exactly today's
   single-grant verification.
2. **Per link `i = 1..n`:**
   - `typ(G_i) = ba+cap-delegated` (closed-set match; else fail closed).
   - `G_i.header` carries exactly `{alg, kid, typ, jwk}`; `jwk` is the parent-holder public key
     (§2). Closed-set match on the header; reject extras.
   - `ba_dlg(G_i)` is a base64url claim; decode to 32 raw bytes; re-derive the parent's raw hash
     via `CompactJws.hash(G_{i-1})` (the RAW variant); compare raw-to-raw with `secure_equal?`
     (mirrors `runtime.ex:482-484`).
   - Bind the signer: `Jwk.thumbprint_raw(G_i.header.jwk) == G_{i-1}.cnf.jkt`, then
     `ed25519_verify(G_i.sig, G_i.signing_input, G_i.header.jwk.public_key)` (§2).
   - `attenuate(G_i, G_{i-1})` holds (§3, all four sub-relations).
   - `G_i`'s own time/size/header closed-set checks pass under the successor bounds.
3. **Depth bound — REQUIRED and finite.** `bounds.delegation_depth` is a REQUIRED successor-major
   bound: a positive integer that MUST be supplied and finite. Its absence is a configuration
   error (fail closed), NOT a default-to-unbounded. Verification requires `n <=
   bounds.delegation_depth`; exceeding depth fails closed. (The current major has no such bound
   because it has no delegation; the successor major defines it as part of its `Bounds`.)
4. **Chain input size — bounded separately.** The depth bound caps chain DEPTH (work along one
   root→leaf path), not breadth: a caller may present a forest of chains sharing a root. Per-grant
   size is already bounded by `bounds.compact_bytes`; the successor major bounds the total chain
   input (count and/or aggregate bytes) to prevent a quadratic-work fan-out where M chains of
   depth ≤ N force O(M·N) work. (Depth caps depth; fan-out is bounded by a separate successor-
   major input-size bound.)
5. **Cycle safety.** A `ba_dlg` hash chain cannot express a cycle (a grant's hash cannot equal an
   earlier grant's hash without a SHA-256 second-preimage collision), and a child's `ba_dlg`
   cannot point forward (it binds the PARENT, which precedes it in the walk). The depth bound is
   the operational bound; hash-chain acyclicity is the structural property.
6. **Leaf binding.** The leaf `G_n` + its holder proof are verified by a successor-major
   delegated-leaf verification that runs the SAME checks today's combined verification runs over
   a single grant — not merely `proof.ath`, and NOT today's `check_envelope` byte-for-byte. The
   leaf checks are: `proof.ath` = raw hash of `G_n` (`runtime.ex:482-484`); the leaf's audience
   set contains `expected.audience` (`runtime.ex:466`); the proof's operation is in the leaf's
   operation set and the leaf's selectors match the arguments (`runtime.ex:497-498`); and the
   time/window checks run against the leaf (`runtime.ex:468-469`). These four checks are restated
   because attenuation (§3) is a link-by-link PARENT→CHILD relation — it guarantees `G_n` is no
   wider than `G_0`, NOT that `G_n` satisfies the caller's `expected` context. In particular,
   §3.4 audience containment gives `G_n.audiences ⊆ G_0.audiences`, which combined with step 1's
   `expected.audience ∈ G_0.audiences` does NOT entail `expected.audience ∈ G_n.audiences` — a
   leaf may have narrowed to a subset excluding `expected.audience` (e.g. leaf audience {B},
   root audience {A,B}, request for A); the leaf's own audience check closes that gap.

   It is NOT today's `check_envelope` unchanged: today's grant parse rejects `ba+cap-delegated`
   at the closed typ check (`runtime.ex:280`, `typ = "ba+cap"` only), the closed header-key set
   (`runtime.ex:240`, `@grant_header_keys ~w(alg kid typ)` — no `jwk`), and the closed payload-
   key set (`runtime.ex:241`, `@grant_payload_keys` — no `ba_dlg`). A `ba+cap-delegated` leaf
   carrying `jwk` + `ba_dlg` therefore cannot be parsed by today's `check_envelope`. The
   successor major defines a delegated-leaf parse path that admits exactly `typ = ba+cap-
   delegated`, header `{alg, kid, typ, jwk}`, and the `ba_dlg` payload claim (closed-set, reject
   extras — the same closed posture, widened only for these reserved names), and THEN runs the
   four leaf checks above. The check SEMANTICS (audience/operation/selectors/time/ath) are
   reused from today; the PARSE path is a successor-major addition. The chain proof is the
   ordered attenuated grants root→leaf plus the leaf's holder proof.

This algorithm is SPECIFIED, not implemented. It is what the successor major implements; the
current major has none of it. The successor major owns the concrete `bounds.delegation_depth`
value, the chain input-size bound, and the `ba+cap-delegated` header shape.

## Alternatives considered

- **Verbatim-PREFIX selector containment** (a draft of §3.2). Rejected (design-adversarial
  Challenge 3): `match_all/3`'s `Enum.all?` (`selector.ex:23`) is order-independent, so a prefix
  rule would reject a reordered-but-strictly-narrower child, making the rule stricter than the
  semantic attenuation it encodes and making the "completeness" claim false.
- **Counted-MULTISET selector containment** (a draft of §3.2, after the PREFIX rejection).
  Rejected (cross-vendor review): the matcher's conjunction is idempotent — `Enum.all?([S, S])`
  accepts exactly the arguments `Enum.all?([S])` does — so a counted-multiset rule would reject
  an equality-preserving delegation `parent [S, S] → child [S]` (the child's single `S` cannot
  "account for" the parent's two), even though `Accept([S]) = Accept([S, S])` and the delegation
  widens nothing. Set containment on the DISTINCT tuples is the right relation for an algebra
  where duplicates carry no acceptance semantics.
- **Today's `check_envelope` UNCHANGED for the delegated leaf** (a draft of §4 step 6). Rejected
  (cross-vendor review, blocking): today's grant parse rejects `ba+cap-delegated` at the closed
  typ check (`runtime.ex:280`), the closed header-key set (`runtime.ex:240`, no `jwk`), and the
  closed payload-key set (`runtime.ex:241`, no `ba_dlg`). A delegated leaf carrying `jwk` +
  `ba_dlg` cannot be parsed by today's `check_envelope`, so "UNCHANGED" was unrealizable. The
  successor major defines a delegated-leaf parse path (closed-set, widened only for the reserved
  names) that THEN runs the same audience/operation/selectors/time/ath checks today's combined
  verification runs.
- **Verify the link signature "under `cnf.jkt`" without a header key** (a draft of §2). Rejected
  (design-adversarial Challenge 2, blocking): `cnf.jkt` is a 32-byte thumbprint digest
  (`runtime.ex:296-298`), not a public key; `Grant.t()` carries no holder key or principal.
  Ed25519 verify needs the public key, recoverable only from a `jwk`. The header-`jwk` shape
  reuses the existing, codebase-proven proof-holder-key mechanism rather than inventing a new
  key-bearing claim.
- **A caveat DSL (Macaroons/biscuits-style).** Rejected (ADR 0006 §5): an open-ended caveat
  interpreter is exactly the extension surface this protocol's closed posture forbids. The closed
  selector algebra IS the attenuation language.
- **In-place amendment of ADR 0006.** Rejected: ADR 0006 records the decision across many
  surfaces; the mechanism earns its own numbered ADR for traceability and the charter's "every
  product-shaping decision lands as a numbered public ADR" rule.
- **General selector implication.** Rejected (§3.2): not mechanically checkable without
  re-implementing the matcher (= interpretation, forbidden by ADR 0006 §5), and buys no
  accepted-set expressiveness over set containment on distinct tuples.

## Consequences

- A successor major implementing delegation implements `ba_dlg`, `ba+cap-delegated` with a header
  `jwk`, the depth-bounded chain-verification algorithm, and the four-part attenuation relation.
- The reserved `ba_dlg` claim and `ba+cap-delegated` typ are REJECTED by the current major's
  closed profile — the rejection evidence is the CODE's closed typ set
  `{ba+cap, dpop+jwt, ba+chain-anchor, ba+key-transition}` (`compact_jws.ex:117,149-150`,
  `runtime.ex:280`) and closed grant claim set (`runtime.ex:47-49`, no `ba_dlg`), neither of
  which admits the reserved names. (The unchanged conformance corpus at `agreed=259` is
  CONSISTENT with this — it exercises the closed code sets — but is not itself the rejection
  proof for names that live in docs only, since the corpus verifies code behavior, not docs
  reservations. Same honesty line as ADR 0009.)
- Activation is a successor-contract-major decision, gated by the deprecation-prerequisites rule
  ([standards-track.md](../design/standards-track.md) § Parallel-version support: published
  profile + corpus + two independent passing implementations). The current major's wire profile,
  bounds, and verdicts are unchanged.
- The successor major owns the concrete `bounds.delegation_depth` value, the chain input-size
  bound, the `ba+cap-delegated` header shape, and any `ba_obo`/principal-binding interaction.
  None of these are pinned by this ADR; this ADR specifies the mechanism that constrains them.
