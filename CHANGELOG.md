# Changelog

All notable changes to `bounded_authority_protocol` are documented here.

## [Unreleased]

### Added — IANA registration templates + spec-facts rule 7 (no wire change)

- **`docs/design/iana/`**: the machine-readable registration sources and rendered ready-to-file
  markdown for the profile's IANA entries. JSON Web Token Claims Registry (its published
  four-field format, Specification Required): `ba_inv`, `ba_op`, `ba_req` ready to file;
  `ba_dlg`, `ba_offline`, `ba_sut` reserved-marked and NOT filed. Media types (RFC 6838
  section 5.6 field template, LIMITED USE): `application/ba-cap+jwt`,
  `application/ba-chain-anchor+jwt`, `application/ba-key-transition+jwt` ready to file;
  `application/ba-cap-delegated+jwt`, `application/ba-suite-attestation+jwt` reserved. The
  drafted `ba+*` wire `typ` values are NOT registrable as-is (`+cap` is not a registered
  structured suffix; `+jwt` is) — **the wire `typ` values are unchanged**; the media-type
  namespace is distinct. Filing is externally gated (the BAP-08 official-submission
  preconditions); the templates make in-repo readiness verifiable.
- **Spec §IANA considerations** (section 20): the registration requests, the reserved names,
  and the namespace distinction, per RFC 8126 guidance (read first-hand).
- **registries.md typ table gains the media-type column**; purposes are now byte-exact shared
  facts between the registries document and the IANA sources.
- **Spec-facts rule 7**: registries.md == IANA template sources, exact names/statuses/purposes
  both directions, with two documented allowsets (`ba_obo`: reserved without a template by
  design; `dpop+jwt`: registered by RFC 9449) — BAP-12's acceptance criterion mechanized.
  Mutation leg proven red (flipped template status caught, named) and restored.

### Added — the v1 specification `spec/bap-v1.md`; authority swap certified with an EMPTY delta

- **`spec/bap-v1.md`** (kramdown-rfc conventions, `[@RFC2119]`-style citations, no IETF
  stream/IPR title-block fields — in-repo readiness, zero submission intent): the complete
  normative v1 profile in one language-neutral document — conformance language and the
  closed-rejection invariant, suite identity, normative references without repo paths, the
  abstract tagged data model and typed projection, JSON decoding and JCS serialization,
  base64url, wire objects (headers, claims, selectors, URI normalization), signing and digest
  inputs with the `BAP1-*` domain separators, the consumption chain / boundary anchors /
  authenticated key transitions / anchored export framing folded NORMATIVE from ADR 0004, the
  public verification contract as algorithm prose (the Elixir bindings and frozen façade moved
  to informative Appendix C), hard maxima, the untrusted key locator, and the `typ` registry.
  Informative appendices: B the CDDL summary, C the reference mappings and tagged-algebra
  binding table, D the requirement-inventory pointer.
- **The authority swap is certified**: the spec-facts extractor now reads `spec/bap-v1.md`
  (all ten anchors in the one normative document) and `extract(new spec) ==
  spec/facts/baseline-v1.json` byte-for-byte — the frozen pre-swap extraction, EMPTY delta.
  `docs/protocol-v1.md` keeps its anchors but is no longer read (the derived view lands with
  its own landing); ADR 0004 and registries.md remain extended records.
- **Framing oracle** (new spec-facts rule): a corpus archive-bearing valid case's real bytes
  are re-parsed against the EXTRACTED framing facts (archive prefix, UINT32_BE nonzero-length
  frames, exact EOF) — a spec whose framing prose drifts from accepted bytes reds even when
  the delta gate happens to pass. Proven red twice during construction (wrong prefix form,
  wrong chunk decoding) and green on the shipped corpus.
- **`spec/cddl/bap-v1.cddl`** (informative): the closed wire objects in CDDL, honest about
  CDDL-inexpressible invariants (duplicate names, canonical bytes, tagged integer/float,
  binary framing). **CI coherence job** (`scripts/check_cddl_coherence.rb`, pinned cddl
  validator 0.12.14, executed locally at authoring): every valid corpus case's CDDL-covered
  artifact validates (grant/proof/anchor/transition payloads, consumption rows), and four
  PINNED invalid exemplars (regexp/size/closed-set violations) reject — the pinned list cannot
  go vacuous. A pinned-and-checksummed kramdown-rfc 1.7.40 render job renders the spec to
  xml2rfc v3 (verified locally: renders clean).
- The spec-facts battery entries re-anchored at the spec (a digit drift or deleted anchor in
  `spec/bap-v1.md` reds). `mix spec.facts` green against the NEW authority in ~0.1s.

### Added — spec-facts mutation battery (no wire, bound, or verdict change)

- **`scripts/check_spec_facts_mutations.exs` + `mix spec_facts.mutations` (wired into
  `mix quality`)**: the spec-facts gate's own red-capability battery, mirroring the conformance
  mutation-gate doctrine — scratch-copy isolation, one anchored source mutation per entry,
  baseline-green non-vacuity (a deleted target can never score as "caught"), and one
  inverted-assertion calibration self-proof executed at authoring (under a neutered rule-1
  assertion the bounds mutation SURVIVES green — the exact condition the battery raises on).
  Seven entries, each proven red in-landing: spec bounds digit, live Bounds digit, requirement
  statement softening, cited-count drift, revision-citation drift, deleted anchor, and a
  renamed optional-unobserved coverage mark (the marks file is load-bearing). The privacy-canary
  mutation stays outside the battery by design — the canary sweep needs the real git worktree
  and carries its own calibration tests.

### Added — spec-facts drift gate against the current authority (no wire, bound, or verdict change)

- **`spec/tools/extract_facts.exs` + `spec/facts/baseline-v1.json`**: the normative facts of the
  CURRENT authority (`docs/protocol-v1.md` + ADR 0004 byte definitions + the registries typ
  table) are now machine-extracted from ten closed `<!-- facts:key -->` anchor regions (bounds,
  header members, grant/proof claims, selector kinds, typ values, domain separators, digest
  constructions, archive framing, error shape) and frozen as a byte-deterministic baseline. A
  future editor who changes any normative fact — spec, bound, corpus, requirement map, or
  registry — is stopped by `mix spec.facts` naming the divergent pole pair.
- **`scripts/check_spec_facts.exs` + `mix spec.facts` (wired into `mix quality`)**: rule 1b
  (extraction == frozen baseline), rule 2 (spec closed sets ⊇ the corpus's valid-case member
  unions, direction-aware, with justified optional-unobserved marks in
  `spec/facts/coverage-v1.json`), rule 3 (spec REQ-id set == requirement-map set, each defined
  once), rule 4 (requirement-statement hashes == `spec/facts/requirement-statements-v1.json` —
  silent softening reds), rule 5 (map-cited counts re-derived from the live corpus index),
  rule 6 (map cites the corpus revision integer), rule 9 (every authority file git-tracked and
  thus inside the public-surface privacy gate's full-tree canary sweep — the ADR 0023 topology;
  no term list is tracked), rule 10 (anchor completeness: every normative table inside exactly
  one anchored region, with the JSON-algebra binding table's coverage mechanically verified
  against the typed-projection facts). Rule 1's bounds-dump equality lives as
  `test/spec_facts_test.exs` (needs the compiled Bounds module).
- The gate ships GREEN against the old authority — the guards are proven against the world they
  protect BEFORE the authority swap. Every rule proven red-capable at landing by a named
  mutation (spec digit, Bounds digit, map statement softening, cited count, revision citation,
  a planted privacy-canary term in an authority doc, a deleted anchor — each caught, each
  restored). Gate runtime ~0.2s; rules 7 (IANA), 8 (formal companions), and 11 (keyword census)
  arrive with their owning landings.

### Added — corpus revision sidecar + re-derivability generator (no case byte or verdict change)

- **`priv/conformance/v1/corpus/revision.json`**: the corpus's monotone revision integer (1)
  with a generated-from provenance note, hash-covered as an entry in `index.json`'s per-file
  SHA `files` set and enforced by exact file-set equality in every consumer — a tampered,
  deleted, malformed, or wrongly-shaped sidecar fails every loader closed. `index.json` bytes
  change once (the single files entry; 283 cases, verdicts, counts, and applicability are
  byte-identical). The corpus-index schema's file-path pattern admits exactly the one reserved
  root path. All six certified-index-SHA pins rotated in the same commit via the regeneration
  script (ADR 0019 atomic-landing template), and both vendored SDK snapshots re-copied.
- **`conformance/generators/`**: the corpus re-derivability tooling (authoring tooling, not a
  runner, not in the published package). `build_corpus.mjs --verify` proves the shipped corpus
  equals a rebuild from its frozen case files plus the shipped curated inputs (n_a reasons +
  the public-key fingerprint census), including re-derivation of every tamper case's verbatim
  artifact; `--rebuild-index`/`--bump-revision` are the amendment path. The README records the
  honest provenance: the signed fixtures were minted with ephemeral keys at authoring time and
  cannot be re-minted; everything derived is machine-rebuilt and byte-verified.
- Every corpus consumer recognizes the sidecar fail-closed (Elixir loader + CLI, the
  independent Node runner, and the TypeScript/Python/Rust/Go SDK runners — the two loaders that
  previously skipped case-free files silently now enforce the sidecar's SHA and closed shape).
- `docs/design/requirement-map.md` cites the revision integer (the `format`-string citation
  was constant across revisions and could detect nothing); the five consumer-doc digest
  citations refreshed to the rotated values.

### Added — corpus digest regeneration gate (no wire, bound, or verdict change)

- **`scripts/regen_corpus_digests.exs` + `mix corpus.digests`**: one command regenerates every
  certified corpus index-SHA machine pin — the four SDK conformance runners in their native
  encodings (base64url: TypeScript, Go; hex: Python, Rust) plus the two Elixir pins (the CLI's
  fail-closed certified-corpus assertion and its test mirror) — and the check leg, wired into
  `mix quality`, fails red the moment any pinned constant drifts from the live `index.json`
  digest (corrupt-one-constant and scratch-index-byte mutation legs proven red at landing). The
  Elixir-side pin itself landed in the 0.1.2 hardening; this closes the tooling gap the BAP-07
  gate-integrity review recorded and makes every future corpus rotation a single-command,
  same-commit affair (ADR 0019 atomic-landing template). No corpus byte changes in this landing:
  all six constants keep their current values, and `--write` is byte-idempotent today.

### Fixed — public-history privacy boundary

- Public documentation and reachable Git history no longer identify private product repositories
  or their deployment topology. ADR 0023 records the durable boundary and the all-ref rewrite.
- `bounded_authority` is explicitly a private commercial application: it must never be published
  to public Hex, is not currently distributed through private Hex, and any future private-Hex
  release requires both a paid subscription and fresh owner approval for that exact release.

### Fixed — v1 selector contract reconciliation

- The protocol and both shipped selector schemas now describe the released `all` behavior: `all`
  accepts any of the three recognized member sets and treats `path`/`value(s)` as inert. Go,
  TypeScript, Python, and Rust now reject every other member combination, matching the Elixir
  reference and independent runner. ADR 0021 records the zero-verdict-change erratum.

### Added — Go verifier SDK (BAP-16; no Elixir package change)

- **`sdks/go/` — the typed Go verifier SDK** for the frozen v1 profile, authored from the spec +
  ADRs + conformance corpus alone (ADR 0014 D5): the 17-function façade plus versioned primitives,
  zero runtime dependencies (stdlib `crypto/ed25519` + `crypto/sha256` only), Go floor 1.25. Passes
  all 283 conformance vectors from a vendored corpus snapshot with startup index SHA-256 assertion
  and the two-boundary key census (`agreed=283 disagreed=0 census=11`). The per-language
  permissiveness battery ships with per-clause red-capable legs for every closure and gate (no F1
  debt: 14 mechanical mutation probes proven RED at authoring), including ADR 0017's five clauses
  (closed Result panic guard, pre-digest hoist with a zero-hash work pin via the internal
  `archiveDigest` seam, canonical byte-equality, signature width at decode, role-bounded frame
  reads) and ADR 0018's bounds threading incl. `assemble_compact` caller limits and nested-pins
  identity semantics. Purity vet + zero-dependency license gate (each red-capable) and a
  `go-conformance` CI job. Not in the Hex `files:` list; no registry-publish infrastructure
  (ADR 0015 graduation posture).
- **Cross-vendor hardening (codex + claude review, fix pass `fbff228`):** proof-claim presence
  tracking, export anchor-chain cross-binding, standalone genesis zero-hash, port-overflow
  closure, embedded-IPv6 group counting with dotted-form preservation, post-decode host
  classification with lowercased decoded bytes, tightened integer-magnitude enforcement,
  UTF-8 object-version validation, chunk-vs-byte bound separation at encode, a digest-deriving
  export producer, proof-producer nonce support, constant-time nonce comparison, and
  runner/purity-gate hardening — each behavioral fix pinned by a red-capable
  review-regression leg.

## [0.1.2] — 2026-08-20

### Changed — release/verification gate hardening (no wire, bound, or verdict change)

- **`mix conformance.verify` pins the certified corpus index SHA-256** (ADR 0014 D4). The Elixir
  verifier CLI now fails closed unless the loaded corpus is the exact certified snapshot — closing
  the gap where a self-consistent but shrunken corpus (regenerated index) passed integrity and
  agreement. Parity with the three SDK runners, which already pin the identical value.
- **The architecture gate asserts every pinned beam is present** (keys-⊆-present). A pinned public
  surface deleted or renamed without updating the allowance now reds the gate instead of vanishing
  silently.
- **The SDK publish guard scans SDK scripts, Makefiles, justfiles, and composite actions**, not
  only workflows and top-level manifests — a registry-publish command can no longer hide in an SDK
  release script or a composite action.

## [0.1.1] — 2026-08-20

### Added

- **Ship `priv/conformance/v1/vectors/` in the Hex package.** The four named vectors
  (`grant-holder-proof`, `chain-semantic-edge`, `consumption-chain-archive`, `manifest`)
  are the acceptance oracle a holder-side consumer verifies its envelope production against
  (ADR 0013's corpus-as-oracle posture). 0.1.0 shipped `corpus` + `schemas` but not
  `vectors`, so a Hex consumer could not reach the oracle vector; 0.1.1 ships it. Public
  test data, same class as the already-shipped corpus — no private material (verified: the
  manifest carries only discovery roots and public-key fingerprints). The exact-file
  package census is extended to match. Zero wire byte, bound, or verdict change.

## [0.1.0] — 2026-08-20

### Added

- **First public release (BAP-07, executed 2026-08-20 by owner decision).** The exact reviewed
  candidate published to Hex as `bounded_authority_protocol` 0.1.0. Connected verification: the
  private runtime's PostgreSQL 18 gate passed 996/996 against the pinned candidate, and the
  consumer's gates passed 819 tests including the immutable authority-contract bundle's 15
  consumer cases; the opt-in live-endpoint consumer gate was provisioned and run for this
  closeout. Fresh correctness, security, and gate-integrity reviews closed with their findings
  fixed in this landing; the cross-vendor peer (codex) returned no findings, and the third-family
  GLM lens was a named sensitivity-policy skip. The publication sweep in this landing: the
  private-strategy links left the README, every unpublished/deferred claim in the shipped docs
  became the published truth, ADR 0008 gained the 2026-08-20 amendment lifting the deferral, the
  consumer-seams design note left the package and hexdocs, the mutation batteries gained
  baseline-green runs (an entry now fails if its target test cannot run green unmutated), the
  bounds-aware facade gained widening/malformed-bounds rejection legs, and `.gitignore`/dependabot
  gained the public-repo hygiene the security review named. The `v0.1.0` tag moved to the
  published commit so hexdocs `source_ref` links resolve.

### Fixed

- **BAP-07 readiness reconciled across the repo docs.** The ROADMAP row's acceptance still named
  the retired private-runtime PG 16/17/18 matrix (the private runtime's ADR 0010 made PostgreSQL 18
  the sole supported major); the ROADMAP Next-action note, the release-candidate contract's Status,
  the README Status, and SECURITY.md's supported-versions note each described BAP-07 as gated on the
  private runtime's connected gates —
  private BA-14 completed 2026-08-18, so BAP-07 is fully unblocked (the Hex-publication half stays
  deferred by maintainer decision). Docs-only: zero code, wire, bound, or verdict change.
- **Cross-vendor review round 18 (codex blocking + claude should-fix/notes, all closed).**
  Codex (blocking): the TS shape gate's nested expected-export members were opaque `"object"`
  specs, so a malformed nested struct (chain missing `previousHash`, empty anchor) passed the
  gate and the clause-3 hoist then derefed the missing field — a `TypeError` escape past
  `trying()`; the nested members are now fully specified (chain/anchor/transition field shapes,
  `archived.chunks` as a bytes sequence), red-leg + mutation proven (opaque specs → RED). Claude
  (should-fix): the Python and Rust hoists walked `expected.transitions` per-element BEFORE the
  `key_transitions` count ceiling, regressing the round-3 ceiling-first invariant the TS sibling
  kept; the ceiling now runs at the top of the hoist in both (the dead later duplicate removed).
  Claude (notes, reconciled): the entry-position shape gate's sequence walks before count
  ceilings are a documented accepted margin (typeof-only per element); Python's body-level
  `bytearray` tolerance was dead under the exact-bytes gate and is reconciled to bytes-only.
  The timed-out fable peer's transcript was mined: it was converging on the ordering finding
  (fixed) and an API-shape note that is benign (the SDKs' optional bounds default to maximum —
  behavior-identical to the reference's public façade).
- **Round-12..14 per-clause pin debt paid on the touched surfaces (ADR 0017's Honest limit,
  amended).** The 2026-08-18 cluster's legs double as the owed per-clause pins: the pre-digest
  export gates (version shape/equality, key-count, key-id charset, key magnitude) are now pinned as
  WORK legs in the Python battery (reject with zero sha256 calls — all five mutation-proven
  load-bearing) with TS/Rust verdict matrices. Root cause of the "unpayable" debt: each gate is
  verdict-subsumed by a later gate, so verdict legs were structurally impossible; the work form is
  the red-capable pin. Still owed and disclosed: the standalone anchor-path `anchor_bytes` gates
  (round 12) and allocation bounds (round 15) on untouched surfaces.
- **ADR 0018's named `assemble_compact` divergence closed: caller bounds threaded through
  assembly in all three SDKs.** The reference takes limits at assemble (`runtime.ex:147-155` →
  `CompactJws.assemble` — encoded-segment bounds, compact_bytes, and the kind re-parse against
  `Bounds.coerce(limits)`); the SDKs hardcoded maximum. Each SDK now takes an optional bounds
  parameter (Python `bounds: Bounds | None = None`, TypeScript `bounds?: Bounds`, Rust
  `bounds: Option<&Bounds>` — an additive public-API change; absent bounds = maximum, backward
  compatible) and threads it through the reference's gates. `signature_bytes` carries no
  assemble-time gate — fixed-width at Bounds construction (the reference's check is subsumed).
  Mutation-proven per SDK (reverting the threading reddens each battery's tightened-bounds legs).
- **ADR 0017 exception 2 closed: the expected-anchor identity ordering divergence (all three
  SDKs).** The reference validates the expected struct (chain + both anchors' identity/binding
  well-formedness + transitions) BEFORE hashing the archive chunks (`anchored_export_codec.ex:88-104`);
  the SDKs ran those gates only post-digest. Verdict-invariant by subsumption — the fix restores the
  clause-3 work ordering: malformed caller metadata now rejects without hashing the archive. The
  Python battery proves it behaviorally (sha256 call-count == 0 on malformed-expected rejections,
  mutation-proven); TS and Rust pin the ordering structurally (hoist block before the digest site,
  mutation-proven) plus verdict-matrix legs.
- **ADR 0017 exception 1 closed: the SDK closed-Result escape family (Python + TypeScript).** A
  mechanical family sweep (every façade × every parameter × wrong-typed values, then every struct
  field the same way) proved the 2026-08-17 ledgered Python escapes were not two instances but a
  total class: 31/34 Python parameter sites and every caller-supplied struct field raised
  `AttributeError`/`TypeError` past the closed `Result`, and TypeScript — whose coercion the ADR
  had classed as a "disclosed margin" — silently accepted `requestDigest(123/true/null/{})`
  (digesting the coerced text) and threw `TypeError` past `trying()` on 109 parameter positions.
  Both dynamic SDKs now gate every façade argument's shape before the body runs (Python:
  annotation-driven `_closed_shape` over the declared dataclass shapes, `bool` ≠ `int`; TS:
  `closedShape` with per-façade shape specs). Rust excludes the class by typing. The per-SDK
  family-sweep batteries in `tests/test_permissiveness.{py,ts}` are the pre-fix red run and are
  mutation-proven per façade. Exception 2 (expected-anchor identity post-digest) remains open.

### Added

- **Bounds-aware public compact assembly and current-major issuer posture.** Add the public
  `BoundedAuthorityProtocol.V1.assemble_compact/3` facade over the existing bounded runtime
  primitive; `/2` remains exactly `/3` with profile maxima. Native tests cover byte equality for
  grant, proof, boundary-anchor, and key-transition compacts; tightened encoded-segment and final-
  compact rejection; and continued rejection of `ba_dlg` / `ba+cap-delegated` in current v1.
  [ADR 0020](docs/adr/0020-bounds-aware-assembly-and-issuer-reauthorization-posture.md) records that
  a private authority may issue an independently valid, narrower current-v1 grant to a new holder,
  while lineage remains runtime-only and portable holder-signed delegation remains successor-major.

- **The SDK contract ADRs (BAP-15 documentation slice).** Three new accepted ADRs record contracts
  that had shipped as code + ROADMAP evidence amendments only: [ADR 0017](docs/adr/0017-inter-sdk-behavioral-contract.md)
  (the inter-SDK behavioral contract the 17-round cross-vendor hardening arc converged on — closed
  Result surface, type strictness, pre-hash validation, canonical-form byte equality +
  signature-width gates, role-bounded frame reads), [ADR 0018](docs/adr/0018-sdk-bounds-contract.md)
  (the caller-tightenable bounds contract through the expected structs, including the
  nested-pins identity semantics and the named `assemble_compact` maximum-bounds divergence), and
  [ADR 0019](docs/adr/0019-corpus-artifact-distribution.md) (ADR 0015 Decision 6's deferred
  corpus-artifact question settled: per-SDK binding until the first SDK graduation, on the traced
  two-SDK bump-amplitude evidence). Fact corrections in the same landing: ADR 0014's Node floor
  corrected to >= 22 (raised at `d9df0bf` on Node 20 EOL) and its `@noble/curves` "optional
  browser-build path" claim withdrawn (never present in `sdks/` history); ADR 0008's BAP-07
  "publishes the exact candidate" consequence annotated with the maintainer's Hex-publication
  deferral (the `v0.1.0` git tag at `c65d3be` is the internal pin). Zero wire-behavior change. The
  ADR-0017 authoring review (cross-vendor) surfaced two verified SDK contract exceptions, disclosed
  as ADR 0017's named exceptions and routed as SDK-code fixes: a Python closed-Result escape
  (non-string `request_digest` operation / `ConsumptionEntry.chain_id` raises `AttributeError` past
  the façade), and all three SDKs validating the expected-anchor identity fields post-digest where
  the reference validates them pre-digest.

- **BAP-09 SDK conformance hardening (TypeScript + Python).** The TS + Python verifier SDKs now
  enforce two checks the Elixir reference has and the SDKs were missing: (1) a decoded
  **signature-width gate** in `parseCompact`/`parse_compact` (`len(signature) == signature_bytes`,
  mirroring `runtime.ex:237`/`:259` — `scanCompact`/`scan_compact` intentionally stays shape-only,
  mirroring `CompactJws.scan`); (2) **canonical-form equality** for boundary-anchor + key-transition
  compacts — the protected header AND payload segments must equal the exact JCS re-encoding
  (mirroring `boundary_anchor_codec.ex:95-96,118-119` + `key_transition_codec.ex:127-128,151-152`),
  so a non-canonical encoding (e.g. reordered members) is rejected. New red-capable tests cover the
  anchor + transition canonical paths (header + payload) and the signature-width gate. Verified: TS
  92 unit + conformance 283/283; Python 62 unit + conformance 283/283. (The Rust/Go SDKs — BAP-15/16
  — may carry the same gaps; a separate check is owed.)

- **All-SDK pre-hash validation hardening (BAP-15, cross-vendor rounds 11-15).** The archive
  verify paths across Rust/TS/Python now validate the full caller-context shape BEFORE the
  digest: the object versions (string, non-empty, UTF-8 bytes <= 512, well-formed, equal),
  the key chain (exact count, key-id ASCII-unreserved class + width), key windows
  (integral + magnitude + ordering), and identifier well-formedness — malformed metadata
  no longer forces maximum-sized hashing, ill-formed strings fail closed in every SDK
  (Python's UnicodeEncodeError escape closed; TS's silent U+FFFD replacement closed), and
  frame reads are role-bounded per chain_row_bytes/anchor_bytes.

- **Result-contract fail-closure + ChainInput type strictness (BAP-15, cross-vendor rounds 16-17).**
  Every path where a caller-supplied Python value could raise out of the closed Result API
  now fails closed instead *(2026-08-17 delta: "every" was overclaimed — two further escape paths
  were found by the ADR-0017 review and routed; see the SDK contract ADRs row below)*: ill-formed
  or non-str identifier strings (`_utf8_bytes` gates
  chain_ids, key_ids, versions, and every expected-side string the header construction
  encodes), non-int chain integers (gated before the sequence arithmetic), non-bytes chunk
  elements, and Boolean ChainInput integers (True == 1 no longer verifies — TS's strict
  equality and Rust's typing already rejected them). The TS chunk-type sibling gate added
  for family symmetry; the check_chain chain_id StringOrURI shape validation that only
  Rust carried is now in all three SDKs.

- **Rust SDK bounds parity (BAP-15; closes the LAST named delta).** Caller-tightenable
  bounds through the expected structs — the exact reference/sibling shape: five additive
  `Option<Bounds>` fields (None = the profile maximum), the nested-bounds pins with identity
  semantics (a present nested must coerce-equal the outer; an absent nested is valid only under
  an effectively-untightened outer — identity overrides are NOT tightening), and the resolved
  bounds threaded through every ceiling at encode AND verify + the standalone chain/anchor/
  transition entries. 27 mutation-proven legs at closeout (permissiveness 39 → 67 — the original 12 plus
  the five the four closeout lenses forced: the chain_rows count, the standalone
  transition, the verify-pin family on a REAL corpus-signed archive, and the two
  encode-pin isolations; the standalone anchor leg, the chunk-count MAGIC pin now reachable and landed, and a 7/7
  Elixir oracle receipt (local re-runnable .forge artifact). `assemble_compact` stays at maximum
  (the siblings too). (Scope driver: the 2026-08-14 session direction — the session's input,
  not this entry's verdict.)

- **TypeScript + Python encode-path validation parity (BAP-15).** Both sibling SDKs gain the
  same producer contract the Rust SDK just closed: a full `checkChain` re-check of the rows, and
  gated parses + 7-field matches for the START anchor, the END anchor, and every transition
  (their expected-side + key-path validations were already present — the deltas were the parses,
  the matches, and the row re-check; the start anchor was framed raw too, plan-review F1).
  15 legs per SDK at closeout (control + 8 tampers + the six pin/threading legs the
  delta- and diff-reviews forced; the five pin legs each isolated under their named
  mutation, the threading leg joint-by-construction per the settled diff-review record),
  each proven red-capable; TS 107 unit + conformance 283/283; Python 77 + conformance 283/283.
  mypy/ruff/purity/license clean. With this, all three shipped SDKs enforce the reference
  producer's full contract; the Go SDK (BAP-16) picks it up at authoring.

- **Rust SDK encode-path validation parity (BAP-15).** `encode_anchored_export` now enforces the
  Elixir reference producer's FULL validation contract (`anchored_export_codec.ex` encode):
  expected-side consistency (chain_id binding of both anchors + all transitions; the
  start/end sequence + hash bindings), a full `check_chain` re-check of the rows, gated parses
  + 7-field matches for BOTH anchors and every transition (the width/canonical gates now
  reached at encode), and the key-path walk (running key, strictly-after transition times,
  seen-list cycle guard, end anchor binding the final key with NON-STRICT `>=` chronology).
  19 red-capable battery legs at closeout (permissiveness 19 → 38), each mutation-proven; every leg
  verified against the Elixir reference oracle (20/20 fixtures — the 15 + control + the four
  closeout-lens additions; the receipt is a local re-runnable .forge artifact). Honest
  residuals, both NAMED: the TypeScript/Python SDKs carried the same producer permissiveness
  (CLOSED by the sibling entries above); the Rust SDK is a documented maximum-bounds posture
  at encode (the reference + siblings thread caller-tightened `expected.bounds` — carrying
  that is a public-API change, its own slice; the sibling identity fix also WIDENS TS/Python
  VERIFY-path acceptance for identity-override configurations, matching the reference; the
  Rust chunk-count parity fix is a latent verdict-tightening flip unreachable at the frozen
  maximum bounds — its pin is owed by the future caller-bounds slice).

- **Rust SDK conformance hardening (BAP-15).** The Rust verifier SDK now enforces the same two
  checks the Elixir reference has (closing the "separate check owed" note above, mirroring
  `18c6467`): (1) a decoded **signature-width gate** in all four `decode_*_parts` fns
  (`REQ1-BOUNDS-fixed-widths`, mirroring `runtime.ex:237`/`:259`,
  `boundary_anchor_codec.ex:88`, `key_transition_codec.ex:120`) — public verdict flips on
  `decode_grant`/`decode_proof` (accepted a wrong-width signature at decode) and
  `encode_anchored_export` (the start-anchor parse never width-checked its signature segment);
  (2) **canonical-form equality** for boundary-anchor + key-transition compacts — the four
  validators now assert `jcs_encode(value) == segment_bytes` for the protected header AND
  payload (mirroring `boundary_anchor_codec.ex:95-96,118-119` +
  `key_transition_codec.ex:127-128,151-152`), so a non-canonical (member-reordered) segment is
  rejected across `assemble_compact`, `verify_historical_anchor`, `verify_key_transition`,
  `encode_anchored_export`, and `verify_anchored_export`. Nine red-capable battery legs
  (4 canonical + 2 decode-width + 1 export-encode width + 2 canonical-exclusion pins + the
  four closeout-lens legs), each mutation-proven. Verified: cargo 338 unit + conformance 283/283 + permissiveness 38;
  clippy/fmt clean. Honest residuals, all
  routed: the encode path validates less than the reference producer — it frames the END
  anchor AND every TRANSITION raw without parsing them (the reference parses both anchors +
  all transitions through the width/canonical-gating codecs,
  `anchored_export_codec.ex:40-52`), binds the start anchor by sequence only (the reference
  matches all signed fields via `anchor_matches?`/`transition_matches?`), and does not
  re-check rows against the chain at encode (`ConsumptionChain.check`). A non-canonical or
  wrong-width end anchor or transition is therefore still accepted at Rust encode (probe-
  proven; caught downstream — `verify_anchored_export` gates all of them); closing these
  flips further verdict classes and is its own reviewed change. The Go SDK (BAP-16) picks
  both classes up at authoring.

- **BAP-17 — offline-eligible grant claims (reserve + specify).** Reserve the `ba_offline`
  grant-payload claim name in the [registries](docs/design/registries.md) (issuer-set offline
  floor limits: maximum value with explicit currency, maximum offline use count, offline-window
  expiry — a closed nested object; absence means online-only, per
  [R-BAP-1](docs/design/offline-authorization-requirements.md)). [ADR 0016](docs/adr/0016-offline-eligible-grant-claims.md)
  carries the activating-major mechanism to spec quality: the closed `{cnt, cur, max, win}` object,
  the non-authorizing facts contract (an `offline_eligible` flag + `win` only — magnitudes are read
  from the decoded grant, not redacted facts), malformed⇒`:invalid` (online-only is the *absent*
  default), a wire-layer `max × cnt` ceiling (the cross-language SDKs compute exposure in fixed-width
  integers), the `ba_dlg` attenuation composition, and the freshness scoping. **Activation is a
  successor contract-major** — the closed v1 profile rejects `ba_offline` today (the `v0.1.0`-amend
  alternative was considered and is the heavier path: the published governance change-class rule, the
  three corpus-SHA-pinning SDKs, and intra-major fragmentation). This is a design-only slice: zero
  `lib/`/`docs/protocol-v1.md`/`priv/conformance/` wire-behavior change (mirror BAP-11/BAP-14); an
  R-BAP-2 legacy-rejection tripwire is added under `test/`. The offline runtime arc (private
  `bounded_authority` BA-20..23) is successor-major-gated by this reservation.

- Close the **BAP-15 Rust verifier SDK** (Tasks 15–17 + closeout; the library Tasks 1–14 were already
  landed and verified green). `sdks/rust/tests/permissiveness.rs` is the named per-language permissiveness
  battery exercising all six ADR 0014 D6 closures through the public crate boundary (duplicate-reject,
  source-order preservation, raw-lexeme ceiling, single-value, int/float tag distinction, base64url
  pad-bits), each documented with its red-capable mutation. Closure #6 — the `(d)`-class per-node encode
  bounds — is now enforced IN `jcs_encode`'s recursion (depth + total_nodes + a per-node `jcs_bytes`
  early bail), so a hand-built value passed directly to the public primitive cannot force unbounded
  recursion, traversal, or intermediate allocation. This narrows `jcs_encode`'s accept set
  (verdict-preserving on every corpus case — all corpus inputs are decode-bounded within the same
  ceilings; verified lib 331/331, conformance 283/283); the depth and total_nodes guards are proven
  red-capable by live mutation. `sdks/rust/tools/purity_check.sh` + `license_check.sh` enforce the
  lib-path purity invariant (no I/O/clock/RNG/network/env in `src/`; `#![forbid(unsafe_code)]` is the
  compile-time `unsafe` half) and the runtime dependency-license allowlist (15 runtime deps, all
  permissive; dev-deps excluded as non-consumer-facing) — both shellcheck-clean and red-capable. The
  `rust-conformance` CI job (`.github/workflows/sdks.yml`) runs fmt + clippy + the full `cargo test`
  (unit + permissiveness + 283-vector conformance + census) + purity + license on the MSRV 1.81
  toolchain. The publish guard now scans `sdks/*/Cargo.toml` and blocks `cargo publish` /
  `cargo release publish` / `cargo-release publish` / `crate-ci/cargo-release` (ADR 0015). New docs:
  [`sdks/rust/README.md`](sdks/rust/README.md) and the deployment guide
  (`docs/deployment/rust-sdk.md`) (AWS Lambda `provided.al2023`; PostgreSQL
  `plrust` — ed25519-dalek-based verification is NOT plrust-trusted-mode-compatible as built). The three
  signed anchored-export rows in [`docs/design/conformance-contract.md`](docs/design/conformance-contract.md)
  are updated to their landed case ids. Zero wire byte, bound, or verdict change to the Elixir package.
- Close the BAP-15 prerequisite spec/corpus gaps (no-key half). `docs/protocol-v1.md` gains a
  normative **JCS string and number serialization** subsection transcribing RFC 8785 §3.2.2.2–3
  (control-range escapes, raw DEL `U+007F`, ECMAScript `Number::toString` float thresholds
  `e < -6` / `e >= 21`, `-0`→`0`, shortest-round-trip digits — both ECMA §7.1.12.1 and TC39
  §6.1.6.1.20 cited). The conformance corpus grows **259 → 280 cases**: 5 JCS float cases pinning
  both threshold sides, a raw-DEL bare-string case, an astral-codepoint (U+10000) raw-emit case, a
  float `cast_arguments` request-digest case, malformed-UTF-8-member-name and float-magnitude
  `json.decode` rejects, three malformed-IPv6 `uri.normalize` rejects, a key-locator
  protected-only (empty-segment) valid case, three `check_chain` rejects (canonical re-encode,
  sequence-zero, genesis previous-hash forge), the byte-level cross-vendor findings for
  `encode_consumption_entry` (seq-1 nonzero previous), `boundary_anchor_signing_input` (seq-0
  nonzero chain_hash), `encode_anchored_export` (start-anchor sequence binding — a signed start
  anchor carries a bogus sequence, isolating `start.sequence == first_sequence-1`), and
  `verify_anchored_export` (empty chunk). Every invalid case is a one-defect **skip-would-accept**
  construction (a verifier that drops its target check would accept it) — proven by defect-injecting
  each target check in the independent runner and confirming the case flips. The two
  `encode_/verify_anchored_export.maximum_plus_one` `n_a` reasons are corrected to name all three
  bounds (`archive_bytes` + `archive_chunks` + `historical_key_transitions`) and the loader
  representation constraint. The independent Node runner is strengthened to mirror the reference's
  IPv6-structure (node:net `isIP`, replacing a crude charset check), consumption-entry and
  boundary-anchor genesis bindings, `check_chain` positive-`first_sequence` and canonical-rehash
  (hashing the canonical re-encode, not raw row bytes, matching `ConsumptionChain.parse_row/1`),
  anchored-export start/end anchor bindings, and verify per-chunk emptiness — the invariants the new
  cases exposed; every new case is dual-verified (`agreed=280 disagreed=0`). SDK
  `CERTIFIED_INDEX_SHA` constants (Python hex + TypeScript base64url) rebind to the new `index.json`.
  The encode_anchored_export binding case's authoring key is seed-generated and never enters the
  import-boundary census (encode frames signatures, never verifies them), so
  `public_key_fingerprints` stays 8 and the manifest three-partition is unchanged.
- Close the BAP-15 prerequisite corpus gap (signed half). The conformance corpus grows
  **280 → 283 cases** with three signed `verify_anchored_export` cases exercising ADR 0004's
  authenticated key-transition path: `#2` non-monotone chronology (two transitions with non-monotone
  `effective_at` → `invalid_time`), `#2` fingerprint cycle (B→C→B → `invalid_key`), and `#3`
  one-key/zero-transition valid (the equal start/end-time same-key case). Three new seeded Ed25519
  keys join `public_key_fingerprints` (**8→11**) since the export verifier imports them; their seeds
  never enter the corpus. The independent Node runner is strengthened to mirror the reference's
  cross-transition invariants (`validate_expected_key_path`): strictly-increasing transition times,
  fingerprint no-cycle, and the end-anchor chronologically at-or-after the last transition — gates
  the per-element compact checks cannot express. Every new invalid case is a one-defect
  **skip-would-accept** construction (a monotone / no-cycle variant accepts); every new case is
  dual-verified (`agreed=283 disagreed=0`). SDK `CERTIFIED_INDEX_SHA` constants (Python hex +
  TypeScript base64url) rebind to the new `index.json`; the vector manifest's canonical fingerprint
  set grows 19→22 and the corpus partition 8→11.
- Record the SDK graduation and publish-topology decision: cross-language verifier SDKs are
  authored under `sdks/` (per [ADR 0014](docs/adr/0014-cross-language-verifier-sdks.md)) but each
  graduates to its own per-SDK repository (`bounded_authority_protocol_<lang>`) on first
  publication; the decision boundary is publication irreversibility, not SDK count
  ([ADR 0015](docs/adr/0015-sdk-graduation-and-publish-topology.md)). Zero wire byte, bound, or
  verdict change.
- Ship the ADR 0015 enforcement layer: a tracked pre-commit hook
  (`scripts/hooks/pre-commit`, single pattern source `scripts/check_sdk_publish_infra.sh`, installed
  via `scripts/install-hooks.sh`) and the `sdk-publish-guard` CI job
  ([`.github/workflows/sdk-publish-guard.yml`](.github/workflows/sdk-publish-guard.yml)) that together
  reject SDK registry-publish infrastructure committed to the monorepo. Honesty limit: catches
  committed publish infrastructure, not a literal ad-hoc publish run against a working tree; CI on
  main is the non-bypassable backstop, the local hook is honor-system. Bypass:
  `git commit --no-verify`.
- Add ROADMAP rows BAP-15 (Rust verifier SDK) and BAP-16 (Go verifier SDK) — typed reimplementations
  of the frozen v1 profile from spec + corpus alone, authored under `sdks/` and graduating per
  [ADR 0015](docs/adr/0015-sdk-graduation-and-publish-topology.md). Post-1.0 rows; no code shipped.
- Ship cross-language verifier SDKs (TypeScript `@bounded-authority/verifier` + Python
  `bounded-authority-verifier`) under `sdks/` — typed reimplementations of the frozen v1 profile from
  the spec + corpus alone, with no code-level derivation from the Elixir reference
  ([ADR 0014](docs/adr/0014-cross-language-verifier-sdks.md)). Each passes all 283 conformance vectors
  (recomputed from scratch), asserts the corpus `index.json` SHA at startup, and proves every
  permissiveness closure red-capable via a per-language mutation-gate. They are verifiers, not
  authority runtimes (no key selection, replay reservation, or execution grant). NOT in the Hex
  package `files:` (they are not Elixir). The `sdks-conformance` CI job
  ([`.github/workflows/sdks.yml`](.github/workflows/sdks.yml)) gates every `sdks/**` /
  `priv/conformance/**` change. Zero wire byte, bound, or verdict change to the Elixir package.
- Draft the capability-authorization extension as a pre-submission package for the MCP
  experimental-extension track (`docs/extensions/` — a draft `.mdx`, a draft
  Extensions-Track SEP, and an Agent Payments Protocol (AP2) mandate-mapping note;
  [ADR 0013](docs/adr/0013-capability-authorization-extension.md)), documenting the already-normative
  v1 protocol. Identifier `io.bounded-authority/capability-authorization`. Partial conformance to the
  MCP official-submission bar (SEP-2133); official submission is gated on external preconditions
  (a reference implementation in an official MCP SDK, a working group + Extension Maintainers +
  sponsor, SEP acceptance, and
  IANA registration of the `ba_*`/`ba+*` names via BAP-12). The extension documents are repo-tracked,
  excluded from the Hex package census (pre-submission drafts). Zero wire byte, bound, or verdict
  change.
- Publish the governance policy (change classes, change-control triggers, errata no-verdict-flip
  prohibition, deprecation windows, security-release handling) as a standalone normative project
  document ([docs/governance.md](docs/governance.md); [ADR 0011](docs/adr/0011-published-governance.md))
  — a companion republication of the charter § Governance, which remains the authoritative source.
  [SECURITY.md](SECURITY.md) cross-references the verdict-change rule; the
  [errata registry](docs/errata.md) header retargets to governance.md as the published policy home;
  `SECURITY.md`, `docs/governance.md`, and `docs/design/standards-track.md` join
  `.forge/critical-surfaces` (SECURITY.md a retroactive gap close since BAP-06). Zero wire byte,
  bound, or verdict change.
- Resolve a contradiction in the deprecation/security policy: the twelve-month deprecation-window
  minimum (`REQ1-EVO-deprecation-window-minimum`) is scoped to planned deprecations, and a security
  contract-major (one remediating a verdict-changing vulnerability) is exempt — its accelerated
  overlap window is published at announcement, proportional to severity, and a deployment-decided
  sunset, never a silent change ([ADR 0012](docs/adr/0012-security-release-accelerated-deprecation-window.md);
  charter § The evolution contract + § Governance; [governance.md](docs/governance.md) re-synced).
  Deployment-policy refinement only — zero wire byte, bound, or verdict change.

### Changed

- **Documentation corrections (2026-08-18 alignment-audit items 1, 4, 7).** SECURITY.md's "most
  recent package-bearing verified source" re-anchored from the BAP-06 head to the SDK
  behavioral-closure cluster head `c281938`, with the superlative date-bounded ("as of
  2026-08-18") so the claim expires visibly instead of silently: CI run 32118915019 and
  supply-chain run 32118915034 passed at that exact revision, and the doc's own verification
  recipe was re-run against the downloaded archive — checksum OK (ubuntu-built archive SHA-256
  `c9b5b0cf…`), SLSA build-provenance attestation verified constrained to this repository, the
  supply-chain workflow, `refs/heads/main`, that source digest, and GitHub-hosted runners; BAP-06
  `4c64be3` joins the earlier-heads list. The TypeScript conformance runner's startup comment
  miscited the corpus binding as "ADR 0014 D8" (enforcement posture) — corrected to D4, matching
  the file's own correct citations. usage-rules rule 13's era-frozen "BAP-04 verification is
  implemented" now states the v1 verification surface is implemented. Docs-only — no code, wire,
  bound, or verdict change.
- **Documentation reconciliation — status prose frozen at the BAP-10 era (alignment-audit items
  1–9).** `AGENTS.md` "Current state" rewritten from the tracker: names the closed set (BAP-00..06,
  08..11, 13..15, 17), the three verifier SDKs under `sdks/` (ADR 0014/0015 graduation topology,
  none published), ADRs 0001–0016, and the 283-case corpus + verifier CLI. README's status section
  corrected the same way; the BAP-07 framing in README, SECURITY.md, and the release-candidate
  contract now records the maintainer decision (Hex publication deferred — internal consumption via
  the `v0.1.0` git tag at `c65d3be`, not a registry pin). SECURITY.md now cites the most recent
  package-bearing verified head (BAP-06 `4c64be3`) with the BAP-05/BAP-04 history retained. The
  TypeScript and Python SDK READMEs no longer point Install at registry URLs that do not resolve —
  they carry the Rust README's reserved-identifier/not-yet-published framing, and "one of two" SDK
  prose corrected to three; `sdks/README.md` floor corrected to Node >= 22 with the not-published
  disclaimer. `docs/design/offline-authorization-requirements.md` status now points at the closed
  BAP-17 row (ADR 0016). ROADMAP repairs: BAP-17 added to the complete list, the Rust façade count
  corrected 15 → 17 (the exported public contract), and amendment #2's garbled closure/residual
  splice repaired so the `assemble_compact` maximum-bounds residual stands as its own sentence,
  consistent with amendment #3's restatement. Docs-only — no code, wire, bound, or verdict change.

## 0.1.0 release-candidate record — 2026-08-17 (published above as [0.1.0])

### Added

- Initialize the public Apache-2.0 repository and cold-start architecture authority.
- Define the deterministic verifier boundary, public/private dependency direction, protocol
  charter, threat model, conformance contract, ADR, and implementation roadmap.
- Close BAP-00 after public-remote verification, cross-repository documentation reconciliation,
  security-contract hardening, local-link/browser checks, independent reviews, and tamper-gate
  verification.
- Add the unpublished `:bounded_authority_protocol` 0.1.0 Mix package with zero production
  dependencies, no application callback, and no supervision tree.
- Enforce the pure-library boundary across source AST, compiled imports, application metadata,
  dependency declarations, and the exact packed/unpacked Hex archive.
- Add full local quality, coverage, documentation, advisory, closed license, CycloneDX,
  fresh-consumer, public CI, checksum, provenance-attestation, and SBOM-attestation gates.
- Freeze the normative v1 header, claim, selector, JSON, encoding, URI, domain-separator, bound,
  and fixed-error tables with primary RFC and OTP provenance.
- Add bounded ordered JSON decoding with recursive duplicate rejection, strict canonical
  base64url decoding, and a protected-header-only untrusted key locator.
- Add allow, deny, malformed, exact-boundary, deterministic malformed-input sweep, symmetric
  numeric-magnitude, package-consumer, and purity-boundary proof.
- Enforce raw numeric-lexeme bytes and exact decimal magnitude before OTP conversion; validate the
  companion Draft 2020-12 schemas with an independent validator and distinguish their structural
  code-point limits from the normative UTF-8 byte contract.
- Align the tracked roadmap with Forge's authored-row contract while preserving BAP-00 through
  BAP-07 identities and exact dependency labels.
- Document the exact public `BoundedAuthorityProtocol.V1.Json.decode/2` and
  `BoundedAuthorityProtocol.V1.Base64Url.decode/2` surfaces, tightening-only positive-integer
  limits, structural-schema boundary, and fixed value-free errors.
- Extend the packed external consumer to exercise both decoder success and rejection paths, and
  add mutation-red proof that escaped string content cannot hide a following over-limit number.
- Reconcile the BAP-02 final trusted-main receipts and degraded peer-review record.
- Add deterministic standard compact-JWS grant and RFC 9449 holder-proof producers, exact external
  signature assembly, and bounded grant/proof decoders.
- Add RFC 8785 canonical JSON, RFC 7638 public Ed25519 JWK thumbprints, bounded HTTPS URI
  normalization, type-preserving request digests, and conjunctive selector evaluation.
- Add standalone raw-grant verification and combined raw-envelope verification with exact
  issuer/audience/time/holder/request/nonce/operation bindings and redacted, non-authorizing
  verified facts.
- Add public-only grant/holder-proof vectors, independent Node verification, exact public-key
  census, meaningful byte-tamper and duplicate-member cases, portable timing/allocation bounds,
  architecture census updates, and unpacked external-consumer API proof.
- Close BAP-03 at package-bearing head `f322e08bba665374599b9f53c362966b6b59710a`
  after the supported CI matrix, complete quality/package boundary, independent Node verification,
  exact archive checksum, SLSA provenance, and CycloneDX SBOM attestation passed. The single final
  review admitted five findings; all five were fixed in one pass without review recursion.
- Add closed canonical consumption rows with domain-separated hashes and mandatory-boundary raw
  chain verification for genesis and continued ranges.
- Add deterministic standard-JWS boundary anchors and authenticated historical-key transitions,
  including derived RFC 7638 fingerprints and lower-inclusive/upper-exclusive validity windows.
- Add deterministic binary anchored-export framing and atomic raw-chunk verification of complete
  digest, exact out-of-band object version, exact EOF, ordered key rollover, both signed
  boundaries, and every canonical row.
- Add closed fixed-redacted non-authorizing chain, anchor, transition, and anchored-export facts;
  exact tightening-only archive bounds; constant-time fixed-width comparisons; and expanded
  source/BEAM architecture accounting.
- Add five Draft 2020-12 structural schemas and public-only same-key, rollover, shortened,
  relinked, same-ID/equal-time, signed cross-chain, signed reverse-time, and signed invalid-genesis
  evidence. The project-independent Node verifiers prove an exact two-way eleven-key census split
  into exact per-verifier sets observed at their public-key import boundaries,
  49 named decoded-byte, structural, boundary, coverage, chronology, and limit cases, two direct
  valid chain cases, and seven signed semantic-edge cases; the isolated mutation gate proves 47
  source-level invariants go red. Published fixture verdicts and complete redacted
  chain/anchor/transition/export facts are exact-checked rather than treated as commentary.
- Add the maximum-count, maximum-width worst-of-20 chain/archive resource gate, with every sample
  isolated in a fresh monitored process, plus ADR 0004, normative documentation, and packed
  external-consumer coverage.
- Validate every nested expected field and historical-key shape before archive hashing or parsing;
  reject duplicate outer conformance JSON members; and detect self-identifying Ed25519 PKCS#8 DER
  regardless of its surrounding field name.
- Make Ed25519 public-key/signature and SHA-256 digest widths immutable bounds so tightening cannot
  produce or admit a structurally nonconforming cryptographic value.
- Centralize strict StringOrURI validation across grant/proof and BAP-04 identifiers so malformed
  percent escapes and non-URI bytes cannot enter any producer or verifier path.
- Preserve exact package-boundary accounting across supported Elixir compiler versions and pin
  bitstring match sizes required by Elixir 1.20.
- Close BAP-04 at package-bearing head `c4d7716de6499f29524e60638207b1c36e9484b3`
  after the supported CI matrix, complete quality/package boundary, independent Node verification,
  47/47 mutation battery, maximum-shape resource gate, exact archive checksum, SLSA provenance,
  and CycloneDX SBOM attestation passed.
- Author roadmap rows BAP-08 (capability-authorization extension proposal for the MCP
  `modelcontextprotocol/ext-auth` extensions repository plus an AP2 mandate-mapping note;
  depends on BAP-04 only) and BAP-09 (thin TypeScript and Python verifier SDKs consuming only
  the published spec and vectors; depends on BAP-05). Each row's own ADR lands when its work
  starts; neither changes any wire format, limit, or verification rule.
- Close the check_envelope selector-binding gap: add a non-trivial (`equals`) selector valid case
  plus an `invalid_selector` case, teach the independent Node verifier to evaluate grant selectors,
  and add a `selector-reject` mutation — so a verifier that ignores grant selectors now fails the
  corpus. Uses two new deterministic conformance keypairs (census 6→8); a companion
  `proof_signing_input` valid case carries the new holder key as a labeled field so the
  cross-verifier census discovery scan finds it (corpus 212→215).
- Close the check_envelope authority-binding gap the same re-signing capability exposed: the
  holder (`cnf.jkt`), grant (`ath`), request-argument (`ba_req`), and operation (`ba_op`) bindings
  had no corpus case isolating them, so a verifier omitting any one of them still scored a perfect
  corpus run — omitting the holder binding accepts any holder's proof against any grant. Add four
  `invalid_claim` cases (each a one-defect variant of a shared valid base, with the named binding
  as the sole rejecter) and four matching mutation-battery entries. The `ba_op` case needs a
  hand-built proof payload: the request digest is computed over the server-derived operation, never
  over the proof's own `ba_op` claim, so only a dishonest producer — which the façade cannot be —
  emits a proof whose two operation fields disagree (corpus 215→219).
- Add an empty-path `invalid_selector` case so the independent runner's selector shape and width
  validation is falsifiable: the official rejects an empty selector path at grant decode, and a
  matcher treating `[]` as "the root" would accept what the official refuses (corpus 219→220).
- Close the independent runner's remaining permissiveness against the official decoder, so it can
  no longer certify a grant the reference implementation refuses. Six divergences, each now carried
  by a corpus case and a mutation entry: an extra member inside the closed `cnf` map; a
  non-printable byte in an operation name (the official requires printable ASCII); a structurally
  invalid selector on a NON-matching operation, and duplicate operation names (the official
  validates every operation and enforces global name uniqueness, not just the requested one); a
  lone surrogate in a selector path (the official requires valid UTF-8); and a `__proto__` member
  in a selector value, which the tagged projection silently dropped to the prototype setter so that
  two structurally different values compared equal — a collapse that reached the request digest as
  well as selector matching. Selector values are now also held to the protocol JSON bounds. The
  same operation validation is applied on `verify_grant`, which reaches the same official decode
  path (corpus 220→247; `check_envelope/invalid_encoding` 6, `verify_grant/invalid_encoding` 5).
- Add `.gitleaks.toml`: the `jwt` and `generic-api-key` rules are allowlisted for the conformance
  corpus and vector paths only, where all 283 findings are JWT-shaped high-entropy public test
  material (109 `jwt`, 174 `generic-api-key`, the latter entirely key fingerprints). Every other
  default rule still applies in those trees — a `ghp_…` token committed there is still caught —
  and every rule applies everywhere else. Stated residual: a credential matching ONLY those two
  rules, under those two machine-generated fixture directories, is not flagged.
- Complete the payload-field decode mirror, closing the last of the runner's permissiveness
  against the official decoder. The runner previously validated only the grant/proof fields the
  expected-context comparison happened to touch; it now mirrors decode_grant_fields /
  decode_proof_fields field for field — issuer/grant-id/audience StringOrURI validity and length,
  audience count bound and uniqueness, coherent times (iat<exp, nbf<exp), method token charset,
  invocation UUID shape, and htu normalization — wherever it reads a grant or proof payload
  (check_envelope, verify_grant, decode_grant, decode_proof). Nine cases on the DECODE surfaces
  (no expected context to mask the validator, so each is the sole reject reason) with six mutation
  entries prove them; corpus 236→247. One bound stays out of scope by construction: the aggregate
  total_nodes/depth budget the official applies across the whole payload cannot appear inline (such
  an input exceeds string_bytes) and these surfaces take no `.raw` sidecar, so it is exercised at
  the json.decode surface instead. Two further field checks the first mirror pass missed,
  found by the closeout review: the StringOrURI structural gate (the official validates
  iss/jti/aud through URI.new, so it rejects a non-numeric port, an unterminated IPv6
  literal, or a double `@`; the byte-only mirror accepted them — now matched to URI.new
  across a 56-input boundary set, using node:net for IPv6 literals so the mirror is neither
  looser nor stricter), and the optional proof nonce (present must be a 1..nonce_bytes
  well-formed string). Each with a decode case and mutation entry; corpus 236→247.
- Close three further runner/official divergences the final cross-vendor pass found in selector
  value validation, each now carried by a corpus case and a mutation entry: the magnitude bound
  (the official caps |value| at 9007199254740991 and rejects 2^53; the runner checked only
  finiteness), and a one-byte floor on object member keys that the official does not impose — the
  runner rejected `{"":1}`, which `Json.decode` and `Jcs.encode` both accept, making it STRICTER
  than the reference. Corpus 233→236 (a valid empty-object-key case pins the strictness fix).
- Adopt the standards track charter (ADR 0006, `docs/design/standards-track.md`,
  `docs/design/registries.md`, `docs/errata.md`): evolution above the permanently closed wire
  format via parallel contract-majors with published deprecation windows; the current profile
  named as cryptographic suite `BAP1-Ed25519-SHA256` with an ML-DSA succession path and
  cross-suite countersignature design for long-retention evidence; RFC 2119 requirement
  identifiers with corpus traceability and IANA registration templates as release-gating roadmap
  rows; delegation-with-attenuation decided (chained grants, `ba_dlg`/`ba_obo`/`ba+cap-delegated`
  reserved, the conjunctive selector algebra as the attenuation language, no caveat DSL);
  revocation and principal-binding deployment guidance homed; governance (change classes, errata
  registry with the no-verdict-flip invariant, comment-window triggers) published. No wire byte,
  bound, or verdict changes; new roadmap rows gate first publication on the unretrofittable items.
- Add the portable v1 conformance corpus (247 cases across 28 surfaces with a total
  surface × class applicability matrix, `.raw` sidecars for oversize wire inputs) and the pure
  `Conformance.Corpus`/`Runner`/`Report` core that loads, executes, and reports agreement.
- Harden the corpus against vacuous green: author the invalid vectors the crypto verifying
  surfaces were missing — algorithm-confusion (`alg:"none"`), meaningful-byte signature/commitment/
  anchor tampers (via a target-addressed tamper loader that binds a single-byte flip to the
  compact / grant / proof / row / chunk bytes), and archive/chain/envelope binding failures — plus
  exact-bound and maximum-plus-one pairs for every `json.decode` structural limit. Each new invalid
  vector is a one-defect construction confirmed rejected by BOTH the official facade and the
  independent Node runner; every remaining not-applicable applicability cell carries a falsifiable
  inexpressibility reason. The independent Node runner gained the request-binding (method / URI /
  invocation / operation / nonce) and object-name-byte checks the new vectors surfaced.
- Add the deterministic offline verifier CLI (escript `bounded_authority_conformance`,
  `--corpus DIR` required, exits 0/1/2) with an exact-path purity carve-out (File/IO in `cli.ex`,
  `System.halt` in `cli/main.ex` only) enforced by the architecture gate.
- Add the independent Node second-implementation runner
  (`conformance/corpus_independent.mjs`, node:* only) that recomputes every corpus verdict from
  scratch — making the corpus normative. Evolve the public-key census to three partitions
  (bap03 + chain_archive + corpus = the canonical set); the corpus self-census is hard two-way.
- Add stream_data property gates (JCS determinism/idempotence, base64url round-trip/pad rejection,
  URI normalization idempotence, facade closure totality) and a deterministic-PRNG fuzz gate.
- Add the source-isolated conformance mutation battery (proving the corpus integrity, CLI
  carve-out, and runner-verdict gates actually catch their named failures); wire both mutation
  batteries into `mix quality`. CI pins Node 20 for the quality job.
- Close BAP-05 with ADR 0005 (corpus formats, sidecar rule, published-artifacts definition,
  applicability matrix + n_a criterion, census evolution, CLI contract, carve-out shape,
  gate set). The corpus ships in the published package; the fresh-consumer check runs the packaged
  escript against the packaged corpus, proving published-set sufficiency.
- Close the remaining independent-runner permissiveness residuals surfaced by a cross-vendor design
  review (corpus grows 247 → 259 cases). The Node runner now mirrors the official on: the integer
  magnitude bound for every integer claim (a proof `iat` of 2^53 is rejected); the full
  `request_digest` gate on `cast_arguments` — operation validity, per-node bounds, `total_nodes`, and
  `jcs_bytes` on the type-tagged projection, not an unbounded digest; and whole-payload container
  depth on grant/proof payloads (a payload nested past depth 32 is rejected at parse). Fix the sibling
  `jsonDecode` per-node-type depth error (it rejected a 32-deep scalar-inner nest the official
  accepts — the too-strict direction that fails a conforming verifier). Twelve exact-bound /
  maximum-plus-one cases and seven source mutations pin each, each verdict confirmed against the
  official facade. ADR 0005 corrected: whole-payload depth and value-carried `cast_arguments`
  node/byte bounds are inline-expressible and now tested; only compact-carried whole-payload
  `total_nodes` and an inline 65-member `object_members` remain enforced-without-a-red-case.
- Close BAP-06: lock the 0.1.0 release-candidate public API surface (enumerated in the
  [release-candidate contract](release-candidate-contract.md) and enforced by the
  `@compiled_export_allowances` architecture-gate pin; [ADR 0008](adr/0008-release-candidate-contract.md)),
  add the `release.candidate` reproducibility gate (two cache-isolated builds, byte-equal SHA-256,
  wired into `mix quality`), and author the candidate-facing docs (release-candidate-contract.md,
  SECURITY.md, CHANGELOG `[0.1.0]`, README). Zero wire byte, bound, or verdict change. Published
  2026-08-20 — BAP-07 published the exact candidate after the connected gates passed.
