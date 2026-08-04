# ADR 0005: Portable conformance corpus and verifier CLI

- Status: accepted
- Date: 2026-08-02

## Context

BAP-05 must deliver a language-neutral conformance corpus and a deterministic offline verifier
CLI so that any implementation of the v1 protocol — the reference Elixir package, the future
BAP-09 TypeScript/Python SDKs, or a third-party implementation — can prove byte-exact agreement
with the normative v1 parsing/verification profile (ADR 0002) on the same fixed inputs. The
corpus IS the normative evidence: a wrong expected byte or a misclassified cell certifies future
nonconforming implementations, and the failure is maximally quiet (nothing fails today).

Two prior conformance surfaces existed but were each scoped to one fixture family: the
grant-holder-proof vectors (BAP-03) and the chain/archive vectors (BAP-04), each with its own
independent Node verifier. Neither covered the full surface set, neither was total (every
surface × class applicability cell), and neither had a single canonical corpus identity a
consumer could pin.

## Decision

### Corpus format

A corpus is a directory carrying an `index.json` plus case files under `cases/<area>/*.json`
and `.raw` sidecars for oversize wire inputs. The index format is
`bounded-authority-protocol-v1-conformance-corpus-index` with: `public_key_fingerprints`
(sorted; the full set of keys the corpus declares, equal to what an independent runner imports),
`files` (path / SHA-256 / case-count triples; ≤256 entries), `total_cases`, and `applicability`
(an object keyed by the 28 surface names, each with 16 class leaves — an integer count for
populated cells or `"n_a"` for not-applicable). Case file format is
`bounded-authority-protocol-v1-conformance-cases`; case members: `id`, `surface` (closed
28-value enum), `class` (closed 16-value enum), `input` (byte forms: `text` / `base64url` /
`raw_file`+`sha256_base64url` sidecar), `expected` (`verdict:"valid"` + exact outputs, or bare
`verdict:"invalid"`), and optional `tamper` (verbatim artifact + derivation descriptor).

### Sidecar rule

Inputs that exceed the corpus loader's own JSON byte bound (a wire input at the maximum-plus-one
boundary) ride as a `.raw` sidecar: the case references it by `raw_file` + `sha256_base64url`,
and the loader binds the sidecar's hash before feeding its bytes (bypassing the loader's own
decoder) to the facade. This lets the corpus pin the maximum-plus-one magnitude ceiling
(`9007199254740992` raw JSON bytes) even though that literal cannot appear in a corpus JSON file
(it exceeds the decoder's own magnitude bound by construction).

### Published-artifacts definition

The published artifact set is exactly the Hex `files:` list: `lib`, `priv/conformance/v1/corpus`
(the corpus itself), `priv/conformance/v1/schemas`, the docs, and the package metadata files.
The corpus is self-contained — an independent runner verifies against a tree containing ONLY the
corpus directory (no vectors, no schemas, no source) and agrees on every case.

### Applicability matrix + n_a criterion

Every surface × class cell is either populated (≥1 executed case) or explicitly `n_a`. The `n_a`
criterion is falsifiable and mechanical: a cell is `n/a` only when the input algebra cannot
express that class for that surface (e.g. a pure decoder has no `invalid_nonce` class). Required
cells (valid, boundary_near, exact_bound, maximum_plus_one where expressible) must be ≥1; `n_a`
cells must be 0. Enforced in both directions by both the official loader and the independent
runner, and pinned byte-exact in ExUnit.

**n_a reason obligation (Q29).** Each `n_a` leaf carries a one-line falsifiable reason naming
what the surface's input algebra cannot express: a leaf is either a positive integer count OR the
object `{"n_a": "<reason>"}` (the bare string `"n_a"` is also accepted for backward shape
compatibility, but the shipped corpus uses the object form everywhere so every not-applicable
cell is reviewable). The reason is for human review, not machine logic — the loader and the
independent runner treat `{"n_a": reason}` identically to the bare `"n_a"` string (zero executed
cases). Flipping a required cell to `n_a` therefore requires writing a mechanical impossibility
claim that review can falsify; the "author fixes the matrix too" variant of V2 is met with a
falsifiable-reason obligation, not trust. The shape, the reasons, and the loader's acceptance of
the object form are all pinned in ExUnit.

### Skip-would-accept construction discipline (BAP-05 hardening, C7)

The profile is deliberately VALUE-FREE: every implementation returns exactly `{:error, :invalid}`
with no reason, so no runner can observe *why* a case rejected, and the `class` label is author
metadata a gate cannot machine-verify against the reason. Per-class assurance for the invalid
vectors therefore rests on CONSTRUCTION, stated as a hard authoring invariant: **each invalid
vector differs from a passing valid case in EXACTLY the one dimension its class names, constructed
so that an implementation which SKIPS the check the class names would ACCEPT it.** Only then does
"rejected" ⟺ "the named check ran". Enforcement is threefold and honest about its limit: (i)
one-defect construction, reviewable per case; (ii) the valid base is a corpus case that is
ACCEPTED; (iii) the vector is REJECTED by both the official facade and the independent Node runner.
What cannot be mechanically enforced (value-free errors) is a construction discipline, not an
observed reason.

Load-bearing corollaries. `invalid_algorithm` is `alg:"none"` + an unchanged payload + the
original signature KEPT — NOT a naive `alg` swap (rejected by signature mismatch regardless of
alg-checking), nor `alg:"HS256"` + a 32-byte HMAC signature (rejected by the fixed 64-byte Ed25519
signature-width guard, not the alg check), nor `alg:"none"` + an EMPTY signature (the empty segment
is rejected by the compact structural scan BEFORE the algorithm pin runs, so it would test the
scan, not the pin — a cross-vendor finding). Keeping the original signature lets the compact pass
the structural scan so the algorithm pin is the rejecter. On the pure DECODE surfaces
(`decode_grant`/`decode_proof`), which perform no signature verification, the algorithm pin is the
SOLE rejecter of an `alg:"none"` header — removing it accepts the vector, so skip-would-accept holds
cleanly (the `alg-header-reject` mutation proves it). On the VERIFY surfaces the algorithm pin fires
first, but the signature check ALSO rejects `alg:"none"` (changing the header invalidates the
signature over the original header), so the vector is double-protected: it confirms the verifier
rejects algorithm confusion, but a single mutation removing only the algorithm pin is masked by the
signature check. This double-protection is inherent — a validly-signed `alg:"none"` token does not
exist (the algorithm has no signature to be valid under) — and is disclosed here rather than left
implied. A class that cannot be constructed to satisfy skip-would-accept by mutating an existing
valid case — i.e. it needs a validly-wrong signature — is an ESCALATION candidate kept `n_a` with a
falsifiable reason, never a silently-weaker vector. Both standing examples of this class,
`check_envelope/invalid_selector` and `check_envelope/invalid_claim`, are now CLOSED (see "Selector
binding — closed" and "Authority bindings — closed" below). Their `n_a` reasons both ended in
"re-signing, out of scope", and that constraint is exactly what the selector remediation lifted:
**once re-signing became available, every reason resting on it expired, and leaving a sibling cell
`n_a` on an expired reason is a self-contradiction the applicability gate cannot see** (it checks
only that a reason string is present). An `n_a` reason naming a PROCESS constraint rather than an
input-algebra impossibility must therefore be re-derived whenever that constraint changes — the
lesson the closeout lenses surfaced by proving three bindings unexercised.

**Selector binding — closed (BAP-05 selector remediation).** Formerly the single valid
`check_envelope` case carried an `all` selector (matches any root), so the positive selector path
was vacuous and there was no `invalid_selector` case — a verifier that ignored grant selectors still
passed the whole corpus. Now closed: a valid case with a non-trivial `equals ["record","id"]`
selector plus an `invalid_selector` case (a validly-signed grant carrying that selector, with a
proof over `cast_arguments` that satisfy `ba_req` but FAIL the selector — reaching the selector
check at `runtime.ex`'s `Selector.match_all` for the right reason, proven by a right-reason control
and a `selector-reject` mutation) exercise both directions. The independent Node verifier now
evaluates grant selectors on the `check_envelope` path (unique operation by `ba_op`, then a
conjunctive `match_all` over `cast_arguments`), so both implementations reject the `invalid_selector`
case. Applicability: `check_envelope/valid` is `2`, `invalid_selector` is `2` (the second is the
empty-path case recorded below). Re-signing required
two new deterministic conformance keypairs (the original corpus keys' private seeds are unrecoverable
— generation was throwaway), growing the corpus key census 6→8; see "Census evolution" below.
The cross-verifier discovery scan (bap03 + chain_archive `discoverPublicKeys`) finds keys in
labeled JSON fields only — it never decodes compact JWS — so every canonical key must appear in at
least one labeled field under the discovery roots. The new issuer key is carried by the selector
cases' `trusted_issuer.public_key`; the new holder key lives only inside the proof compacts, so a
companion `proof_signing_input` valid case (`proof-signing-input-valid-distinct-holder`) carries it
as a labeled `holder_public_key` input, keeping the field-discovered set equal to the canonical 19.

**Authority bindings — closed (BAP-05 selector closeout).** Closing the selector cell exposed the
same vacuity in its siblings. `check_envelope` binds nine things (`docs/protocol-v1.md` § Public
verification contract), but the corpus isolated only six: neutralizing the holder binding
(`cnf.jkt`), the grant binding (`ath`), or the request-argument binding (`ba_req`) one at a time
left the ENTIRE corpus green, so a verifier omitting any one of them scored a perfect run and would
be certified conformant. The holder-binding case is the severe one — without it any holder's
validly-signed proof is accepted against a grant issued to a different holder, a total
proof-of-possession bypass on a corpus published as normative evidence for third-party verifiers.
Now closed by three `invalid_claim` cases, each a one-defect variant of a shared valid base whose
named binding is the SOLE rejecter (right-reason controls in the generator; three matching
mutation-battery entries prove each goes red):
`check-envelope-invalid-claim-holder-binding` (proof signed by a declared key that is not the
grant's `cnf.jkt` holder), `-grant-binding` (a proof minted over grant A presented with grant B,
same holder and same arguments, so only `ath` fails), and `-request-arguments` (the harness supplies
`cast_arguments` the proof never signed; the grant carries `all`, so only `ba_req` fails).
A fourth case, `-operation-binding`, closes the `ba_op` binding. It was first claimed to be
subsumed by `ba_req` on the reasoning that the request digest covers `[operation,
cast_arguments]`; the delta review falsified that. The digest the verifier compares against is
computed from the SERVER-derived `expected.operation` (`runtime.ex:489-491`), never from
`proof.ba_op`, and nothing else in `verify_proof_parsed` reads `proof.operation` — so the binding at
`:488` is the only constraint on that holder-signed claim. Subsumption holds only for an HONEST
producer that wrote the same operation into both fields, which is precisely the assumption a
conformance corpus may not make: a dishonest holder signs `ba_op: "write"` alongside a `ba_req`
computed over `"read"`, and with the binding removed the false claim is accepted and rides into
`EnvelopeFacts.operation`. Bounded honestly, this is not an authorization bypass — grant scope
lookup and selector matching both key on `expected.operation` — but it is a spec-mandated binding
(`docs/protocol-v1.md` § Public verification contract) that the corpus could not see. The case
carries a hand-built proof payload because the producer façade derives `ba_op` and `ba_req` from
one field and therefore cannot express the defect; that inexpressibility is exactly why the binding
went unexercised.

Applicability: `check_envelope/invalid_claim` is `4`. No new keys — every case reuses the two
keypairs the selector remediation declared, so the census stays at 8.

**Independent-runner permissiveness.** A second `invalid_selector` case,
`check-envelope-invalid-selector-empty-path`, carries a grant whose `equals` selector has an EMPTY
path and a value equal to the whole `cast_arguments`. The official rejects it at grant decode
(`valid_path?` requires a non-empty path); an independent matcher that treats `[]` as "the root"
matches and accepts. The case exists so the Node matcher's shape and width validation is
FALSIFIABLE: without it the hardening would be defensive code no gate could prove, and a regression
loosening it would leave every gate green. Its mutation entry
(`check-envelope-node-selector-path-validation-removal`) proves the red. Like the `ba_op` proof,
this grant is hand-signed — the official producer refuses to build it, which is what a
nonconforming issuer would have to do.

**Independent-runner permissiveness — closed (BAP-05 selector closeout).** The runner exists to
disagree with the official; a runner that is more PERMISSIVE than the official is the one failure
that cannot surface as a disagreement on a valid corpus, because it only accepts things the corpus
does not contain. Six such divergences were found by the closeout lenses and the cross-vendor peers
and are now closed, each with a corpus case AND a mutation entry (removing the guard makes the
runner accept what the official refuses, so the corpus disagrees): the closed `cnf` map; the
printable-ASCII operation-name rule; validation of EVERY operation's selectors rather than only the
requested one; global operation-name uniqueness; UTF-8 validity of selector path segments (a lone
surrogate passes a byte-length check); and prototype safety in the tagged projection, where a
`__proto__` member was absorbed by the prototype setter so two different values canonicalized
identically — a collapse that reached `ba_req` as well as selector identity. Selector values are
also held to the protocol JSON bounds (`Jcs.encode(value, bounds)` in the official). The operation
validation is shared with `verify_grant`, which reaches the same official decode path.

The payload-field mirror completes the same closure at the decode surfaces. The runner had
validated only the grant/proof fields the expected-context comparison happened to touch; it now
mirrors `decode_grant_fields`/`decode_proof_fields` field for field — StringOrURI validity and
length for issuer/grant-id/audience, the audience count bound and uniqueness, `coherent_times?`,
the method token charset, the invocation-UUID shape, and `htu` normalization — wherever it reads a
grant or proof payload. These cases live on `decode_grant`/`decode_proof` deliberately: those
surfaces carry NO expected context, so a malformed field is rejected SOLELY by its validator, which
is why each case is non-vacuous. On `check_envelope` the same malformed field would be rejected
first by the expected-context equality (a wrong `htm` never equals the expected method), which
masks the validator and makes such a case vacuous — a trap this closeout hit and corrected by
moving the cases to the decode surfaces.

Two field checks the first mirror pass missed were found by the closeout review and closed: the
StringOrURI structural gate (the official validates `iss`/`jti`/`aud` through `URI.new`, not only the
byte set, so it rejects a non-numeric port, an unterminated IPv6 literal, or a double `@` — the
byte-only mirror accepted them; the mirror now matches `URI.new` across a 56-input boundary set and
uses `node:net` for IPv6 literals so it is neither looser nor stricter), and the optional proof
`nonce` (present must be a 1..`nonce_bytes` well-formed string). Both were reported with byte-identical
differential evidence — the reviewer built hand-signed grants/proofs and compared the official
`decode_grant`/`decode_proof` against the runner — which is the standard the field mirror is now held
to, since agreement on the corpus alone cannot catch a permissiveness the corpus does not exercise.

One bound is deliberately NOT mirrored at these surfaces, stated rather than hidden: the aggregate
`total_nodes`/`depth` budget the official applies across the WHOLE payload. An input that violates
it necessarily exceeds `string_bytes` once encoded, so it cannot appear inline in a case file, and
`check_envelope`/`verify_grant`/`decode_*` accept no `.raw` sidecar — so this boundary is exercised
at the `json.decode` surface (which does take a sidecar) rather than duplicated here. An earlier
attempt to add a whole-payload bounds pass to the runner was reverted because it duplicated the
per-field/per-selector string checks and thereby made an existing mutation vacuous — the granular
validators are the faithful and independently provable mirror.

The general lesson, recorded because it generalizes past this surface: for a differential checker,
"both implementations agree on the corpus" only constrains the runner where the corpus has cases.
Permissiveness is invisible to agreement by construction, so it must be closed by reading the
reference implementation's validators and mirroring them, then PROVING each mirror with a case that
goes red when the mirror is removed — and the case must be placed where NO other check masks the
one it targets.

The tamper verbatim-vs-derived audit binds a single-byte flip to a named `tamper.target`
(`compact` / `grant` / `proof` / `rows[i]` / `chunks[i]`), so a meaningful-byte tamper can address
the signature / key / commitment / row / anchor bytes of the cryptographic surfaces; both the
official loader and the independent Node runner re-derive base-with-one-flip and require byte
equality, so a tamper case that labels a flip it did not perform is rejected at load.

### bounds.new constant-pinning (Q31) + two-key exception

The `bounds.new` surface pins every immutable profile maximum as portable data. For every key of
the maxima table (`lib/bounded_authority_protocol/v1/bounds.ex:91-130`), the corpus carries a
tighten-to-exact-maximum case (`class: exact_bound`, verdict `valid`) and, except for the
exclusions below, a tighten-to-maximum-plus-one case (`class: maximum_plus_one`, verdict
`invalid` — widening violates the tightening-only contract). The fixed-width keys
(`public_key_bytes`, `signature_bytes`, `digest_bytes`) instead carry change-rejection cases
(`class: invalid_limit`) exercising both below- and above-max values: a fixed-width key cannot be
tightened OR widened, so its max+1 value is a fixed-width CHANGE (`invalid_limit`), not a
tightening-contract violation (`maximum_plus_one`). They therefore carry NO `maximum_plus_one`
case — the `-above` `invalid_limit` case is the max+1 pin — and the `maximum_plus_one` totality
pin excludes them alongside the magnitude keys. A second implementation with any mistyped maximum
constant fails these cases; no oversized artifact is needed to pin any constant.

**Two-key exception (mechanically forced).** `integer_magnitude` and `float_magnitude` ship the
tighten-to-exact-maximum `valid` pin only — they cannot carry the tighten-to-maximum-plus-one
member because the +1 literal (`9,007,199,254,740,992`) exceeds the decoder's own magnitude
ceiling (`lib/bounded_authority_protocol/v1/json.ex:147`, `9,007,199,254,740,991`), so any
corpus JSON file containing it is rejected by the corpus loader by construction. The `bounds.new`
input is structured JSON, so the `.raw` sidecar escape (which applies only to byte-bearing
fields) does not help. The magnitude ceiling itself is still portably pinned through `json.decode`
`maximum_plus_one` cases whose input is a `.raw` sidecar carrying the raw JSON bytes
`9007199254740992` → expected `verdict: "invalid"`. The exception and its mechanical reason are
pinned in ExUnit (the two keys' `maximum_plus_one` absence is asserted).

### Legacy-depth subsumption (V5) + the [:::] divergence

The corpus subsumes the legacy code-embedded case sets as data: all 18 legacy URI byte-values
from `conformance/bap03_independent.mjs:22-41` and the legacy duplicate-member case appear as
corpus data. The 6 idempotent-valid legacy URIs port as `uri.normalize` `valid` cases (normalized
output equals input); the 5 normalizable-but-non-idempotent legacy URIs (e.g. default-port,
uppercase-host, percent-encoded-tilde, dot-segments) port as `valid` cases whose pinned normalized
output differs from the input — faithfully subsuming the byte value AND pinning the normalization
behavior; the 6 URIs rejected by both implementations port as `invalid_uri` cases.

**`https://[:::]/` is omitted (implementation-divergent).** This one legacy URI diverges between
the two implementations: `V1.Uri.normalize/2` rejects it (`:invalid`, treating `:::` as an
invalid IPv6 literal), while the independent Node runner accepts it and normalizes it to
`https://[:::]/`. Any declared verdict makes exactly one side disagree, breaking the hard
"both sides agree (exit 0)" normativity constraint. It is therefore omitted from the corpus; the
other 17 of 18 legacy byte-values are subsumed. The divergence is recorded here (rather than
hidden) so it is visible and tracked; resolving it (harmonizing the IPv6-literal acceptance rule
across both implementations) is a frozen-profile change owned by a separate task, not a
conformance-corpus concern. The 17 port-able cases and the omission are pinned in ExUnit.


### Census evolution + index self-census

The corpus index declares `public_key_fingerprints` — the full set of public keys carried by the
corpus case data (4 valid verify-surface keys + 2 invalid_key-case keys = 6, plus the 2
selector-remediation keys = 8; the selector fixtures re-sign with a new issuer + holder keypair
because the original corpus keys' private seeds are unrecoverable). An independent
runner's published-mode census is HARD two-way: the keys observed at its crypto import boundary
must equal the index's declared set exactly, both directions, always — no softness (a vacuous
green is the V4 hole this design exists to kill). The vector manifest grows to three partitions
(bap03 + chain_archive + corpus); the three-partition union equals the canonical set (19 keys),
and the corpus partition (8) equals the index list.

The census is TWO-BOUNDARY (BAP-05 hardening): the discovery census above is the
partition-membership set (every key the fixtures carry); a SECOND assertion proves the runner
genuinely imported the verification keys — the set of keys fed to `createPublicKey` on a
verification surface (verify_grant / check_envelope / verify_historical_anchor /
verify_key_transition / verify_anchored_export + chain checks) must equal the verification keys the
corpus declares for those surfaces. Producer-only keys (raw-thumbprint signing-input surfaces that
never import a key) are exempt. This closes the hole a discovery-only census leaves open — it stays
green even if the runner never actually imports anything.

### CLI contract

The verifier is shipped as an escript `bounded_authority_conformance`. `--corpus DIR` is REQUIRED
(no default — a wrong-corpus run that exits 0 is a quiet misverification path in the tool built
to eliminate quiet misverification; the escript's `:code.priv_dir` default resolves to an
archive-internal path and a CWD-relative default silently points into a consumer's own `priv/`).
Exit 0 only on complete agreement; 1 on any integrity/verdict/coverage failure; 2 on usage error.
The report is deterministic JCS bytes binding the index SHA-256 it ran against. No clock, network,
randomness, or trust selection.

### Carve-out shape

The package remains pure (AGENTS rule 2): no runtime side-effects in the verification path. The
CLI is a single I/O carve-out — `cli.ex` does argv parsing + `File.read`/`File.ls`/`File.write`/
`File.dir?`/`IO.binwrite`/`Path.join` only, delegating every judgment to the pure
`Corpus`/`Runner`/`Report` core; `cli/main.ex` is the two-line escript entry (`System.halt`). The
architecture gate keys the allowance per-file-per-function (a `System.halt` in `cli.ex` is denied;
a `File.write` in `cli/main.ex` is denied), and no module outside `conformance/` may reference the
`Conformance.Cli` module. A new ignore-modules pin asserts `test_coverage[:ignore_modules]` equals
exactly `[Cli.Main]`.

### Gate set + battery placement

The conformance surface is gated by: corpus integrity (per-file SHA-256, file-set equality both
directions, counts, case-id uniqueness, applicability totality both directions, tamper
verbatim-vs-derived, `.raw` hash binding); the official CLI; the independent Node runner (proves
normativity — a value that only round-trips the official implementation is not normative until an
independent runner agrees); property + fuzz gates (facade closure totality — every input returns
`{:ok,_}|{:error,:invalid}`, never raises); and a source-isolated mutation battery proving every
named integrity check and the carve-out keying actually catch the failures they claim. Both
mutation batteries (chain_archive + conformance) run in `mix quality` (measured basis ~155s +
the existing battery, under the 8-minute threshold).

### Package-files decision

The corpus ships in the published package (`files:` += `priv/conformance/v1/corpus`), and the
fresh-consumer package check runs the packaged escript against the packaged corpus, proving the
published set is sufficient for verification.

## Consequences

- A second implementation that disagrees with the corpus is a conformance failure by definition;
  the corpus is now the arbiter, not the reference implementation.
- Adding a new surface requires populating its applicability row and landing cases for every
  populated class, or the corpus fails to load.
- The index's `public_key_fingerprints` must track the corpus case data exactly; adding a
  verify-surface case with a new key requires updating the index + manifest partition + canonical
  set in the same commit.
- The CLI carve-out is the package's only I/O surface; widening it (a second File/IO call outside
the exact allowance) turns the architecture gate red and the mutation battery red.
- Every `n_a` applicability cell carries a falsifiable reason (`{"n_a": "<reason>"}`); removing a
  reason or weakening it to a bare `"n_a"` is a visible diff against the pinned reason set, and
  the loader rejects any leaf that is neither an integer, the bare `"n_a"`, nor the exact
  `{"n_a": <string>}` shape.
- Adding a new maxima key requires landing both the `exact_bound` and (except for magnitude keys)
  the `maximum_plus_one` `bounds.new` pins, or the Q31 pin goes red.
