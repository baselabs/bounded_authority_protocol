# The implementer's guide: building a conforming BAP v1 verifier

Everything a fifth implementer needs to build a verifier that passes the conformance corpus —
without reading any sibling runner's source. The normative authority is the specification
(`spec/bap-v1.md` in the repository; the package ships it); this guide is the operational
recipe.

## 1. Read in this order

1. The specification — sections 4 (conformance language), 7 (abstract data model), 8-9
   (decoding, base64url), 10-14 (wire objects, signing/digest inputs), 15-18 (chain and
   archive), 16 (verification contract), 17 (bounds).
2. The requirement map (`docs/design/requirement-map.md`) — every `REQ1-*` id to its
   conformance evidence cells.
3. This guide, then the corpus.

## 2. The conformance-runner contract

A conforming runner:

1. Loads the corpus directory: `index.json` (the integrity binding), the per-file case JSON,
   any `.raw` sidecars, and the `revision.json` sidecar (see §5).
2. Asserts the corpus identity at startup: the base64url SHA-256 of `index.json`'s exact bytes
   against the certified digest recorded in your runner (rotate it only in the same change as
   the corpus — the repository ships a regeneration script).
3. Verifies corpus integrity itself: per-file SHA-256 against the index, exact file-set
   equality both directions, per-file and total case counts, corpus-wide case-id uniqueness,
   the applicability matrix (every surface × class cell: declared count equals executed
   count; `n_a` cells execute zero), and every tamper case's verbatim artifact re-derived
   from its base case with the documented single-byte xor flip.
4. Executes every case: dispatch by `surface`, apply the case's `input`, compare the outcome
   to `expected.verdict` — valid cases must produce the expected value-bearing facts;
   invalid cases must produce the single closed error value, with no other observable.
5. Prints a machine-readable agreement report and exits nonzero on any disagreement.

Verdict comparison is total: a crash, exception, timeout, or "unsure" on ANY case is a
failure, not a skip. The reference implementations abort the run on any non-protocol error
distinct from a clean rejection.

## 3. The dispatch table

Dispatch is keyed on the case's `surface` field. The 28 surfaces:

| Surface | What it exercises |
|---|---|
| `untrusted_key_locator` | Header-only grant inspection; payload stays opaque |
| `grant_signing_input` / `proof_signing_input` | Deterministic producer: exact JWS signing input |
| `encode_consumption_entry` | Producer: canonical consumption row bytes |
| `check_chain` | Hash-chain verification over raw row bytes and caller boundaries |
| `boundary_anchor_signing_input` / `key_transition_signing_input` | Producers for anchor/transition JWS inputs |
| `encode_anchored_export` | Producer: framed archive bytes |
| `assemble_compact` | Compact JWS assembly from a signing input and a signature |
| `decode_grant` / `decode_proof` | Bounded closed decode (no signature check) |
| `verify_grant` | Grant verification against a trusted issuer and expected context |
| `verify_historical_anchor` / `verify_key_transition` | Historical-key path authentication |
| `verify_anchored_export` | Complete-archive verification (chunks, version, boundaries) |
| `check_envelope` | Combined grant+proof request verification |
| `request_digest` | The domain-separated digest over `[operation, typed(cast_arguments)]` |
| `jcs.encode` | RFC 8785 canonical serialization from the tagged algebra |
| `jwk.encode_public` / `jwk.decode_public` | Closed public OKP JWK handling |
| `jwk.thumbprint_preimage` / `jwk.thumbprint` / `jwk.thumbprint_raw` / `jwk.public_key_thumbprint_raw` | RFC 7638 thumbprints |
| `uri.normalize` | HTTPS URI normalization |
| `json.decode` | The bounded ordered JSON decoder |
| `base64url.decode` | Strict base64url |
| `bounds.new` | Tightening-only bounds construction |

The live authority for this enumeration is the corpus index's `applicability` key set; the
repository's drift gate cross-checks this guide's table against it (see §7).

## 4. The two-boundary key census

The corpus pins its public-key set two ways: every case's key-bearing inputs are fingerprinted
at DISCOVERY (the runner records every public key it encounters while executing) and at
VERIFY-IMPORT (the runner records every key actually passed to its cryptographic verify
primitive). A conforming run asserts:

```
discovered == verify-imported == index.public_key_fingerprints
```

two-way equal. This catches the two classic runner cheats: never actually verifying (empty
verify-import), and accepting fabricated keys (verify-import ⊄ corpus set). The reference
run reports 11 keys.

## 5. Corpus formats

- `index.json` — closed 5-member object: `format`, `public_key_fingerprints`, `files`
  (path, per-file base64url SHA-256, per-file case count), `total_cases`, `applicability`.
- `revision.json` — the corpus revision sidecar: closed 3-member object (format, monotone
  integer `revision`, `generated_from` provenance), hash-covered as a `files` entry and
  enforced by file-set equality. Citation target for corpus-dependent documents.
- Case files — closed objects (`format`, `provenance`, `cases`); every case carries `id`,
  `surface`, `class`, `input`, `expected`. Structural schemas (Draft 2020-12) ship under
  `priv/conformance/v1/schemas/`.
- `.raw` sidecars — opaque byte inputs, hash-bound, never parsed.

## 6. The permissiveness-mutation expectation

Your implementation must not be MORE permissive than the reference. The corpus catches most
of this by disagreement, but each language has its own trap class — prove each of these
red-capable in YOUR language (construct the defect, assert your runner rejects it, then
mechanically remove the guard and watch the test go green — that survivor is the bug):

- **Duplicate-member rejection at every depth** (e.g. `{"a":1,"a":1}`) — most language JSON
  parsers silently keep the last member.
- **Null-prototype equivalence** (the JS `__proto__` class) — constructing objects with
  prototype inheritance can make two distinct values canonicalize identically; use
  prototype-free dictionaries for the tagged algebra.
- **Raw numeric-lexeme ceiling** — the 64-byte ceiling applies to the RAW lexeme before
  conversion, with exact decimal magnitude comparison (no floating-point rounding).
- **Single-value, no trailing content** — input is exactly one complete JSON value plus
  whitespace.
- **Integer/float tag distinction** — `1` and `1.0` are different typed values with different
  request-digest projections; a language that unifies them cannot produce conforming digests.
- **Decode-depth scalar asymmetry** — containers are depth-bounded, scalars are not: a
  maximum-depth-inner SCALAR is valid where a maximum-depth-inner container is not.

## 7. Embedding the spec: the facts-anchor contract

If you embed or derive tooling from the specification: its normative tables carry
`<!-- facts:key -->` anchors (ten closed keys); a byte-deterministic extraction of the
anchored regions is the drift contract between spec, implementation, corpus, and requirement
map. The repository's own gates (extraction equality against a frozen baseline; closed-set
containment of corpus unions; requirement-map reconciliation; keyword census; anchor
completeness) are the reference implementation of that contract.

## 8. Proving it

Run the corpus. A conforming implementation reports 283/283 agreement, census two-way
equality, and the certified index digest. The reference CLI ships in the package as the shape
of the expected output. When you publish, the repository's interoperability record is where
independent implementations record their results.

## 9. Implementing the local-loopback application profile

The standard corpus above remains unchanged. The byte-distinct local-development profile is a
sibling contract defined by `spec/bap-local-loopback-http-v1.md` and certified independently under
`priv/conformance/application-profiles/local-loopback-http/v1`.

A conforming implementation exposes five separately named surfaces: URI normalization, proof
signing-input production, compact assembly, proof decode, and envelope verification. It admits
only literal `127.0.0.1` and `[::1]` HTTP authorities, requires a nonce, signs protected
`typ: "ba+loopback-proof"`, and never infers or retries the standard profile. Pin the exact profile
index SHA-256 (`10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4`), verify the declared
two-file set and per-file hashes, execute all 36 URI and 8 proof cases, then prove both directions
of cross-profile rejection. The repository's real-socket drill additionally exercises IPv4 and
IPv6 listeners plus a verifier-bypass mutation; self-round-trip corpus agreement alone is not
transport evidence.
