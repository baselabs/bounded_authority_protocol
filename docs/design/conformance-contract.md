# Conformance contract

## Normative artifacts

Each released protocol major ships language-neutral JSON fixtures containing:

- exact protected/payload JSON bytes, canonical base64url segments, standard JWS signing inputs,
  public keys, signatures, JWK thumbprints, request preimages, `ath`, and `ba_req`;
- explicit trusted issuer, expected grant/request context, and exact redacted successful facts;
- valid, boundary-near, exact-bound, and maximum-plus-one cases;
- invalid duplicate, encoding, algorithm, key, claim, time, nonce, URI, request, selector, limit,
  and meaningful-byte tamper cases.

Fixtures contain public keys only, no private key/seed, and no production values. Their schema and
ordering are versioned with the protocol major.

Every Draft 2020-12 schema validates against the canonical meta-schema with an independent
validator. Schemas remain structural companions: JSON Schema string length counts code points,
while annotated `x-bap-maximum-utf8-bytes` limits count bytes. Duplicate names, raw numeric
lexemes, decoded-size projection, depth, nodes, canonical encodings, and every byte limit remain
decoder-and-corpus checks.

## Key census integrity

The manifest partitions its canonical public-key fingerprints into exact sorted sets for each
independent verifier. Each set equals—not merely contains—the keys observed at that verifier's
standard-library public-key import boundary, and the exact union equals the canonical manifest set
across every tracked vector. Repository-wide discovery remains a supplemental private-material
and unlisted-key gate; it cannot satisfy import reach. Every fixture key occupies a
schema-declared key-bearing field, and the import boundary computes RFC 7638 OKP thumbprints
instead of trusting claimed fingerprints.

The gate fails in both directions: when a listed fingerprint is removed while its key remains
reachable, when a reached key is assigned to the wrong verifier, and when an unreferenced
fingerprint is added. Manifest membership is never a substitute for signature, holder, or issuer
verification.

## Independent implementation rule

A vector is normative only after a second implementation that imports no project code independently
recomputes canonical base64url, SHA-256/JWK thumbprints, standard JWS messages, Ed25519 validation,
`ath`, request JCS/preimage, `ba_req`, selector identity, URI normalization, and exact verdicts.
A self-round-trip proves only internal consistency. Byte drift or a manifest census mismatch exits
nonzero.

BAP-03's focused vectors and independent verifier are public repository acceptance evidence. The
Hex package ships the protocol schemas, Elixir runtime, and the portable v1 conformance corpus
(68 cases across 28 surfaces with a total surface × class applicability matrix, `.raw` sidecars
for oversize wire inputs). BAP-05's corpus is normative: a second Node implementation
(`conformance/corpus_independent.mjs`, node:* only) independently recomputes every corpus verdict
from scratch and agrees. The corpus index declares its full public-key set
(`public_key_fingerprints`); the independent runner's published-mode census is hard two-way
(observed import-boundary keys == declared, both directions, always). The manifest partitions grow
to three (bap03 + chain_archive + corpus = 17 = canonical set); the corpus partition equals the
index list. The deterministic verifier CLI (escript `bounded_authority_conformance`,
`--corpus DIR` required, exits 0/1/2) runs the pure core against any corpus directory; the report
is deterministic JCS bytes binding the index SHA-256. The `n_a` applicability criterion is
falsifiable: a cell is not-applicable only when the input algebra cannot express that class for
that surface; required cells must be ≥1, `n_a` cells must be 0, both directions enforced.
BAP-06 owns immutable candidate-archive proof.

BAP-04's public-only chain/archive corpus includes genesis, continuation, same-key boundaries,
one-step rollover, multi-step rollover, same-ID/equal-time rollover, and separately valid
shortened, relinked-omission, signed cross-chain, signed reverse-time, and signed
invalid-genesis artifacts. Its independent Node verifier imports no project code and recomputes
strict base64url, JCS, RFC 7638 fingerprints, standard JWS/Ed25519, row-domain hashes, binary
framing and digest, historical intervals, complete EOF, caller boundaries, and result verdicts.
Decoded-byte commitment/link/anchor/transition/signature/key/frame/prefix drift and transition
chronology/path mutations must exit nonzero at their intended verification stage.

## Public verifier API constraints

Conforming APIs:

- expose bounded `untrusted_key_locator/2`, returning only a closed untrusted `kid` hint;
- accept raw compact credentials, exact named structs, already-trusted public keys, expected
  context, evaluation time, and tightening-only bounds;
- revalidate every struct field at every public entry and return only closed verified facts or
  exactly `{:error, :invalid}`;
- permit standalone raw-grant verification to return `GrantFacts`, but never accept decoded/facts
  intermediates as credentials; combined verification re-verifies the raw grant;
- perform no I/O, trust discovery, private-key work, clock read, randomness, replay/state check, or
  effect;
- reject unknown extensions and ambiguous encodings and expose the protocol major in all results.
- require raw canonical rows and raw archived-object chunks, mandatory caller boundaries, exact
  out-of-band object version, exact historical public keys, and authenticated ordered rollover;
- never infer archive completeness from a self-consistent chain or treat current key status as
  evidence for a historical signature.

`GrantFacts` and `EnvelopeFacts` are value-bearing/redacted, contain only their exact documented
fields, have fixed redacted inspection and no generic encoder, and carry
`authorization: :not_evaluated`.

`ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`, and `AnchoredExportFacts` follow the same closed
redacted rule. They contain only bounded identifiers, times, counts, hashes/fingerprints, and
performed-verification labels; no row, commitment, compact JWS, signature, public-key container,
archive bytes, or object version is returned.

## Nonconforming claims

Passing public vectors does not certify live revocation, replay prevention, key custody, issuance,
database correctness, evidence durability, archive deletion, witnesses, transport authentication,
host policy, or business-effect safety. Those require private-runtime and operational tests.

Successful decode is `verification: :not_evaluated`. Successful verification is non-authorizing
facts. The only production invalid result is `{:error, :invalid}`; offline tooling may classify
failures only if those classes cannot widen the runtime surface.
