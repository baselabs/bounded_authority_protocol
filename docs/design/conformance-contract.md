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

The manifest's canonical public-key fingerprint set equals—not merely contains—the set observed at
the independent verifier's public-key import boundary across every tracked vector. Every fixture
key occupies a schema-declared key-bearing field, and the boundary computes RFC 7638 OKP
thumbprints instead of trusting claimed fingerprints.

The gate fails in both directions: when a listed fingerprint is removed while its key remains
reachable, and when an unreferenced fingerprint is added. Manifest membership is never a substitute
for signature, holder, or issuer verification.

## Independent implementation rule

A vector is normative only after a second implementation that imports no project code independently
recomputes canonical base64url, SHA-256/JWK thumbprints, standard JWS messages, Ed25519 validation,
`ath`, request JCS/preimage, `ba_req`, selector identity, URI normalization, and exact verdicts.
A self-round-trip proves only internal consistency. Byte drift or a manifest census mismatch exits
nonzero.

BAP-03's focused vectors and independent verifier are public repository acceptance evidence. The
Hex package continues to ship the protocol schemas and Elixir runtime only. BAP-05 owns the
portable corpus/verifier surface, and BAP-06 owns immutable candidate-archive proof.

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

`GrantFacts` and `EnvelopeFacts` are value-bearing/redacted, contain only their exact documented
fields, have fixed redacted inspection and no generic encoder, and carry
`authorization: :not_evaluated`.

## Nonconforming claims

Passing public vectors does not certify live revocation, replay prevention, key custody, issuance,
database correctness, evidence durability, archive deletion, witnesses, transport authentication,
host policy, or business-effect safety. Those require private-runtime and operational tests.

Successful decode is `verification: :not_evaluated`. Successful verification is non-authorizing
facts. The only production invalid result is `{:error, :invalid}`; offline tooling may classify
failures only if those classes cannot widen the runtime surface.
