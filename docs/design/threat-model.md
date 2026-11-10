# Threat model

This model covers every profile the package verifies: contract-majors 1 and 2 (Ed25519),
contract-major 3 (ES256 over P-256), the local-loopback HTTP proof profile, and the
role-attestation and content-assertion profiles.

## Protected properties

- A malformed or altered grant/proof cannot verify.
- A proof cannot be reused for another grant, request, operation, endpoint, holder, invocation,
  time/nonce context, or selector-disallowed argument.
- Standard JWS signing input, JCS, JWK thumbprints, URI normalization, and request digests have one
  exact byte interpretation.
- Unknown versions, fields, algorithms, extensions, or alternate encodings cannot become
  permissive compatibility.
- Untrusted input, decoded structs, or caller-provided facts cannot select an issuer key, expected
  server context, or operational authority.
- Over-limit input is rejected before attacker-amplified allocation or cryptography. This
  includes the host-supplied cast arguments: the request-digest projection enforces its depth,
  node, container, and string budgets while it walks the argument tree, on every contract-major.
- Conforming verifiers reach the same verdict for the same issuer-signed bytes. Selector values
  whose meaning differs between conforming implementations (a float zero in an `equals` value or
  a `one_of` member) are rejected at decode, and producers refuse float-tagged whole-number
  selector values ([erratum 6](../errata.md)).
- An ES256 signature verifies only in its canonical low-S form, under a public key that is a valid
  uncompressed P-256 point, so a valid signature cannot be re-encoded into a second accepted
  credential with a different digest.
- Product/private dependencies, state, I/O, clock, randomness, signing, or secrets cannot enter
  the public package unnoticed.
- Errors remain fixed/value-free; facts structs inspect as fixed redacted text; credentials, proofs,
  decoded proofs, expected requests, and signing inputs inspect with their compact credentials,
  cast arguments, nonces, and signing bytes redacted; tracked fixtures contain no private key or
  seed. Redaction protects against accidental logging only: it is not a defense against code that
  reads a field and logs it.
- A missing or surplus manifest fingerprint cannot hide keyed test material.
- A truncated, reordered, relinked, cross-chain, wrong-generation, or trailing-byte archive cannot
  satisfy exact caller boundaries and complete-object verification.
- An unauthenticated, reordered, duplicated, cyclic, reverse-time, or out-of-window key transition
  cannot advance the historical verification key.
- Literal-loopback HTTP cannot be smuggled through the standard `dpop+jwt` profile, selected from
  untrusted metadata, widened to another loopback spelling, hostname, proxy target, or non-loopback
  endpoint, or accepted without an exact server nonce.
- Bytes of one profile never verify under another: each contract-major rejects every other
  major's artifacts by their `v` claim and domain separators, and each sibling profile has its own
  protected `typ` that every other profile rejects in both directions.
- A role attestation cannot outlive its attestor key's window or attest its own attestor key; a
  content assertion cannot verify for other content bytes, another context, or outside its window,
  and a successor cannot run backward or skip its predecessor's exact digest.
- The conformance CLI reads only the files a certified corpus index names, refuses symbolic links
  and over-size files, and exits `0` only when it executed every certified case exactly once.

## Primary adversaries

- a caller controlling grant/proof bytes and model-selected arguments;
- a bearer-token thief without the holder private key;
- a holder attempting request, selector, operation, URI, algorithm, header, claim, encoding, or
  time/nonce substitution;
- a consumer treating pure verified facts as live authority;
- a contributor adding a trust-selection seam, accepting a forgeable intermediate, or weakening a
  bound;
- a fixture producer whose implementation agrees only with itself or whose manifest omits a key;
- an input sender using duplicate fields, alternate base64url, private JWK members, HTTP or
  ambiguous URIs, malformed Ed25519 or P-256 points and signatures, or maximum-plus-one
  structures, including a deeply nested or very large argument tree aimed at the request digest.
- a forger presenting a small-order or non-canonical Ed25519 key with a signature made without
  any private key, or one secret presenting several mixed-order variants of its key to evade a
  deny list or a rotation check.
- an ES256 attacker presenting the high-S twin `(r, n - s)` of a valid signature, an out-of-range
  `r` or `s`, a point off the curve or with coordinates not below `p`, or a DER-encoded signature
  where the raw form belongs.
- an issuer or holder exploiting divergent verifiers: signing bytes that one conforming verifier
  accepts and another rejects, such as a selector value whose equality depends on the sign of a
  float zero.
- an attestor presenting a self-attestation, an attestation outside its own key window, or a
  content assertion replayed for changed content or a reversed lineage.
- an archive controller supplying a validly signed shorter history, relinked omission, stale object
  generation, incomplete chunk stream, or forged historical-key path.
- local malware or another same-host process attempting proof replay, alternate-host spelling,
  `Host`/forwarding-header confusion, or cross-profile fallback against a development listener.

## Required controls

- closed bounded decoding and emitting before expensive cryptography;
- exact named structured inputs, field revalidation, explicit trusted key/context/time/bounds, and
  raw compact credentials at verification boundaries;
- exact RFC 7515 JWS, RFC 8785 JCS, RFC 7638/8037 OKP thumbprints, RFC 9449 DPoP, HTTPS URI,
  request digest, temporal, nonce, and semantic selector rules;
- no trust discovery, private key, callback, live state, side effect, or implicit clock;
- raw fixed-size hash/fingerprint comparisons and fixed value-free errors;
- strict Ed25519 verification on every Ed25519 surface (canonical point encodings, small-order
  rejection, `S < L`, and the cofactorless equation), key acceptance at every key-bearing input and
  producer, and the host torsion-free check at enrollment, trust install, and deny-list comparison
  ([`spec/bap-v1.md` § 14.1](../../spec/bap-v1.md#strict-ed25519), erratum 2);
- ES256 verification on every contract-major 3 surface: raw 64-byte `r || s` with `0 < r < n` and
  `0 < s <= n/2`, uncompressed SEC1 public keys with coordinates below `p` on the curve, and
  producer surfaces that refuse a non-canonical signature instead of normalizing it
  ([`spec/bap-v3.md` § 3](../../spec/bap-v3.md#suite-rules), erratum 3);
- producer refusal of any signature a conforming signer never emits, on every suite (erratum 3),
  and of float-tagged whole-number selector values (erratum 6);
- official and independent public-only vectors, exact two-way key-census equality, meaningful-byte
  tamper, duplicate/encoding, property/fuzz, timing/allocation, and source-isolated mutation-red
  gates;
- architecture/package tests rejecting runtime, product, private, encoder, or inspection leaks.
- a byte-distinct signed application-profile identity; exact literal-loopback URI normalization;
  mandatory nonce; one trusted caller-selected profile; real IPv4/IPv6 socket drills deriving the
  target from listener/request state rather than proxy metadata.
- mandatory caller chain/anchor/transition/digest/object-version context; exact archive EOF;
  lower-inclusive/upper-exclusive historical windows; authenticated positional rollover; and
  constant-time fixed-width hash/fingerprint comparisons.

## Adjacent controls outside this library

Trusted-key resolution, key custody, issuance, revocation ordering, replay reservation, execution
claims, evidence appends, archive privileges, witnesses, readiness, transport authentication, and
host business authorization remain mandatory but are owned by a stateful authority runtime or the
host. ES256 signing in a KMS or HSM, including DER-to-raw conversion and low-S normalization, is
the signer's duty.
For literal-loopback HTTP, TLS confidentiality and server authentication are absent and same-host
process isolation is not provided. The host must reserve nonce and invocation before effect and
must not treat loopback reachability as caller identity.
