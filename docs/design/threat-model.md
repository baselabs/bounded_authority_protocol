# Threat model

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
- Over-limit input is rejected before attacker-amplified allocation or cryptography.
- Product/private dependencies, state, I/O, clock, randomness, signing, or secrets cannot enter
  the public package unnoticed.
- Errors remain fixed/value-free; `GrantFacts` and `EnvelopeFacts` inspection remains
  fixed/redacted; tracked fixtures contain no private key or seed. Other public inputs, hints,
  configuration, and explicitly unverified values retain ordinary Elixir inspection.
- A missing or surplus manifest fingerprint cannot hide keyed test material.
- A truncated, reordered, relinked, cross-chain, wrong-generation, or trailing-byte archive cannot
  satisfy exact caller boundaries and complete-object verification.
- An unauthenticated, reordered, duplicated, cyclic, reverse-time, or out-of-window key transition
  cannot advance the historical verification key.
- Literal-loopback HTTP cannot be smuggled through the standard `dpop+jwt` profile, selected from
  untrusted metadata, widened to another loopback spelling, hostname, proxy target, or non-loopback
  endpoint, or accepted without an exact server nonce.

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
  ambiguous URIs, malformed Ed25519 points/signatures, or maximum-plus-one structures.
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
host business authorization remain mandatory but are owned by the private runtime or host.
For literal-loopback HTTP, TLS confidentiality and server authentication are absent and same-host
process isolation is not provided. The host must reserve nonce and invocation before effect and
must not treat loopback reachability as caller identity.
