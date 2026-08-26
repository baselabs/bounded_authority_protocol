<!-- DERIVED VIEW — generated from spec/bap-v1.md; DO NOT EDIT.
     Regenerate: mix run --no-start spec/tools/render_derived.exs --write -->

# Bounded Authority Protocol v1 Wire Profile

Document status: normative for contract-major 1. Document revision: rev 1. This document is the
single normative authority for the v1 wire profile. It is authored to be verifiable in-repo: a
machine extraction of its normative tables is frozen and drift-gated, and every requirement
statement carries a stable requirement identifier mapped to conformance evidence. It makes no
submission claim about any external venue.

A conforming implementation rejects every unlisted member, value, encoding, or extension with a
single closed error value. Successful decode or verification is not a trust-selection or
authorization decision: verification produces facts, never authority (see (#verification)).

## 1. Introduction

The Bounded Authority Protocol (BAP) is a provider-neutral, deterministic profile for bounded
proof-of-possession authority. A grant binds an issuer's key to a holder's key and to a closed
set of permitted operations; a holder's proof binds one request to exactly one grant; a
consumption chain and its archived export bind a sequence of commitments to signed boundaries
and an authenticated historical-key path. Every artifact is small, closed, and independently
verifiable with public keys only.

The profile defines canonical grant, proof, request-binding, consumption-chain, and archive
formats; pure verification functions; and an independently executable conformance corpus. It
does not grant operational authority by itself: key custody, trusted-key discovery, issuance,
revocation state, replay reservation, and every operational decision belong to a stateful
authority runtime outside this profile.

## 2. Terminology

grant:
: A closed, issuer-signed capability object binding an issuer key, a holder key thumbprint,
  temporal validity, and a closed set of permitted operations.

proof:
: A closed, holder-signed request-binding object in the DPoP family [RFC9449], binding one
  HTTP method, target URI, invocation identifier, operation name, request digest, and the grant
  digest.

facts:
: The value-bearing, redacted, non-authorizing results of successful verification. Facts state
  what was cryptographically checked; they carry explicit not-evaluated markers for trust and
  authorization and are never execution credentials.

compact value:
: The RFC 7515 compact JWS serialization `BASE64URL(protected) "." BASE64URL(payload) "." BASE64URL(signature)`.

tagged algebra:
: The profile's abstract JSON data model (see (#datamodel)), which preserves scalar-type
  distinctions that raw JSON text does not.

contract-major:
: The leading integer of the profile version (v1). Successor majors carry complete, closed,
  parallel profiles.

## 3. Overview

An issuer mints a grant over a holder's public-key thumbprint and a closed operation set. To
act, the holder presents the grant compact value together with a freshly signed proof whose
`ath` claim is the SHA-256 of the exact grant compact bytes and whose request digest covers the
server-derived operation and typed arguments. A verifier with the issuer's public key and the
expected request context checks every binding and returns redacted facts. Consumption of an
authorized request is recorded as a canonical row in a hash chain; boundary anchors sign a
range's ends; key transitions authenticate the historical key path; and an anchored export
packages header, anchors, transitions, and rows as length-framed bytes with an exact EOF, so an
offline verifier can re-derive and check every byte against caller-supplied boundaries and an
out-of-band stored-object version.

Every closed set in this profile is exactly that — closed. The rejection of everything unlisted
is not a defensive posture but the profile's central safety invariant.

## 4. Conformance language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals,
as shown here. Lowercase forms carry their normal English meaning and impose no requirement.

The closed-rejection rule is the profile's central invariant (`REQ1-CORE-reject-unlisted`): a
conforming implementation rejects every unlisted member, value, encoding, or extension. It is
stated once here as the rationale; each per-section closed-set statement below is its own MUST
(`REQ1-HEADER-closed-set`, `REQ1-CLAIM-closed-set`, ...) and maps to the conformance cells of
the surface it governs. Requirement identifiers are stable and their mapping to conformance
evidence is published in the requirement map (Appendix C locates the companion artifacts).

## 5. Suite identity

This profile constitutes the cryptographic suite `BAP1-Ed25519-SHA256`: EdDSA over Ed25519
[RFC8032] [RFC8037], SHA-256 digests, RFC 8785 canonical bytes [RFC8785], and the `BAP1-*`
domain separators, with the fixed widths listed in the bounds table (#maxima). Every artifact
self-declares this identity through its `v` claim, `typ` header, `alg` value, and domain
separators. Evolution happens above this profile, never inside it: successor contract-majors
carry their own complete closed profiles and suites, a proof's contract-major MUST equal its
grant's (`REQ1-CORE-proof-major-equals-grant`), and the closed-rejection rule above is exactly
what makes parallel majors safe — an artifact of any other major or suite fails closed here
(`REQ1-CORE-cross-major-reject`).

## 6. Normative references

[RFC2119]: Key words for use in RFCs to Indicate Requirement Levels
[RFC8174]: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
[RFC8259]: The JavaScript Object Notation (JSON) Data Interchange Format
[RFC8785]: JSON Canonicalization Scheme (JCS)
[RFC4648]: The Base16, Base32, and Base64 Data Encodings
[RFC7515]: JSON Web Signature (JWS)
[RFC7519]: JSON Web Token (JWT)
[RFC7638]: JSON Web Key (JWK) Thumbprint
[RFC8032]: Edwards-Curve Digital Signature Algorithm (EdDSA)
[RFC8037]: Algorithm Identifiers for Ed25519 in JOSE
[RFC3986]: Uniform Resource Identifier (URI): Generic Syntax
[RFC6838]: Media Type Specifications and Registration Procedures
[RFC9449]: OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)

These references supply generic encodings. The closed fields, values, digest prefixes, and
bounds in the sections below are this profile's choices.

## 7. Abstract data model {#datamodel}

The profile's data model is a tagged JSON algebra: a closed set of typed values that preserves
the distinctions raw JSON text does not (an integer versus an integral float; source member
order; duplicate-name rejection before any map conversion).

- A decoded value is exactly one of: null, boolean, integer, non-integer finite number, string,
  array of values, or object of (name, value) members.
- Objects retain source member order and never collapse duplicate names: a duplicate name at
  any depth is rejected before map conversion (`REQ1-JSON-no-duplicate`). Input MUST be one
  complete RFC 8259 value followed only by JSON whitespace (`REQ1-JSON-single-value`). UTF-8 is
  mandatory; strings are preserved without Unicode normalization
  (`REQ1-JSON-no-normalization`).
- Before number conversion, the decoder scans raw RFC 8259 number lexemes outside strings,
  enforces the lexeme byte ceiling of the bounds table, and compares exact decimal magnitude
  without floating-point rounding (`REQ1-JSON-raw-lexeme`). Integers and finite floats are
  bounded symmetrically to `-9007199254740991..9007199254740991`
  (`REQ1-JSON-number-bounds`).

The typed projection below maps the tagged algebra onto closed JSON for digest construction:
each tagged value projects to a two-element array whose first element names the type, so an
integer and an integral float never canonicalize identically. JCS orders projected object
members.

<!-- facts:digest-constructions -->
Grant and proof compact values use the exact RFC 7515 signing input:

```text
ASCII(base64url(protected) || "." || base64url(payload))
```

No bytes precede or follow it (`REQ1-SIGNING-exact-input`). Verification uses the exact received
segments; correctly signed closed JSON objects may use any member order (`REQ1-SIGNING-any-order`).
Producers emit one deterministic JCS representation (`REQ1-SIGNING-deterministic-produce`).

The verifier validates the fixed 32-byte public-key and 64-byte signature encodings, completes
all bounded parsing and contextual checks, and then delegates Ed25519 verification to the
underlying cryptographic backend. A backend rejection or exception returns exactly the profile's
closed error value (`REQ1-SIGNING-backend-reject`).

The request digest is:

```text
base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
```

The prefix is exact ASCII including its final zero byte (`REQ1-SIGNING-digest-prefix`). `typed/1`
projects the tagged JSON algebra to the following closed JSON form before JCS:

| tagged value | projected JSON |
|---|---|
| `:null` | `["null"]` |
| `{:boolean, value}` | `["boolean", value]` |
| `{:integer, value}` | `["integer", value]` |
| `{:float, value}` | `["float", value]` |
| `{:string, value}` | `["string", value]` |
| `{:array, values}` | `["array", [typed(value), ...]]` |
| `{:object, members}` | `["object", {member: typed(value), ...}]` |

<!-- facts:domain-separators -->
JCS orders projected object members. The explicit scalar tags preserve the protocol's semantic
distinction between an integer and an integral float even though RFC 8785 emits both numeric
payloads with the same JSON number bytes. `cast_arguments` may be any tagged JSON value.
The `BAP1-*` domain separators below are the suite-identity markers of `BAP1-Ed25519-SHA256`
(a successor suite binds its own `BAP<contract-major>-*` separators under its own major).
`BAP1-CHAIN\0` and `BAP1-ARCHIVE\0` remain reserved for the chain and archive constructions
of (#chain) and (#archive). The retired `BAP1-GRANT\0` and `BAP1-PROOF\0` strings are invalid
signing prefixes (`REQ1-SIGNING-retired-prefixes`).

## 8. JSON decoding and canonical serialization

A conforming decoder produces the tagged algebra of (#datamodel) under the resource limits of
(#maxima): raw and decoded sizes precede decoding; structure and scalar limits apply while
decoding; all precede cryptography (`REQ1-BOUNDS-ordering`).

Canonical serialization emits RFC 8785 bytes from the tagged algebra only. String escaping
follows RFC 8785 section 3.2.2.2 exactly: the ASCII control range `U+0000..U+001F` serializes
as `\b`, `\t`, `\n`, `\f`, `\r` for `U+0008/0009/000A/000C/000D` respectively and as lowercase
`\u00XX` for every other control code point; every other code point serializes as its UTF-8
encoding unless it is `U+005C` (`\\`) or `U+0022` (`\"`). `U+007F` (DELETE) is outside the
control range and is emitted as the raw byte `0x7f`. Lone surrogates are rejected.

Number serialization follows RFC 8785 section 3.2.2.3 (the ECMAScript `Number::toString`
operation): a finite float serializes as the shortest decimal text that round-trips under
binary64, fixed or scientific by the decimal exponent `e` of the leading digit — scientific
when `e < -6` or `e >= 21` (lowercase `e`, mandatory exponent sign), fixed otherwise. `0.0` and
`-0.0` both serialize as `0`. An integer serializes as plain decimal text with no exponent.
Non-finite floats are rejected (`REQ1-JSON-jcs-exact`).

## 9. Base64url

Segments use only `A-Z`, `a-z`, `0-9`, `-`, and `_` (`REQ1-B64-alphabet`). Padding and
whitespace are forbidden (`REQ1-B64-no-padding`). Length modulo four equal to one is invalid
(`REQ1-B64-length`). Decoding succeeds only when unpadded re-encoding reproduces the input
exactly, rejecting non-zero unused pad bits and alternate encodings
(`REQ1-B64-canonical`).

## 10. Protected headers

The protected headers bind the suite `BAP1-Ed25519-SHA256` via their `alg` and `typ` values.
Member order is insignificant and the member sets are exact:

<!-- facts:header-members -->
| Compact value | Members |
|---|---|
| grant | `alg: "EdDSA"`, `typ: "ba+cap"`, `kid: key_identifier` |
| proof | `alg: "EdDSA"`, `typ: "dpop+jwt"`, `jwk: public_OKP_JWK` |

`crit`, `b64`, embedded grant keys, unknown algorithms, and every unlisted member are invalid
(`REQ1-HEADER-closed-set`). Grant `kid` is a case-sensitive 1–128 byte string of ASCII letters,
digits, `-`, `.`, `_`, or `~` (`REQ1-HEADER-kid-bytes`). It is an untrusted hint, not a trust
selector (`REQ1-HEADER-kid-not-selector`).

The proof JWK is exactly `{crv: "Ed25519", kty: "OKP", x: canonical_base64url_32_bytes}` in any
member order (`REQ1-HEADER-proof-jwk`). Every additional member, including private `d`, is
invalid (`REQ1-HEADER-no-private-jwk`). Its RFC 7638 thumbprint preimage is exactly:

```json
{"crv":"Ed25519","kty":"OKP","x":"<canonical-x>"}
```

The thumbprint is unpadded base64url SHA-256 of those UTF-8 bytes (`REQ1-HEADER-thumbprint`).
Verified facts carry the raw 32-byte digest (`REQ1-HEADER-digest-width`). Issuer-key
fingerprinting uses the same construction over the caller's raw 32-byte public key; `kid` is
excluded (`REQ1-HEADER-issuer-fingerprint`).

## 11. Claims

All claim objects are closed (`REQ1-CLAIM-closed-set`). Names and string values are
case-sensitive (`REQ1-CLAIM-case-sensitive`).

<!-- facts:grant-claims -->
| Grant claim | Type |
|---|---|
| `v` | integer, exactly `1` |
| `iss`, `jti` | non-empty StringOrURI, at most 512 UTF-8 bytes |
| `aud` | one StringOrURI or a nonempty unique array of at most 64 |
| `iat`, `nbf`, `exp` | integral NumericDate |
| `cnf` | exact object `{jkt: canonical_base64url_sha256}` |
| `operations` | nonempty array of at most 64 operation objects |

An operation is exactly `{name: string, selectors: selector_array}`. Names are unique within the
grant and contain 1–128 printable ASCII bytes. The ordered selector array has 1–64 members
(`REQ1-CLAIM-operation-shape`).

<!-- facts:proof-claims -->
| Proof claim | Type |
|---|---|
| `v` | integer, exactly `1` |
| `jti` | non-empty StringOrURI, at most 512 UTF-8 bytes |
| `htm` | 1–32 byte case-sensitive RFC 9110 HTTP method token |
| `htu` | normalized hierarchical HTTPS target URI |
| `iat` | integral NumericDate |
| `nonce` | optional non-empty string, at most 512 UTF-8 bytes |
| `ba_inv` | lowercase RFC 4122 UUID |
| `ba_op` | 1–128 byte printable ASCII operation name |
| `ath`, `ba_req` | canonical unpadded base64url SHA-256 |

Every proof requires every row except `nonce`; no other claim is accepted
(`REQ1-CLAIM-proof-required`, `REQ1-CLAIM-no-extra`). `ath` is SHA-256 over the ASCII bytes of
the complete received grant compact value (`REQ1-CLAIM-ath`). The method accepts ASCII letters,
digits, the punctuation bytes ``! # $ % & ' * + - . ^ _ | ~``, and grave accent
(`REQ1-CLAIM-htm-bytes`). It is compared byte-for-byte and is never case-normalized
(`REQ1-CLAIM-htm-no-case-normalize`).

The grant `v` claim MUST be exactly the integer `1` (`REQ1-CLAIM-v`). The proof `v` claim MUST
be exactly the integer `1` (`REQ1-CLAIM-proof-v`).

## 12. Selector algebra

Selectors are closed ordered objects with exactly one of three recognized member sets:
`{kind}`, `{kind,path,value}`, or `{kind,path,values}`
(`REQ1-SELECTOR-closed-set`). The `kind` selects how that recognized set is interpreted:

<!-- facts:selector-kinds -->
| Kind | Recognized members and interpretation |
|---|---|
| all | Any recognized member set; `path`, `value`, and `values` are inert when present |
| equals | Exactly `{kind: "equals", path: path, value: JSON_value}` |
| one-of | Exactly `{kind: "one_of", path: path, values: non_empty_JSON_array}` |

An `all` selector's inert members remain subject to the enclosing bounded JSON decoder but do
not need to satisfy the active `equals` or `one_of` shapes. No other member combination is
recognized.

A path has 1–32 object-member names, each 1–128 UTF-8 bytes. Paths traverse objects only and
never index arrays (`REQ1-SELECTOR-path-shape`). `one_of` contains at most 256 values
(`REQ1-SELECTOR-one-of-size`).

Selectors are applied conjunctively to the server-derived tagged arguments. `all` matches any
JSON root. `equals` and `one_of` require the path to exist (`REQ1-SELECTOR-path-required`).
Semantic identity preserves tagged scalar distinctions, compares arrays positionally, and
compares duplicate-free objects recursively as unordered key/value sets
(`REQ1-SELECTOR-semantic-identity`). It never gives source member order meaning or collapses
integer and float tags (`REQ1-SELECTOR-no-tag-collapse`). No selector grants business
authorization (`REQ1-SELECTOR-not-authorization`).

## 13. URI normalization

Target URIs are bounded ASCII, hierarchical, and HTTPS-only, with a nonempty authority and host
and no user information, fragment, or query. Normalization lowercases scheme and host;
uppercases percent hex; decodes only percent-encoded unreserved octets; preserves
percent-encoded reserved octets as path data; removes complete dot segments; maps an empty path
to `/`; drops port 443; and preserves a valid nondefault port and all other path bytes. It
performs no DNS, IDNA, or network work.

The host uses the exact RFC 3986 grammar: `reg-name` contains only unreserved, sub-delim, or
valid percent-encoded octets; IPv4 uses exact `dec-octet` forms without leading-zero
alternatives; and a bracketed IP literal contains a complete IPv6address or IPvFuture. A
present port is one or more decimal digits in `1..65535`; its canonical form removes leading
zeroes and omits `443`. Empty ports and malformed IPv4, IPv6, or IPvFuture literals are
invalid.

HTTP, another scheme, an authority-less form, malformed percent escapes, ambiguous
authority/port syntax, control/non-ASCII bytes, and out-of-range ports are invalid
(`REQ1-URI-reject-list`). Both expected and proof URIs MUST already equal the normal form
(`REQ1-URI-pre-normalized`); the normalizer performs no DNS, IDNA, or network work
(`REQ1-URI-no-network`).

## 14. Signing and digest inputs

See (#datamodel) for the exact signing input, the request-digest construction, the typed
projection, and the `BAP1-*` domain separators.

## 15. Consumption chain and anchored export {#chain}

<!-- facts:archive-framing -->
### Consumption rows

One row is the closed JCS object:

```json
{"chain_id":"<StringOrURI>","commitment":"<base64url-32>","previous":"<base64url-32>","sequence":1,"v":1}
```

Its raw hash is `SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)`. Sequence one requires the
all-zero predecessor. Verification accepts a nonempty proper list of raw row binaries and an
expected-chain context; it requires exact canonical bytes, chain identity, consecutive
sequence, predecessor links, row count, first/last sequence, caller predecessor, and caller
head.

### Boundary anchors

A boundary anchor is standard compact JWS with exact protected header
`{"alg":"EdDSA","kid":"...","typ":"ba+chain-anchor"}` and a closed JCS payload binding protocol
version, anchor identity and time, chain identity, sequence, chain hash, and the RFC 7638
fingerprint derived from the raw Ed25519 public key. Sequence zero requires the all-zero hash.

The caller supplies one exact historical public key and expected-anchor context. Verification
requires the signed values, key ID, derived fingerprint, Ed25519 signature, and
`valid_from <= anchored_at < valid_before`; an unbounded upper interval is the only open one.

### Authenticated key transitions

A transition is standard compact JWS with exact protected type `ba+key-transition`. Its closed
payload binds transition and chain identities, effective time, current fingerprint, next key
ID, and next fingerprint. The current key signs it. Current and next public keys/fingerprints
must differ, while their key IDs may be equal; the effective time must lie in both historical
intervals.

An anchored export advances through the caller-supplied ordered key list positionally.
Transition times strictly increase, fingerprints cannot cycle, the start anchor precedes every
transition, and the end anchor is at or after the last transition, including exactly at its
effective time. Equal start/end times are permitted only for the no-transition same-key case.

### Anchored export framing {#archive}

The archive is the exact binary concatenation:

```text
"BAP1-ARCHIVE\0EXPORT\0"
frame(canonical_header)
frame(start_anchor_compact)
frame(each ordered transition_compact)
frame(each canonical row)
frame(end_anchor_compact)
EOF
```

Every frame is `UINT32_BE(nonzero_length) || bytes`. The closed header binds chain identity,
first/last sequence, row count, transition count, predecessor, head, and version one.
Verification scans a bounded nonempty proper flat chunk list incrementally, requires exact EOF,
hashes every raw byte, and compares the raw SHA-256 digest in constant time. It also requires
exact equality between the observed object-store version and caller-supplied expected version.
The version is out-of-band context; it is not embedded in the archive.

The verifier authenticates both anchors and every transition, checks all rows again, and
requires the authenticated start/end tuples to equal the caller's chain boundaries. Producer
results and facts are not accepted as stored objects or credentials.

The archive-byte ceiling is exactly:

```text
20 + 8,196 + 2 × 8,196 + 256 × 8,196 + 65,536 × 4,100
```

## 16. Public verification contract {#verification}

The verification surfaces are: the untrusted key locator; grant and proof signing-input
construction; compact assembly; grant and proof decode; grant verification; combined
envelope checking; request-digest construction; consumption-entry encoding; chain checking;
boundary-anchor and key-transition signing-input construction; anchored-export encoding and
verification; and the versioned primitives (canonical serialization, public JWK encode/decode
and thumbprints, URI normalization, bounds construction).

Every verification function is a pure function from caller-supplied bytes and caller-supplied
trusted inputs and expected context to one of: a value-bearing, redacted facts result, or the
single closed error value (`REQ1-VERIFY-revalidate` revalidates every structured input field at
each public boundary). Verification never selects trusted keys, reserves replay, checks live
revocation, grants execution, or overrides a host policy. Compact assembly accepts exactly a
signing input and a 64-byte signature — never a key, signer, or callback
(`REQ1-VERIFY-no-signer-callback`).

<!-- facts:error-shape -->
Every function returns `{:ok, value}` or exactly `{:error, :invalid}` (`REQ1-VERIFY-return-shape`).

Decode results carry an explicit verification-not-evaluated marker
(`REQ1-VERIFY-decode-not-evaluated`). Grant and envelope facts carry an explicit
authorization-not-evaluated marker (`REQ1-VERIFY-grant-not-authorized`); chain, anchor, and
transition facts carry only the trust marker. Facts are value-bearing and redacted, with fixed
redacted rendering and no generic encoder, string, or enumeration protocol
(`REQ1-VERIFY-facts-redacted`, `REQ1-VERIFY-facts-not-credentials`). No facts result contains
arguments, selector values, raw credentials, signatures, JWK containers, or nonces, and no
facts result is accepted as credentials.

Grant verification requires exact key ID, signature, issuer, and audience
(`REQ1-VERIFY-grant-exact`); coherent signed times `iat < exp` and `nbf < exp`
(`REQ1-VERIFY-grant-times`); and independently:

```text
iat <= evaluation_time + skew
nbf <= evaluation_time + skew
exp > evaluation_time - skew
```

It does not require `iat <= nbf` (`REQ1-VERIFY-no-iat-nbf-order`). Skew is at most 60 seconds and proof maximum age at most 300
seconds (`REQ1-VERIFY-time-bounds`). Proof time is inclusive:

```text
evaluation_time - proof_max_age - skew <= iat <= evaluation_time + skew
```

The nonce is absent in not-required mode and present exactly once and equal in required mode
(`REQ1-VERIFY-nonce-mode`). Combined verification re-verifies the raw grant; verifies holder
signature and thumbprint; and binds `ath`, method, URI, invocation, operation, request digest,
time, nonce, and every selector (`REQ1-VERIFY-envelope-binding`).

Chain verification accepts raw canonical row bytes and mandatory caller boundaries
(`REQ1-CHAIN-raw-rows-bounds`). Anchored-export verification accepts only the raw archive
chunks, the stored-object version, an ordered historical public-key chain, and complete
expected chain/anchor/transition/digest/object-version context
(`REQ1-EXPORT-input-shape`). It scans and hashes the complete archive, requires exact EOF,
authenticates both boundaries and every positional transition, and then independently checks
every row (`REQ1-EXPORT-complete-scan`). The stored-object version is exact out-of-band
expected context (`REQ1-EXPORT-version-exact`). Commitment preimages remain opaque and private
(`REQ1-EXPORT-preimage-private`). A self-consistent chain does not certify that no row was
deleted: validly signed shortened or relinked artifacts fail only when compared with the
original caller boundaries (`REQ1-CHAIN-no-deletion-cert`). Successful facts state the
performed cryptographic checks and always retain the trust-not-evaluated marker
(`REQ1-CHAIN-facts-not-evaluated`); chain, anchor, and transition facts make no authorization
field part of their exact public shape (`REQ1-CHAIN-facts-shape`).

Language bindings, the frozen reference API surface, and the companion artifact locations are
informative (Appendix C).

## 17. Hard maxima {#maxima}

<!-- facts:bounds -->
| Resource | Maximum |
|---|---:|
| compact input bytes | 65,536 |
| encoded segment bytes | 32,768 |
| decoded segment bytes | 24,576 |
| raw JSON bytes | 65,536 |
| nesting depth | 32 |
| members per object | 64 |
| items per array | 256 |
| total JSON value nodes | 4,096 |
| string bytes | 8,192 |
| object-name bytes | 128 |
| numeric lexeme bytes | 64 |
| integer magnitude | 9,007,199,254,740,991 |
| float magnitude | 9,007,199,254,740,991 |
| `kid` bytes | 128 |
| JCS output bytes | 65,536 |
| normalized target URI bytes | 8,192 |
| issuer, audience, or token identifier bytes | 512 |
| nonce bytes | 512 |
| HTTP method bytes | 32 |
| operation name bytes | 128 |
| audiences per grant | 64 |
| operations per grant | 64 |
| selectors per operation | 64 |
| selector path segments | 32 |
| values in `one_of` | 256 |
| Ed25519 public key / signature bytes | 32 / 64 |
| SHA-256 digest bytes | 32 |
| clock skew seconds | 60 |
| proof maximum age seconds | 300 |
| canonical consumption row bytes | 4,096 |
| consumption rows per range | 65,536 |
| boundary anchor or key-transition compact bytes | 8,192 |
| anchored-export header bytes | 8,192 |
| historical key transitions | 256 |
| anchored-export chunks | 65,796 |
| anchored-export bytes | 270,820,384 |
| object-store version bytes | 512 |

Callers MAY tighten resource ceilings with a positive integer (`REQ1-BOUNDS-tighten-only`). The
32-byte public-key and digest widths and 64-byte signature width are the immutable
cryptographic constants of the suite `BAP1-Ed25519-SHA256` — they are protocol constants, MUST
remain exact (`REQ1-BOUNDS-fixed-widths`), and cannot be tightened or widened (a successor
suite carries its own widths under its own contract-major). Unknown, non-integer, zero,
negative, widening, or fixed-width-changing limits are invalid
(`REQ1-BOUNDS-reject-list`). Raw and encoded sizes precede decoding; decoded-size projection
precedes allocation; structure and scalar limits apply while decoding/emitting; all precede
cryptography (`REQ1-BOUNDS-ordering`).

## 18. Untrusted key locator

The locator bounds the complete compact input, requires exactly three segments, then bounds,
decodes, and validates only the protected grant header
(`REQ1-LOCATOR-three-segments`). The payload and signature stay opaque
(`REQ1-LOCATOR-opaque-payload`). It returns only the key identifier and an explicit
trust-not-evaluated marker. It does not select a key, decode claims or signature bytes, verify,
evaluate trust, or authorize (`REQ1-LOCATOR-not-authority`,
`REQ1-LOCATOR-no-value-leak`). Every failure returns the closed error value without input
values (`REQ1-LOCATOR-no-value-leak`).

## 19. `typ` values

The `typ` registry of this profile:

<!-- facts:typ-values -->
| Value | Status | Purpose |
|---|---|---|
| `ba+cap` | active | Capability grant (compact JWS) |
| `dpop+jwt` | active | Holder proof (RFC 9449) |
| `ba+chain-anchor` | active | Signed consumption-chain boundary anchor |
| `ba+key-transition` | active | Authenticated historical-key transition |
| `ba+cap-delegated` | reserved | Delegated attenuated grant |
| `ba+suite-attestation` | reserved | Cross-suite content-covering countersignature |

The closed v1 profile rejects the reserved values today; their activation is a successor
contract-major.

## 20. IANA considerations

IANA is asked to register the following claim names in the JSON Web Token Claims Registry
[RFC7519] (Specification Required): `ba_inv` (invocation UUID), `ba_op` (operation name), and
`ba_req` (request digest). The names `ba_dlg`, `ba_offline`, and `ba_sut` are reserved by this
profile and are NOT registered; no implementation or deployment may use them for anything else
before their activating contract-major.

IANA is asked to register the media types `application/ba-cap+jwt`,
`application/ba-chain-anchor+jwt`, and `application/ba-key-transition+jwt` (RFC 6838 [RFC6838]
field template; LIMITED USE). The names `application/ba-cap-delegated+jwt` and
`application/ba-suite-attestation+jwt` are reserved for a successor contract-major and are NOT
registered. The media-type namespace is distinct from the wire `typ` header values, which are
unchanged by this section.

The ready-to-file registration templates, their machine-readable sources, and the exact
reconciliation with the profile's registries document are published with the specification's
companion artifacts; the filing itself follows the profile's external submission
preconditions.

## 21. Security considerations

### Assets and security goals

The assets are the integrity properties of the wire objects: a grant may only be minted by the
issuer's key; a proof only by the holder's key; a request binding only to the exact bytes it
names; a consumption chain only to the exact ordered rows and caller boundaries it records; an
anchored export only to the complete archived object generation it frames
(`REQ1-CORE-reject-unlisted`). Confidentiality is NOT an asset of this profile: every wire
object is plaintext JSON by design; the profile provides authenticity and integrity, and
callers transport it over TLS like any other bearer-presented credential.

### Adversaries and trust boundaries

The profile assumes the standard Internet threat position for the verifier's inputs: an
attacker controls the network path and can read, drop, reorder, or forge every delivered byte.
Specific adversaries: (i) a thief of presented credentials lacking the holder's private key;
(ii) the legitimate holder attempting request, operation, URI, selector, algorithm, claim,
encoding, or time/nonce substitution within an otherwise valid proof; (iii) a malicious or
compromised issuer attempting scope widening across grants; (iv) an archive controller
supplying a validly signed but shortened, relinked, cross-chain, or wrong-generation history;
(v) a contributor weakening the profile itself. The trust boundary is exact: raw credential
bytes cross INTO verification; only caller-supplied trusted keys and expected context cross
with them; redacted facts and nothing else cross out.

### Controls, each mapped to its requirement

Bounded closed parsing precedes all cryptography, defeating allocation amplification and
encoding smuggling (`REQ1-BOUNDS-ordering`, `REQ1-CORE-reject-unlisted`). Exact-byte
constructions — the RFC 7515 signing input, RFC 8785 canonical bytes, the typed projection,
and the domain-separated digests — remove ambient-byte and canonicalization-confusion attacks
(`REQ1-SIGNING-exact-input`, `REQ1-SIGNING-digest-prefix`). Holder possession is proven by the
`cnf` thumbprint and proof-key binding (`REQ1-VERIFY-envelope-binding`); grant binding by the
`ath` grant digest (`REQ1-CLAIM-ath`); request binding by the server-derived request digest
over `[operation, typed(cast_arguments)]` (`REQ1-CLAIM-ath`, `REQ1-VERIFY-envelope-binding`);
temporal validity by bounded signed times with capped skew and proof age
(`REQ1-VERIFY-time-bounds`); freshness by exact nonce mode semantics
(`REQ1-VERIFY-nonce-mode`). Historical key paths advance only through positionally
authenticated, strictly time-increasing, cycle-free transitions
(`REQ1-CORE-cross-major-reject` frames the suite identity; the transition controls are the
archive-section closed-set requirements), and archive acceptance requires the complete scan,
exact EOF, and exact caller boundaries so that validly signed truncations fail
(`REQ1-EXPORT-complete-scan`, `REQ1-CHAIN-no-deletion-cert`).

### Verification is not authority (a security property, not a disclaimer)

A successful verification proves only that caller-supplied bytes satisfy caller-supplied
trusted inputs and expected context (`REQ1-LOCATOR-not-authority`,
`REQ1-CHAIN-facts-not-evaluated`). Trust selection, replay reservation, revocation state, and
every operational decision are outside this profile BY DESIGN — an implementation that treats
a facts result as execution authority has moved those checks to nothing, which is a security
hole in that implementation, not a gap in this profile. Facts are value-bearing, redacted, and
carry explicit not-evaluated markers so they cannot silently become credentials
(`REQ1-VERIFY-facts-not-credentials`).

### Out of scope, explicitly

Key custody, trusted-key discovery and rotation policy, issuance policy, revocation checking,
replay reservation, storage of consumption evidence, witness or recovery processes, denial-of-
service mitigation at the deployment boundary, and side-channel hardening of the host platform
are outside this profile (the profile's own fixed-width comparisons are constant-time where
they compare secrets-adjacent digests). Cryptographic primitive compromise (Ed25519, SHA-256)
breaks the corresponding suite entirely; the profile's succession design confines the response
to a new contract-major with its own closed suite.

### Residual risks

A presented-but-stolen-then-replayed proof inside the skew/proof-age window is indistinguish
from fresh use: replay reservation is the runtime's responsibility, and the window bounds
(rather than eliminates) exposure. A fully compromised issuer mints valid grants; detection is
an operational concern. A conforming verifier that receives correct-but-wrong trusted keys
(the wrong issuer key, the wrong expected context) verifies garbage as valid: the profile
binds bytes to inputs, not inputs to reality. Archive completeness against a malicious
controller requires the caller to retain or derive the intended boundaries
(`REQ1-CHAIN-no-deletion-cert`). Implementation error is a standing residual risk; the
conformance corpus and the mutation gates exist to make the common classes loud.

## 22. Privacy considerations

### Correlation surfaces

The profile's identifiers are correlation surfaces. A grant `jti` is globally unique per grant
and observable by every verifier the holder presents to; the proof `jti` is unique per proof;
`ba_inv` binds a single logical invocation across grant, proof, and the consumption row that
records it. Issuer identifiers (`iss`) and audiences (`aud`) name services and can cluster
holders by the set of issuers they present credentials from. Deployments minimize linkage by
scoping identifier allocation per audience where the runtime supports it and by treating the
correlation of presentation patterns across verifiers as an accepted property of
proof-of-possession credentials of this shape.

### Longitudinal evidence in chains and archives

Consumption chains and anchored exports are designed to be durable, verifiable evidence: rows
commit to invocation-level digests and are sequentially hash-linked, anchors sign the range
ends, and archives freeze complete object generations. The privacy consequence is that
retention decisions made by the runtime ARE the privacy posture — the profile makes evidence
compact and independently checkable, and it makes deletion detectable (a shortened archive
fails the original boundaries), which is a integrity-privacy tension deployments resolve by
policy: retention windows, minimization of commitment preimages (which stay opaque and private
by construction), and audience-scoped chain identifiers are the available controls.

### Nonce handling

Proof nonces are single-use correlation values visible to the verifier that demanded them.
They enable per-verifier linkability of otherwise unlinkable presentations. Deployments that
require nonces scope them per verifier and rotate them; deployments that do not require them
leave the claim absent (its optionality is a privacy feature).

### Redacted facts as a privacy control

Verification facts are value-bearing but redacted: they carry identifiers and digests, never
cast arguments, selector values, raw credentials, signatures, JWK containers, or nonces
(`REQ1-VERIFY-facts-redacted`). This bounds what a logging or telemetry layer can accumulate
from verification outcomes — the loudest privacy control in the profile — and deployments keep
it intact by not logging the raw inputs alongside the facts. (informative)

# Appendix A. Worked examples (generated from the conformance corpus)

<!-- examples:begin -->
## A.1. Accepted examples

### A valid grant (decode surface)

Corpus case `grant-decode-valid` (surface `decode_grant`, class `valid`).

- **Compact:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9.NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA`
- **Outcome:** accepted — verification succeeds with redacted, non-authorizing facts

### A valid holder proof (decode surface)

Corpus case `proof-decode-valid` (surface `decode_proof`, class `valid`).

- **Compact:** `eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ilcxczd5RTlmR0RNQmJtZHBxWVZ3UTFoRENYdHpPZVBVRDNmSWYxdDdGRGsifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiJzVjhkZ1ZLcFExTHZpa1lrNmVvOEd2RGZhYkpyMWd0VlhrdkRnazdxLVpZIiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoidXYyMFBpQzh0UlFvT3k5LWVSbEJGUFFuZ3RpRFhrd19TQ2JiZ3p4akMyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOjEiLCJ2IjoxfQ.BUONibEL8cesx2D905h2CwHhL8sdtZ33sABKd7jRl27UdBOo0jpQX9UGl8VLlpEVxSFiZlhBGwNg85VBakhwAw`
- **Outcome:** accepted — verification succeeds with redacted, non-authorizing facts

### A valid grant (verification surface)

Corpus case `verify-grant-valid` (surface `verify_grant`, class `valid`).

- **Compact:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9.NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA`
- **Outcome:** accepted — verification succeeds with redacted, non-authorizing facts

### A valid request envelope

Corpus case `check-envelope-valid` (surface `check_envelope`, class `valid`).

- **Grant:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9.NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA`
- **Proof:** `eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ilcxczd5RTlmR0RNQmJtZHBxWVZ3UTFoRENYdHpPZVBVRDNmSWYxdDdGRGsifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiJzVjhkZ1ZLcFExTHZpa1lrNmVvOEd2RGZhYkpyMWd0VlhrdkRnazdxLVpZIiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoidXYyMFBpQzh0UlFvT3k5LWVSbEJGUFFuZ3RpRFhrd19TQ2JiZ3p4akMyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOjEiLCJ2IjoxfQ.BUONibEL8cesx2D905h2CwHhL8sdtZ33sABKd7jRl27UdBOo0jpQX9UGl8VLlpEVxSFiZlhBGwNg85VBakhwAw`
- **Outcome:** accepted — verification succeeds with redacted, non-authorizing facts

### A valid consumption chain

Corpus case `check-chain-valid` (surface `check_chain`, class `valid`).

- **Outcome:** accepted — verification succeeds with redacted, non-authorizing facts

### A valid anchored export

Corpus case `verify-anchored-export-valid` (surface `verify_anchored_export`, class `valid`).

- **Outcome:** accepted — verification succeeds with redacted, non-authorizing facts

## A.2. Rejected examples

### Rejected: malformed encoding (decode surface)

Corpus case `grant-decode-invalid-encoding` (surface `decode_grant`, class `invalid_encoding`).

- **Compact:** `bad`
- **Outcome:** rejected — the single closed error value, no other observable

### Rejected: algorithm none

Corpus case `grant-decode-invalid-algorithm-none` (surface `decode_grant`, class `invalid_algorithm`).

- **Compact:** `eyJhbGciOiJub25lIiwia2lkIjoiaXNzdWVyIiwidHlwIjoiYmErY2FwIn0.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9.NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA`
- **Outcome:** rejected — the single closed error value, no other observable

### Rejected: incoherent signed times

Corpus case `decode-grant-invalid-encoding-times-iat-ge-exp` (surface `decode_grant`, class `invalid_encoding`).

- **Compact:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6IlRySTFnOWhlcjVtek50ZHdUaFV5cXd3R2ZaVkxLZDNNTW9Xa1JZLUZuOGMifSwiZXhwIjoyMDAwLCJpYXQiOjIwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OmZpZWxkcyIsIm5iZiI6MTAwMCwib3BlcmF0aW9ucyI6W3sibmFtZSI6InJlYWQiLCJzZWxlY3RvcnMiOlt7ImtpbmQiOiJhbGwifV19XSwidiI6MX0.tsqChETJ86teYYzsBsHMhg5uxFoCwNdbUhoXWC9Zp8yBddfp8OFPnAxjwDTbgkffuO9nDhdtl5dekbT0m4UWCA`
- **Outcome:** rejected — the single closed error value, no other observable

### Rejected: duplicate audience

Corpus case `decode-grant-invalid-encoding-audiences-duplicate` (surface `decode_grant`, class `invalid_encoding`).

- **Compact:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9hLnRlc3QiLCJodHRwczovL2EudGVzdCJdLCJjbmYiOnsiamt0IjoiVHJJMWc5aGVyNW16TnRkd1RoVXlxd3dHZlpWTEtkM01Nb1drUlktRm44YyJ9LCJleHAiOjIwMDAsImlhdCI6MTAwMCwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS50ZXN0IiwianRpIjoidXJuOmV4YW1wbGU6Z3JhbnQ6ZmllbGRzIiwibmJmIjoxMDAwLCJvcGVyYXRpb25zIjpbeyJuYW1lIjoicmVhZCIsInNlbGVjdG9ycyI6W3sia2luZCI6ImFsbCJ9XX1dLCJ2IjoxfQ.iyY5mBkEqFJyVSsAa0P71OZi1JqeCa17C3tAx7aVafnHBJnPtXsBGzODdd7_DHW9lV8ZrwFRYoTZdV0wgOE0DQ`
- **Outcome:** rejected — the single closed error value, no other observable

### Rejected: holder binding mismatch

Corpus case `check-envelope-invalid-claim-holder-binding` (surface `check_envelope`, class `invalid_claim`).

- **Grant:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6IlRySTFnOWhlcjVtek50ZHdUaFV5cXd3R2ZaVkxLZDNNTW9Xa1JZLUZuOGMifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OmJpbmRpbmctYSIsIm5iZiI6MTAwMCwib3BlcmF0aW9ucyI6W3sibmFtZSI6InJlYWQiLCJzZWxlY3RvcnMiOlt7ImtpbmQiOiJhbGwifV19XSwidiI6MX0.TWfkUWpq2AwChiE35-rrkbyxgXTr8aywpRJAOX2LI7IJ2AcJ7AyBuMIbA5r90Ow8wSdXjIQIXRyJobTGCNr-Dg`
- **Proof:** `eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlRMV3I5cTE1LV9XcnZNcjh3bW5ZWE5KbEh0UzRoYldHbnlRYTdmQ2x1aWsifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiIwZ3Nqd1QtRHkzZkp1S2xGZXNFYWhjQ3YzNG91eERjcFk3aUZ3cFFhSlV3IiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoidXYyMFBpQzh0UlFvT3k5LWVSbEJGUFFuZ3RpRFhrd19TQ2JiZ3p4akMyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOmJpbmRpbmctd3JvbmctaG9sZGVyIiwidiI6MX0.-6-8UsOBgxTXbprpywP1kyPyhARQMyCgSAMb4iFj_9ZEyfVhxa-7iXNeY2eWeFyl_x_sRLmBmwgtBQt8-CNjCg`
- **Outcome:** rejected — the single closed error value, no other observable

### Rejected: selector-disallowed arguments

Corpus case `check-envelope-invalid-selector` (surface `check_envelope`, class `invalid_selector`).

- **Grant:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6IlRySTFnOWhlcjVtek50ZHdUaFV5cXd3R2ZaVkxLZDNNTW9Xa1JZLUZuOGMifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OnNlbGVjdG9yLTEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiZXF1YWxzIiwicGF0aCI6WyJyZWNvcmQiLCJpZCJdLCJ2YWx1ZSI6InJlYy0xIn1dfV0sInYiOjF9.RhKhp0dsUxk_YOZyRjTJlnkVNVoOJdeW6bFTLDP3Z3IZaTScAVSdC9jvU0kx2EXJi3O2tFLlqBV6uP3kCAfvCQ`
- **Proof:** `eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImRDSzVpSFdZQm80eXhFU0tsSnJiS1EwUFRqVzU0QnNPNWZHaDVnRC1KblEifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiJldnl3ZGx0Q2FGSDFPVTRaN0M0bGVENGJma3FOVkF2SWlYVmhrWXRTX0RZIiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoiSXVRSXhZOHZ6Ny03MkhjMlQ0b2JBZ0l6Sm5GRk1sQjJDTGlnYmhWZHpDUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOnNlbGVjdG9yLXJlamVjdCIsInYiOjF9.QxlsuJEJIw6DUTVxqTIvS8IFMloBHgoCectZ0CSaiq0cRmgHK2HjrVQLvBPipD9IOClS81Lf9nIW6y0Ynl0iBg`
- **Outcome:** rejected — the single closed error value, no other observable

### Rejected: missing required nonce

Corpus case `check-envelope-invalid-nonce-required` (surface `check_envelope`, class `invalid_nonce`).

- **Grant:** `eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9.NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA`
- **Proof:** `eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ilcxczd5RTlmR0RNQmJtZHBxWVZ3UTFoRENYdHpPZVBVRDNmSWYxdDdGRGsifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiJzVjhkZ1ZLcFExTHZpa1lrNmVvOEd2RGZhYkpyMWd0VlhrdkRnazdxLVpZIiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoidXYyMFBpQzh0UlFvT3k5LWVSbEJGUFFuZ3RpRFhrd19TQ2JiZ3p4akMyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOjEiLCJ2IjoxfQ.BUONibEL8cesx2D905h2CwHhL8sdtZ33sABKd7jRl27UdBOo0jpQX9UGl8VLlpEVxSFiZlhBGwNg85VBakhwAw`
- **Outcome:** rejected — the single closed error value, no other observable
<!-- examples:end -->






# Appendix B. CDDL representation (informative) {#cddl}

An informative CDDL summary of the wire objects is published alongside this specification. It
is NOT a machine-checked authority: the structural authority is the set of JSON Schemas and
the conformance corpus (Appendix C). CDDL cannot express several closed-profile invariants
(duplicate-name rejection at byte level, exact canonical encodings, raw lexeme bounds).

# Appendix C. Reference mappings (informative)

The tagged algebra binds to the reference implementation's values as follows (the same
tagged-value notation the typed projection in (#datamodel) uses):

| JSON | Elixir value |
|---|---|
| null | `:null` |
| boolean | `{:boolean, boolean}` |
| integer | `{:integer, integer}` |
| non-integer number | `{:float, finite_float}` |
| string | `{:string, UTF-8_binary}` |
| array | `{:array, [value]}` |
| object | `{:object, [{UTF-8_binary, value}]}` |

The frozen reference implementation of this profile is the `bounded_authority_protocol`
package. Its public v1 façade is the following locked API surface (enforced by the package's
architecture gate; listed here informatively):

```elixir
untrusted_key_locator(binary(), Bounds.t() | map())
grant_signing_input(Grant.t(), Bounds.t() | map())
proof_signing_input(Proof.t(), Bounds.t() | map())
assemble_compact(SigningInput.t(), binary())
assemble_compact(SigningInput.t(), binary(), Bounds.t() | map())
decode_grant(binary(), Bounds.t() | map())
decode_proof(binary(), Bounds.t() | map())
verify_grant(binary(), TrustedIssuer.t(), ExpectedGrant.t())
check_envelope(Credentials.t(), ExpectedRequest.t())
request_digest(binary(), Json.value(), Bounds.t() | map())
encode_consumption_entry(ConsumptionEntry.t(), Bounds.t() | map())
check_chain(ChainInput.t(), ExpectedChain.t())
boundary_anchor_signing_input(BoundaryAnchor.t(), Bounds.t() | map())
key_transition_signing_input(KeyTransition.t(), Bounds.t() | map())
encode_anchored_export(AnchoredExportInput.t(), ExpectedExport.t())
verify_historical_anchor(binary(), HistoricalPublicKey.t(), ExpectedAnchor.t())
verify_key_transition(binary(), HistoricalPublicKey.t(), HistoricalPublicKey.t(),
  ExpectedKeyTransition.t())
verify_anchored_export(ArchivedObject.t(), HistoricalKeyChain.t(),
  ExpectedAnchoredExport.t())
```

The untrusted key locator returns exactly:

```elixir
{:ok, %BoundedAuthorityProtocol.V1.KeyLocator{kid: kid, trust: :not_evaluated}}
```

The Elixir bindings map the tagged algebra as: `:null`, `{:boolean, b}`, `{:integer, n}`, `{:float, f}`,
`{:string, s}`, `{:array, [value]}`, `{:object, [{name, value}]}`; the closed error value is
`{:error, :invalid}`. Companion artifacts: the conformance corpus (283 cases over 28 surfaces,
certified index digest and monotone revision integer in its `revision.json` sidecar), the
structural JSON Schemas (Draft 2020-12), the requirement-to-conformance map (REQ1-* to corpus
cells), the registries document, and the standards-track charter. The corpus is the
machine-checked oracle; requirement identifiers and their evidence cells are enumerated in
Appendix D.

# Appendix D. Requirement inventory (informative)

Every `REQ1-*` identifier used in this document is defined exactly once in the
requirement-to-conformance map, together with its conformance evidence cells; the inventory is
published there and drift-gated against this document by the spec-facts machinery. This
appendix intentionally carries no second copy: a duplicated inventory is a drift surface, not
documentation.

---

Generated from `spec/bap-v1.md` rev 1 (the single normative authority).
