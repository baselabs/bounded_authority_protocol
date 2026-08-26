---
title: Bounded Authority Protocol v1 Wire Profile
abbrev: BAP v1
docname: bap-v1
---

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
: A closed, holder-signed request-binding object in the DPoP family [@RFC9449], binding one
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
as described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they appear in all capitals,
as shown here. Lowercase forms carry their normal English meaning and impose no requirement.

The closed-rejection rule is the profile's central invariant (`REQ1-CORE-reject-unlisted`): a
conforming implementation rejects every unlisted member, value, encoding, or extension. It is
stated once here as the rationale; each per-section closed-set statement below is its own MUST
(`REQ1-HEADER-closed-set`, `REQ1-CLAIM-closed-set`, ...) and maps to the conformance cells of
the surface it governs. Requirement identifiers are stable and their mapping to conformance
evidence is published in the requirement map (Appendix C locates the companion artifacts).

## 5. Suite identity

This profile constitutes the cryptographic suite `BAP1-Ed25519-SHA256`: EdDSA over Ed25519
[@RFC8032] [@RFC8037], SHA-256 digests, RFC 8785 canonical bytes [@RFC8785], and the `BAP1-*`
domain separators, with the fixed widths listed in the bounds table (#maxima). Every artifact
self-declares this identity through its `v` claim, `typ` header, `alg` value, and domain
separators. Evolution happens above this profile, never inside it: successor contract-majors
carry their own complete closed profiles and suites, a proof's contract-major MUST equal its
grant's (`REQ1-CORE-proof-major-equals-grant`), and the closed-rejection rule above is exactly
what makes parallel majors safe — an artifact of any other major or suite fails closed here
(`REQ1-CORE-cross-major-reject`).

## 6. Normative references

[@RFC2119]: Key words for use in RFCs to Indicate Requirement Levels
[@RFC8174]: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
[@RFC8259]: The JavaScript Object Notation (JSON) Data Interchange Format
[@RFC8785]: JSON Canonicalization Scheme (JCS)
[@RFC4648]: The Base16, Base32, and Base64 Data Encodings
[@RFC7515]: JSON Web Signature (JWS)
[@RFC7519]: JSON Web Token (JWT)
[@RFC7638]: JSON Web Key (JWK) Thumbprint
[@RFC8032]: Edwards-Curve Digital Signature Algorithm (EdDSA)
[@RFC8037]: Algorithm Identifiers for Ed25519 in JOSE
[@RFC3986]: Uniform Resource Identifier (URI): Generic Syntax
[@RFC9449]: OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)

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
contract-major. IANA registration templates for these values and the profile's claim names are
carried in the IANA considerations (added by a companion landing).

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
package (v1 façade functions listed in the package's locked API surface). Its Elixir bindings
map the tagged algebra as: `:null`, `{:boolean, b}`, `{:integer, n}`, `{:float, f}`,
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
