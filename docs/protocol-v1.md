# Bounded Authority Protocol v1 wire profile

Status: normative for v1. The package remains unpublished. ADR 0003 explicitly supersedes the
earlier grant/proof separator rows before release; every other change requires the contract-major
and SemVer process.

This document freezes the byte-level profile. A conforming implementation rejects every unlisted
member, value, encoding, or extension with exactly `{:error, :invalid}`. Successful decode or
verification is not a trust-selection or authorization decision.

## Normative sources

- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON grammar, UTF-8, interoperable integer
  range, and parser resource limits.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): I-JSON, duplicate-name prohibition, no
  Unicode normalization, UTF-16 property sorting, and deterministic serialization.
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648): base64url alphabet and canonical pad bits.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) and
  [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519): compact JWS signing input, registered claim
  types, NumericDate, and case-sensitive StringOrURI comparison.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638),
  [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), and
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037): public OKP JWK thumbprints, Ed25519 keys and
  signatures, and EdDSA use in JOSE.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) and
  [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): URI normalization and DPoP bindings.
- [Erlang/OTP `json`](https://www.erlang.org/doc/apps/stdlib/json.html): OTP 27+ ordered decode
  callbacks and incomplete/invalid UTF-8 failures.
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation):
  structural validation semantics, including code-point-based string length.

These references supply generic encodings. The closed fields, values, digest prefixes, and bounds
below are this profile's choices.

## JSON algebra and decoding

`BoundedAuthorityProtocol.V1.Json.decode/2` returns exactly:

| JSON | Elixir value |
|---|---|
| null | `:null` |
| boolean | `{:boolean, boolean}` |
| integer | `{:integer, integer}` |
| non-integer number | `{:float, finite_float}` |
| string | `{:string, UTF-8_binary}` |
| array | `{:array, [value]}` |
| object | `{:object, [{UTF-8_binary, value}]}` |

Objects retain source member order. Names remain binaries and are never atomized. A duplicate name
at any depth is rejected before map conversion. Input is one complete RFC 8259 value followed only
by JSON whitespace. UTF-8 is mandatory; strings are preserved without Unicode normalization.

Before number conversion, the decoder scans raw RFC 8259 number lexemes outside strings, enforces
the 64-byte ceiling, and compares exact decimal magnitude without floating-point rounding. Integers
and finite floats are bounded symmetrically to `-9007199254740991..9007199254740991`.

`BoundedAuthorityProtocol.V1.Jcs.encode/2` accepts only this tagged algebra. It enforces every JSON
and output bound while emitting RFC 8785 bytes: exact string escaping, invalid-Unicode rejection,
unsigned UTF-16 object-name sorting at every depth, preserved array order, and exact ECMAScript
binary64 number text, including `-0` as `0`, fixed/exponent thresholds, lowercase `e`, and a
positive exponent `+`.

## Structural schemas

Draft 2020-12 schemas under `priv/conformance/v1/schemas/` are structural companion artifacts.
Every schema validates against the canonical Draft 2020-12 meta-schema. They are not standalone
byte-level oracles: `maxLength` counts code points, while `x-bap-maximum-utf8-bytes` annotations
name UTF-8 byte ceilings. The bounded decoder and vectors enforce duplicates, raw numeric lexemes,
decoded-size projection, depth, total nodes, canonical encodings, and every byte limit.

## Base64url

Segments use only `A-Z`, `a-z`, `0-9`, `-`, and `_`. Padding and whitespace are forbidden. Length
modulo four equal to one is invalid. Decoding succeeds only when unpadded re-encoding reproduces
the input exactly, rejecting non-zero unused pad bits and alternate encodings.

## Protected headers

Member order is insignificant and the member sets are exact:

| Compact value | Members |
|---|---|
| grant | `alg: "EdDSA"`, `typ: "ba+cap"`, `kid: key_identifier` |
| proof | `alg: "EdDSA"`, `typ: "dpop+jwt"`, `jwk: public_OKP_JWK` |

`crit`, `b64`, embedded grant keys, unknown algorithms, and every unlisted member are invalid.
Grant `kid` is a case-sensitive 1–128 byte string of ASCII letters, digits, `-`, `.`, `_`, or `~`.
It is an untrusted hint, not a trust selector.

The proof JWK is exactly `{crv: "Ed25519", kty: "OKP", x: canonical_base64url_32_bytes}` in any
member order. Every additional member, including private `d`, is invalid. Its RFC 7638 thumbprint
preimage is exactly:

```json
{"crv":"Ed25519","kty":"OKP","x":"<canonical-x>"}
```

The thumbprint is unpadded base64url SHA-256 of those UTF-8 bytes. Verified facts carry the raw
32-byte digest. Issuer-key fingerprinting uses the same construction over the caller's raw
32-byte public key; `kid` is excluded.

## Claims

All claim objects are closed. Names and string values are case-sensitive.

| Grant claim | Type |
|---|---|
| `v` | integer, exactly `1` |
| `iss`, `jti` | non-empty StringOrURI, at most 512 UTF-8 bytes |
| `aud` | one StringOrURI or a nonempty unique array of at most 64 |
| `iat`, `nbf`, `exp` | integral NumericDate |
| `cnf` | exact object `{jkt: canonical_base64url_sha256}` |
| `operations` | nonempty array of at most 64 operation objects |

An operation is exactly `{name: string, selectors: selector_array}`. Names are unique within the
grant and contain 1–128 printable ASCII bytes. The ordered selector array has 1–64 members.

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

Every proof requires every row except `nonce`; no other claim is accepted. `ath` is SHA-256 over
the ASCII bytes of the complete received grant compact value. The method accepts ASCII letters,
digits, the punctuation bytes `! # $ % & ' * + - . ^ _ | ~`, and grave accent. It is compared
byte-for-byte and is never case-normalized.

## Selector algebra

Selectors are closed ordered objects:

| Kind | Exact members |
|---|---|
| all | `{kind: "all"}` |
| equals | `{kind: "equals", path: path, value: JSON_value}` |
| one-of | `{kind: "one_of", path: path, values: non_empty_JSON_array}` |

A path has 1–32 object-member names, each 1–128 UTF-8 bytes. Paths traverse objects only and never
index arrays. `one_of` contains at most 256 values.

Selectors are applied conjunctively to the server-derived tagged arguments. `all` matches any JSON
root. `equals` and `one_of` require the path to exist. Semantic identity preserves tagged scalar
distinctions, compares arrays positionally, and compares duplicate-free objects recursively as
unordered key/value sets. It never gives source member order meaning or collapses integer and float
tags. No selector grants business authorization.

## URI normalization

Target URIs are bounded ASCII, hierarchical, and HTTPS-only, with a nonempty authority and host and
no user information, fragment, or query. Normalization lowercases scheme and host; uppercases
percent hex; decodes only percent-encoded unreserved octets; preserves percent-encoded reserved
octets as path data; removes complete dot segments; maps an empty path to `/`; drops port 443; and
preserves a valid nondefault port and all other path bytes. It performs no DNS, IDNA, or network
work.

The host uses the exact RFC 3986 grammar: `reg-name` contains only unreserved, sub-delim, or valid
percent-encoded octets; IPv4 uses exact `dec-octet` forms without leading-zero alternatives; and a
bracketed IP literal contains a complete IPv6address or IPvFuture. A present port is one or more
decimal digits in `1..65535`; its canonical form removes leading zeroes and omits `443`. Empty ports
and malformed IPv4, IPv6, or IPvFuture literals are invalid.

HTTP, another scheme, an authority-less form, malformed percent escapes, ambiguous authority/port
syntax, control/non-ASCII bytes, and out-of-range ports are invalid. Both expected and proof URIs
must already equal the normal form.

## Signing and digest inputs

Grant and proof compact values use the exact RFC 7515 signing input:

```text
ASCII(base64url(protected) || "." || base64url(payload))
```

No bytes precede or follow it. Verification uses the exact received segments; correctly signed
closed JSON objects may use any member order. Producers emit one deterministic JCS representation.

The verifier validates the fixed 32-byte public-key and 64-byte signature encodings, completes
all bounded parsing and contextual checks, and then delegates Ed25519 verification to the
supported OTP `:crypto` backend. A backend rejection or exception returns exactly
`{:error, :invalid}`.

The request digest is:

```text
base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
```

The prefix is exact ASCII including its final zero byte. `typed/1` projects the tagged JSON algebra
to the following closed JSON form before JCS:

| tagged value | projected JSON |
|---|---|
| `:null` | `["null"]` |
| `{:boolean, value}` | `["boolean", value]` |
| `{:integer, value}` | `["integer", value]` |
| `{:float, value}` | `["float", value]` |
| `{:string, value}` | `["string", value]` |
| `{:array, values}` | `["array", [typed(value), ...]]` |
| `{:object, members}` | `["object", {member: typed(value), ...}]` |

JCS orders projected object members. The explicit scalar tags preserve the protocol's semantic
distinction between an integer and an integral float even though RFC 8785 emits both numeric
payloads with the same JSON number bytes. `cast_arguments` may be any tagged JSON value.
`BAP1-CHAIN\0` and `BAP1-ARCHIVE\0` remain reserved for BAP-04. The retired
`BAP1-GRANT\0` and `BAP1-PROOF\0` strings are invalid signing prefixes.

## Public verification contract

The frozen v1 façade is:

```elixir
untrusted_key_locator(binary(), Bounds.t() | map())
grant_signing_input(Grant.t(), Bounds.t() | map())
proof_signing_input(Proof.t(), Bounds.t() | map())
assemble_compact(SigningInput.t(), binary())
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

Every function returns `{:ok, value}` or exactly `{:error, :invalid}`. Only bounds accept a map;
all other structured inputs are exact named structs and each public entry revalidates every field.
`assemble_compact/2` accepts exactly a `SigningInput` and a 64-byte signature, never a key, signer,
or callback. Decode results carry `verification: :not_evaluated`.

The public versioned primitive modules additionally expose
`BoundedAuthorityProtocol.V1.Jcs.encode/2`,
`BoundedAuthorityProtocol.V1.Jwk.encode_public/2`, `decode_public/2`,
`thumbprint_preimage/2`, `thumbprint/2`, `thumbprint_raw/2`, and
`public_key_thumbprint_raw/2`, plus `BoundedAuthorityProtocol.V1.Uri.normalize/2`.
Request-digest, selector, and compact-JWS composition mechanics remain internal implementation
behind the supported façade; their modules are not additional stable façade contracts.
The existing BAP-02 `untrusted_key_locator/1` convenience arity uses profile maxima; the BAP-03
façade functions expose only the arities printed above. `Bounds.maximum/0` returns the immutable
profile maxima, `Bounds.new/0,1` constructs tightening-only limits, and every limits-taking public
boundary revalidates a `Bounds` struct or tightening map.

`TrustedIssuer` contains exact `kid` and raw 32-byte public key. `ExpectedGrant` contains issuer,
audience, integral evaluation time, nonnegative skew, and tightening bounds. Grant verification
requires exact key ID, signature, issuer, and audience; coherent signed times `iat < exp` and
`nbf < exp`; and independently:

```text
iat <= evaluation_time + skew
nbf <= evaluation_time + skew
exp > evaluation_time - skew
```

It does not require `iat <= nbf`. `GrantFacts` contains exactly version, issuer, grant ID, raw
32-byte issuer-key fingerprint, raw 32-byte holder thumbprint, matched audience, grant times, and
`authorization: :not_evaluated`.

`ExpectedRequest` additionally contains a case-sensitive RFC 9110 token method, normalized HTTPS URI, lowercase RFC 4122
invocation UUID, operation, any tagged JSON cast arguments, positive proof maximum age, and
`:not_required | {:required, nonce}`. Proof time is inclusive:

```text
evaluation_time - proof_max_age - skew <= iat <= evaluation_time + skew
```

Skew is at most 60 seconds and proof maximum age at most 300 seconds. Nonce must be absent in
`:not_required` mode and present exactly once and equal in required mode. Combined verification
re-verifies the raw grant; verifies holder signature/thumbprint; and binds `ath`, method, URI,
invocation, operation, `ba_req`, time, nonce, and every selector.

`GrantFacts` and `EnvelopeFacts` are value-bearing and redacted non-authorizing results with fixed
redacted inspection and no generic encoder, string, or enumeration protocol. `EnvelopeFacts` adds
proof ID, invocation ID, operation, normalized URI, raw grant/request hashes, and proof issuance
time. Neither result contains arguments, selector values, raw credentials, signatures, JWK
containers, or nonces, and neither is accepted as credentials.

## Hard maxima

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

Callers may tighten resource ceilings with a positive integer. The 32-byte public-key and digest
widths and 64-byte signature width are protocol constants and must remain exact. Unknown,
non-integer, zero, negative, widening, or fixed-width-changing limits are invalid. Raw and encoded
sizes precede decoding; decoded-size projection precedes allocation; structure and scalar limits
apply while decoding/emitting; all precede cryptography.

## Untrusted key locator

`BoundedAuthorityProtocol.V1.untrusted_key_locator/2` bounds the complete compact input, requires
exactly three segments, then bounds, decodes, and validates only the protected grant header. The
payload and signature stay opaque. It returns only:

```elixir
{:ok, %BoundedAuthorityProtocol.V1.KeyLocator{kid: kid, trust: :not_evaluated}}
```

It does not select a key, decode claims/signature bytes, verify, evaluate trust, or authorize.
Every failure returns `{:error, :invalid}` without input values.
The locator retains its documented `/1` profile-maximum convenience arity and `/2`
tightening-limits arity.

## Consumption chain and anchored export

The normative consumption row, row-domain hash, boundary-anchor JWS, historical-key-transition
JWS, archive framing, object-version binding, temporal intervals, and non-authorizing result
contract are frozen in [ADR 0004](adr/0004-consumption-chain-rollover-and-anchored-export-verification.md).

Chain verification accepts raw canonical row bytes and mandatory caller boundaries. Anchored
export verification accepts only `%ArchivedObject{chunks: raw_binary_chunks, version: version}`,
an ordered historical public-key chain, and complete expected chain/anchor/transition/digest/
object-version context. It scans and hashes the complete archive, requires exact EOF, authenticates
both boundaries and every positional transition, and then independently checks every row.

The stored-object version is exact out-of-band expected context. Commitment preimages remain
opaque and private. A self-consistent chain does not certify that no row was deleted: validly
signed shortened or relinked artifacts fail only when compared with the original caller
boundaries. Successful facts state the performed cryptographic checks and always retain
`trust: :not_evaluated`. Only `AnchoredExportFacts` additionally carries
`authorization: :not_evaluated`; chain, anchor, and transition facts make no authorization field
part of their exact public shape.
