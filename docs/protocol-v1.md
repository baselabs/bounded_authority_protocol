# Bounded Authority Protocol v1 wire profile

Status: normative and immutable for v1. The package remains unpublished.

This document freezes the byte-level profile. A conforming implementation rejects every
unlisted member, value, encoding, or extension with the single public result
`{:error, :invalid}`. A successful parse is not a trust or authorization decision.

## Normative sources

- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON grammar, UTF-8, interoperable integer
  range, and parser resource limits.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): I-JSON constraints, duplicate-name
  prohibition, no Unicode normalization, and later canonical serialization.
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648): base64url alphabet, rejection of
  non-alphabet bytes, and canonical zero pad bits.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): compact JWS shape, unpadded base64url, UTF-8
  protected headers, and case-sensitive `kid` treatment.
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519): registered claim value types, NumericDate,
  and case-sensitive StringOrURI comparison.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) and
  [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): URI syntax normalization and DPoP target
  URI treatment.
- [Erlang/OTP `json`](https://www.erlang.org/doc/apps/stdlib/json.html): OTP 27+ ordered decode
  callbacks and incomplete/invalid UTF-8 failures.

These references supply generic encodings. The closed fields, values, separators, and bounds
below are this profile's choices.

## JSON algebra and decoding

The decoder returns exactly:

| JSON | Elixir value |
|---|---|
| null | `:null` |
| boolean | `{:boolean, boolean}` |
| integer | `{:integer, integer}` |
| non-integer number | `{:float, finite_float}` |
| string | `{:string, UTF-8_binary}` |
| array | `{:array, [value]}` |
| object | `{:object, [{UTF-8_binary, value}]}` |

Objects retain source member order. Names remain binaries and are never atomized. A duplicate
name at any depth is rejected while the ordered member list is being built, before any map
conversion. Input must be one complete RFC 8259 value followed only by JSON whitespace. UTF-8 is
mandatory. Strings are preserved exactly; Unicode normalization is forbidden.

All numbers are limited symmetrically to
`-9007199254740991..9007199254740991`, the exact interoperable integer range identified by
RFC 8259. Floats must also be finite.

## Base64url

Segments use only `A-Z`, `a-z`, `0-9`, `-`, and `_`. Padding and whitespace are forbidden.
Length modulo four equal to one is invalid. Decoding is accepted only when re-encoding the
decoded bytes without padding reproduces the input exactly; this rejects non-zero unused pad
bits and alternate encodings.

## Protected headers

Member order is not significant. The set is exact:

| Compact value | Members |
|---|---|
| grant | `alg: "EdDSA"`, `typ: "ba+cap"`, `kid: key_identifier` |
| proof | `alg: "EdDSA"`, `typ: "dpop+jwt"`, `jwk: public_OKP_JWK` |

`crit`, `b64`, embedded grant keys, unknown algorithms, and every unlisted member are invalid.
The grant `kid` is a case-sensitive 1–128 byte string containing only ASCII letters, digits,
`-`, `.`, `_`, or `~`. It is an untrusted hint, not a trust selector.

## Claims

All claim objects are closed. Claim names and string values are case-sensitive.

| Grant claim | Type |
|---|---|
| `v` | integer, exactly `1` |
| `iss`, `jti` | non-empty StringOrURI |
| `aud` | non-empty StringOrURI or non-empty array of unique StringOrURI |
| `iat`, `nbf`, `exp` | integral NumericDate |
| `cnf` | exact object `{jkt: base64url_sha256_thumbprint}` |
| `operations` | non-empty array of operation objects |

An operation object is exactly `{name: string, selectors: selector_array}`. Operation names are
1–128 byte printable ASCII strings. The array is ordered and non-empty.

| Proof claim | Type |
|---|---|
| `v` | integer, exactly `1` |
| `jti` | non-empty StringOrURI |
| `htm` | uppercase HTTP method |
| `htu` | normalized target URI |
| `iat` | integral NumericDate |
| `nonce` | non-empty string; present only when a challenge requires it |
| `ba_inv` | lowercase RFC 4122 UUID string |
| `ba_op` | 1–128 byte printable ASCII operation name |
| `ath`, `ba_req` | unpadded base64url SHA-256 values |

Every proof requires `v`, `jti`, `htm`, `htu`, `iat`, `ba_inv`, `ba_op`, `ath`, and `ba_req`.
`nonce` is conditionally present only for a challenged proof. No other claim is accepted.

## Selector algebra

Selectors are closed ordered JSON objects:

| Kind | Exact members |
|---|---|
| all | `{kind: "all"}` |
| equals | `{kind: "equals", path: path, value: JSON_value}` |
| one-of | `{kind: "one_of", path: path, values: non_empty_JSON_array}` |

A path is a non-empty array of 1–128 byte UTF-8 object-member names. Paths do not index arrays.
Selector order is significant. No selector implies business authorization.

## URI normalization

The normalized target URI is absolute and has no user information, fragment, or query. Lowercase
the scheme and host; uppercase percent-encoding hex digits; decode percent-encoded unreserved
characters; remove dot segments; replace an empty path with `/`; remove the default port for
`http` or `https`; preserve all other path bytes. This is syntax normalization, not a network
lookup. DPoP comparison uses the normalized URI without query or fragment.

## Domain separators

The following ASCII byte strings include the final zero byte:

| Use | Bytes |
|---|---|
| grant signing | `BAP1-GRANT\0` |
| proof signing | `BAP1-PROOF\0` |
| request digest | `BAP1-REQUEST\0` |
| chain link | `BAP1-CHAIN\0` |
| archive manifest | `BAP1-ARCHIVE\0` |

No other separator is accepted for v1.

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

Callers may tighten any maximum with a positive value. Unknown limits, zero/negative values, or
widening attempts are invalid. Raw and encoded sizes are checked before decoding; decoded-size
projection precedes allocation; structure and scalar limits are enforced during ordered decoding;
all precede cryptography.

## Untrusted key locator

`BoundedAuthorityProtocol.V1.untrusted_key_locator/2` requires exactly three dot-separated compact
segments. It bounds and decodes only the protected grant header, enforces its exact closed table,
and returns only:

```elixir
{:ok, %BoundedAuthorityProtocol.V1.KeyLocator{kid: kid, trust: :not_evaluated}}
```

It does not decode payload claims or signature bytes. It does not select a trusted key, verify a
signature, evaluate trust, or authorize. Every failure returns `{:error, :invalid}` without
including input values.
