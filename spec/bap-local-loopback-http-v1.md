---
title: BAP Local Loopback HTTP Proof Profile 1
docname: bap-local-loopback-http-v1
---

# BAP Local Loopback HTTP Proof Profile 1

Document status: normative for application proof profile
`bap-application-proof/local-loopback-http/1`. Document revision: rev 1. This document composes with
the contract-major 1 grant and common proof mechanics in [BAP v1](bap-v1.md); it does not change that
profile's `dpop+jwt` proof contract or verdicts.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD
NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals.

## 1. Scope and profile identity

This profile defines a holder proof for direct HTTP requests to exact literal loopback endpoints.
It binds a contract-major 1 `ba+cap` grant and reuses the BAP1 proof claim names, bounds, Ed25519 JWS,
holder-key thumbprint, grant digest, request digest, temporal checks, selector checks, and redacted
facts contract (`REQ-LLH1-CORE-compose-v1`).

The profile identity is `bap-application-proof/local-loopback-http/1`. A conforming proof MUST carry
protected `typ: "ba+loopback-proof"` (`REQ-LLH1-CORE-profile-identity`). A standard BAP1
`dpop+jwt` verifier MUST reject this `typ`, and this profile MUST reject `dpop+jwt`
(`REQ-LLH1-CORE-cross-profile-reject`).

Profile selection is trusted caller code expressed through a separately named public API. It MUST
NOT be inferred from a proof, URI, request header, forwarded metadata, environment value, bounds
map, or failed verification, and a verifier MUST NOT retry another profile after failure
(`REQ-LLH1-CORE-no-inference-fallback`).

## 2. Protected header and proof claims

The protected header has exactly these members:

| Member | Required value |
|---|---|
| `alg` | `EdDSA` |
| `typ` | `ba+loopback-proof` |
| `jwk` | public Ed25519 OKP JWK under the BAP1 rules |

Every unlisted member or value is invalid (`REQ-LLH1-HEADER-closed-set`). The header is protected by
the JWS signature; altering `typ` or any other protected byte invalidates the proof
(`REQ-LLH1-HEADER-signed-identity`).

The proof payload uses exactly the BAP1 proof members `v`, `jti`, `htm`, `htu`, `iat`, `nonce`,
`ba_inv`, `ba_op`, `ath`, and `ba_req`. Every member is required, including `nonce`; no other member
is accepted (`REQ-LLH1-CLAIM-closed-required`). `v` MUST be the integer `1`, and the bound grant MUST
be contract-major 1 (`REQ-LLH1-CLAIM-grant-major`).

`nonce` MUST be a non-empty valid UTF-8 string within the BAP1 nonce bound. Envelope verification
MUST receive `{:required, expected_nonce}` or its language-binding equivalent and MUST compare the
proof nonce exactly (`REQ-LLH1-CLAIM-nonce-required`). Not-required nonce mode is invalid for this
profile.

All other claim validation and the `ath`, `ba_req`, time, method, invocation, operation, selector,
holder, issuer, audience, and signature bindings are exactly the BAP1 rules
(`REQ-LLH1-CLAIM-v1-bindings`).

## 3. Target URI

The `htu` value MUST be a canonical ASCII hierarchical URI under this section
(`REQ-LLH1-URI-canonical`). Producers MUST reject a target that is not already equal to its canonical
form; decoders and envelope verifiers MUST reject a proof whose encoded `htu` is not canonical
(`REQ-LLH1-URI-pre-normalized`).

### 3.1 Admitted scheme and authority

The scheme MUST be `http`, compared ASCII case-insensitively on normalization and emitted lowercase
(`REQ-LLH1-URI-http`). The host bytes MUST be exactly `127.0.0.1` or `[::1]`
(`REQ-LLH1-URI-exact-hosts`).

The following are invalid (`REQ-LLH1-URI-host-reject-list`):

- `localhost`, any registered name, or a trailing-dot or percent-encoded name;
- any other address in `127.0.0.0/8`;
- shortened, single-integer, hexadecimal, octal, leading-zero-octet, mixed-base, or
  percent-encoded IPv4;
- expanded IPv6 loopback, IPv4-mapped IPv6, IPvFuture, or a zone identifier;
- user information, an empty authority, or an authority suffix;
- `https` or any other scheme.

Normalization and verification MUST NOT perform DNS, IDNA, socket, proxy, environment, or filesystem
work. `Host`, `Forwarded`, `X-Forwarded-*`, and equivalent metadata are not inputs to this profile
(`REQ-LLH1-URI-no-network-proxy`).

### 3.2 Port

An absent port denotes HTTP port 80. An explicit port MUST contain only ASCII decimal digits, parse
to `1..65535`, and be emitted without leading zeroes. Effective port 80 is omitted; every other port
is retained (`REQ-LLH1-URI-port`).

### 3.3 Path and forbidden components

The BAP1 path-normalization algorithm applies unchanged: an empty path becomes `/`, unreserved
escapes decode, retained percent escapes use uppercase hex, and complete dot segments are removed
(`REQ-LLH1-URI-path`). Query, fragment, control bytes, non-ASCII bytes, malformed percent escapes,
and output above `bounds.uri_bytes` are invalid (`REQ-LLH1-URI-reject-list`).

Examples:

```text
http://127.0.0.1                  -> http://127.0.0.1/
HTTP://127.0.0.1:04000/a/../b     -> http://127.0.0.1:4000/b
http://[::1]:80/api               -> http://[::1]/api
http://[::1]:4318/api             -> http://[::1]:4318/api
```

## 4. Public verification contract

A language binding MUST expose separately named equivalents of these five surfaces
(`REQ-LLH1-API-complete`):

1. URI normalization;
2. proof signing-input production;
3. compact assembly from signing input and external signature;
4. proof decoding;
5. combined raw-envelope verification.

The Elixir reference namespace is
`BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1`. Its functions return the same
success shapes as the corresponding BAP1 functions and the single `{:error, :invalid}` failure
shape (`REQ-LLH1-API-return-shape`). It owns no signer and accepts no private key or signing callback
(`REQ-LLH1-API-no-signer`).

Compact assembly MUST revalidate the protected header, payload, target URI, nonce, segment bounds,
and signature width under this profile before returning a compact artifact
(`REQ-LLH1-API-assembly-revalidate`). Producer, assembler, decoder, and envelope verifier MUST use
the same profile semantics (`REQ-LLH1-API-symmetry`).

Verification facts remain the BAP1 redacted, value-bearing, non-authorizing facts. No transport
decision, raw credential, signature, nonce, private key, or application authorization result is
added (`REQ-LLH1-API-facts`).

## 5. Security and host obligations

Literal loopback HTTP supplies neither TLS confidentiality nor server authentication. Loopback is a
host boundary, not a user/process isolation boundary. This profile MUST NOT be represented as
equivalent to HTTPS or used for non-loopback transport (`REQ-LLH1-SECURITY-honest-scope`).

The verifying host MUST derive the expected scheme, literal listener address, bound port, and direct
request path from trusted listener/request state, not forwarding metadata
(`REQ-LLH1-HOST-direct-target`). It MUST reserve the nonce and invocation for single use before a
business effect, use environment-appropriate issuer/audience/trust configuration, and tighten proof
age and skew to its observed request/clock envelope (`REQ-LLH1-HOST-replay-trust`). These are host
requirements; the stateless public verifier checks supplied bytes and context but owns no replay
state or effect.

A caller MUST select exactly one proof profile for a listener and MUST NOT implement try-standard-
then-loopback or try-loopback-then-standard fallback (`REQ-LLH1-HOST-one-profile`).

## 6. Conformance and release

This profile has a separate language-neutral corpus, certified index digest, monotone revision,
requirement applicability map, and independent implementation. Cases cover every surface, exact
IPv4/IPv6 accepts, every rejection family, cross-profile rejection, mandatory nonce, assembly,
meaningful-byte tampers, and unchanged execution of the complete BAP1 corpus
(`REQ-LLH1-CONFORMANCE-complete`).

`proof-cases.json` MAY carry one closed `expected_overrides` member on an envelope case. Revision 1
admits exactly one of `trusted_issuer_public_key` (canonical base64url public key bytes) or
`invocation_id` (the expected invocation identifier). Consumers MUST apply that expected-context
override before evaluating `envelope_local` and MUST reject unknown or combined overrides. These
cases make trust and invocation binding independently observable rather than relying on a bad
signature or another earlier rejection.

Revision 1's certified `index.json` SHA-256 is
`10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4`. Every corpus consumer MUST
pin that digest independently, require the exact two-file set `profile.json` and
`proof-cases.json`, and require profile identity, revision, and case counts before trusting the
per-file digests.

Every shipped verifier SDK MUST implement its relevant profile surfaces and pass the certified
corpus before release (`REQ-LLH1-CONFORMANCE-sdks`). A corpus disagreement or an existing BAP1 byte
or verdict change blocks release (`REQ-LLH1-CONFORMANCE-no-drift`).

Release evidence MUST include real HTTP client/server exchanges on both `127.0.0.1` and `::1` using
the public profile API, ephemeral in-memory signing keys, direct listener facts, and secret-free
receipts. A mock, stub, fake server, proxy, canned response, or request-production-only test is not
conformance evidence (`REQ-LLH1-CONFORMANCE-real-network`).

The profile is adopted only from an immutable public package and exact source/corpus identities,
never a path or mutable Git dependency (`REQ-LLH1-RELEASE-immutable`).

## 7. IANA considerations

IANA is asked to register `application/ba-loopback-proof+jwt` using the RFC 6838 field template
under LIMITED USE. The ready-to-file source and rendered form live in
`docs/design/iana/media-types.json` and `docs/design/iana/media-types.md`. Filing remains gated on
the protocol's first external submission; this profile and its protected `ba+loopback-proof` wire
`typ` do not claim an existing registration (`REQ-LLH1-IANA-template`).
