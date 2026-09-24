# Getting started

This guide walks a new consumer from zero to a verified grant envelope, using only the public
package and public keys.

## What you are holding

`bounded_authority_protocol` is a pure, deterministic verification library: it proves that
caller-supplied bytes satisfy caller-supplied trusted inputs and expected context. It never
selects trusted keys, reserves replay, checks revocation, or grants execution — those belong to
a stateful authority runtime. Read the [standard specification](../../spec/bap-v1.md) for the
normative profile; this guide is operational.

## Installation

OBSERVED September 24, 2026: the [Hex release API](https://hex.pm/api/packages/bounded_authority_protocol/releases/0.6.1)
reports release 0.6.1 published on September 23, 2026:

```elixir
defp deps do
  [{:bounded_authority_protocol, "~> 0.6.2"}]
end
```

`v0.6.2` is the cross-Elixir compilation and scan-sensitivity repair patch; `v0.6.1` is the
cross-vendor repair patch; `v0.6.0` adds the role-attestation sibling profile.
`v0.5.0` was the ES256 contract-major 3
activation source release (spec-facts v2/v3 baselines shipped); `v0.5.1` was a docs-maintenance
patch; `v0.4.0` was the v2 source release; `v0.4.1` was the toolchain
release; `v0.4.2` was a documentation-truth patch. The immutable
package identity is the published Hex release, whose
registry checksum was read back against the tagged-tree build. Depend on the package identity —
never a tag or a mutable checkout. To produce (rather than verify) signed envelopes, see the
holder-side companion package
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter).

Zero runtime dependencies. The verification surfaces live under `BoundedAuthorityProtocol.V1`.

## First verification

```elixir
# The caller supplies EVERYTHING: raw bytes, trusted keys, expected context, limits.
{:ok, facts} =
  BoundedAuthorityProtocol.V1.check_envelope(credentials, expected_request)

# facts is value-bearing and redacted: identifiers, digests, times, and
# authorization: :not_evaluated. It is not a decision and not a credential.
```

`credentials` carries the exact grant and proof compact values as received; `expected_request`
carries the method, normalized URI, invocation id, operation, cast arguments, proof age, and
nonce mode. Every mismatch — wrong key, wrong audience, expired, tampered byte, disallowed
selector, wrong nonce mode — returns exactly `{:error, :invalid}`.

## The three rules that surprise newcomers

1. **Facts are not authority.** A green verification proves byte-level properties against the
   inputs YOU supplied. An operational decision needs a stateful runtime that owns trust
   selection, replay reservation, and revocation.
2. **Everything is closed.** Unknown members, alternate encodings, duplicate names, and
   over-limit structures are rejected — there is no permissive mode.
3. **Time is an input.** The verifier reads no clock; you pass the evaluation time, skew, and
   proof maximum age explicitly.

## Verifying your implementation

The package ships the 283-case conformance corpus. Run the deterministic verifier CLI against
it:

```sh
mix escript.build
./bounded_authority_conformance --corpus priv/conformance/v1/corpus
```

Exit 0 is complete agreement (283/283) with the certified corpus digest pinned.

## Local-loopback HTTP development

Version 0.3.0 adds a byte-distinct application proof for a direct local development listener.
Select `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1` explicitly; its five
surfaces normalize the target, produce the proof signing input, assemble the compact proof, decode
it, and verify the envelope. It accepts only canonical `http://127.0.0.1` or `http://[::1]`
targets and requires a server nonce. `localhost`, alternate numeric loopback spellings, query or
fragment components, userinfo, forwarding-derived authority, and every non-loopback host fail
closed.

Standard `BoundedAuthorityProtocol.V1` functions reject local-profile proof bytes, and the
local-profile functions reject standard `dpop+jwt` bytes. Do not infer a profile from input bytes
or retry another profile after rejection. Loopback HTTP is not TLS and does not isolate another
local process; the host still owns listener configuration, replay reservation, and authorization.
The [Livebook](../livebooks/bap-walkthrough.livemd) runs both profiles with ephemeral keys.

## Where to go next

- The [standard specification](../../spec/bap-v1.md) — the standard profile authority.
- The [local-loopback profile](../../spec/bap-local-loopback-http-v1.md) — the byte-distinct
  application profile authority.
- [Upgrading](upgrading.md) — the published compatibility contract.
- The [implementer's guide](implementers-guide.md) — building a verifier in any language.
