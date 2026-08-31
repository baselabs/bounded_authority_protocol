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

After 0.3.0 is separately published to Hex and the registry exposes the immutable archive:

```elixir
defp deps do
  [{:bounded_authority_protocol, "~> 0.3.0"}]
end
```

`v0.3.0` is the reviewable source release; it does not stand in for an immutable Hex package
identity, and the dependency above does not resolve before publication and registry read-back.

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
