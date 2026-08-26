# Getting started

This guide walks a new consumer from zero to a verified grant envelope, using only the public
package and public keys.

## What you are holding

`bounded_authority_protocol` is a pure, deterministic verification library: it proves that
caller-supplied bytes satisfy caller-supplied trusted inputs and expected context. It never
selects trusted keys, reserves replay, checks revocation, or grants execution — those belong to
a stateful authority runtime. Read `the specification <../spec/bap-v1.md>`_ for the normative
profile; this guide is operational.

## Installation

```elixir
defp deps do
  [{:bounded_authority_protocol, "~> 0.2"}]
end
```

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
mix bounded_authority_conformance --corpus priv/conformance/v1/corpus
```

Exit 0 is complete agreement (283/283) with the certified corpus digest pinned.

## Where to go next

- The `specification <../spec/bap-v1.md>`_ — the single normative authority.
- [Upgrading](upgrading.md) — the published compatibility contract.
- The [implementer's guide](implementers-guide.md) — building a verifier in any language.
