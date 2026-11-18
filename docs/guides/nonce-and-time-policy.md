# Nonce and time policy

Supply integer Unix seconds from your trusted host clock as `evaluation_time`; the package
never reads a clock. `clock_skew` is a nonnegative integer at most 60 and `proof_max_age` a
positive integer at most 300. Reject a clock reading your service cannot trust; the verifier
cannot detect that your supplied time is false. Synchronize every verifier instance's clock.

A grant accepts `not_before - skew <= evaluation_time < expires_at + skew`. A proof accepts
`issued_at - skew <= evaluation_time <= issued_at + proof_max_age + skew`. Standalone role
and content attestations use the half-open `nbf <= now < exp` window without skew, and their
entire window must fit inside the supplied attestor key's validity.

`ExpectedRequest.nonce` is `:not_required` (the proof must have no nonce) or
`{:required, expected_value}` (the proof must carry exactly that value). Nonce presence alone is
insufficient. A host creates, scopes, stores, and retires challenges; the local-loopback profile
always requires one. Never accept a nonce just because the credential supplies it.

Proof freshness and execution replay are separate policies. Reserve the issuer/grant/invocation
identity durably and atomically before an effect, through grant expiry plus the service's
maximum permitted skew, or longer in authoritative execution history. A holder can sign a new
proof for an old invocation after the first proof expires. The
[service notebook](../notebooks/service-integration.livemd) asserts this retention boundary and
its runner test proves that proof-lifetime retention fails it.
