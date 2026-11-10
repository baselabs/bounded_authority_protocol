defmodule BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts do
  @moduledoc """
  Non-authorizing verified content assertion facts; caller owns trust and persistence.

  ## Fields

  * `version` - always `1`.
  * `attestor_key_id` - the attestor key identifier, the header `kid`: 1 to `kid_bytes` (128) bytes
    of ASCII letters, digits, `-`, `.`, `_` or `~`.
  * `attestor_key_fingerprint` - the raw 32-byte RFC 7638 fingerprint of the attestor key.
  * `jti` - the assertion identifier: non-empty StringOrURI of at most `identifier_bytes` (512)
    UTF-8 bytes.
  * `iss` - the asserted issuer: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `aud` - the one audience: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8 bytes.
  * `sub` - the stable assertion-lineage identifier: non-empty StringOrURI of at most
    `identifier_bytes` (512) UTF-8 bytes.
  * `profile` - the semantic-profile identifier, compared as data: non-empty StringOrURI of at most
    `identifier_bytes` (512) UTF-8 bytes.
  * `profile_digest` - an opaque raw 32-byte caller-pinned profile identity.
  * `content_digest` - the raw 32-byte digest of the exact content bytes (see `BoundedAuthorityProtocol.ContentAssertion.V1.content_digest/2`).
  * `gen` - the generation, `1` to `integer_magnitude`; `1` exactly when `prev` is 32 zero bytes.
  * `prev` - the raw 32-byte `BoundedAuthorityProtocol.ContentAssertion.V1.assertion_digest/2` of the predecessor, or 32 zero bytes at generation
    1.
  * `iat` - the issue time, integer Unix time in seconds.
  * `nbf` - the start of the window, integer Unix time in seconds; `iat <= nbf`.
  * `exp` - the exclusive end of the window, integer Unix time in seconds; `nbf < exp`.
  * `digest` - the raw 32-byte `BoundedAuthorityProtocol.ContentAssertion.V1.assertion_digest/2` of the verified compact (a successor's `prev`).
  * `verification` - always `:signature_and_window`.
  * `trust` - always `:not_evaluated`.
  """

  @enforce_keys [
    :version,
    :attestor_key_id,
    :attestor_key_fingerprint,
    :jti,
    :iss,
    :aud,
    :sub,
    :profile,
    :profile_digest,
    :content_digest,
    :gen,
    :prev,
    :iat,
    :nbf,
    :exp,
    :digest,
    :verification,
    :trust
  ]
  defstruct @enforce_keys

  @typedoc "Facts from a verified content assertion."
  @type t :: %__MODULE__{
          version: 1,
          attestor_key_id: binary(),
          attestor_key_fingerprint: binary(),
          jti: binary(),
          iss: binary(),
          aud: binary(),
          sub: binary(),
          profile: binary(),
          profile_digest: binary(),
          content_digest: binary(),
          gen: integer(),
          prev: binary(),
          iat: integer(),
          nbf: integer(),
          exp: integer(),
          digest: binary(),
          verification: :signature_and_window,
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts<redacted>"
      )
end
