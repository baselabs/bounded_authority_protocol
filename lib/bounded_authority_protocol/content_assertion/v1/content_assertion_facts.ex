defmodule BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts do
  @moduledoc "Non-authorizing verified content assertion facts; caller owns trust and persistence."

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
