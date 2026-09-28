defmodule BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertion do
  @moduledoc "Producer inputs for a standalone digest-bound content assertion."

  @enforce_keys [
    :attestor_key_id,
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
    :exp
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          attestor_key_id: binary(),
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
          exp: integer()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertion do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertion<redacted>"
      )
end
