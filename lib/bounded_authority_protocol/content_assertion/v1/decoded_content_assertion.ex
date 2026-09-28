defmodule BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion do
  @moduledoc "Untrusted bounded content assertion fields; decoding establishes no signature or trust."

  @enforce_keys [
    :version,
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
    :exp,
    :verification
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
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
          exp: integer(),
          verification: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion<redacted>"
      )
end
