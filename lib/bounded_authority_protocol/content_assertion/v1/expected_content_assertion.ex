defmodule BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion do
  @moduledoc "Explicit trusted key, exact context, content digest, time and bounds."

  @enforce_keys [
    :attestor,
    :issuer,
    :audience,
    :subject,
    :profile,
    :profile_digest,
    :content_digest,
    :now,
    :bounds
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          attestor: BoundedAuthorityProtocol.V1.HistoricalPublicKey.t(),
          issuer: binary(),
          audience: binary(),
          subject: binary(),
          profile: binary(),
          profile_digest: binary(),
          content_digest: binary(),
          now: integer(),
          bounds: BoundedAuthorityProtocol.V1.Bounds.t() | map()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion<redacted>"
      )
end
