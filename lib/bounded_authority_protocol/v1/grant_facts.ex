defmodule BoundedAuthorityProtocol.V1.GrantFacts do
  @moduledoc "Closed value-bearing, redacted, non-authorizing verified grant facts."

  @enforce_keys [
    :version,
    :issuer,
    :grant_id,
    :issuer_key_fingerprint,
    :holder_thumbprint,
    :matched_audience,
    :issued_at,
    :not_before,
    :expires_at,
    :authorization
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          issuer: binary(),
          grant_id: binary(),
          issuer_key_fingerprint: binary(),
          holder_thumbprint: binary(),
          matched_audience: binary(),
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          authorization: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.GrantFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V1.GrantFacts<redacted>")
end
