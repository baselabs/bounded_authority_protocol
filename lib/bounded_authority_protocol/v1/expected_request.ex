defmodule BoundedAuthorityProtocol.V1.ExpectedRequest do
  @moduledoc "Explicit expected context for combined raw-envelope verification."

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.TrustedIssuer

  @enforce_keys [
    :trusted_issuer,
    :issuer,
    :audience,
    :method,
    :target_uri,
    :invocation_id,
    :operation,
    :cast_arguments,
    :evaluation_time,
    :clock_skew,
    :proof_max_age,
    :nonce,
    :bounds
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          trusted_issuer: TrustedIssuer.t(),
          issuer: binary(),
          audience: binary(),
          method: binary(),
          target_uri: binary(),
          invocation_id: binary(),
          operation: binary(),
          cast_arguments: Json.value(),
          evaluation_time: integer(),
          clock_skew: non_neg_integer(),
          proof_max_age: pos_integer(),
          nonce: :not_required | {:required, binary()},
          bounds: Bounds.t() | map()
        }
end
