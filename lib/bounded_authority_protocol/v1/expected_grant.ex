defmodule BoundedAuthorityProtocol.V1.ExpectedGrant do
  @moduledoc "Explicit expected context for standalone raw-grant verification."

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [:issuer, :audience, :evaluation_time, :clock_skew, :bounds]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          issuer: binary(),
          audience: binary(),
          evaluation_time: integer(),
          clock_skew: non_neg_integer(),
          bounds: Bounds.t() | map()
        }
end
