defmodule BoundedAuthorityProtocol.V1.ExpectedChain do
  @moduledoc "Mandatory caller-derived boundaries for one nonempty consumption-chain range."

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [
    :chain_id,
    :first_sequence,
    :last_sequence,
    :row_count,
    :previous_hash,
    :last_hash,
    :bounds
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          chain_id: binary(),
          first_sequence: pos_integer(),
          last_sequence: pos_integer(),
          row_count: pos_integer(),
          previous_hash: binary(),
          last_hash: binary(),
          bounds: Bounds.t() | map()
        }
end
