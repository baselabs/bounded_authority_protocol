defmodule BoundedAuthorityProtocol.V1.ConsumptionEntry do
  @moduledoc "Closed deterministic consumption-chain row producer input."

  @enforce_keys [:chain_id, :sequence, :previous_hash, :commitment]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          chain_id: binary(),
          sequence: pos_integer(),
          previous_hash: binary(),
          commitment: binary()
        }
end
