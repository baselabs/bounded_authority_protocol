defmodule BoundedAuthorityProtocol.V1.ChainFacts do
  @moduledoc "Closed redacted non-authorizing consumption-chain facts."

  @enforce_keys [
    :version,
    :chain_id,
    :first_sequence,
    :last_sequence,
    :row_count,
    :previous_hash,
    :last_hash,
    :verification,
    :trust
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          chain_id: binary(),
          first_sequence: pos_integer(),
          last_sequence: pos_integer(),
          row_count: pos_integer(),
          previous_hash: binary(),
          last_hash: binary(),
          verification: :boundary_consistent,
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.ChainFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V1.ChainFacts<redacted>")
end
