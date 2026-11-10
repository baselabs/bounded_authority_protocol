defmodule BoundedAuthorityProtocol.V1.ChainFacts do
  @moduledoc """
  Closed redacted non-authorizing consumption-chain facts.

  ## Fields

  * `version` - the contract-major, always `1`.
  * `chain_id` - the verified chain identity.
  * `first_sequence` - the sequence number of the first row checked.
  * `last_sequence` - the sequence number of the last row checked.
  * `row_count` - the number of rows checked.
  * `previous_hash` - the raw 32-byte hash that preceded the first row.
  * `last_hash` - the raw 32-byte hash of the last row (the head).
  * `verification` - always `:boundary_consistent`: the rows are consistent with the caller's
    boundaries.
  * `trust` - always `:not_evaluated`.
  """

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

  @typedoc "Facts from a consistent consumption-chain range."
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
