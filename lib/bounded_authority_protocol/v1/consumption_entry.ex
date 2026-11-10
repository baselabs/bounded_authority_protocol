defmodule BoundedAuthorityProtocol.V1.ConsumptionEntry do
  @moduledoc """
  Closed deterministic consumption-chain row producer input.

  ## Fields

  * `chain_id` - the chain identity: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `sequence` - the row's positive sequence number; `1` starts a chain.
  * `previous_hash` - the raw 32-byte hash of the preceding row; 32 zero bytes when `sequence` is
    `1`.
  * `commitment` - a raw 32-byte opaque commitment to the consumption record; its preimage stays
    private to the caller.
  """

  @enforce_keys [:chain_id, :sequence, :previous_hash, :commitment]
  defstruct @enforce_keys

  @typedoc "Producer input for one consumption-chain row."
  @type t :: %__MODULE__{
          chain_id: binary(),
          sequence: pos_integer(),
          previous_hash: binary(),
          commitment: binary()
        }
end
