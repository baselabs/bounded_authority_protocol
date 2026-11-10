defmodule BoundedAuthorityProtocol.V1.ExpectedChain do
  @moduledoc """
  Mandatory caller-derived boundaries for one nonempty consumption-chain range.

  Supply these from your own records, never from the rows being checked: a consistent chain cannot
  by itself show that no row was removed.

  ## Fields

  * `chain_id` - the chain identity: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `first_sequence` - the expected sequence number of the first row.
  * `last_sequence` - the expected sequence number of the last row.
  * `row_count` - the expected number of rows.
  * `previous_hash` - the raw 32-byte hash of the row before `first_sequence` (32 zero bytes when it
    is `1`).
  * `last_hash` - the raw 32-byte hash of the row at `last_sequence` (the head).
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

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

  @typedoc "Caller boundaries for the façade's `check_chain/2` (for example `BoundedAuthorityProtocol.V1.check_chain/2`)."
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
