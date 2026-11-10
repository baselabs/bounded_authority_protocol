defmodule BoundedAuthorityProtocol.V1.ChainInput do
  @moduledoc """
  Raw canonical consumption rows presented for chain verification.

  ## Fields

  * `rows` - a nonempty list of raw canonical row binaries in sequence order, at most `chain_rows`
    (65,536) rows of at most `chain_row_bytes` (4,096) bytes each.
  """

  @enforce_keys [:rows]
  defstruct @enforce_keys

  @typedoc "Raw rows for the façade's `check_chain/2` (for example `BoundedAuthorityProtocol.V1.check_chain/2`)."
  @type t :: %__MODULE__{rows: [binary()]}
end
