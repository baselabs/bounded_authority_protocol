defmodule BoundedAuthorityProtocol.V1.ChainInput do
  @moduledoc "Raw canonical consumption rows presented for chain verification."

  @enforce_keys [:rows]
  defstruct @enforce_keys

  @type t :: %__MODULE__{rows: [binary()]}
end
