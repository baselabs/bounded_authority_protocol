defmodule BoundedAuthorityProtocol.V1.EncodedAnchoredExport do
  @moduledoc "Exact archive chunks, complete digest, and byte count from deterministic framing."

  @enforce_keys [:chunks, :digest, :byte_count]
  defstruct @enforce_keys

  @type t :: %__MODULE__{chunks: [binary()], digest: binary(), byte_count: pos_integer()}
end
