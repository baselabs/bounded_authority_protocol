defmodule BoundedAuthorityProtocol.V1.ArchivedObject do
  @moduledoc "Raw stored-object chunks and exact observed object-store version."

  @enforce_keys [:chunks, :version]
  defstruct @enforce_keys

  @type t :: %__MODULE__{chunks: [binary()], version: binary()}
end
