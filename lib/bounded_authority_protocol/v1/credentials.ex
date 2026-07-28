defmodule BoundedAuthorityProtocol.V1.Credentials do
  @moduledoc "Closed raw compact grant and proof credentials."

  @enforce_keys [:grant, :proof]
  defstruct @enforce_keys

  @type t :: %__MODULE__{grant: binary(), proof: binary()}
end
