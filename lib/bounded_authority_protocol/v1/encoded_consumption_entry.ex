defmodule BoundedAuthorityProtocol.V1.EncodedConsumptionEntry do
  @moduledoc "Exact canonical consumption row bytes and domain-separated row hash."

  @enforce_keys [:bytes, :hash]
  defstruct @enforce_keys

  @type t :: %__MODULE__{bytes: binary(), hash: binary()}
end
