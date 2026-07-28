defmodule BoundedAuthorityProtocol.V1.Operation do
  @moduledoc "Closed producer input for one named operation and its ordered selectors."

  alias BoundedAuthorityProtocol.V1.Selector

  @enforce_keys [:name, :selectors]
  defstruct @enforce_keys

  @type t :: %__MODULE__{name: binary(), selectors: [Selector.t()]}
end
