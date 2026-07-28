defmodule BoundedAuthorityProtocol.V1.HistoricalKeyChain do
  @moduledoc "Ordered nonempty caller-supplied historical public-key chain."

  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @enforce_keys [:keys]
  defstruct @enforce_keys

  @type t :: %__MODULE__{keys: [HistoricalPublicKey.t()]}
end
