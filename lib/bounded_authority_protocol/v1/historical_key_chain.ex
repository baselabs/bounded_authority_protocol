defmodule BoundedAuthorityProtocol.V1.HistoricalKeyChain do
  @moduledoc """
  Ordered nonempty caller-supplied historical public-key chain.

  ## Fields

  * `keys` - a nonempty ordered list of `BoundedAuthorityProtocol.V1.HistoricalPublicKey` structs:
    the start anchor's key first, then one key per transition, in order (at most `key_transitions`
    (256) transitions).
  """

  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @enforce_keys [:keys]
  defstruct @enforce_keys

  @typedoc "The ordered key history for an anchored export."
  @type t :: %__MODULE__{keys: [HistoricalPublicKey.t()]}
end
