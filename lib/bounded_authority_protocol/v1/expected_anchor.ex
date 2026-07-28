defmodule BoundedAuthorityProtocol.V1.ExpectedAnchor do
  @moduledoc "Exact expected context for one historical boundary anchor."

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [
    :anchor_id,
    :anchored_at,
    :chain_id,
    :sequence,
    :chain_hash,
    :key_id,
    :key_fingerprint,
    :bounds
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          anchor_id: binary(),
          anchored_at: integer(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary(),
          key_id: binary(),
          key_fingerprint: binary(),
          bounds: Bounds.t() | map()
        }
end
