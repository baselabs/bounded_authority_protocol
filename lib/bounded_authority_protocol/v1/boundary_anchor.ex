defmodule BoundedAuthorityProtocol.V1.BoundaryAnchor do
  @moduledoc "Closed deterministic boundary-anchor signing input."

  @enforce_keys [
    :anchor_id,
    :anchored_at,
    :chain_id,
    :sequence,
    :chain_hash,
    :key_id,
    :public_key
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          anchor_id: binary(),
          anchored_at: integer(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary(),
          key_id: binary(),
          public_key: binary()
        }
end
