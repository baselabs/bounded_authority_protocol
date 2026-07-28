defmodule BoundedAuthorityProtocol.V1.KeyTransition do
  @moduledoc "Closed deterministic historical-key transition signing input."

  @enforce_keys [
    :transition_id,
    :chain_id,
    :effective_at,
    :current_key_id,
    :current_public_key,
    :next_key_id,
    :next_public_key
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          transition_id: binary(),
          chain_id: binary(),
          effective_at: integer(),
          current_key_id: binary(),
          current_public_key: binary(),
          next_key_id: binary(),
          next_public_key: binary()
        }
end
