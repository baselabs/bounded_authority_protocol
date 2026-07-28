defmodule BoundedAuthorityProtocol.V1.ExpectedKeyTransition do
  @moduledoc "Exact expected context for one authenticated historical-key transition."

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [
    :transition_id,
    :chain_id,
    :effective_at,
    :current_key_id,
    :current_key_fingerprint,
    :next_key_id,
    :next_key_fingerprint,
    :bounds
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          transition_id: binary(),
          chain_id: binary(),
          effective_at: integer(),
          current_key_id: binary(),
          current_key_fingerprint: binary(),
          next_key_id: binary(),
          next_key_fingerprint: binary(),
          bounds: Bounds.t() | map()
        }
end
