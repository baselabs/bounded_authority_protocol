defmodule BoundedAuthorityProtocol.V1.HistoricalPublicKey do
  @moduledoc "One exact caller-supplied historical public key and validity window."

  @enforce_keys [:key_id, :public_key, :valid_from, :valid_before]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          key_id: binary(),
          public_key: binary(),
          valid_from: integer(),
          valid_before: integer() | :unbounded
        }
end
