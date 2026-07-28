defmodule BoundedAuthorityProtocol.V1.Grant do
  @moduledoc "Closed deterministic grant producer input."

  alias BoundedAuthorityProtocol.V1.Operation

  @enforce_keys [
    :key_id,
    :issuer,
    :grant_id,
    :audiences,
    :issued_at,
    :not_before,
    :expires_at,
    :holder_thumbprint,
    :operations
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          key_id: binary(),
          issuer: binary(),
          grant_id: binary(),
          audiences: [binary()],
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          holder_thumbprint: binary(),
          operations: [Operation.t()]
        }
end
