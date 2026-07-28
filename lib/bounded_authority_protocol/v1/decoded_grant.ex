defmodule BoundedAuthorityProtocol.V1.DecodedGrant do
  @moduledoc "Closed bounded decoded grant with explicitly unevaluated verification."

  alias BoundedAuthorityProtocol.V1.Operation

  @enforce_keys [
    :version,
    :key_id,
    :issuer,
    :grant_id,
    :audiences,
    :issued_at,
    :not_before,
    :expires_at,
    :holder_thumbprint,
    :operations,
    :verification
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          key_id: binary(),
          issuer: binary(),
          grant_id: binary(),
          audiences: [binary()],
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          holder_thumbprint: binary(),
          operations: [Operation.t()],
          verification: :not_evaluated
        }
end
