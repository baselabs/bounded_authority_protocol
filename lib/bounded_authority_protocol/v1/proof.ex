defmodule BoundedAuthorityProtocol.V1.Proof do
  @moduledoc "Closed deterministic holder-proof producer input."

  alias BoundedAuthorityProtocol.V1.Json

  @enforce_keys [
    :holder_public_key,
    :proof_id,
    :method,
    :target_uri,
    :issued_at,
    :nonce,
    :invocation_id,
    :operation,
    :grant_compact,
    :cast_arguments
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          holder_public_key: binary(),
          proof_id: binary(),
          method: binary(),
          target_uri: binary(),
          issued_at: integer(),
          nonce: nil | binary(),
          invocation_id: binary(),
          operation: binary(),
          grant_compact: binary(),
          cast_arguments: Json.value()
        }
end
