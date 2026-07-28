defmodule BoundedAuthorityProtocol.V1.DecodedProof do
  @moduledoc "Closed bounded decoded proof with explicitly unevaluated verification."

  @enforce_keys [
    :version,
    :proof_id,
    :method,
    :target_uri,
    :issued_at,
    :nonce,
    :invocation_id,
    :operation,
    :grant_hash,
    :request_hash,
    :holder_public_key,
    :holder_thumbprint,
    :verification
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          proof_id: binary(),
          method: binary(),
          target_uri: binary(),
          issued_at: integer(),
          nonce: nil | binary(),
          invocation_id: binary(),
          operation: binary(),
          grant_hash: binary(),
          request_hash: binary(),
          holder_public_key: binary(),
          holder_thumbprint: binary(),
          verification: :not_evaluated
        }
end
