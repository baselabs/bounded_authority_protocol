defmodule BoundedAuthorityProtocol.RoleAttestation.V1.RoleAttestation do
  @moduledoc "One producer-side role attestation: an attestor key binding a subject key to a role."

  @enforce_keys [:attestor_key_id, :jti, :key_id, :public_key, :role, :nbf, :exp]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          attestor_key_id: binary(),
          jti: binary(),
          key_id: binary(),
          public_key: binary(),
          role: binary(),
          nbf: integer(),
          exp: integer()
        }
end
