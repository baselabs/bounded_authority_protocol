defmodule BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation do
  @moduledoc "Closed bounded decode of one role attestation without trust evaluation."

  @enforce_keys [
    :version,
    :attestor_key_id,
    :jti,
    :key_id,
    :public_key,
    :role,
    :nbf,
    :exp,
    :verification
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          attestor_key_id: binary(),
          jti: binary(),
          key_id: binary(),
          public_key: binary(),
          role: binary(),
          nbf: integer(),
          exp: integer(),
          verification: :not_evaluated
        }
end
