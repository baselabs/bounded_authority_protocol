defmodule BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation do
  @moduledoc "Exact expected context for one role attestation: attestor trust, subject binding, now, bounds."

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @enforce_keys [:attestor, :subject_key_id, :subject_public_key, :now, :bounds]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          attestor: HistoricalPublicKey.t(),
          subject_key_id: binary(),
          subject_public_key: binary(),
          now: integer(),
          bounds: Bounds.t() | map()
        }
end
