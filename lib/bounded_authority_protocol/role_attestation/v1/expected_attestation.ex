defmodule BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation do
  @moduledoc """
  Exact expected context for one role attestation: attestor trust, subject binding, now, bounds.

  ## Fields

  * `attestor` - the `BoundedAuthorityProtocol.V1.HistoricalPublicKey` of the attestor you trust
    (key id, raw 32-byte key and validity window); the attestation window must lie inside it.
  * `subject_key_id` - the subject key identifier the attestation must name.
  * `subject_public_key` - the subject's raw 32-byte Ed25519 public key the attestation must name.
  * `now` - the caller's current time, integer Unix time in seconds; it must lie in `[nbf, exp)`.
    The library reads no clock.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @enforce_keys [:attestor, :subject_key_id, :subject_public_key, :now, :bounds]
  defstruct @enforce_keys

  @typedoc "Expected context for `BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2`."
  @type t :: %__MODULE__{
          attestor: HistoricalPublicKey.t(),
          subject_key_id: binary(),
          subject_public_key: binary(),
          now: integer(),
          bounds: Bounds.t() | map()
        }
end
