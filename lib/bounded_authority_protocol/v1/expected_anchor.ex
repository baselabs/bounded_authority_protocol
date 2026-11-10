defmodule BoundedAuthorityProtocol.V1.ExpectedAnchor do
  @moduledoc """
  Exact expected context for one historical boundary anchor.

  ## Fields

  * `anchor_id` - the expected anchor identity.
  * `anchored_at` - the expected anchor time, integer Unix time in seconds.
  * `chain_id` - the chain identity: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `sequence` - the expected anchored sequence number.
  * `chain_hash` - the expected raw 32-byte chain hash at `sequence`.
  * `key_id` - the expected signing key identifier.
  * `key_fingerprint` - the expected raw 32-byte RFC 7638 fingerprint of the signing key.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [
    :anchor_id,
    :anchored_at,
    :chain_id,
    :sequence,
    :chain_hash,
    :key_id,
    :key_fingerprint,
    :bounds
  ]
  defstruct @enforce_keys

  @typedoc "Expected context for one boundary anchor."
  @type t :: %__MODULE__{
          anchor_id: binary(),
          anchored_at: integer(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary(),
          key_id: binary(),
          key_fingerprint: binary(),
          bounds: Bounds.t() | map()
        }
end
