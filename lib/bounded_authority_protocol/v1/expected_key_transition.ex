defmodule BoundedAuthorityProtocol.V1.ExpectedKeyTransition do
  @moduledoc """
  Exact expected context for one authenticated historical-key transition.

  ## Fields

  * `transition_id` - the expected transition identity.
  * `chain_id` - the chain identity: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `effective_at` - the expected effective time, integer Unix time in seconds.
  * `current_key_id` - the expected signing key identifier.
  * `current_key_fingerprint` - the expected raw 32-byte RFC 7638 fingerprint of the signing key.
  * `next_key_id` - the expected next key identifier.
  * `next_key_fingerprint` - the expected raw 32-byte RFC 7638 fingerprint of the next key.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [
    :transition_id,
    :chain_id,
    :effective_at,
    :current_key_id,
    :current_key_fingerprint,
    :next_key_id,
    :next_key_fingerprint,
    :bounds
  ]
  defstruct @enforce_keys

  @typedoc "Expected context for one key transition."
  @type t :: %__MODULE__{
          transition_id: binary(),
          chain_id: binary(),
          effective_at: integer(),
          current_key_id: binary(),
          current_key_fingerprint: binary(),
          next_key_id: binary(),
          next_key_fingerprint: binary(),
          bounds: Bounds.t() | map()
        }
end
