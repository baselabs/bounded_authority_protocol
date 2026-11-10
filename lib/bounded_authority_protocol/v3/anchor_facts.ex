defmodule BoundedAuthorityProtocol.V3.AnchorFacts do
  @moduledoc """
  Closed redacted non-authorizing historical-anchor facts.

  ## Fields

  * `version` - the contract-major, always `3`.
  * `anchor_id` - the verified anchor identity.
  * `anchored_at` - the verified anchor time, integer Unix time in seconds.
  * `chain_id` - the verified chain identity.
  * `sequence` - the anchored sequence number (0 anchors an empty chain).
  * `chain_hash` - the raw 32-byte chain hash at `sequence`.
  * `key_fingerprint` - the raw 32-byte RFC 7638 fingerprint of the signing key.
  * `verification` - always `:signature_and_window`: the signature verified and `anchored_at` lies
    inside the key's validity window.
  * `trust` - always `:not_evaluated`.
  """

  @enforce_keys [
    :version,
    :anchor_id,
    :anchored_at,
    :chain_id,
    :sequence,
    :chain_hash,
    :key_fingerprint,
    :verification,
    :trust
  ]
  defstruct @enforce_keys

  @typedoc "Facts from a verified boundary anchor."
  @type t :: %__MODULE__{
          version: 3,
          anchor_id: binary(),
          anchored_at: integer(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary(),
          key_fingerprint: binary(),
          verification: :signature_and_window,
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V3.AnchorFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V3.AnchorFacts<redacted>")
end
