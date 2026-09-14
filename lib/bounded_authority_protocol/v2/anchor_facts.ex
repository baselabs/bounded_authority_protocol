defmodule BoundedAuthorityProtocol.V2.AnchorFacts do
  @moduledoc "Closed redacted non-authorizing historical-anchor facts."

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

  @type t :: %__MODULE__{
          version: 2,
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

defimpl Inspect, for: BoundedAuthorityProtocol.V2.AnchorFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V2.AnchorFacts<redacted>")
end
