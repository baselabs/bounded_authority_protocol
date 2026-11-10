defmodule BoundedAuthorityProtocol.V2.KeyTransitionFacts do
  @moduledoc """
  Closed redacted non-authorizing authenticated key-transition facts.

  ## Fields

  * `version` - the contract-major, always `2`.
  * `transition_id` - the verified transition identity.
  * `effective_at` - the verified effective time, integer Unix time in seconds.
  * `chain_id` - the verified chain identity.
  * `current_key_fingerprint` - the raw 32-byte RFC 7638 fingerprint of the key that signed the
    transition.
  * `next_key_fingerprint` - the raw 32-byte RFC 7638 fingerprint of the key it authenticates.
  * `verification` - always `:authenticated_transition`.
  * `trust` - always `:not_evaluated`.
  """

  @enforce_keys [
    :version,
    :transition_id,
    :effective_at,
    :chain_id,
    :current_key_fingerprint,
    :next_key_fingerprint,
    :verification,
    :trust
  ]
  defstruct @enforce_keys

  @typedoc "Facts from a verified key transition."
  @type t :: %__MODULE__{
          version: 2,
          transition_id: binary(),
          effective_at: integer(),
          chain_id: binary(),
          current_key_fingerprint: binary(),
          next_key_fingerprint: binary(),
          verification: :authenticated_transition,
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V2.KeyTransitionFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V2.KeyTransitionFacts<redacted>")
end
