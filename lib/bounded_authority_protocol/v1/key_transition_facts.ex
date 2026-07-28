defmodule BoundedAuthorityProtocol.V1.KeyTransitionFacts do
  @moduledoc "Closed redacted non-authorizing authenticated key-transition facts."

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

  @type t :: %__MODULE__{
          version: 1,
          transition_id: binary(),
          effective_at: integer(),
          chain_id: binary(),
          current_key_fingerprint: binary(),
          next_key_fingerprint: binary(),
          verification: :authenticated_transition,
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.KeyTransitionFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V1.KeyTransitionFacts<redacted>")
end
