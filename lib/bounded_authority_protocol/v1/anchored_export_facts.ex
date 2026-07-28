defmodule BoundedAuthorityProtocol.V1.AnchoredExportFacts do
  @moduledoc "Closed redacted non-authorizing atomic anchored-export facts."

  @enforce_keys [
    :version,
    :chain_id,
    :first_sequence,
    :last_sequence,
    :row_count,
    :previous_hash,
    :last_hash,
    :digest,
    :start_anchor_id,
    :start_anchored_at,
    :start_key_fingerprint,
    :end_anchor_id,
    :end_anchored_at,
    :end_key_fingerprint,
    :transition_count,
    :verification,
    :trust,
    :authorization
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          chain_id: binary(),
          first_sequence: pos_integer(),
          last_sequence: pos_integer(),
          row_count: pos_integer(),
          previous_hash: binary(),
          last_hash: binary(),
          digest: binary(),
          start_anchor_id: binary(),
          start_anchored_at: integer(),
          start_key_fingerprint: binary(),
          end_anchor_id: binary(),
          end_anchored_at: integer(),
          end_key_fingerprint: binary(),
          transition_count: non_neg_integer(),
          verification: :anchored_export,
          trust: :not_evaluated,
          authorization: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.AnchoredExportFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V1.AnchoredExportFacts<redacted>")
end
