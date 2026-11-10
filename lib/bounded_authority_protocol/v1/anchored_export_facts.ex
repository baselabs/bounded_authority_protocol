defmodule BoundedAuthorityProtocol.V1.AnchoredExportFacts do
  @moduledoc """
  Closed redacted non-authorizing atomic anchored-export facts.

  ## Fields

  * `version` - the contract-major, always `1`.
  * `chain_id` - the verified chain identity.
  * `first_sequence` - the first exported sequence number.
  * `last_sequence` - the last exported sequence number.
  * `row_count` - the number of exported rows.
  * `previous_hash` - the raw 32-byte hash that preceded the first row.
  * `last_hash` - the raw 32-byte hash of the last row.
  * `digest` - the raw 32-byte SHA-256 of the complete archive bytes.
  * `start_anchor_id` - the start anchor's identity.
  * `start_anchored_at` - the start anchor's time, integer Unix time in seconds.
  * `start_key_fingerprint` - the raw 32-byte fingerprint of the key that signed the start anchor.
  * `end_anchor_id` - the end anchor's identity.
  * `end_anchored_at` - the end anchor's time, integer Unix time in seconds.
  * `end_key_fingerprint` - the raw 32-byte fingerprint of the key that signed the end anchor.
  * `transition_count` - the number of authenticated key transitions in the archive.
  * `verification` - always `:anchored_export`.
  * `trust` - always `:not_evaluated`.
  * `authorization` - always `:not_evaluated`.
  """

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

  @typedoc "Facts from a verified anchored export."
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
