defmodule BoundedAuthorityProtocol.V1.AnchoredExportInput do
  @moduledoc """
  Raw rows and compact JWS values presented for deterministic archive framing.

  ## Fields

  * `rows` - the raw canonical rows to export, in sequence order.
  * `start_anchor` - the boundary-anchor compact at the start of the range, at most `anchor_bytes`
    (8,192).
  * `transitions` - the ordered key-transition compacts, at most `key_transitions` (256).
  * `end_anchor` - the boundary-anchor compact at the end of the range.
  """

  @enforce_keys [:rows, :start_anchor, :transitions, :end_anchor]
  defstruct @enforce_keys

  @typedoc "Producer input for anchored-export framing."
  @type t :: %__MODULE__{
          rows: [binary()],
          start_anchor: binary(),
          transitions: [binary()],
          end_anchor: binary()
        }
end
