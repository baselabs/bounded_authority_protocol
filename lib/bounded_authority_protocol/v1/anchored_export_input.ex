defmodule BoundedAuthorityProtocol.V1.AnchoredExportInput do
  @moduledoc "Raw rows and compact JWS values presented for deterministic archive framing."

  @enforce_keys [:rows, :start_anchor, :transitions, :end_anchor]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          rows: [binary()],
          start_anchor: binary(),
          transitions: [binary()],
          end_anchor: binary()
        }
end
