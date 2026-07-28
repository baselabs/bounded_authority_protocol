defmodule BoundedAuthorityProtocol.V1.ExpectedAnchoredExport do
  @moduledoc "Mandatory caller context for atomic anchored-export verification."

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition

  @enforce_keys [
    :chain,
    :start_anchor,
    :transitions,
    :end_anchor,
    :digest,
    :object_version,
    :bounds
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          chain: ExpectedChain.t(),
          start_anchor: ExpectedAnchor.t(),
          transitions: [ExpectedKeyTransition.t()],
          end_anchor: ExpectedAnchor.t(),
          digest: binary(),
          object_version: binary(),
          bounds: Bounds.t() | map()
        }
end
