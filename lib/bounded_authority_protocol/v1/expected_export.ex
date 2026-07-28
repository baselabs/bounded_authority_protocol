defmodule BoundedAuthorityProtocol.V1.ExpectedExport do
  @moduledoc "Exact semantic context required before deterministic archive framing."

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition

  @enforce_keys [:chain, :start_anchor, :transitions, :end_anchor, :bounds]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          chain: ExpectedChain.t(),
          start_anchor: ExpectedAnchor.t(),
          transitions: [ExpectedKeyTransition.t()],
          end_anchor: ExpectedAnchor.t(),
          bounds: Bounds.t() | map()
        }
end
