defmodule BoundedAuthorityProtocol.V1.ExpectedExport do
  @moduledoc """
  Exact semantic context required before deterministic archive framing.

  ## Fields

  * `chain` - the `BoundedAuthorityProtocol.V1.ExpectedChain` the rows must satisfy.
  * `start_anchor` - the `BoundedAuthorityProtocol.V1.ExpectedAnchor` for the start anchor.
  * `transitions` - the ordered `BoundedAuthorityProtocol.V1.ExpectedKeyTransition` list.
  * `end_anchor` - the `BoundedAuthorityProtocol.V1.ExpectedAnchor` for the end anchor.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition

  @enforce_keys [:chain, :start_anchor, :transitions, :end_anchor, :bounds]
  defstruct @enforce_keys

  @typedoc "Semantic context checked before archive framing."
  @type t :: %__MODULE__{
          chain: ExpectedChain.t(),
          start_anchor: ExpectedAnchor.t(),
          transitions: [ExpectedKeyTransition.t()],
          end_anchor: ExpectedAnchor.t(),
          bounds: Bounds.t() | map()
        }
end
