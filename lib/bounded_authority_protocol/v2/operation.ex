defmodule BoundedAuthorityProtocol.V2.Operation do
  @moduledoc """
  Closed producer input for one named operation and its ordered selectors.

  ## Fields

  * `name` - the operation name: 1 to `operation_bytes` (128) printable ASCII bytes, unique within
    the grant.
  * `selectors` - an ordered nonempty list of at most `selectors` (64)
    `BoundedAuthorityProtocol.V2.Selector` terms (kinds `:all`, `equals`, `one_of` and the inclusive
    ranges `lte` and `gte`), applied conjunctively to the request's typed arguments.
  """

  alias BoundedAuthorityProtocol.V2.Selector

  @enforce_keys [:name, :selectors]
  defstruct @enforce_keys

  @typedoc "One named operation and its selectors."
  @type t :: %__MODULE__{name: binary(), selectors: [Selector.t()]}
end
