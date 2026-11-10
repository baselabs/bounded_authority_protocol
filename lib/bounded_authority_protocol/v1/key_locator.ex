defmodule BoundedAuthorityProtocol.V1.KeyLocator do
  @moduledoc """
  An untrusted key identifier hint.

  This value carries no authorization or trust decision.

  ## Fields

  * `kid` - the grant header's `kid`: 1 to `kid_bytes` (128) bytes of ASCII letters, digits, `-`,
    `.`, `_` or `~`.
  * `trust` - always `:not_evaluated`.
  """

  @enforce_keys [:kid, :trust]
  defstruct [:kid, :trust]

  @typedoc "An untrusted `kid` hint."
  @type t :: %__MODULE__{kid: binary(), trust: :not_evaluated}
end
