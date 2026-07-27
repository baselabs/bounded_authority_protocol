defmodule BoundedAuthorityProtocol.V1.KeyLocator do
  @moduledoc """
  An untrusted key identifier hint.

  This value carries no authorization or trust decision.
  """

  @enforce_keys [:kid, :trust]
  defstruct [:kid, :trust]

  @type t :: %__MODULE__{kid: binary(), trust: :not_evaluated}
end
