defmodule BoundedAuthorityProtocol.V1.TrustedIssuer do
  @moduledoc "Caller-supplied already-trusted issuer key context."

  @enforce_keys [:key_id, :public_key]
  defstruct @enforce_keys

  @type t :: %__MODULE__{key_id: binary(), public_key: binary()}
end
