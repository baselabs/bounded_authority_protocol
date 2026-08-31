defmodule BoundedAuthorityProtocol.V1.SigningInput do
  @moduledoc "Closed deterministic standard-JWS signing input."

  @enforce_keys [:kind, :protected_segment, :payload_segment, :message]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          kind:
            :grant
            | :proof
            | :local_loopback_http_proof
            | :boundary_anchor
            | :key_transition,
          protected_segment: binary(),
          payload_segment: binary(),
          message: binary()
        }
end
