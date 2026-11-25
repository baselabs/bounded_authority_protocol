defmodule BoundedAuthorityProtocol.ActionApproval.V1.Record do
  @moduledoc """
  Exact subject, action, resource set, request revision, and approver role
  carried by the action approval profile.
  """

  @enforce_keys [:subject, :action, :request_id, :approver_role, :resources, :revision_digest]
  defstruct @enforce_keys

  @typedoc "An approval record with a raw 32-byte revision digest."
  @type t :: %__MODULE__{
          subject: binary(),
          action: binary(),
          request_id: binary(),
          approver_role: binary(),
          resources: [binary()],
          revision_digest: binary()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ActionApproval.V1.Record do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.ActionApproval.V1.Record<redacted>")
end
