defmodule BoundedAuthorityProtocol.V1.EnvelopeFacts do
  @moduledoc "Closed value-bearing, redacted, non-authorizing verified envelope facts."

  @enforce_keys [
    :version,
    :issuer,
    :grant_id,
    :issuer_key_fingerprint,
    :holder_thumbprint,
    :matched_audience,
    :issued_at,
    :not_before,
    :expires_at,
    :authorization,
    :proof_id,
    :invocation_id,
    :operation,
    :target_uri,
    :grant_hash,
    :request_hash,
    :proof_issued_at
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          version: 1,
          issuer: binary(),
          grant_id: binary(),
          issuer_key_fingerprint: binary(),
          holder_thumbprint: binary(),
          matched_audience: binary(),
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          authorization: :not_evaluated,
          proof_id: binary(),
          invocation_id: binary(),
          operation: binary(),
          target_uri: binary(),
          grant_hash: binary(),
          request_hash: binary(),
          proof_issued_at: integer()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.EnvelopeFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V1.EnvelopeFacts<redacted>")
end
