defmodule BoundedAuthorityProtocol.V2.GrantFacts do
  @moduledoc """
  Closed value-bearing, redacted, non-authorizing verified grant facts.

  ## Fields

  * `version` - the contract-major, always `2`.
  * `issuer` - the verified `iss` claim.
  * `grant_id` - the verified `jti` claim.
  * `issuer_key_fingerprint` - the raw 32-byte RFC 7638 thumbprint of the trusted issuer public key
    the caller supplied.
  * `holder_thumbprint` - the raw 32-byte RFC 7638 thumbprint the grant confirms (`cnf.jkt`).
  * `matched_audience` - the expected audience, which the grant's `aud` contains.
  * `issued_at` - the grant `iat`, integer Unix time in seconds.
  * `not_before` - the grant `nbf`, integer Unix time in seconds.
  * `expires_at` - the grant `exp`, integer Unix time in seconds.
  * `authorization` - always `:not_evaluated`: these facts are never an authorization decision.
  """

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
    :authorization
  ]
  defstruct @enforce_keys

  @typedoc "Facts from a verified grant."
  @type t :: %__MODULE__{
          version: 2,
          issuer: binary(),
          grant_id: binary(),
          issuer_key_fingerprint: binary(),
          holder_thumbprint: binary(),
          matched_audience: binary(),
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          authorization: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V2.GrantFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V2.GrantFacts<redacted>")
end
