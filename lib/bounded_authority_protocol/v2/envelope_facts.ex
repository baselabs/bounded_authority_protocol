defmodule BoundedAuthorityProtocol.V2.EnvelopeFacts do
  @moduledoc """
  Closed value-bearing, redacted, non-authorizing verified envelope facts.

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
  * `proof_id` - the verified proof `jti`.
  * `invocation_id` - the verified `ba_inv`; reserve it against replay yourself.
  * `operation` - the verified operation name.
  * `target_uri` - the verified normalized target URI.
  * `grant_hash` - the raw 32-byte SHA-256 of the grant compact the proof is bound to.
  * `request_hash` - the raw 32-byte request digest the proof is bound to.
  * `proof_issued_at` - the proof `iat`, integer Unix time in seconds.
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

  @typedoc "Facts from a verified grant and proof."
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

defimpl Inspect, for: BoundedAuthorityProtocol.V2.EnvelopeFacts do
  def inspect(_value, _options),
    do: Inspect.Algebra.string("#BoundedAuthorityProtocol.V2.EnvelopeFacts<redacted>")
end
