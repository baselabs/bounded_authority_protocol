defmodule BoundedAuthorityProtocol.V3.DecodedProof do
  @moduledoc """
  Closed bounded decoded proof with explicitly unevaluated verification.

  Returned by `BoundedAuthorityProtocol.V3.decode_proof/2` for diagnosis only; it is never a verified value.

  ## Fields

  * `version` - the contract-major, always `3`.
  * `proof_id` - the `jti` claim: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `method` - the `htm` claim, byte-for-byte as signed.
  * `target_uri` - the `htu` claim; decode refuses a value that is not already in normal form.
  * `issued_at` - the `iat` claim, integer Unix time in seconds.
  * `nonce` - the `nonce` claim, or `nil` when absent. Redacted by `inspect/2`.
  * `invocation_id` - the `ba_inv` claim, a lowercase RFC 4122 UUID.
  * `operation` - the `ba_op` claim, the operation name.
  * `grant_hash` - the decoded `ath` claim: the raw 32-byte SHA-256 of the grant compact the proof
    names.
  * `request_hash` - the decoded `ba_req` claim: the raw 32-byte request digest.
  * `holder_public_key` - the holder's raw 65-byte uncompressed SEC1 P-256 point `0x04 || x || y`,
    decoded from the header JWK.
  * `holder_thumbprint` - the raw 32-byte RFC 7638 thumbprint of the header JWK.
  * `verification` - always `:not_evaluated`: no signature, key or expected context was checked.
  """

  @enforce_keys [
    :version,
    :proof_id,
    :method,
    :target_uri,
    :issued_at,
    :nonce,
    :invocation_id,
    :operation,
    :grant_hash,
    :request_hash,
    :holder_public_key,
    :holder_thumbprint,
    :verification
  ]
  defstruct @enforce_keys

  @typedoc "An unverified decoded proof."
  @type t :: %__MODULE__{
          version: 3,
          proof_id: binary(),
          method: binary(),
          target_uri: binary(),
          issued_at: integer(),
          nonce: nil | binary(),
          invocation_id: binary(),
          operation: binary(),
          grant_hash: binary(),
          request_hash: binary(),
          holder_public_key: binary(),
          holder_thumbprint: binary(),
          verification: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V3.DecodedProof do
  # Redacts credential-bearing fields so routine logging never prints them.
  def inspect(
        %BoundedAuthorityProtocol.V3.DecodedProof{
          version: version,
          proof_id: proof_id,
          method: method,
          target_uri: target_uri,
          issued_at: issued_at,
          nonce: nonce,
          invocation_id: invocation_id,
          operation: operation,
          grant_hash: grant_hash,
          request_hash: request_hash,
          holder_public_key: holder_public_key,
          holder_thumbprint: holder_thumbprint,
          verification: verification
        },
        _options
      ) do
    Inspect.Algebra.string(
      "#BoundedAuthorityProtocol.V3.DecodedProof<" <>
        "version: " <>
        Kernel.inspect(version) <>
        ", " <>
        "proof_id: " <>
        Kernel.inspect(proof_id) <>
        ", " <>
        "method: " <>
        Kernel.inspect(method) <>
        ", " <>
        "target_uri: " <>
        Kernel.inspect(target_uri) <>
        ", " <>
        "issued_at: " <>
        Kernel.inspect(issued_at) <>
        ", " <>
        "nonce: " <>
        optional_nonce(nonce) <>
        ", " <>
        "invocation_id: " <>
        Kernel.inspect(invocation_id) <>
        ", " <>
        "operation: " <>
        Kernel.inspect(operation) <>
        ", " <>
        "grant_hash: " <>
        Kernel.inspect(grant_hash) <>
        ", " <>
        "request_hash: " <>
        Kernel.inspect(request_hash) <>
        ", " <>
        "holder_public_key: " <>
        Kernel.inspect(holder_public_key) <>
        ", " <>
        "holder_thumbprint: " <>
        Kernel.inspect(holder_thumbprint) <>
        ", " <>
        "verification: " <>
        Kernel.inspect(verification) <>
        ">"
    )
  end

  defp optional_nonce(nil), do: "nil"
  defp optional_nonce(_nonce), do: ":redacted"
end
