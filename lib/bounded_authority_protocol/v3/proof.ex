defmodule BoundedAuthorityProtocol.V3.Proof do
  @moduledoc """
  Closed deterministic holder-proof producer input.

  ## Fields

  * `holder_public_key` - the holder's raw 65-byte uncompressed SEC1 P-256 point `0x04 || x || y`,
    embedded in the proof header as a public JWK; it must pass
    `BoundedAuthorityProtocol.Es256.acceptable_public_key?/1` and match the grant's
    `holder_thumbprint`.
  * `proof_id` - the `jti` claim: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `method` - the `htm` claim: a 1 to `method_bytes` (32) byte RFC 9110 method token, compared
    byte-for-byte and never case-normalized (`"POST"` and `"post"` differ).
  * `target_uri` - the `htu` claim: the HTTPS target URI already in normal form
    (`BoundedAuthorityProtocol.V1.Uri.normalize/2`), at most `uri_bytes` (8,192) bytes; a value that
    is not already normalized is refused.
  * `issued_at` - the `iat` claim, integer Unix time in seconds.
  * `nonce` - `nil` for no nonce, or a non-empty UTF-8 string of at most `nonce_bytes` (512) bytes.
    Redacted by `inspect/2`.
  * `invocation_id` - the `ba_inv` claim: a lowercase RFC 4122 UUID naming this one invocation;
    reserving it against replay stays with the caller.
  * `operation` - the `ba_op` claim: the operation name, 1 to `operation_bytes` (128) printable
    ASCII bytes; it must name an operation of the grant.
  * `grant_compact` - the exact grant compact the proof is bound to; the proof carries the SHA-256
    of these bytes (`ath`). Redacted by `inspect/2`.
  * `cast_arguments` - the typed request arguments as a tagged
    `BoundedAuthorityProtocol.V1.Json.value()` (for example `{:object, [{"amount", {:integer,
    5}}]}`); the proof binds their request digest (`ba_req`). Redacted by `inspect/2`.
  """

  alias BoundedAuthorityProtocol.V1.Json

  @enforce_keys [
    :holder_public_key,
    :proof_id,
    :method,
    :target_uri,
    :issued_at,
    :nonce,
    :invocation_id,
    :operation,
    :grant_compact,
    :cast_arguments
  ]
  defstruct @enforce_keys

  @typedoc "Producer input for `BoundedAuthorityProtocol.V3.proof_signing_input/2`."
  @type t :: %__MODULE__{
          holder_public_key: binary(),
          proof_id: binary(),
          method: binary(),
          target_uri: binary(),
          issued_at: integer(),
          nonce: nil | binary(),
          invocation_id: binary(),
          operation: binary(),
          grant_compact: binary(),
          cast_arguments: Json.value()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V3.Proof do
  # Redacts credential-bearing fields so routine logging never prints them.
  def inspect(
        %BoundedAuthorityProtocol.V3.Proof{
          holder_public_key: holder_public_key,
          proof_id: proof_id,
          method: method,
          target_uri: target_uri,
          issued_at: issued_at,
          nonce: nonce,
          invocation_id: invocation_id,
          operation: operation,
          grant_compact: _grant_compact,
          cast_arguments: _cast_arguments
        },
        _options
      ) do
    Inspect.Algebra.string(
      "#BoundedAuthorityProtocol.V3.Proof<" <>
        "holder_public_key: " <>
        Kernel.inspect(holder_public_key) <>
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
        "grant_compact: :redacted, " <>
        "cast_arguments: :redacted" <>
        ">"
    )
  end

  defp optional_nonce(nil), do: "nil"
  defp optional_nonce(_nonce), do: ":redacted"
end
