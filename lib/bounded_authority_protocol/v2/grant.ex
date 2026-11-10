defmodule BoundedAuthorityProtocol.V2.Grant do
  @moduledoc """
  Closed deterministic grant producer input.

  ## Fields

  * `key_id` - the issuer key identifier written to the protected `kid` header: 1 to `kid_bytes`
    (128) bytes of ASCII letters, digits, `-`, `.`, `_` or `~`. An untrusted lookup hint, never a
    trust selector.
  * `issuer` - the `iss` claim: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes, compared byte-for-byte.
  * `grant_id` - the `jti` claim: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `audiences` - the `aud` claim: a nonempty list of unique StringOrURI values, at most `audiences`
    (64) entries of at most `identifier_bytes` bytes each.
  * `issued_at` - the `iat` claim, integer Unix time in seconds.
  * `not_before` - the `nbf` claim, integer Unix time in seconds.
  * `expires_at` - the `exp` claim, integer Unix time in seconds; it must be after both `issued_at`
    and `not_before` (`issued_at <= not_before` is not required).
  * `holder_thumbprint` - the holder confirmation (`cnf.jkt`) as the raw 32-byte RFC 7638 SHA-256
    thumbprint of the holder's public JWK, not base64url; compute it with
    `BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw/2`.
  * `operations` - a nonempty list of at most `operations` (64)
    `BoundedAuthorityProtocol.V2.Operation` structs with unique names.
  """

  alias BoundedAuthorityProtocol.V2.Operation

  @enforce_keys [
    :key_id,
    :issuer,
    :grant_id,
    :audiences,
    :issued_at,
    :not_before,
    :expires_at,
    :holder_thumbprint,
    :operations
  ]
  defstruct @enforce_keys

  @typedoc "Producer input for `BoundedAuthorityProtocol.V2.grant_signing_input/2`."
  @type t :: %__MODULE__{
          key_id: binary(),
          issuer: binary(),
          grant_id: binary(),
          audiences: [binary()],
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          holder_thumbprint: binary(),
          operations: [Operation.t()]
        }
end
