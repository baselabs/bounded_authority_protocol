defmodule BoundedAuthorityProtocol.V2.DecodedGrant do
  @moduledoc """
  Closed bounded decoded grant with explicitly unevaluated verification.

  Returned by `BoundedAuthorityProtocol.V2.decode_grant/2` for diagnosis only; it is never a verified value.

  ## Fields

  * `version` - the contract-major, always `2`.
  * `key_id` - the issuer key identifier read from the protected `kid` header: 1 to `kid_bytes`
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
  * `holder_thumbprint` - the decoded `cnf.jkt`: the raw 32-byte RFC 7638 thumbprint of the holder's
    public JWK.
  * `operations` - the decoded operations as `BoundedAuthorityProtocol.V2.Operation` structs, in
    grant order.
  * `verification` - always `:not_evaluated`: no signature, key or expected context was checked.
  """

  alias BoundedAuthorityProtocol.V2.Operation

  @enforce_keys [
    :version,
    :key_id,
    :issuer,
    :grant_id,
    :audiences,
    :issued_at,
    :not_before,
    :expires_at,
    :holder_thumbprint,
    :operations,
    :verification
  ]
  defstruct @enforce_keys

  @typedoc "An unverified decoded grant."
  @type t :: %__MODULE__{
          version: 2,
          key_id: binary(),
          issuer: binary(),
          grant_id: binary(),
          audiences: [binary()],
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          holder_thumbprint: binary(),
          operations: [Operation.t()],
          verification: :not_evaluated
        }
end
