defmodule BoundedAuthorityProtocol.HolderCustodyAttestation.V1.HolderCustodyAttestation do
  @moduledoc """
  Producer input for an attestor's binding of a holder key to a custody class.

  ## Fields

  * `attestor_key_id`: the attestor key identifier, written to the header `kid`: 1 to `kid_bytes`
    (128) bytes of ASCII letters, digits, `-`, `.`, `_` or `~`.
  * `jti`: the attestation identifier: non-empty StringOrURI of at most `identifier_bytes` (512)
    UTF-8 bytes; the audit and revocation-reference handle.
  * `key_id`: the subject key identifier: 1 to `kid_bytes` (128) bytes of ASCII letters, digits,
    `-`, `.`, `_` or `~`.
  * `public_key`: the subject's raw 32-byte Ed25519 public key; it must pass
    `BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1`.
  * `custody_class`: exactly `"standard"` or `"hosted"`.
  * `nbf`: the start of the acceptance window, integer Unix time in seconds.
  * `exp`: the exclusive end of the window, integer Unix time in seconds; it must be after `nbf`.
  """

  @enforce_keys [:attestor_key_id, :jti, :key_id, :public_key, :custody_class, :nbf, :exp]
  defstruct @enforce_keys

  @typedoc "Producer input for one holder custody attestation."
  @type t :: %__MODULE__{
          attestor_key_id: binary(),
          jti: binary(),
          key_id: binary(),
          public_key: binary(),
          custody_class: binary(),
          nbf: integer(),
          exp: integer()
        }
end
