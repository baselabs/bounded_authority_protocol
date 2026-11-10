defmodule BoundedAuthorityProtocol.V1.TrustedIssuer do
  @moduledoc """
  Caller-supplied already-trusted issuer key context.

  The library never discovers or selects keys: the caller supplies the one key it trusts.

  ## Fields

  * `key_id` - the exact `kid` the grant header must carry: 1 to `kid_bytes` (128) bytes of ASCII
    letters, digits, `-`, `.`, `_` or `~`.
  * `public_key` - the issuer's raw public key in the suite's fixed width: 32-byte Ed25519 under
    contract-majors 1 and 2, the 65-byte uncompressed SEC1 P-256 point `0x04 || x || y` under
    contract-major 3.
  """

  @enforce_keys [:key_id, :public_key]
  defstruct @enforce_keys

  @typedoc "An already-trusted issuer key."
  @type t :: %__MODULE__{key_id: binary(), public_key: binary()}
end
