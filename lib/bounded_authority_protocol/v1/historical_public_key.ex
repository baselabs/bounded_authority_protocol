defmodule BoundedAuthorityProtocol.V1.HistoricalPublicKey do
  @moduledoc """
  One exact caller-supplied historical public key and validity window.

  ## Fields

  * `key_id` - the key identifier: 1 to `kid_bytes` (128) bytes of ASCII letters, digits, `-`, `.`,
    `_` or `~`.
  * `public_key` - the raw public key in the suite's fixed width: 32-byte Ed25519 under
    contract-majors 1 and 2, the 65-byte uncompressed SEC1 P-256 point `0x04 || x || y` under
    contract-major 3.
  * `valid_from` - the inclusive start of the window, integer Unix time in seconds.
  * `valid_before` - the exclusive end of the window, integer Unix time in seconds, or `:unbounded`.
  """

  @enforce_keys [:key_id, :public_key, :valid_from, :valid_before]
  defstruct @enforce_keys

  @typedoc "One historical public key and its validity window."
  @type t :: %__MODULE__{
          key_id: binary(),
          public_key: binary(),
          valid_from: integer(),
          valid_before: integer() | :unbounded
        }
end
