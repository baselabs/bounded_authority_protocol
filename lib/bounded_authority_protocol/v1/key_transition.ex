defmodule BoundedAuthorityProtocol.V1.KeyTransition do
  @moduledoc """
  Closed deterministic historical-key transition signing input.

  ## Fields

  * `transition_id` - the transition identity: non-empty StringOrURI of at most `identifier_bytes`
    (512) UTF-8 bytes.
  * `chain_id` - the chain identity: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `effective_at` - when the next key takes over, integer Unix time in seconds; it must lie inside
    both keys' validity windows.
  * `current_key_id` - the identifier of the signing (current) key: 1 to `kid_bytes` (128) bytes of
    ASCII letters, digits, `-`, `.`, `_` or `~`.
  * `current_public_key` - the current key's raw public key in the suite's fixed width: 32-byte
    Ed25519 under contract-majors 1 and 2, the 65-byte uncompressed SEC1 P-256 point `0x04 || x ||
    y` under contract-major 3; it signs the transition.
  * `next_key_id` - the identifier of the next key: 1 to `kid_bytes` (128) bytes of ASCII letters,
    digits, `-`, `.`, `_` or `~`; it may equal `current_key_id`.
  * `next_public_key` - the next key, in the same width; it must differ from `current_public_key`.
  """

  @enforce_keys [
    :transition_id,
    :chain_id,
    :effective_at,
    :current_key_id,
    :current_public_key,
    :next_key_id,
    :next_public_key
  ]
  defstruct @enforce_keys

  @typedoc "Producer input for one historical-key transition."
  @type t :: %__MODULE__{
          transition_id: binary(),
          chain_id: binary(),
          effective_at: integer(),
          current_key_id: binary(),
          current_public_key: binary(),
          next_key_id: binary(),
          next_public_key: binary()
        }
end
