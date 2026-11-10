defmodule BoundedAuthorityProtocol.V1.BoundaryAnchor do
  @moduledoc """
  Closed deterministic boundary-anchor signing input.

  ## Fields

  * `anchor_id` - the anchor identity: non-empty StringOrURI of at most `identifier_bytes` (512)
    UTF-8 bytes.
  * `anchored_at` - the anchor time, integer Unix time in seconds.
  * `chain_id` - the chain identity: non-empty StringOrURI of at most `identifier_bytes` (512) UTF-8
    bytes.
  * `sequence` - the anchored sequence number; `0` anchors an empty chain and requires a
    `chain_hash` of 32 zero bytes.
  * `chain_hash` - the raw 32-byte chain hash at `sequence`.
  * `key_id` - the signing key identifier, written to `kid`: 1 to `kid_bytes` (128) bytes of ASCII
    letters, digits, `-`, `.`, `_` or `~`.
  * `public_key` - the signer's raw public key in the suite's fixed width: 32-byte Ed25519 under
    contract-majors 1 and 2, the 65-byte uncompressed SEC1 P-256 point `0x04 || x || y` under
    contract-major 3; the payload binds its RFC 7638 fingerprint.
  """

  @enforce_keys [
    :anchor_id,
    :anchored_at,
    :chain_id,
    :sequence,
    :chain_hash,
    :key_id,
    :public_key
  ]
  defstruct @enforce_keys

  @typedoc "Producer input for one boundary anchor."
  @type t :: %__MODULE__{
          anchor_id: binary(),
          anchored_at: integer(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary(),
          key_id: binary(),
          public_key: binary()
        }
end
