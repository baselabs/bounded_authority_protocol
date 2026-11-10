defmodule BoundedAuthorityProtocol.V1.EncodedAnchoredExport do
  @moduledoc """
  Exact archive chunks, complete digest, and byte count from deterministic framing.

  ## Fields

  * `chunks` - the archive bytes as an ordered nonempty chunk list; their concatenation is the
    archive.
  * `digest` - the raw 32-byte SHA-256 of the complete archive bytes; store it in your own records.
  * `byte_count` - the total archive length in bytes, at most `archive_bytes`.
  """

  @enforce_keys [:chunks, :digest, :byte_count]
  defstruct @enforce_keys

  @typedoc "A framed anchored export."
  @type t :: %__MODULE__{chunks: [binary()], digest: binary(), byte_count: pos_integer()}
end
