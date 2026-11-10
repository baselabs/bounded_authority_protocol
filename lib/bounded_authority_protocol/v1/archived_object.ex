defmodule BoundedAuthorityProtocol.V1.ArchivedObject do
  @moduledoc """
  Raw stored-object chunks and exact observed object-store version.

  ## Fields

  * `chunks` - the stored archive bytes as an ordered nonempty chunk list, exactly as read back, at
    most `archive_chunks` (65,796) chunks and `archive_bytes` in total.
  * `version` - the object-store version you observed when reading, at most `object_version_bytes`
    (512) bytes; compared exactly with the expected version.
  """

  @enforce_keys [:chunks, :version]
  defstruct @enforce_keys

  @typedoc "A stored archive as read back."
  @type t :: %__MODULE__{chunks: [binary()], version: binary()}
end
