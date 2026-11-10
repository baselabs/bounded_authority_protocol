defmodule BoundedAuthorityProtocol.V1.ExpectedAnchoredExport do
  @moduledoc """
  Mandatory caller context for atomic anchored-export verification.

  Supply every value from your own records, never from the archive being verified.

  ## Fields

  * `chain` - the `BoundedAuthorityProtocol.V1.ExpectedChain` boundaries of the exported range.
  * `start_anchor` - the `BoundedAuthorityProtocol.V1.ExpectedAnchor` for the start anchor.
  * `transitions` - the ordered `BoundedAuthorityProtocol.V1.ExpectedKeyTransition` list.
  * `end_anchor` - the `BoundedAuthorityProtocol.V1.ExpectedAnchor` for the end anchor.
  * `digest` - the expected raw 32-byte SHA-256 of the complete archive.
  * `object_version` - the expected object-store version string.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition

  @enforce_keys [
    :chain,
    :start_anchor,
    :transitions,
    :end_anchor,
    :digest,
    :object_version,
    :bounds
  ]
  defstruct @enforce_keys

  @typedoc "Expected context for the façade's `verify_anchored_export/3` (for example `BoundedAuthorityProtocol.V1.verify_anchored_export/3`)."
  @type t :: %__MODULE__{
          chain: ExpectedChain.t(),
          start_anchor: ExpectedAnchor.t(),
          transitions: [ExpectedKeyTransition.t()],
          end_anchor: ExpectedAnchor.t(),
          digest: binary(),
          object_version: binary(),
          bounds: Bounds.t() | map()
        }
end
