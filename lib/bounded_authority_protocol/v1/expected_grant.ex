defmodule BoundedAuthorityProtocol.V1.ExpectedGrant do
  @moduledoc """
  Explicit expected context for standalone raw-grant verification.

  ## Fields

  * `issuer` - the expected `iss`, compared byte-for-byte.
  * `audience` - one audience your service answers to; the grant's `aud` must contain it.
  * `evaluation_time` - the caller's current time, integer Unix time in seconds; the library reads
    no clock.
  * `clock_skew` - the tolerated clock skew in seconds, `0` to `clock_skew` (60).
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds

  @enforce_keys [:issuer, :audience, :evaluation_time, :clock_skew, :bounds]
  defstruct @enforce_keys

  @typedoc "Expected context for the façade's `verify_grant/3` (for example `BoundedAuthorityProtocol.V1.verify_grant/3`)."
  @type t :: %__MODULE__{
          issuer: binary(),
          audience: binary(),
          evaluation_time: integer(),
          clock_skew: non_neg_integer(),
          bounds: Bounds.t() | map()
        }
end
