defmodule BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion do
  @moduledoc """
  Explicit trusted key, exact context, content digest, time and bounds.

  ## Fields

  * `attestor` - the `BoundedAuthorityProtocol.V1.HistoricalPublicKey` of the attestor you trust;
    the assertion window must lie inside its validity window.
  * `issuer` - the expected `iss`.
  * `audience` - the expected `aud`.
  * `subject` - the expected `sub`.
  * `profile` - the expected `profile`.
  * `profile_digest` - the expected raw 32-byte profile digest.
  * `content_digest` - the expected raw 32-byte content digest; there is no opt-out.
  * `now` - the caller's current time, integer Unix time in seconds; it must satisfy `nbf <= now <
    exp`.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  @enforce_keys [
    :attestor,
    :issuer,
    :audience,
    :subject,
    :profile,
    :profile_digest,
    :content_digest,
    :now,
    :bounds
  ]
  defstruct @enforce_keys

  @typedoc "Expected context for `BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion/2`."
  @type t :: %__MODULE__{
          attestor: BoundedAuthorityProtocol.V1.HistoricalPublicKey.t(),
          issuer: binary(),
          audience: binary(),
          subject: binary(),
          profile: binary(),
          profile_digest: binary(),
          content_digest: binary(),
          now: integer(),
          bounds: BoundedAuthorityProtocol.V1.Bounds.t() | map()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion<redacted>"
      )
end
