defmodule BoundedAuthorityProtocol.V1.ExpectedRequest do
  @moduledoc """
  Explicit expected context for combined raw-envelope verification.

  Every value here comes from the caller's own request handling and records, never from the
  credentials being checked. The same struct serves contract-majors 1, 2 and 3 and the
  local-loopback HTTP profile (which requires a nonce).

  ## Fields

  * `trusted_issuer` - the `BoundedAuthorityProtocol.V1.TrustedIssuer` your service already trusts.
  * `issuer` - the expected grant `iss`, compared byte-for-byte.
  * `audience` - one audience your service answers to; the grant's `aud` must contain it.
  * `method` - the request method as received, compared byte-for-byte (never case-normalized).
  * `target_uri` - the request target as your server derives it, already in normal form
    (`BoundedAuthorityProtocol.V1.Uri.normalize/2`).
  * `invocation_id` - the lowercase RFC 4122 UUID your service assigned to this invocation.
  * `operation` - the operation name the request performs.
  * `cast_arguments` - the typed arguments your server derived from the request, as a tagged
    `BoundedAuthorityProtocol.V1.Json.value()`; every selector of the operation must accept them.
    Redacted by `inspect/2`.
  * `evaluation_time` - the caller's current time, integer Unix time in seconds; the library reads
    no clock.
  * `clock_skew` - the tolerated clock skew in seconds, `0` to `clock_skew` (60).
  * `proof_max_age` - the maximum proof age in seconds, `1` to `proof_max_age` (300).
  * `nonce` - `:not_required` (the proof must carry no nonce) or `{:required, nonce}` (the proof
    must carry exactly `nonce`). The nonce is redacted by `inspect/2`.
  * `bounds` - a `BoundedAuthorityProtocol.V1.Bounds` struct or a map of tightening overrides; `%{}`
    means the profile maxima (see `BoundedAuthorityProtocol.V1.Bounds.coerce/1`).
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.TrustedIssuer

  @enforce_keys [
    :trusted_issuer,
    :issuer,
    :audience,
    :method,
    :target_uri,
    :invocation_id,
    :operation,
    :cast_arguments,
    :evaluation_time,
    :clock_skew,
    :proof_max_age,
    :nonce,
    :bounds
  ]
  defstruct @enforce_keys

  @typedoc "Expected context for the façade's `check_envelope/2` (for example `BoundedAuthorityProtocol.V1.check_envelope/2`)."
  @type t :: %__MODULE__{
          trusted_issuer: TrustedIssuer.t(),
          issuer: binary(),
          audience: binary(),
          method: binary(),
          target_uri: binary(),
          invocation_id: binary(),
          operation: binary(),
          cast_arguments: Json.value(),
          evaluation_time: integer(),
          clock_skew: non_neg_integer(),
          proof_max_age: pos_integer(),
          nonce: :not_required | {:required, binary()},
          bounds: Bounds.t() | map()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.ExpectedRequest do
  # Redacts credential-bearing fields so routine logging never prints them.
  def inspect(
        %BoundedAuthorityProtocol.V1.ExpectedRequest{
          trusted_issuer: trusted_issuer,
          issuer: issuer,
          audience: audience,
          method: method,
          target_uri: target_uri,
          invocation_id: invocation_id,
          operation: operation,
          cast_arguments: _cast_arguments,
          evaluation_time: evaluation_time,
          clock_skew: clock_skew,
          proof_max_age: proof_max_age,
          nonce: nonce,
          bounds: bounds
        },
        _options
      ) do
    Inspect.Algebra.string(
      "#BoundedAuthorityProtocol.V1.ExpectedRequest<" <>
        "trusted_issuer: " <>
        Kernel.inspect(trusted_issuer) <>
        ", " <>
        "issuer: " <>
        Kernel.inspect(issuer) <>
        ", " <>
        "audience: " <>
        Kernel.inspect(audience) <>
        ", " <>
        "method: " <>
        Kernel.inspect(method) <>
        ", " <>
        "target_uri: " <>
        Kernel.inspect(target_uri) <>
        ", " <>
        "invocation_id: " <>
        Kernel.inspect(invocation_id) <>
        ", " <>
        "operation: " <>
        Kernel.inspect(operation) <>
        ", " <>
        "cast_arguments: :redacted, " <>
        "evaluation_time: " <>
        Kernel.inspect(evaluation_time) <>
        ", " <>
        "clock_skew: " <>
        Kernel.inspect(clock_skew) <>
        ", " <>
        "proof_max_age: " <>
        Kernel.inspect(proof_max_age) <>
        ", " <>
        "nonce: " <>
        expected_nonce(nonce) <>
        ", " <>
        "bounds: " <>
        Kernel.inspect(bounds) <>
        ">"
    )
  end

  defp expected_nonce(:not_required), do: ":not_required"
  defp expected_nonce({:required, _nonce}), do: "{:required, :redacted}"
  defp expected_nonce(_nonce), do: ":redacted"
end
