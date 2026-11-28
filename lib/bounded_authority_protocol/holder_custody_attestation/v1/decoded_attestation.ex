defmodule BoundedAuthorityProtocol.HolderCustodyAttestation.V1.DecodedAttestation do
  @moduledoc """
  Closed bounded decode of one holder custody attestation without trust evaluation.

  Returned by `BoundedAuthorityProtocol.HolderCustodyAttestation.V1.decode_attestation/2`
  for diagnosis. Its claims are unverified.

  ## Fields

  * `version`: always `1`.
  * `attestor_key_id`: the header `kid`.
  * `jti`: the attestation identifier.
  * `key_id`: the subject key identifier.
  * `public_key`: the subject's raw 32-byte Ed25519 public key.
  * `custody_class`: `"standard"` or `"hosted"`.
  * `nbf`: the start of the window, integer Unix time in seconds.
  * `exp`: the exclusive end of the window, integer Unix time in seconds.
  * `verification`: always `:not_evaluated`.
  """

  @enforce_keys [
    :version,
    :attestor_key_id,
    :jti,
    :key_id,
    :public_key,
    :custody_class,
    :nbf,
    :exp,
    :verification
  ]
  defstruct @enforce_keys

  @typedoc "An unverified decoded holder custody attestation."
  @type t :: %__MODULE__{
          version: 1,
          attestor_key_id: binary(),
          jti: binary(),
          key_id: binary(),
          public_key: binary(),
          custody_class: binary(),
          nbf: integer(),
          exp: integer(),
          verification: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.HolderCustodyAttestation.V1.DecodedAttestation do
  def inspect(value, _options),
    do: Inspect.Algebra.string(BoundedAuthorityProtocol.DiagnosticRendering.render(value))
end
