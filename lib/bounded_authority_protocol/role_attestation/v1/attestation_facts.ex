defmodule BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts do
  @moduledoc """
  Closed value-bearing, redacted, non-authorizing verified role-attestation facts.

  ## Fields

  * `version` - always `1`.
  * `attestor_key_id` - the verified attestor key identifier.
  * `attestor_key_fingerprint` - the raw 32-byte RFC 7638 fingerprint of the attestor key.
  * `subject_key_id` - the verified subject key identifier.
  * `subject_key_fingerprint` - the raw 32-byte RFC 7638 fingerprint of the subject key.
  * `role` - the attested role, `"issuer"` or `"holder"`.
  * `jti` - the attestation identifier.
  * `nbf` - the start of the window, integer Unix time in seconds.
  * `exp` - the exclusive end of the window, integer Unix time in seconds.
  * `verification` - always `:signature_and_window`.
  * `trust` - always `:not_evaluated`.
  """

  @enforce_keys [
    :version,
    :attestor_key_id,
    :attestor_key_fingerprint,
    :subject_key_id,
    :subject_key_fingerprint,
    :role,
    :jti,
    :nbf,
    :exp,
    :verification,
    :trust
  ]
  defstruct @enforce_keys

  @typedoc "Facts from a verified role attestation."
  @type t :: %__MODULE__{
          version: 1,
          attestor_key_id: binary(),
          attestor_key_fingerprint: binary(),
          subject_key_id: binary(),
          subject_key_fingerprint: binary(),
          role: binary(),
          jti: binary(),
          nbf: integer(),
          exp: integer(),
          verification: :signature_and_window,
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts<redacted>"
      )
end
