defmodule BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts do
  @moduledoc "Closed value-bearing, redacted, non-authorizing verified role-attestation facts."

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
