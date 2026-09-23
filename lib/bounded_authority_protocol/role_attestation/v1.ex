defmodule BoundedAuthorityProtocol.RoleAttestation.V1 do
  @moduledoc "Explicit entry point for the byte-distinct role-attestation profile (bap-role-attestation/1)."

  alias BoundedAuthorityProtocol.RoleAttestation.V1.Codec
  alias BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation
  alias BoundedAuthorityProtocol.RoleAttestation.V1.RoleAttestation
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.SigningInput

  @doc "Builds the deterministic role-attestation signing input."
  @spec attestation_signing_input(RoleAttestation.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  defdelegate attestation_signing_input(attestation, limits), to: Codec, as: :signing_input

  @doc "Assembles a role attestation at profile maxima."
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc "Assembles a role attestation under caller bounds."
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Codec.assemble(signing_input, signature, limits)

  @doc "Boundedly decodes a role attestation without evaluating trust."
  @spec decode_attestation(binary(), Bounds.t() | map()) ::
          {:ok, BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation.t()}
          | {:error, :invalid}
  defdelegate decode_attestation(compact, limits), to: Codec, as: :decode

  @doc "Verifies a role attestation against caller-supplied attestor trust, subject binding, and now."
  @spec verify_attestation(binary(), ExpectedAttestation.t()) ::
          {:ok, BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts.t()}
          | {:error, :invalid}
  defdelegate verify_attestation(compact, expected), to: Codec, as: :verify
end
