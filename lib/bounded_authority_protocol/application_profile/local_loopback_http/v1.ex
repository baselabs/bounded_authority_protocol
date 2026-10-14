defmodule BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1 do
  @moduledoc "Explicit entry point for the byte-distinct local-loopback HTTP application proof profile."

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.Uri
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Runtime
  alias BoundedAuthorityProtocol.V1.SigningInput

  @doc "Normalizes one bounded local-loopback HTTP target URI without DNS or network access."
  defdelegate normalize_uri(uri, limits), to: Uri, as: :normalize

  @doc "Builds the deterministic byte-distinct local-loopback proof signing input."
  defdelegate proof_signing_input(proof, limits),
    to: Runtime,
    as: :local_loopback_proof_signing_input

  @doc "Assembles a local-loopback proof at profile maxima."
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc """
  Assembles a local-loopback proof under caller bounds.

  Since 0.9.0 (unreleased, planned for 0.9.0), assembly also refuses, with `{:error, :invalid}`, a
  signature that no conforming signer emits: an Ed25519 signature whose `S` is not below the group
  order or whose `R` is non-canonical or of small order (erratum 3). It never rewrites the
  signature bytes it accepts.
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Runtime.assemble_local_loopback_compact(signing_input, signature, limits)

  @doc "Boundedly decodes a local-loopback proof without evaluating trust."
  defdelegate decode_proof(compact, limits), to: Runtime, as: :decode_local_loopback_proof

  @doc "Verifies a raw grant and local-loopback proof against server-derived context."
  defdelegate check_envelope(credentials, expected_request),
    to: Runtime,
    as: :check_local_loopback_envelope
end
