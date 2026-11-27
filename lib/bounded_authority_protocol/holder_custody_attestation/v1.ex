defmodule BoundedAuthorityProtocol.HolderCustodyAttestation.V1 do
  @moduledoc """
  Source candidate for standalone Ed25519 holder custody attestations
  (`bap-holder-custody-attestation/1`).

  An attestor signs a holder key's custody class for a bounded window. Callers explicitly choose
  this namespace. See the
  [normative specification](../spec/bap-holder-custody-attestation-v1.md).

  ## Required context

  `verify_attestation/2` takes raw compact bytes and a
  `BoundedAuthorityProtocol.HolderCustodyAttestation.V1.ExpectedAttestation`. Supply an
  already-trusted `BoundedAuthorityProtocol.V1.HistoricalPublicKey` as `attestor`, the expected
  `subject_key_id` and raw 32-byte `subject_public_key`, integer Unix seconds as `now`, and
  `bounds`. The attestation window must fit within the attestor key's validity window, and
  `nbf <= now < exp`. Empty bounds use profile maxima. Overrides can only tighten them.

  ## Operations and results

  * `attestation_signing_input/2` returns `{:ok, SigningInput}` with exact JWS signing bytes.
    The caller signs elsewhere; no private key enters this package.
  * `assemble_compact/2` and `assemble_compact/3` return `{:ok, compact}` after validating the
    profile and signature encoding. Assembly does not establish cryptographic validity or trust.
  * `decode_attestation/2` returns `{:ok, DecodedAttestation}` for diagnosis without verifying
    a signature. Decoded claims are untrusted.
  * `verify_attestation/2` returns `{:ok, AttestationFacts}` after signature, context, key-window,
    and time checks. Facts have redacted inspection and `trust: :not_evaluated`.

  All four families return exactly `{:error, :invalid}` on malformed or over-limit inputs,
  context mismatches, or failed checks; errors carry no values or diagnostic reason. Success
  never makes the subject key trusted or authorizes an operation. The host decides trust and
  owns revocation, replay reservation, and any maximum-lifetime policy.

  ## Executed example

  The [recipe](../docs/guides/recipes.md#verify-a-holder-custody-attestation) shows signing,
  assembly, decoding and verification against an independently supplied subject.
  """

  alias BoundedAuthorityProtocol.HolderCustodyAttestation.V1.Codec
  alias BoundedAuthorityProtocol.HolderCustodyAttestation.V1.ExpectedAttestation
  alias BoundedAuthorityProtocol.HolderCustodyAttestation.V1.HolderCustodyAttestation
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.SigningInput

  @doc """
  Builds the deterministic holder custody attestation signing input.

  ## Examples

      iex> BoundedAuthorityProtocol.HolderCustodyAttestation.V1.attestation_signing_input(
      ...>   %{},
      ...>   %{}
      ...> )
      {:error, :invalid}
  """
  @spec attestation_signing_input(HolderCustodyAttestation.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  defdelegate attestation_signing_input(attestation, limits), to: Codec, as: :signing_input

  @doc """
  Assembles a holder custody attestation at profile maxima.

  ## Examples

      iex> BoundedAuthorityProtocol.HolderCustodyAttestation.V1.assemble_compact(%{}, "")
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc """
  Assembles a holder custody attestation under caller bounds.

  Assembly applies BAP1 rule S1 to the signature encoding and emits accepted signature bytes
  unchanged.

  ## Examples

      iex> BoundedAuthorityProtocol.HolderCustodyAttestation.V1.assemble_compact(%{}, "", %{})
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Codec.assemble(signing_input, signature, limits)

  @doc """
  Boundedly decodes a holder custody attestation without evaluating trust.

  ## Examples

      iex> BoundedAuthorityProtocol.HolderCustodyAttestation.V1.decode_attestation("", %{})
      {:error, :invalid}
  """
  @spec decode_attestation(binary(), Bounds.t() | map()) ::
          {:ok, BoundedAuthorityProtocol.HolderCustodyAttestation.V1.DecodedAttestation.t()}
          | {:error, :invalid}
  defdelegate decode_attestation(compact, limits), to: Codec, as: :decode

  @doc """
  Verifies a holder custody attestation against the supplied attestor, subject binding and time.

  ## Examples

      iex> BoundedAuthorityProtocol.HolderCustodyAttestation.V1.verify_attestation("", %{})
      {:error, :invalid}
  """
  @spec verify_attestation(binary(), ExpectedAttestation.t()) ::
          {:ok, BoundedAuthorityProtocol.HolderCustodyAttestation.V1.AttestationFacts.t()}
          | {:error, :invalid}
  defdelegate verify_attestation(compact, expected), to: Codec, as: :verify
end
