defmodule BoundedAuthorityProtocol.RoleAttestation.V1 do
  @moduledoc """
  Standalone Ed25519 role attestations (`bap-role-attestation/1`), not grant credentials.

  An attestor signs a subject key's binding to the closed role `"issuer"` or `"holder"` for a
  bounded window. The profile's bytes are distinct from grants, proofs, and content assertions;
  callers explicitly choose this namespace. See the
  [normative specification](../spec/bap-role-attestation-v1.md).

  ## Required context

  `verify_attestation/2` takes raw compact bytes and a
  `BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation`. Supply an already-trusted
  `BoundedAuthorityProtocol.V1.HistoricalPublicKey` as `attestor`, the expected `subject_key_id`
  and raw 32-byte `subject_public_key`, integer Unix seconds as `now`, and `bounds`. The complete
  attestation window must fit within the attestor key's validity window, and `nbf <= now < exp`.
  `%{}` bounds use profile maxima; overrides can only tighten them. No clock or trust store is read.

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

  [The role-attestation recipe](../docs/guides/recipes.md#verify-a-role-attestation) generates
  ephemeral keys, signs and assembles an attestation, decodes it, and verifies both a matching
  subject and a rejected mismatch. The documentation consumer executes that exact code.
  """

  alias BoundedAuthorityProtocol.RoleAttestation.V1.Codec
  alias BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation
  alias BoundedAuthorityProtocol.RoleAttestation.V1.RoleAttestation
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.SigningInput

  @doc """
  Builds the deterministic role-attestation signing input.

  ## Examples

      iex> BoundedAuthorityProtocol.RoleAttestation.V1.attestation_signing_input(%{}, %{})
      {:error, :invalid}
  """
  @spec attestation_signing_input(RoleAttestation.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  defdelegate attestation_signing_input(attestation, limits), to: Codec, as: :signing_input

  @doc """
  Assembles a role attestation at profile maxima.

  ## Examples

      iex> BoundedAuthorityProtocol.RoleAttestation.V1.assemble_compact(%{}, "")
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc """
  Assembles a role attestation under caller bounds.

  Since 0.9.0, assembly also refuses, with `{:error, :invalid}`, a
  signature that no conforming signer emits: an Ed25519 signature whose `S` is not below the group
  order or whose `R` is non-canonical or of small order (erratum 3). It never rewrites the
  signature bytes it accepts.

  ## Examples

      iex> BoundedAuthorityProtocol.RoleAttestation.V1.assemble_compact(%{}, "", %{})
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Codec.assemble(signing_input, signature, limits)

  @doc """
  Boundedly decodes a role attestation without evaluating trust.

  ## Examples

      iex> BoundedAuthorityProtocol.RoleAttestation.V1.decode_attestation("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec decode_attestation(binary(), Bounds.t() | map()) ::
          {:ok, BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation.t()}
          | {:error, :invalid}
  defdelegate decode_attestation(compact, limits), to: Codec, as: :decode

  @doc """
  Verifies a role attestation against caller-supplied attestor trust, subject binding, and now.

  ## Examples

      iex> BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec verify_attestation(binary(), ExpectedAttestation.t()) ::
          {:ok, BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts.t()}
          | {:error, :invalid}
  defdelegate verify_attestation(compact, expected), to: Codec, as: :verify
end
