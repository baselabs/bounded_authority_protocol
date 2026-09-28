defmodule BoundedAuthorityProtocol.ContentAssertion.V1 do
  @moduledoc """
  Explicit standalone content-assertion profile: signatures bind exact content digests,
  caller-supplied context and a bounded window. Verification never grants authority.
  The caller owns content semantics, trusted key selection, replay and durable lineage state.
  """
  alias BoundedAuthorityProtocol.ContentAssertion.V1.{
    Codec,
    ContentAssertion,
    ContentAssertionFacts,
    DecodedContentAssertion,
    ExpectedContentAssertion
  }

  alias BoundedAuthorityProtocol.V1.{Bounds, SigningInput}

  @doc "Produces deterministic signing bytes for this closed profile."
  @spec assertion_signing_input(ContentAssertion.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  defdelegate assertion_signing_input(assertion, limits), to: Codec, as: :signing_input

  @doc "Assembles and revalidates this profile at the maximum bounds."
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(input, signature), do: assemble_compact(input, signature, %{})

  @doc "Assembles and revalidates this profile under tightened bounds."
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  defdelegate assemble_compact(input, signature, limits), to: Codec, as: :assemble

  @doc "Decodes bounded fields without evaluating the signature or trust."
  @spec decode_assertion(binary(), Bounds.t() | map()) ::
          {:ok, DecodedContentAssertion.t()} | {:error, :invalid}
  defdelegate decode_assertion(compact, limits), to: Codec, as: :decode

  @doc "Verifies against explicit public trust, complete expected context and time."
  @spec verify_assertion(binary(), ExpectedContentAssertion.t()) ::
          {:ok, ContentAssertionFacts.t()} | {:error, :invalid}
  defdelegate verify_assertion(compact, expected), to: Codec, as: :verify

  @doc "Hashes nonempty exact content bytes in the fixed content domain; never parses them."
  @spec content_digest(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  defdelegate content_digest(bytes, limits), to: Codec

  @doc "Hashes exact profile-parseable compact bytes; establishes no signature or trust."
  @spec assertion_digest(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  defdelegate assertion_digest(compact, limits), to: Codec

  @doc "Checks pairwise lineage facts; caller owns their provenance, current trust and high-water state."
  @spec verify_successor(ContentAssertionFacts.t(), ContentAssertionFacts.t(), Bounds.t() | map()) ::
          :ok | {:error, :invalid}
  defdelegate verify_successor(previous, next, limits), to: Codec
end
