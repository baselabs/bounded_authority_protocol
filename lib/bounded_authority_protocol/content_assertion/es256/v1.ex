defmodule BoundedAuthorityProtocol.ContentAssertion.ES256.V1 do
  @moduledoc """
  Standalone ES256 content assertions (`bap-content-assertion-es256/1`).

  Signatures bind exact content digests, caller-pinned profile identity, context, a generation,
  predecessor digest, and a bounded window. These are byte-distinct sibling assertions, not
  grants or request proofs. See the [normative specification](../spec/bap-content-assertion-es256-v1.md).

  ## Required context

  `verify_assertion/2` takes compact bytes and a
  `BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ExpectedContentAssertion`. Supply the already-trusted
  attestor `BoundedAuthorityProtocol.V1.HistoricalPublicKey`, exact `issuer`, `audience`, `subject`,
  and `profile` strings, raw 32-byte `profile_digest` and `content_digest`, integer Unix seconds
  as `now`, and `bounds`. No digest check can be opted out of. The assertion's entire window must
  fit within the attestor key's validity window, and `nbf <= now < exp`. Bounds can only tighten
  profile maxima; `%{}` uses those maxima. The library reads no clock or key store.

  ## Operations and results

  * `assertion_signing_input/2` returns `{:ok, SigningInput}`; sign its `message` outside this
    package. `assemble_compact/2` and `assemble_compact/3` return `{:ok, compact}` after checking
    the profile and signature encoding, without establishing signature validity or trust.
  * `decode_assertion/2` returns `{:ok, DecodedContentAssertion}` without checking the signature.
  * `verify_assertion/2` returns `{:ok, ContentAssertionFacts}` with redacted inspection and
    `trust: :not_evaluated`. This checks the supplied public key, context, digest, and window.
  * `content_digest/2` returns `{:ok, raw_32_byte_digest}` for nonempty exact content bytes.
    `assertion_digest/2` returns the same result shape for exact profile-parseable compact bytes;
    it does not check their signature or canonicalize them.
  * `verify_successor/3` returns `:ok`, not new facts, for a consistent pair of supplied facts.
    It checks their lineage relationship without verifying either fact's provenance.

  Each operation returns exactly `{:error, :invalid}` for invalid inputs or a failed check. A
  digest proves neither content meaning nor approval. The caller must verify each assertion,
  choose trusted keys, check revocation, reserve replay, and maintain durable lineage high-water
  state. A valid pair alone cannot exclude a fork or rollback. Success never grants execution.
  """
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.{
    ContentAssertion,
    ContentAssertionFacts,
    DecodedContentAssertion,
    ExpectedContentAssertion
  }

  alias BoundedAuthorityProtocol.ContentAssertion.V1.Codec
  alias BoundedAuthorityProtocol.V1.{Bounds, SigningInput}

  @doc """
  Produces deterministic signing bytes for this closed profile.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.assertion_signing_input(%{}, %{})
      {:error, :invalid}
  """
  @spec assertion_signing_input(ContentAssertion.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  def assertion_signing_input(assertion, limits),
    do: Codec.signing_input(assertion, limits, :es256)

  @doc """
  Assembles and revalidates this profile at the maximum bounds.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.assemble_compact(%{}, "")
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(input, signature), do: assemble_compact(input, signature, %{})

  @doc """
  Assembles and revalidates this profile under tightened bounds.

  Accepts a raw 64-byte P-256 signature with in-range scalars and low S.
  Assembly emits the accepted signature bytes unchanged.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.assemble_compact(%{}, "", %{})
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(input, signature, limits),
    do: Codec.assemble(input, signature, limits, :es256)

  @doc """
  Decodes bounded fields without evaluating the signature or trust.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.decode_assertion("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec decode_assertion(binary(), Bounds.t() | map()) ::
          {:ok, DecodedContentAssertion.t()} | {:error, :invalid}
  def decode_assertion(compact, limits), do: Codec.decode(compact, limits, :es256)

  @doc """
  Verifies against explicit public trust, complete expected context and time.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.verify_assertion("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec verify_assertion(binary(), ExpectedContentAssertion.t()) ::
          {:ok, ContentAssertionFacts.t()} | {:error, :invalid}
  def verify_assertion(compact, expected), do: Codec.verify(compact, expected, :es256)

  @doc """
  Hashes nonempty exact content bytes in the fixed content domain; never parses them.

  ## Examples

      iex> {:ok, first} = BoundedAuthorityProtocol.ContentAssertion.ES256.V1.content_digest("first", %{})
      iex> {:ok, second} = BoundedAuthorityProtocol.ContentAssertion.ES256.V1.content_digest("second", %{})
      iex> byte_size(first) == 32 and first != second
      true
      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.content_digest("", %{})
      {:error, :invalid}
  """
  @spec content_digest(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  defdelegate content_digest(bytes, limits), to: Codec

  @doc """
  Hashes exact profile-parseable compact bytes; establishes no signature or trust.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.assertion_digest("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec assertion_digest(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def assertion_digest(compact, limits), do: Codec.assertion_digest(compact, limits, :es256)

  @doc """
  Checks pairwise lineage consistency and returns `:ok` or `{:error, :invalid}`.

  This compares caller-supplied facts; it neither verifies their provenance nor returns new
  verified facts. Verify both assertions first and retain authoritative high-water state to
  detect forks or rollback. Current trust and authorization remain the caller's responsibility.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.ES256.V1.verify_successor(%{}, %{}, %{})
      {:error, :invalid}
  """
  @spec verify_successor(ContentAssertionFacts.t(), ContentAssertionFacts.t(), Bounds.t() | map()) ::
          :ok | {:error, :invalid}
  def verify_successor(previous, next, limits),
    do: Codec.verify_successor(previous, next, limits, :es256)
end
