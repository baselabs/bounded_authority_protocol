defmodule BoundedAuthorityProtocol.ContentAssertion.V1 do
  @moduledoc """
  Standalone Ed25519 content assertions (`bap-content-assertion/1`).

  Signatures bind exact content digests, caller-pinned profile identity, context, a generation,
  predecessor digest, and a bounded window. These are byte-distinct sibling assertions, not
  grants or request proofs. See the [normative specification](../spec/bap-content-assertion-v1.md).

  ## Required context

  `verify_assertion/2` takes compact bytes and a
  `BoundedAuthorityProtocol.ContentAssertion.V1.ExpectedContentAssertion`. Supply the already-trusted
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

  ## Executed example

  [The content-assertion recipe](../docs/guides/recipes.md#verify-content-and-its-successor)
  hashes content, signs two generations, verifies both, and checks their successor relationship.
  It also checks rejection of a changed content digest. The documentation consumer executes
  the exact example against this package.


  The native reference example also produces, decodes, and verifies two assertions. Signing
  happens in the caller; the final tuple contains generations and the consistency verdict.

      iex> alias BoundedAuthorityProtocol.ContentAssertion.V1, as: Content
      iex> alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
      iex> {public, private} = :crypto.generate_key(:eddsa, :ed25519); :ok
      :ok
      iex> {:ok, digest} = Content.content_digest("article bytes", %{})
      iex> assertion = %Content.ContentAssertion{
      ...>   attestor_key_id: "attestor-1", jti: "assertion-1", iss: "issuer", aud: "reader",
      ...>   sub: "article-1", profile: "article-profile", profile_digest: <<1::256>>,
      ...>   content_digest: digest, gen: 1, prev: <<0::256>>, iat: 100, nbf: 100, exp: 200
      ...> }
      iex> {:ok, input} = Content.assertion_signing_input(assertion, %{})
      iex> signature = :crypto.sign(:eddsa, :none, input.message, [private, :ed25519])
      iex> {:ok, compact} = Content.assemble_compact(input, signature)
      iex> {:ok, ^compact} = Content.assemble_compact(input, signature, %{})
      iex> {:ok, decoded} = Content.decode_assertion(compact, %{})
      iex> expected = %Content.ExpectedContentAssertion{
      ...>   attestor: %HistoricalPublicKey{key_id: "attestor-1", public_key: public, valid_from: 90, valid_before: 300},
      ...>   issuer: "issuer", audience: "reader", subject: "article-1", profile: "article-profile",
      ...>   profile_digest: <<1::256>>, content_digest: digest, now: 120, bounds: %{}
      ...> }
      iex> {:ok, first} = Content.verify_assertion(compact, expected)
      iex> {:ok, predecessor} = Content.assertion_digest(compact, %{})
      iex> second_input = %{assertion | jti: "assertion-2", gen: 2, prev: predecessor, iat: 130, nbf: 130}
      iex> {:ok, input} = Content.assertion_signing_input(second_input, %{})
      iex> signature = :crypto.sign(:eddsa, :none, input.message, [private, :ed25519])
      iex> {:ok, compact} = Content.assemble_compact(input, signature)
      iex> {:ok, second} = Content.verify_assertion(compact, %{expected | now: 140})
      iex> {decoded.gen, second.gen, Content.verify_successor(first, second, %{})}
      {1, 2, :ok}
  """
  alias BoundedAuthorityProtocol.ContentAssertion.V1.{
    Codec,
    ContentAssertion,
    ContentAssertionFacts,
    DecodedContentAssertion,
    ExpectedContentAssertion
  }

  alias BoundedAuthorityProtocol.V1.{Bounds, SigningInput}

  @doc """
  Produces deterministic signing bytes for this closed profile.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.assertion_signing_input(%{}, %{})
      {:error, :invalid}
  """
  @spec assertion_signing_input(ContentAssertion.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  defdelegate assertion_signing_input(assertion, limits), to: Codec, as: :signing_input

  @doc """
  Assembles and revalidates this profile at the maximum bounds.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.assemble_compact(%{}, "")
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(input, signature), do: assemble_compact(input, signature, %{})

  @doc """
  Assembles and revalidates this profile under tightened bounds.

  Since 0.9.0, assembly also refuses, with `{:error, :invalid}`, a
  signature that no conforming signer emits: an Ed25519 signature whose `S` is not below the group
  order or whose `R` is non-canonical or of small order (erratum 3). It never rewrites the
  signature bytes it accepts.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.assemble_compact(%{}, "", %{})
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  defdelegate assemble_compact(input, signature, limits), to: Codec, as: :assemble

  @doc """
  Decodes bounded fields without evaluating the signature or trust.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.decode_assertion("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec decode_assertion(binary(), Bounds.t() | map()) ::
          {:ok, DecodedContentAssertion.t()} | {:error, :invalid}
  defdelegate decode_assertion(compact, limits), to: Codec, as: :decode

  @doc """
  Verifies against explicit public trust, complete expected context and time.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec verify_assertion(binary(), ExpectedContentAssertion.t()) ::
          {:ok, ContentAssertionFacts.t()} | {:error, :invalid}
  defdelegate verify_assertion(compact, expected), to: Codec, as: :verify

  @doc """
  Hashes nonempty exact content bytes in the fixed content domain; never parses them.

  ## Examples

      iex> {:ok, first} = BoundedAuthorityProtocol.ContentAssertion.V1.content_digest("first", %{})
      iex> {:ok, second} = BoundedAuthorityProtocol.ContentAssertion.V1.content_digest("second", %{})
      iex> byte_size(first) == 32 and first != second
      true
      iex> BoundedAuthorityProtocol.ContentAssertion.V1.content_digest("", %{})
      {:error, :invalid}
  """
  @spec content_digest(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  defdelegate content_digest(bytes, limits), to: Codec

  @doc """
  Hashes exact profile-parseable compact bytes; establishes no signature or trust.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.assertion_digest("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec assertion_digest(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  defdelegate assertion_digest(compact, limits), to: Codec

  @doc """
  Checks pairwise lineage consistency and returns `:ok` or `{:error, :invalid}`.

  This compares caller-supplied facts; it neither verifies their provenance nor returns new
  verified facts. Verify both assertions first and retain authoritative high-water state to
  detect forks or rollback. Current trust and authorization remain the caller's responsibility.

  ## Examples

      iex> BoundedAuthorityProtocol.ContentAssertion.V1.verify_successor(%{}, %{}, %{})
      {:error, :invalid}
  """
  @spec verify_successor(ContentAssertionFacts.t(), ContentAssertionFacts.t(), Bounds.t() | map()) ::
          :ok | {:error, :invalid}
  defdelegate verify_successor(previous, next, limits), to: Codec
end
