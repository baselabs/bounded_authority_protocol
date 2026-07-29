defmodule BoundedAuthorityProtocol.V1.ContextValidation do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.StringOrUri

  @zero_hash <<0::256>>

  @spec expected_chain(ExpectedChain.t(), Bounds.t()) :: :ok | {:error, :invalid}
  def expected_chain(%ExpectedChain{} = expected, bounds) do
    if valid_chain_identity?(expected, bounds) and
         valid_chain_range?(expected, bounds) and
         valid_chain_count?(expected, bounds) and
         valid_chain_hashes?(expected, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  def expected_chain(_expected, _bounds), do: {:error, :invalid}

  @spec expected_anchor(ExpectedAnchor.t(), Bounds.t()) :: :ok | {:error, :invalid}
  def expected_anchor(%ExpectedAnchor{} = expected, bounds) do
    if valid_anchor_identity?(expected, bounds) and
         valid_anchor_binding?(expected, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  def expected_anchor(_expected, _bounds), do: {:error, :invalid}

  @spec expected_transition(ExpectedKeyTransition.t(), Bounds.t()) :: :ok | {:error, :invalid}
  def expected_transition(%ExpectedKeyTransition{} = expected, bounds) do
    with true <-
           valid_identifier?(expected.transition_id, bounds) and
             valid_identifier?(expected.chain_id, bounds) and
             valid_time?(expected.effective_at, bounds) and
             valid_key_id?(expected.current_key_id, bounds) and
             valid_key_id?(expected.next_key_id, bounds),
         :ok <-
           distinct_fingerprints(
             expected.current_key_fingerprint,
             expected.next_key_fingerprint,
             bounds
           ) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  def expected_transition(_expected, _bounds), do: {:error, :invalid}

  @spec distinct_fingerprints(binary(), binary(), Bounds.t()) :: :ok | {:error, :invalid}
  def distinct_fingerprints(current, next, %Bounds{} = bounds) do
    if fixed_digest?(current, bounds) and fixed_digest?(next, bounds) do
      if FixedBytes.equal?(current, next), do: {:error, :invalid}, else: :ok
    else
      {:error, :invalid}
    end
  end

  def distinct_fingerprints(_current, _next, _bounds), do: {:error, :invalid}

  @spec historical_key(HistoricalPublicKey.t(), Bounds.t()) :: :ok | {:error, :invalid}
  def historical_key(%HistoricalPublicKey{} = key, bounds) do
    if valid_key_id?(key.key_id, bounds) and is_binary(key.public_key) and
         byte_size(key.public_key) == bounds.public_key_bytes and
         valid_time?(key.valid_from, bounds) and
         valid_before?(key.valid_before, key.valid_from, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  def historical_key(_key, _bounds), do: {:error, :invalid}

  defp valid_chain_identity?(expected, bounds),
    do: valid_identifier?(expected.chain_id, bounds)

  defp valid_chain_range?(expected, bounds),
    do:
      valid_positive_sequence?(expected.first_sequence, bounds) and
        valid_positive_sequence?(expected.last_sequence, bounds) and
        expected.first_sequence <= expected.last_sequence

  defp valid_chain_count?(expected, bounds),
    do:
      is_integer(expected.row_count) and expected.row_count > 0 and
        expected.row_count <= bounds.chain_rows and
        expected.row_count == expected.last_sequence - expected.first_sequence + 1

  defp valid_chain_hashes?(expected, bounds),
    do:
      fixed_digest?(expected.previous_hash, bounds) and
        fixed_digest?(expected.last_hash, bounds) and
        (expected.first_sequence != 1 or
           FixedBytes.equal?(expected.previous_hash, @zero_hash))

  defp valid_anchor_identity?(expected, bounds),
    do:
      valid_identifier?(expected.anchor_id, bounds) and
        valid_time?(expected.anchored_at, bounds) and
        valid_identifier?(expected.chain_id, bounds) and
        valid_key_id?(expected.key_id, bounds)

  defp valid_anchor_binding?(expected, bounds),
    do:
      valid_anchor_sequence?(expected.sequence, bounds) and
        fixed_digest?(expected.chain_hash, bounds) and
        fixed_digest?(expected.key_fingerprint, bounds) and
        (expected.sequence != 0 or FixedBytes.equal?(expected.chain_hash, @zero_hash))

  defp fixed_digest?(value, bounds),
    do: is_binary(value) and byte_size(value) == bounds.digest_bytes

  defp valid_positive_sequence?(value, bounds),
    do: is_integer(value) and value > 0 and value <= bounds.integer_magnitude

  defp valid_anchor_sequence?(value, bounds),
    do: is_integer(value) and value >= 0 and value <= bounds.integer_magnitude

  defp valid_time?(value, bounds),
    do:
      is_integer(value) and value >= -bounds.integer_magnitude and
        value <= bounds.integer_magnitude

  defp valid_before?(:unbounded, _valid_from, _bounds), do: true

  defp valid_before?(valid_before, valid_from, bounds),
    do: valid_time?(valid_before, bounds) and valid_before > valid_from

  defp valid_key_id?(value, bounds),
    do:
      is_binary(value) and byte_size(value) >= 1 and byte_size(value) <= bounds.kid_bytes and
        ascii_key_id?(value)

  defp ascii_key_id?(<<>>), do: true

  defp ascii_key_id?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~],
       do: ascii_key_id?(rest)

  defp ascii_key_id?(_value), do: false

  defp valid_identifier?(value, bounds) do
    is_binary(value) and byte_size(value) >= 1 and
      byte_size(value) <= bounds.identifier_bytes and String.valid?(value) and
      StringOrUri.valid?(value)
  end
end
