defmodule BoundedAuthorityProtocol.V1.ConsumptionChain do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ChainFacts
  alias BoundedAuthorityProtocol.V1.ChainInput
  alias BoundedAuthorityProtocol.V1.ConsumptionEntry
  alias BoundedAuthorityProtocol.V1.EncodedConsumptionEntry
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.StringOrUri

  @domain "BAP1-CHAIN\0"
  @zero_hash <<0::256>>
  @row_keys ~w(chain_id commitment previous sequence v)

  @spec encode(ConsumptionEntry.t(), Bounds.t() | map()) ::
          {:ok, EncodedConsumptionEntry.t()} | {:error, :invalid}
  def encode(%ConsumptionEntry{} = entry, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         :ok <- validate_entry(entry, bounds),
         {:ok, bytes} <- Jcs.encode(row_json(entry), bounds),
         true <- byte_size(bytes) <= bounds.chain_row_bytes do
      {:ok,
       %EncodedConsumptionEntry{
         bytes: bytes,
         hash: :crypto.hash(:sha256, @domain <> bytes)
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def encode(_entry, _limits), do: {:error, :invalid}

  @spec check(ChainInput.t(), ExpectedChain.t()) ::
          {:ok, ChainFacts.t()} | {:error, :invalid}
  def check(%ChainInput{rows: rows}, %ExpectedChain{} = expected) do
    with {:ok, bounds} <- Bounds.coerce(expected.bounds),
         :ok <- validate_expected(expected, bounds),
         expected_count = expected.row_count,
         {:ok, ^expected_count} <- validate_rows(rows, bounds, 0),
         {:ok, final_hash} <-
           check_rows(
             rows,
             bounds,
             expected,
             expected.first_sequence,
             expected.previous_hash
           ),
         true <- FixedBytes.equal?(final_hash, expected.last_hash) do
      {:ok,
       %ChainFacts{
         version: 1,
         chain_id: expected.chain_id,
         first_sequence: expected.first_sequence,
         last_sequence: expected.last_sequence,
         row_count: expected.row_count,
         previous_hash: expected.previous_hash,
         last_hash: expected.last_hash,
         verification: :boundary_consistent,
         trust: :not_evaluated,
         authorization: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def check(_input, _expected), do: {:error, :invalid}

  @doc false
  @spec parse_row(binary(), Bounds.t()) ::
          {:ok, ConsumptionEntry.t(), EncodedConsumptionEntry.t()} | {:error, :invalid}
  def parse_row(bytes, %Bounds{} = bounds)
      when is_binary(bytes) and byte_size(bytes) > 0 and
             byte_size(bytes) <= bounds.chain_row_bytes do
    with {:ok, {:object, members}} <- Json.decode(bytes, bounds),
         {:ok, row} <- closed_row(members),
         {:integer, 1} <- row["v"],
         {:string, chain_id} <- row["chain_id"],
         {:integer, sequence} <- row["sequence"],
         {:string, previous_encoded} <- row["previous"],
         {:ok, previous_hash} <- Base64Url.decode(previous_encoded, bounds),
         {:string, commitment_encoded} <- row["commitment"],
         {:ok, commitment} <- Base64Url.decode(commitment_encoded, bounds),
         entry = %ConsumptionEntry{
           chain_id: chain_id,
           sequence: sequence,
           previous_hash: previous_hash,
           commitment: commitment
         },
         {:ok, %EncodedConsumptionEntry{bytes: ^bytes} = encoded} <- encode(entry, bounds) do
      {:ok, entry, encoded}
    else
      _failure -> {:error, :invalid}
    end
  end

  def parse_row(_bytes, _bounds), do: {:error, :invalid}

  defp check_rows([], _bounds, expected, next_sequence, prior_hash)
       when next_sequence == expected.last_sequence + 1,
       do: {:ok, prior_hash}

  defp check_rows([bytes | rest], bounds, expected, sequence, prior_hash) do
    with {:ok, entry, encoded} <- parse_row(bytes, bounds),
         true <- entry.chain_id == expected.chain_id,
         true <- entry.sequence == sequence,
         true <- FixedBytes.equal?(entry.previous_hash, prior_hash) do
      check_rows(rest, bounds, expected, sequence + 1, encoded.hash)
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_entry(entry, bounds) do
    if valid_identifier?(entry.chain_id, bounds) and valid_sequence?(entry.sequence, bounds) and
         fixed_digest?(entry.previous_hash, bounds) and fixed_digest?(entry.commitment, bounds) and
         (entry.sequence != 1 or FixedBytes.equal?(entry.previous_hash, @zero_hash)) do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_expected(expected, bounds) do
    if valid_expected_range?(expected, bounds) and valid_expected_hashes?(expected, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp valid_expected_range?(expected, bounds),
    do:
      valid_identifier?(expected.chain_id, bounds) and
        valid_sequence?(expected.first_sequence, bounds) and
        valid_sequence?(expected.last_sequence, bounds) and
        expected.first_sequence <= expected.last_sequence and
        is_integer(expected.row_count) and expected.row_count > 0 and
        expected.row_count <= bounds.chain_rows and
        expected.row_count == expected.last_sequence - expected.first_sequence + 1

  defp valid_expected_hashes?(expected, bounds),
    do:
      fixed_digest?(expected.previous_hash, bounds) and
        fixed_digest?(expected.last_hash, bounds) and
        (expected.first_sequence != 1 or
           FixedBytes.equal?(expected.previous_hash, @zero_hash))

  defp validate_rows([], _bounds, 0), do: {:error, :invalid}
  defp validate_rows([], _bounds, count), do: {:ok, count}

  defp validate_rows([row | rest], bounds, count)
       when is_binary(row) and byte_size(row) > 0 and
              byte_size(row) <= bounds.chain_row_bytes and count < bounds.chain_rows,
       do: validate_rows(rest, bounds, count + 1)

  defp validate_rows(_rows, _bounds, _count), do: {:error, :invalid}

  defp row_json(entry) do
    {:object,
     [
       {"chain_id", {:string, entry.chain_id}},
       {"commitment", {:string, Base.url_encode64(entry.commitment, padding: false)}},
       {"previous", {:string, Base.url_encode64(entry.previous_hash, padding: false)}},
       {"sequence", {:integer, entry.sequence}},
       {"v", {:integer, 1}}
     ]}
  end

  defp closed_row(members) when is_list(members) do
    if length(members) == length(@row_keys) and
         Enum.sort(Enum.map(members, &elem(&1, 0))) == @row_keys do
      {:ok, Map.new(members)}
    else
      {:error, :invalid}
    end
  end

  defp valid_sequence?(value, bounds),
    do: is_integer(value) and value > 0 and value <= bounds.integer_magnitude

  defp fixed_digest?(value, bounds),
    do: is_binary(value) and byte_size(value) == bounds.digest_bytes

  defp valid_identifier?(value, bounds) do
    is_binary(value) and byte_size(value) in 1..bounds.identifier_bytes and String.valid?(value) and
      StringOrUri.valid?(value)
  end
end
