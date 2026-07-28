defmodule BoundedAuthorityProtocol.V1.ConsumptionChainTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ChainFacts
  alias BoundedAuthorityProtocol.V1.ChainInput
  alias BoundedAuthorityProtocol.V1.ConsumptionChain
  alias BoundedAuthorityProtocol.V1.ConsumptionEntry
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.FixedBytes

  @zero_hash <<0::256>>
  @commitment_a :crypto.hash(:sha256, "commitment-a")
  @commitment_b :crypto.hash(:sha256, "commitment-b")

  test "encodes exact canonical rows and domain-separated hashes" do
    entry = entry(1, @zero_hash, @commitment_a)

    assert {:ok, encoded} = V1.encode_consumption_entry(entry, %{})

    assert encoded.bytes ==
             ~s({"chain_id":"urn:example:chain","commitment":"#{b64(@commitment_a)}","previous":"#{b64(@zero_hash)}","sequence":1,"v":1})

    assert encoded.hash == :crypto.hash(:sha256, "BAP1-CHAIN\0" <> encoded.bytes)
    refute encoded.hash == :crypto.hash(:sha256, encoded.bytes)
  end

  test "checks genesis and continued ranges only against mandatory caller boundaries" do
    {:ok, first} = V1.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})
    {:ok, second} = V1.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})
    second_hash = second.hash

    expected = expected_chain(1, 2, 2, @zero_hash, second_hash)

    assert {:ok,
            %ChainFacts{
              version: 1,
              chain_id: "urn:example:chain",
              first_sequence: 1,
              last_sequence: 2,
              row_count: 2,
              previous_hash: @zero_hash,
              last_hash: ^second_hash,
              verification: :boundary_consistent,
              trust: :not_evaluated,
              authorization: :not_evaluated
            } = facts} = V1.check_chain(%ChainInput{rows: [first.bytes, second.bytes]}, expected)

    assert inspect(facts) == "#BoundedAuthorityProtocol.V1.ChainFacts<redacted>"

    continued = expected_chain(2, 2, 1, first.hash, second_hash)

    assert {:ok, %ChainFacts{first_sequence: 2}} =
             V1.check_chain(%ChainInput{rows: [second.bytes]}, continued)
  end

  test "rejects noncanonical rows, link/range drift, facts, improper lists, and widened bounds" do
    {:ok, first} = V1.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})
    {:ok, second} = V1.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})
    expected = expected_chain(1, 2, 2, @zero_hash, second.hash)

    reordered =
      ~s({"v":1,"sequence":1,"previous":"#{b64(@zero_hash)}","commitment":"#{b64(@commitment_a)}","chain_id":"urn:example:chain"})

    for input <- [
          %ChainInput{rows: [reordered, second.bytes]},
          %ChainInput{rows: [first.bytes]},
          %ChainInput{rows: [second.bytes, first.bytes]},
          %ChainInput{rows: [first.bytes | second.bytes]},
          %ChainFacts{
            version: 1,
            chain_id: "urn:example:chain",
            first_sequence: 1,
            last_sequence: 2,
            row_count: 2,
            previous_hash: @zero_hash,
            last_hash: second.hash,
            verification: :boundary_consistent,
            trust: :not_evaluated,
            authorization: :not_evaluated
          }
        ] do
      assert {:error, :invalid} = V1.check_chain(input, expected)
    end

    refute_receive _message

    assert {:error, :invalid} =
             V1.check_chain(
               %ChainInput{rows: [first.bytes, second.bytes]},
               %{expected | last_hash: @zero_hash}
             )

    assert {:error, :invalid} =
             V1.encode_consumption_entry(entry(2, @zero_hash, @commitment_b), %{
               chain_row_bytes: 1
             })

    assert {:error, :invalid} =
             V1.encode_consumption_entry(
               %{entry(1, @zero_hash, @commitment_a) | chain_id: "x:%zz"},
               %{}
             )

    maximum = Bounds.maximum()
    assert maximum.archive_chunks == 65_796
    assert maximum.archive_bytes == 270_820_384

    assert maximum.archive_bytes ==
             20 + 8_196 + 2 * 8_196 + 256 * 8_196 + 65_536 * 4_100

    assert {:error, :invalid} = Bounds.new(%{archive_bytes: maximum.archive_bytes + 1})

    assert {:error, :invalid} = ConsumptionChain.encode(%{}, %{})
    assert {:error, :invalid} = ConsumptionChain.check(%{}, %{})
    assert {:error, :invalid} = ConsumptionChain.parse_row(:invalid, Bounds.maximum())
    refute FixedBytes.equal?(:invalid, @zero_hash)

    assert {:error, :invalid} =
             V1.check_chain(
               %ChainInput{rows: []},
               expected_chain(1, 1, 1, @zero_hash, @zero_hash)
             )
  end

  test "sequence, predecessor link, and caller head checks fail independently" do
    {:ok, first} = V1.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})
    {:ok, wrong_link} = V1.encode_consumption_entry(entry(2, @zero_hash, @commitment_b), %{})
    {:ok, wrong_sequence} = V1.encode_consumption_entry(entry(3, first.hash, @commitment_b), %{})

    assert {:error, :invalid} =
             V1.check_chain(
               %ChainInput{rows: [first.bytes, wrong_link.bytes]},
               expected_chain(1, 2, 2, @zero_hash, wrong_link.hash)
             )

    assert {:error, :invalid} =
             V1.check_chain(
               %ChainInput{rows: [first.bytes, wrong_sequence.bytes]},
               expected_chain(1, 2, 2, @zero_hash, wrong_sequence.hash)
             )

    {:ok, second} = V1.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})

    assert {:error, :invalid} =
             V1.check_chain(
               %ChainInput{rows: [first.bytes, second.bytes]},
               expected_chain(1, 2, 2, @zero_hash, @zero_hash)
             )
  end

  defp entry(sequence, previous_hash, commitment) do
    %ConsumptionEntry{
      chain_id: "urn:example:chain",
      sequence: sequence,
      previous_hash: previous_hash,
      commitment: commitment
    }
  end

  defp expected_chain(first_sequence, last_sequence, row_count, previous_hash, last_hash) do
    %ExpectedChain{
      chain_id: "urn:example:chain",
      first_sequence: first_sequence,
      last_sequence: last_sequence,
      row_count: row_count,
      previous_hash: previous_hash,
      last_hash: last_hash,
      bounds: %{}
    }
  end

  defp b64(value), do: Base.url_encode64(value, padding: false)
end
