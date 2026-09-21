defmodule BoundedAuthorityProtocol.V3.ConsumptionChainTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ChainInput
  alias BoundedAuthorityProtocol.V1.ConsumptionEntry
  alias BoundedAuthorityProtocol.V1.EncodedConsumptionEntry
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V3, as: V3
  alias BoundedAuthorityProtocol.V3.ChainFacts
  alias BoundedAuthorityProtocol.V3.ConsumptionChain

  @zero_hash <<0::256>>
  @commitment_a :crypto.hash(:sha256, "commitment-a")
  @commitment_b :crypto.hash(:sha256, "commitment-b")

  test "encodes exact canonical v2 rows with domain-separated hashes" do
    entry = entry(1, @zero_hash, @commitment_a)

    assert {:ok, encoded} = V3.encode_consumption_entry(entry, %{})

    assert encoded.bytes ==
             ~s({"chain_id":"urn:example:chain","commitment":"#{b64(@commitment_a)}","previous":"#{b64(@zero_hash)}","sequence":1,"v":3})

    assert encoded.hash == :crypto.hash(:sha256, "BAP3-CHAIN\0" <> encoded.bytes)
    refute encoded.hash == :crypto.hash(:sha256, encoded.bytes)
  end

  test "parse_row round-trips exact canonical rows and their hashes" do
    {:ok, encoded} = V3.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})

    assert {:ok, parsed_entry, parsed_encoded} =
             ConsumptionChain.parse_row(encoded.bytes, Bounds.maximum())

    assert parsed_entry == entry(1, @zero_hash, @commitment_a)
    assert %EncodedConsumptionEntry{} = parsed_encoded
    assert parsed_encoded.bytes == encoded.bytes
    assert parsed_encoded.hash == encoded.hash
  end

  test "legacy-major rows are rejected by v2 parse_row and check_chain" do
    assert {:ok, v1_first} = V1.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})

    assert {:ok, v1_second} =
             V1.encode_consumption_entry(entry(2, v1_first.hash, @commitment_b), %{})

    assert {:ok, v2_first} = V3.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})

    refute v1_first.bytes == v2_first.bytes
    refute v1_first.hash == v2_first.hash

    assert {:error, :invalid} =
             ConsumptionChain.parse_row(v1_first.bytes, Bounds.maximum())

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: [v1_first.bytes, v1_second.bytes]},
               expected_chain(1, 2, 2, @zero_hash, v1_second.hash)
             )
  end

  test "checks genesis and continued ranges only against mandatory caller boundaries" do
    {:ok, first} = V3.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})
    {:ok, second} = V3.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})
    second_hash = second.hash

    expected = expected_chain(1, 2, 2, @zero_hash, second_hash)

    assert {:ok,
            %ChainFacts{
              version: 3,
              chain_id: "urn:example:chain",
              first_sequence: 1,
              last_sequence: 2,
              row_count: 2,
              previous_hash: @zero_hash,
              last_hash: ^second_hash,
              verification: :boundary_consistent,
              trust: :not_evaluated
            } = facts} = V3.check_chain(%ChainInput{rows: [first.bytes, second.bytes]}, expected)

    assert inspect(facts) == "#BoundedAuthorityProtocol.V3.ChainFacts<redacted>"

    continued = expected_chain(2, 2, 1, first.hash, second_hash)

    assert {:ok, %ChainFacts{first_sequence: 2}} =
             V3.check_chain(%ChainInput{rows: [second.bytes]}, continued)
  end

  test "rejects noncanonical, unclosed, and malformed rows" do
    {:ok, first} = V3.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})
    {:ok, second} = V3.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})
    expected = expected_chain(1, 2, 2, @zero_hash, second.hash)

    # Key order is wire-canonical: a semantically equal row in another order is rejected.
    reordered =
      ~s({"v":3,"sequence":1,"previous":"#{b64(@zero_hash)}","commitment":"#{b64(@commitment_a)}","chain_id":"urn:example:chain"})

    # The closed row shape admits exactly the five v2 keys.
    unclosed =
      ~s({"chain_id":"urn:example:chain","commitment":"#{b64(@commitment_a)}","extra":"x","previous":"#{b64(@zero_hash)}","sequence":1,"v":3})

    for row <- [reordered, unclosed] do
      assert {:error, :invalid} = ConsumptionChain.parse_row(row, Bounds.maximum())
    end

    for input <- [
          %ChainInput{rows: [reordered, second.bytes]},
          %ChainInput{rows: [unclosed, second.bytes]},
          %ChainInput{rows: [first.bytes]},
          %ChainInput{rows: [second.bytes, first.bytes]},
          %ChainInput{rows: [first.bytes | second.bytes]},
          %ChainFacts{
            version: 3,
            chain_id: "urn:example:chain",
            first_sequence: 1,
            last_sequence: 2,
            row_count: 2,
            previous_hash: @zero_hash,
            last_hash: second.hash,
            verification: :boundary_consistent,
            trust: :not_evaluated
          }
        ] do
      assert {:error, :invalid} = V3.check_chain(input, expected)
    end

    refute_receive _message

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: [first.bytes, second.bytes]},
               %{expected | last_hash: @zero_hash}
             )
  end

  test "empty and over-limit row sets fail independently" do
    {:ok, first} = V3.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: []},
               expected_chain(1, 1, 1, @zero_hash, first.hash)
             )

    # Two presented rows against a one-row bound walk past the chain_rows limit.
    {:ok, second} = V3.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})

    bounded = %ExpectedChain{
      expected_chain(1, 1, 1, @zero_hash, first.hash)
      | bounds: %{chain_rows: 1}
    }

    assert {:error, :invalid} =
             V3.check_chain(%ChainInput{rows: [first.bytes, second.bytes]}, bounded)
  end

  test "sequence, chain-id, and predecessor link checks fail independently" do
    {:ok, first} = V3.encode_consumption_entry(entry(1, @zero_hash, @commitment_a), %{})
    {:ok, wrong_link} = V3.encode_consumption_entry(entry(2, @zero_hash, @commitment_b), %{})
    {:ok, wrong_sequence} = V3.encode_consumption_entry(entry(3, first.hash, @commitment_b), %{})
    {:ok, wrong_chain} = V3.encode_consumption_entry(other_chain_entry(2, first.hash), %{})

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: [first.bytes, wrong_link.bytes]},
               expected_chain(1, 2, 2, @zero_hash, wrong_link.hash)
             )

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: [first.bytes, wrong_sequence.bytes]},
               expected_chain(1, 2, 2, @zero_hash, wrong_sequence.hash)
             )

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: [first.bytes, wrong_chain.bytes]},
               expected_chain(1, 2, 2, @zero_hash, wrong_chain.hash)
             )

    {:ok, second} = V3.encode_consumption_entry(entry(2, first.hash, @commitment_b), %{})

    assert {:error, :invalid} =
             V3.check_chain(
               %ChainInput{rows: [first.bytes, second.bytes]},
               expected_chain(1, 2, 2, @zero_hash, @zero_hash)
             )
  end

  test "encode rejects genesis-link violations, row-byte bounds, and bad identifiers" do
    assert {:error, :invalid} =
             V3.encode_consumption_entry(entry(1, <<1::256>>, @commitment_a), %{})

    assert {:error, :invalid} =
             V3.encode_consumption_entry(entry(2, @zero_hash, @commitment_b), %{
               chain_row_bytes: 1
             })

    assert {:error, :invalid} =
             V3.encode_consumption_entry(
               %{entry(1, @zero_hash, @commitment_a) | chain_id: "x:%zz"},
               %{}
             )

    assert {:error, :invalid} = ConsumptionChain.encode(%{}, %{})
    assert {:error, :invalid} = ConsumptionChain.check(%{}, %{})
    assert {:error, :invalid} = ConsumptionChain.parse_row(:invalid, Bounds.maximum())
    assert {:error, :invalid} = ConsumptionChain.parse_row("", Bounds.maximum())
    refute FixedBytes.equal?(:invalid, @zero_hash)
  end

  defp entry(sequence, previous_hash, commitment) do
    %ConsumptionEntry{
      chain_id: "urn:example:chain",
      sequence: sequence,
      previous_hash: previous_hash,
      commitment: commitment
    }
  end

  defp other_chain_entry(sequence, previous_hash) do
    %ConsumptionEntry{
      chain_id: "urn:example:other-chain",
      sequence: sequence,
      previous_hash: previous_hash,
      commitment: @commitment_b
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
