defmodule BoundedAuthorityProtocol.V1.ContextValidationTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ContextValidation
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @zero_hash <<0::256>>

  test "validates every caller-derived archive context independently" do
    bounds = Bounds.maximum()
    fingerprint = :crypto.hash(:sha256, "fingerprint")

    chain = %ExpectedChain{
      chain_id: "urn:example:chain",
      first_sequence: 1,
      last_sequence: 1,
      row_count: 1,
      previous_hash: @zero_hash,
      last_hash: :crypto.hash(:sha256, "last"),
      bounds: bounds
    }

    anchor = %ExpectedAnchor{
      anchor_id: "urn:example:anchor",
      anchored_at: 10,
      chain_id: chain.chain_id,
      sequence: 0,
      chain_hash: @zero_hash,
      key_id: "key-a",
      key_fingerprint: fingerprint,
      bounds: bounds
    }

    transition = %ExpectedKeyTransition{
      transition_id: "urn:example:transition",
      chain_id: chain.chain_id,
      effective_at: 11,
      current_key_id: "key-a",
      current_key_fingerprint: fingerprint,
      next_key_id: "key-b",
      next_key_fingerprint: :crypto.hash(:sha256, "next"),
      bounds: bounds
    }

    key = %HistoricalPublicKey{
      key_id: "key-a",
      public_key: <<0::256>>,
      valid_from: 0,
      valid_before: :unbounded
    }

    assert :ok = ContextValidation.expected_chain(chain, bounds)
    assert :ok = ContextValidation.expected_anchor(anchor, bounds)
    assert :ok = ContextValidation.expected_transition(transition, bounds)
    assert :ok = ContextValidation.historical_key(key, bounds)

    assert {:error, :invalid} =
             ContextValidation.expected_anchor(%{anchor | sequence: -1}, bounds)

    assert {:error, :invalid} =
             ContextValidation.expected_anchor(%{anchor | chain_hash: <<1::256>>}, bounds)

    assert {:error, :invalid} =
             ContextValidation.expected_transition(
               %{transition | next_key_fingerprint: fingerprint},
               bounds
             )

    assert {:error, :invalid} =
             ContextValidation.historical_key(%{key | valid_before: 0}, bounds)
  end
end
