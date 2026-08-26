defmodule BoundedAuthorityProtocol.WalkthroughTest do
  @moduledoc """
  Pins the runnable code shape of the Livebook walkthrough
  (docs/livebooks/bap-walkthrough.livemd): ephemeral runtime keys, produce → assemble →
  verify → reject. The notebook's cells are re-executed here against the real package — if
  the notebook's code stops running, this test fails (a non-running livebook is worse than
  none). A code-shape break (renamed function, changed struct field, changed verdict) reds
  this test before the notebook can rot.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.{
    Credentials,
    ExpectedGrant,
    ExpectedRequest,
    Grant,
    Jwk,
    Operation,
    Proof,
    TrustedIssuer
  }

  test "the walkthrough: produce, assemble, verify, reject — with ephemeral keys" do
    # --- notebook cell 1: ephemeral keys (critical rule 6: nothing tracked) ---
    {issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
    {holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, holder_thumbprint} = Jwk.public_key_thumbprint_raw(holder_public, %{})

    # --- notebook cell 2: build and sign a grant ---
    grant = %Grant{
      key_id: "issuer-1",
      issuer: "https://issuer.example",
      grant_id: "grant-walkthrough-1",
      audiences: ["https://service.example"],
      issued_at: 1_800_000_000,
      not_before: 1_800_000_000,
      expires_at: 1_800_003_600,
      holder_thumbprint: holder_thumbprint,
      operations: [
        %Operation{
          name: "read_record",
          selectors: [
            {:equals, ["record", "region"], {:string, "us-east"}},
            {:one_of, ["record", "tier"], [{:string, "gold"}, {:string, "platinum"}]},
            :all
          ]
        }
      ]
    }

    {:ok, signing_input} = BoundedAuthorityProtocol.V1.grant_signing_input(grant, %{})

    issuer_signature =
      :crypto.sign(:eddsa, :none, signing_input.message, [issuer_private, :ed25519])

    {:ok, grant_compact} =
      BoundedAuthorityProtocol.V1.assemble_compact(signing_input, issuer_signature)

    # --- notebook cell 3: build and sign the holder proof ---
    now = 1_800_001_000

    args_ok =
      {:object,
       [{"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}}]}

    proof = %Proof{
      holder_public_key: holder_public,
      proof_id: "proof-walkthrough-1",
      method: "GET",
      target_uri: "https://service.example/records/1",
      issued_at: now,
      nonce: nil,
      invocation_id: "7d444840-9dc0-11ed-a8fc-0242ac120002",
      operation: "read_record",
      grant_compact: grant_compact,
      cast_arguments: args_ok
    }

    {:ok, proof_input} = BoundedAuthorityProtocol.V1.proof_signing_input(proof, %{})

    holder_signature =
      :crypto.sign(:eddsa, :none, proof_input.message, [holder_private, :ed25519])

    {:ok, proof_compact} =
      BoundedAuthorityProtocol.V1.assemble_compact(proof_input, holder_signature)

    # --- notebook cell 4: verify the grant ---
    trusted = %TrustedIssuer{key_id: "issuer-1", public_key: issuer_public}

    expected_grant = %ExpectedGrant{
      issuer: "https://issuer.example",
      audience: "https://service.example",
      evaluation_time: now,
      clock_skew: 60,
      bounds: %{}
    }

    assert {:ok, grant_facts} =
             BoundedAuthorityProtocol.V1.verify_grant(grant_compact, trusted, expected_grant)

    assert grant_facts.authorization == :not_evaluated

    # --- notebook cell 5: verify the full envelope ---
    credentials = %Credentials{grant: grant_compact, proof: proof_compact}

    expected_request = %ExpectedRequest{
      trusted_issuer: trusted,
      issuer: "https://issuer.example",
      audience: "https://service.example",
      method: "GET",
      target_uri: "https://service.example/records/1",
      invocation_id: "7d444840-9dc0-11ed-a8fc-0242ac120002",
      operation: "read_record",
      cast_arguments: args_ok,
      evaluation_time: now,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: :not_required,
      bounds: %{}
    }

    assert {:ok, envelope_facts} =
             BoundedAuthorityProtocol.V1.check_envelope(credentials, expected_request)

    assert envelope_facts.operation == "read_record"
    assert envelope_facts.authorization == :not_evaluated

    # --- notebook cell 6: every attack fails closed ---
    tampered =
      grant_compact
      |> String.split(".")
      |> List.update_at(2, &flip/1)
      |> Enum.join(".")

    wrong_args = %ExpectedRequest{
      expected_request
      | cast_arguments:
          {:object,
           [
             {"record",
              {:object, [{"tier", {:string, "bronze"}}, {"region", {:string, "us-east"}}]}}
           ]}
    }

    stale = %ExpectedRequest{expected_request | evaluation_time: now + 361}

    assert {:error, :invalid} =
             BoundedAuthorityProtocol.V1.check_envelope(
               %Credentials{grant: tampered, proof: proof_compact},
               expected_request
             )

    assert {:error, :invalid} =
             BoundedAuthorityProtocol.V1.check_envelope(credentials, wrong_args)

    assert {:error, :invalid} = BoundedAuthorityProtocol.V1.check_envelope(credentials, stale)
  end

  test "the notebook's code shape matches this test (a broken notebook reds here)" do
    notebook = File.read!(Path.expand("../docs/livebooks/bap-walkthrough.livemd", __DIR__))
    this_file = File.read!(__ENV__.file)

    for marker <- [
          "grant_signing_input(grant, %{})",
          "proof_signing_input(proof, %{})",
          "assemble_compact(signing_input, issuer_signature)",
          "assemble_compact(proof_input, holder_signature)",
          "public_key_thumbprint_raw(holder_public, %{})",
          "check_envelope(credentials, expected_request)",
          "nonce: :not_required",
          "evaluation_time: now + 361",
          "Bitwise.bxor(byte, 1)"
        ] do
      assert notebook =~ marker,
             "the walkthrough notebook lost its code shape (#{inspect(marker)}) — a non-running livebook is worse than none"

      assert this_file =~ marker
    end
  end

  defp flip(segment) do
    index = div(String.length(segment), 2)
    <<head::binary-size(^index), byte, tail::binary>> = segment
    head <> <<Bitwise.bxor(byte, 1)>> <> tail
  end
end
