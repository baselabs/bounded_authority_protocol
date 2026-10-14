defmodule BoundedAuthorityProtocol.WalkthroughTest do
  @moduledoc """
  Pins the runnable code shape of the Livebook walkthrough
  (docs/livebooks/bap-walkthrough.livemd): ephemeral runtime keys, produce → assemble →
  verify → reject. The first test below evaluates every code cell of the notebook itself, in
  order, against this package (only the `Mix.install` cell is skipped) and asserts each
  section's result — if the notebook's code stops running or a verdict changes, this test
  fails (a non-running livebook is worse than none). The remaining tests restate the earliest
  sections as plain code, so a code-shape break (renamed function, changed struct field,
  changed verdict) also reds here.
  """

  use ExUnit.Case, async: true

  @notebook Path.expand("../docs/livebooks/bap-walkthrough.livemd", __DIR__)
  @strict_ed25519 Path.expand("../priv/conformance/strict-ed25519/cases", __DIR__)
  @invalid {:error, :invalid}

  test "every notebook cell runs, in order, with the verdicts the prose states" do
    {cells, skipped} = notebook_cells()

    # Exactly one cell is not evaluated here: the Mix.install cell (this test runs against the
    # package source instead of the registry).
    assert [install] = skipped
    assert install =~ "Mix.install("

    {results, binding} = evaluate(cells)
    sections = results |> Enum.map(&elem(&1, 0)) |> Enum.uniq()
    assert sections == Enum.map(1..16, &Integer.to_string/1)

    # Sections 6, 8, 10 and 12 end with [{attack, rejected?}]; every attack is rejected.
    for section <- ["6", "8", "10", "12"] do
      [verdicts] = cell_values(results, section)
      assert verdicts != []
      assert Enum.all?(verdicts, fn {_attack, rejected?} -> rejected? == true end), section
    end

    # Section 13: the honest key and signature pass all three strict-Ed25519 checks.
    assert cell_values(results, "13") == [
             %{verify_strict: true, acceptable_public_key?: true, torsion_free?: true}
           ]

    # Section 14, first cell: forgeries grafted onto the notebook's own grant and proof.
    [forgeries, corpus_grants] = cell_values(results, "14")

    assert forgeries == %{
             primitives: %{
               small_order_key_acceptable?: false,
               noncanonical_key_acceptable?: false,
               forgery_under_small_order_key: false,
               forgery_under_noncanonical_key: false,
               s_plus_l: false
             },
             verification: %{
               small_order_key: @invalid,
               noncanonical_key: @invalid,
               s_plus_l: @invalid
             }
           }

    # Section 14, second cell: the certified corpus grants, read from the installed package.
    assert corpus_grants == [
             {"grant-verify-v1-issuer-honest",
              %{
                verify_grant: {:ok, "urn:example:grant:1"},
                acceptable_public_key?: true,
                torsion_free?: true
              }},
             {"grant-verify-v1-issuer-iso-small-order-a-1",
              %{verify_grant: @invalid, acceptable_public_key?: false, torsion_free?: false}},
             {"grant-verify-v1-issuer-iso-noncanonical-a-y-p-plus-0",
              %{verify_grant: @invalid, acceptable_public_key?: false, torsion_free?: false}},
             {"grant-verify-v1-issuer-honest-a-identity-r",
              %{verify_grant: @invalid, acceptable_public_key?: true, torsion_free?: true}},
             {"grant-verify-v1-issuer-s-plus-l",
              %{verify_grant: @invalid, acceptable_public_key?: true, torsion_free?: true}},
             {"grant-verify-v1-issuer-mixed-a-mixed-r-both",
              %{
                verify_grant: {:ok, "urn:example:grant:1"},
                acceptable_public_key?: true,
                torsion_free?: false
              }}
           ]

    # The notebook's inline byte values are the corpus values it cites, and its L is the
    # difference between the corpus's honest and s-plus-l signatures.
    forgeries_file = primitive_cases("key-only-forgeries.json")
    identity_case = Map.fetch!(forgeries_file, "key-only-v1-identity-a-basepoint-r-s1-0")
    noncanonical_case = Map.fetch!(forgeries_file, "key-only-v1-y-p-plus-1-prime-r-0")
    assert binding[:key_only_forgery] == identity_case.signature
    assert binding[:small_order_key] == identity_case.public_key
    assert binding[:noncanonical_key] == noncanonical_case.public_key
    assert noncanonical_case.signature == identity_case.signature

    verify_cases = primitive_cases("verify-strict.json")
    <<r::binary-size(32), honest_s::little-size(256)>> = verify_cases["honest"].signature
    <<^r::binary-size(32), shifted_s::little-size(256)>> = verify_cases["s-plus-l"].signature
    assert binding[:l] == shifted_s - honest_s

    # Section 15: the v3 grant and envelope verify and carry the v3 facts.
    assert cell_values(results, "15") == [
             %{
               grant: %{version: 3, grant_id: "grant-2026-es-001", authorization: :not_evaluated},
               envelope: %{operation: "start_job", authorization: :not_evaluated}
             }
           ]

    # Section 16: the backend accepts the high-S twin; every v3 attack is refused.
    assert cell_values(results, "16") == [
             %{
               backend_accepts_high_s_twin: true,
               rejections: %{
                 high_s: @invalid,
                 major_one_envelope_through_major_three: @invalid,
                 major_one_grant_through_major_three: @invalid,
                 major_three_envelope_through_major_one: @invalid,
                 major_three_envelope_through_major_two: @invalid,
                 wrong_holder_key: @invalid
               }
             }
           ]
  end

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

  test "the notebook carries a runnable local-loopback profile walkthrough" do
    notebook = File.read!(Path.expand("../docs/livebooks/bap-walkthrough.livemd", __DIR__))

    for marker <- [
          "LocalLoopback.normalize_uri(loopback_target, %{})",
          "LocalLoopback.proof_signing_input(loopback_proof, %{})",
          "LocalLoopback.assemble_compact(loopback_input, loopback_signature)",
          "LocalLoopback.check_envelope(loopback_credentials, loopback_expected)",
          "nonce: {:required, loopback_nonce}",
          "%{loopback_expected | nonce: {:required, \"wrong-nonce\"}}"
        ] do
      assert notebook =~ marker,
             "the walkthrough notebook lost its local-loopback code shape (#{inspect(marker)})"
    end

    alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: LocalLoopback

    {issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
    {holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, holder_thumbprint} = Jwk.public_key_thumbprint_raw(holder_public, %{})

    grant = %Grant{
      key_id: "issuer-loopback-1",
      issuer: "urn:example:issuer:loopback",
      grant_id: "urn:example:grant:loopback",
      audiences: ["urn:example:audience:loopback"],
      issued_at: 1_800_010_000,
      not_before: 1_800_010_000,
      expires_at: 1_800_013_600,
      holder_thumbprint: holder_thumbprint,
      operations: [%Operation{name: "read_record", selectors: [:all]}]
    }

    {:ok, grant_input} = BoundedAuthorityProtocol.V1.grant_signing_input(grant, %{})

    grant_signature =
      :crypto.sign(:eddsa, :none, grant_input.message, [issuer_private, :ed25519])

    {:ok, grant_compact} =
      BoundedAuthorityProtocol.V1.assemble_compact(grant_input, grant_signature)

    loopback_target = "http://127.0.0.1:4000/invoke"
    loopback_nonce = "challenge-loopback-001"
    cast_arguments = {:object, [{"record_id", {:string, "record-1"}}]}

    assert {:ok, ^loopback_target} = LocalLoopback.normalize_uri(loopback_target, %{})

    loopback_proof = %Proof{
      holder_public_key: holder_public,
      proof_id: "urn:example:proof:loopback",
      method: "POST",
      target_uri: loopback_target,
      issued_at: 1_800_010_060,
      nonce: loopback_nonce,
      invocation_id: "123e4567-e89b-42d3-a456-426614174001",
      operation: "read_record",
      grant_compact: grant_compact,
      cast_arguments: cast_arguments
    }

    {:ok, loopback_input} = LocalLoopback.proof_signing_input(loopback_proof, %{})

    loopback_signature =
      :crypto.sign(:eddsa, :none, loopback_input.message, [holder_private, :ed25519])

    {:ok, loopback_compact} =
      LocalLoopback.assemble_compact(loopback_input, loopback_signature)

    loopback_credentials = %Credentials{grant: grant_compact, proof: loopback_compact}

    loopback_expected = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{key_id: "issuer-loopback-1", public_key: issuer_public},
      issuer: "urn:example:issuer:loopback",
      audience: "urn:example:audience:loopback",
      method: "POST",
      target_uri: loopback_target,
      invocation_id: "123e4567-e89b-42d3-a456-426614174001",
      operation: "read_record",
      cast_arguments: cast_arguments,
      evaluation_time: 1_800_010_060,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, loopback_nonce},
      bounds: %{}
    }

    assert {:ok, facts} =
             LocalLoopback.check_envelope(loopback_credentials, loopback_expected)

    assert facts.target_uri == loopback_target
    assert facts.authorization == :not_evaluated

    assert {:error, :invalid} =
             LocalLoopback.check_envelope(
               loopback_credentials,
               %{loopback_expected | nonce: {:required, "wrong-nonce"}}
             )

    assert {:error, :invalid} =
             BoundedAuthorityProtocol.V1.check_envelope(
               loopback_credentials,
               loopback_expected
             )
  end

  test "the notebook carries a runnable content-assertion walkthrough" do
    notebook = File.read!(Path.expand("../docs/livebooks/bap-walkthrough.livemd", __DIR__))

    for marker <- [
          "ContentAssertionV1.content_digest(content_bytes, %{})",
          "ContentAssertionV1.assertion_signing_input(assertion, %{})",
          "ContentAssertionV1.assemble_compact(assertion_input, assertion_signature)",
          "ContentAssertionV1.verify_assertion(assertion_compact, expected_assertion)",
          "ContentAssertionV1.verify_successor(assertion_facts, successor_facts, %{})",
          "changed_content:",
          "assertion_through_role: RoleAttestationV1.decode_attestation(assertion_compact, %{})"
        ] do
      assert notebook =~ marker,
             "the walkthrough notebook lost its content-assertion code shape (#{inspect(marker)})"
    end

    alias BoundedAuthorityProtocol.ContentAssertion.V1, as: ContentAssertionV1
    alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestationV1
    alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

    now = 1_800_020_000
    {attestor_public, attestor_private} = :crypto.generate_key(:eddsa, :ed25519)

    content_bytes = ~s({"document":"example","revision":1})
    {:ok, content_digest} = ContentAssertionV1.content_digest(content_bytes, %{})
    profile_digest = :crypto.hash(:sha256, "urn:example:profile:document/1 schema bytes")

    assertion = %ContentAssertionV1.ContentAssertion{
      attestor_key_id: "content-attestor-1",
      jti: "urn:example:assertion:2026-001",
      iss: "urn:example:issuer",
      aud: "urn:example:audience",
      sub: "urn:example:lineage:document-1",
      profile: "urn:example:profile:document/1",
      profile_digest: profile_digest,
      content_digest: content_digest,
      gen: 1,
      prev: <<0::256>>,
      iat: now,
      nbf: now,
      exp: now + 3_600
    }

    {:ok, assertion_input} = ContentAssertionV1.assertion_signing_input(assertion, %{})

    assertion_signature =
      :crypto.sign(:eddsa, :none, assertion_input.message, [attestor_private, :ed25519])

    {:ok, assertion_compact} =
      ContentAssertionV1.assemble_compact(assertion_input, assertion_signature)

    expected_assertion = %ContentAssertionV1.ExpectedContentAssertion{
      attestor: %HistoricalPublicKey{
        key_id: "content-attestor-1",
        public_key: attestor_public,
        valid_from: now - 600,
        valid_before: now + 7_200
      },
      issuer: "urn:example:issuer",
      audience: "urn:example:audience",
      subject: "urn:example:lineage:document-1",
      profile: "urn:example:profile:document/1",
      profile_digest: profile_digest,
      content_digest: content_digest,
      now: now + 60,
      bounds: %{}
    }

    assert {:ok, assertion_facts} =
             ContentAssertionV1.verify_assertion(assertion_compact, expected_assertion)

    assert assertion_facts.trust == :not_evaluated
    refute Map.has_key?(assertion_facts, :authorization)

    assert {:ok, assertion_facts.digest} ==
             ContentAssertionV1.assertion_digest(assertion_compact, %{})

    successor = %{
      assertion
      | jti: "urn:example:assertion:2026-002",
        gen: 2,
        prev: assertion_facts.digest,
        iat: now + 120,
        nbf: now + 120
    }

    {:ok, successor_input} = ContentAssertionV1.assertion_signing_input(successor, %{})

    successor_signature =
      :crypto.sign(:eddsa, :none, successor_input.message, [attestor_private, :ed25519])

    {:ok, successor_compact} =
      ContentAssertionV1.assemble_compact(successor_input, successor_signature)

    {:ok, successor_facts} =
      ContentAssertionV1.verify_assertion(successor_compact, %{
        expected_assertion
        | now: now + 180
      })

    assert :ok = ContentAssertionV1.verify_successor(assertion_facts, successor_facts, %{})

    assert {:error, :invalid} =
             ContentAssertionV1.verify_successor(successor_facts, assertion_facts, %{})

    {:ok, changed_digest} = ContentAssertionV1.content_digest(content_bytes <> " ", %{})

    assert {:error, :invalid} =
             ContentAssertionV1.verify_assertion(assertion_compact, %{
               expected_assertion
               | content_digest: changed_digest
             })

    assert {:error, :invalid} =
             ContentAssertionV1.verify_assertion(assertion_compact, %{
               expected_assertion
               | now: now + 3_600
             })

    assert {:error, :invalid} = RoleAttestationV1.decode_attestation(assertion_compact, %{})
    assert {:error, :invalid} = BoundedAuthorityProtocol.V1.decode_grant(assertion_compact, %{})
  end

  # Splits the notebook into its ```elixir cells. Each evaluated cell is
  # {section_number, code, first_code_line}; the Mix.install cell is returned separately.
  defp notebook_cells do
    {cells, _section, _open} =
      @notebook
      |> File.read!()
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.reduce({[], nil, nil}, fn {line, number}, {cells, section, open} ->
        cond do
          open != nil and line == "```" ->
            {start, lines} = open
            {[{section, lines |> Enum.reverse() |> Enum.join("\n"), start} | cells], section, nil}

          open != nil ->
            {start, lines} = open
            {cells, section, {start, [line | lines]}}

          line == "```elixir" ->
            {cells, section, {number + 1, []}}

          match = Regex.run(~r/^## (\d+)\. /, line) ->
            {cells, Enum.at(match, 1), nil}

          String.starts_with?(line, "## ") ->
            {cells, nil, nil}

          true ->
            {cells, section, open}
        end
      end)

    {skipped, evaluated} =
      cells |> Enum.reverse() |> Enum.split_with(fn {_s, code, _l} -> code =~ "Mix.install(" end)

    {evaluated, Enum.map(skipped, &elem(&1, 1))}
  end

  # Evaluates the cells in order with one shared binding and environment, as Livebook does.
  defp evaluate(cells) do
    {results, binding, _env} =
      Enum.reduce(cells, {[], [], Code.env_for_eval(file: @notebook)}, fn {section, code, line},
                                                                          {results, binding, env} ->
        assert section != nil, "a notebook cell at line #{line} sits outside a numbered section"
        quoted = Code.string_to_quoted!(code, file: @notebook, line: line)
        {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
        {[{section, value} | results], binding, env}
      end)

    {Enum.reverse(results), binding}
  end

  defp cell_values(results, section),
    do: for({^section, value} <- results, do: value)

  defp primitive_cases(file) do
    [@strict_ed25519, "primitive", file]
    |> Path.join()
    |> File.read!()
    |> JSON.decode!()
    |> Map.fetch!("cases")
    |> Map.new(fn %{"id" => id, "input" => input} ->
      {id,
       %{
         public_key: Base.url_decode64!(input["public_key"], padding: false),
         signature: Base.url_decode64!(input["signature"], padding: false)
       }}
    end)
  end

  defp flip(segment) do
    index = div(String.length(segment), 2)
    <<head::binary-size(^index), byte, tail::binary>> = segment
    head <> <<Bitwise.bxor(byte, 1)>> <> tail
  end
end
