defmodule BoundedAuthorityProtocol.V2.RuntimeTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedGrant
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.TrustedIssuer
  alias BoundedAuthorityProtocol.V2

  @issuer_key_id "issuer-a"
  @issuer "https://issuer.example.test"
  @audience "https://resource.example.test"

  test "grant producer emits v2 payload bytes with range selectors" do
    {:ok, input} = V2.grant_signing_input(grant(), %{})

    protected = decode_segment(input.protected_segment)
    payload = decode_segment(input.payload_segment)

    assert %{"v" => 2} = payload
    assert %{"typ" => "ba+cap", "alg" => "EdDSA", "kid" => @issuer_key_id} = protected

    assert [
             %{
               "name" => "transfer",
               "selectors" => [
                 %{"kind" => "gte", "path" => ["amount"], "value" => 50},
                 %{"kind" => "lte", "path" => ["amount"], "value" => 5000}
               ]
             }
           ] = payload["operations"]

    {compact, _public} = signed_grant()

    assert {:ok, %BoundedAuthorityProtocol.V2.DecodedGrant{} = decoded} =
             V2.decode_grant(compact, %{})

    assert decoded.version == 2
    assert decoded.verification == :not_evaluated
    assert decoded.operations == grant().operations
  end

  test "producer rejects non-numeric and malformed range bounds" do
    for selectors <- [
          [{:lte, ["amount"], {:string, "100"}}],
          [{:gte, ["amount"], :null}],
          [{:lte, ["amount"], {:boolean, true}}],
          [{:gte, ["amount"], {:array, []}}],
          [{:lte, [], {:integer, 5}}],
          [{:gte, :not_a_path, {:integer, 5}}],
          [{:lte, ["amount"]}],
          [{:gt, ["amount"], {:integer, 5}}],
          [:unknown]
        ] do
      grant = %{
        grant()
        | operations: [
            %BoundedAuthorityProtocol.V2.Operation{name: "transfer", selectors: selectors}
          ]
      }

      assert {:error, :invalid} = V2.grant_signing_input(grant, %{}), inspect(selectors)
    end
  end

  test "decode rejects non-numeric range bounds and unrecognized kinds on the wire" do
    for selector <- [
          %{"kind" => "lte", "path" => ["amount"], "value" => "100"},
          %{"kind" => "gte", "path" => ["amount"], "value" => nil},
          %{"kind" => "lte", "path" => ["amount"], "value" => true},
          %{"kind" => "gte", "path" => [], "value" => 5},
          %{"kind" => "lt", "path" => ["amount"], "value" => 5},
          %{"kind" => "gt", "path" => ["amount"], "value" => 5}
        ] do
      compact = forged_grant_with_selector(selector)

      assert {:error, :invalid} = V2.decode_grant(compact, %{}), inspect(selector)
    end
  end

  test "verify_grant accepts a correctly signed v2 grant and returns v2 facts" do
    {compact, public} = signed_grant()

    assert {:ok, facts} = V2.verify_grant(compact, trusted(public), expected_grant())

    assert facts.version == 2
    assert facts.issuer == @issuer
    assert facts.grant_id == "urn:example:grant:v2-1"
    assert facts.matched_audience == @audience
    assert facts.authorization == :not_evaluated
    assert inspect(facts) == "#BoundedAuthorityProtocol.V2.GrantFacts<redacted>"

    assert {:ok, issuer_fingerprint} =
             Jwk.public_key_thumbprint_raw(public, %{})

    assert facts.issuer_key_fingerprint == issuer_fingerprint
  end

  test "verify_grant rejects v1-major bytes (no cross-major fallback)" do
    v1_compact = legacy_major_grant()

    assert {:error, :invalid} =
             V2.verify_grant(v1_compact, trusted(legacy_major_key()), expected_grant())

    assert {:error, :invalid} = V2.decode_grant(v1_compact, %{})
  end

  test "verify_grant rejects the v1 closed rejection classes under v2 constants" do
    {compact, public} = signed_grant()

    for {trusted, expected} <- [
          {%TrustedIssuer{key_id: "other-key", public_key: public}, expected_grant()},
          {trusted(public), %{expected_grant() | issuer: "https://other.example.test"}},
          {trusted(public), %{expected_grant() | audience: "https://other.example.test"}},
          {trusted(public), %{expected_grant() | evaluation_time: 500}},
          {trusted(public), %{expected_grant() | evaluation_time: 5_001}},
          {trusted(public), %{expected_grant() | clock_skew: 61}}
        ] do
      assert {:error, :invalid} = V2.verify_grant(compact, trusted, expected), inspect(expected)
    end

    assert {:error, :invalid} =
             V2.verify_grant(flip_segment(compact, 2), trusted(public), expected_grant())
  end

  test "check_envelope accepts interval-bounded arguments and rejects out-of-range ones" do
    for {amount, verdict} <- [
          {50, :ok},
          {5000, :ok},
          {75, :ok},
          {49, :error},
          {5001, :error}
        ] do
      {credentials, expected} = envelope(amount)

      case verdict do
        :ok ->
          assert {:ok, %BoundedAuthorityProtocol.V2.EnvelopeFacts{}} =
                   V2.check_envelope(credentials, expected)

        :error ->
          assert {:error, :invalid} = V2.check_envelope(credentials, expected)
      end
    end
  end

  test "check_envelope binds floats on the float tag and signed zero" do
    # The float bounds are non-integral: JCS serializes integral numbers without
    # a decimal marker, so an integral bound would decode back integer-tagged.
    {credentials, expected} = float_envelope(7.5)
    assert {:ok, _facts} = V2.check_envelope(credentials, expected)

    {credentials, expected} = float_envelope(10.5)
    assert {:ok, _facts} = V2.check_envelope(credentials, expected)

    {credentials, expected} = float_envelope(10.6)
    assert {:error, :invalid} = V2.check_envelope(credentials, expected)

    {credentials, expected} = float_envelope(-0.0)
    assert {:ok, _facts} = V2.check_envelope(credentials, expected)

    {credentials, expected} = float_envelope(-0.6)
    assert {:error, :invalid} = V2.check_envelope(credentials, expected)
  end

  test "check_envelope fails closed on cross-tag operands" do
    # Integer-bound selectors against a float-tagged argument: never matches.
    {credentials, expected} = credentials_and_expected({:float, 50.0})
    assert {:error, :invalid} = V2.check_envelope(credentials, expected)
  end

  test "check_envelope rejects tampered segments and mismatched context" do
    {credentials, expected} = envelope(75)

    for invalid <- [
          %{credentials | grant: flip_segment(credentials.grant, 0)},
          %{credentials | proof: flip_segment(credentials.proof, 2)},
          %{expected | method: "GET"},
          %{expected | operation: "write_record"},
          %{expected | invocation_id: "123e4567-e89b-42d3-a456-426614174001"},
          %{expected | nonce: :not_required},
          %{expected | nonce: {:required, "wrong"}},
          %{expected | proof_max_age: 301}
        ] do
      assert {:error, :invalid} = V2.check_envelope(invalid, expected)
    end
  end

  test "check_envelope returns v2 redacted non-authorizing facts" do
    {credentials, expected} = envelope(75)

    assert {:ok, facts} = V2.check_envelope(credentials, expected)

    assert facts.version == 2
    assert facts.authorization == :not_evaluated
    assert facts.operation == "transfer"
    assert facts.proof_id == "urn:example:proof:v2-1"
    assert facts.grant_hash == :crypto.hash(:sha256, credentials.grant)
    assert inspect(facts) == "#BoundedAuthorityProtocol.V2.EnvelopeFacts<redacted>"
  end

  test "assemble_compact validates the assembled v2 artifact and rejects unknown kinds" do
    {compact, _public} = signed_grant()

    assert {:ok, %BoundedAuthorityProtocol.V1.KeyLocator{trust: :not_evaluated}} =
             V2.untrusted_key_locator(compact, %{})

    {:ok, input} = V2.grant_signing_input(grant(), %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [issuer_private(), :ed25519])
    assert {:ok, assembled} = V2.assemble_compact(input, signature)
    assert {:ok, decoded} = V2.decode_grant(assembled, %{})
    assert decoded.version == 2

    assert {:error, :invalid} = V2.assemble_compact(:not_an_input, signature, %{})
    assert {:error, :invalid} = V2.assemble_compact(input, <<0::504>>, %{})

    local_loopback_kind = %BoundedAuthorityProtocol.V1.SigningInput{
      kind: :local_loopback_http_proof,
      protected_segment: input.protected_segment,
      payload_segment: input.payload_segment,
      message: input.message
    }

    assert {:error, :invalid} = V2.assemble_compact(local_loopback_kind, signature, %{})
  end

  test "every codec delegation arm fails closed on malformed inputs" do
    for {result} <- [
          {V2.encode_consumption_entry(:not_an_entry, %{})},
          {V2.check_chain(:not_an_input, :not_expected)},
          {V2.boundary_anchor_signing_input(:not_an_anchor, %{})},
          {V2.key_transition_signing_input(:not_a_transition, %{})},
          {V2.encode_anchored_export(:not_an_input, :not_expected)},
          {V2.verify_anchored_export(:not_archived, :not_keys, :not_expected)}
        ] do
      assert {:error, :invalid} = result
    end

    assert {:error, :invalid} =
             V2.verify_historical_anchor(:not_binary, :not_a_key, :not_expected)

    assert {:error, :invalid} =
             V2.verify_key_transition(:not_binary, :not_a_key, :not_a_key, :not_expected)
  end

  test "producer and decode error arms for the inherited kinds and fields fail closed" do
    # encode_operations catch-all + equals/one_of producer arms + operation/selector catch-alls
    for operations <- [
          :not_a_list,
          [
            %BoundedAuthorityProtocol.V2.Operation{
              name: "transfer",
              selectors: [{:equals, ["a"], {:integer, 1}}]
            },
            :not_an_operation
          ],
          [
            %BoundedAuthorityProtocol.V2.Operation{
              name: "transfer",
              selectors: [{:equals, [], {:integer, 1}}]
            }
          ],
          [
            %BoundedAuthorityProtocol.V2.Operation{
              name: "transfer",
              selectors: [{:one_of, ["a"], []}]
            }
          ],
          [
            %BoundedAuthorityProtocol.V2.Operation{
              name: "transfer",
              selectors: [{:one_of, [], [{:integer, 1}]}]
            }
          ]
        ] do
      grant = %{grant() | operations: operations}
      assert {:error, :invalid} = V2.grant_signing_input(grant, %{}), inspect(operations)
    end

    # decode: operation/selector non-object catch-alls and bad one_of members
    compact = forged_grant_with_selector(%{"kind" => "one_of", "path" => ["a"], "values" => []})
    assert {:error, :invalid} = V2.decode_grant(compact, %{})

    # decode_audiences: scalar string, list with invalid member, and non-string shapes
    for aud <- [%{}] do
      payload = forged_payload_with("aud", aud)
      assert {:error, :invalid} = V2.decode_grant(forged_grant_with_payload(payload), %{})
    end

    # audience scalar form accepts; invalid scalar rejected
    assert {:error, :invalid} =
             V2.decode_grant(forged_grant_with_payload(forged_payload_with("aud", "")), %{})

    # uuid/nonce/string-list error arms through check_envelope with malformed expected context
    {credentials, expected} = envelope(75)

    for invalid <- [
          %{expected | invocation_id: "not-a-uuid"},
          %{expected | nonce: :bad_expectation},
          %{expected | nonce: {:required, ""}},
          %{expected | trusted_issuer: %TrustedIssuer{key_id: "issuer-a", public_key: <<0>>}}
        ] do
      assert {:error, :invalid} = V2.check_envelope(credentials, invalid)
    end

    # valid_string_list? catch-all via the producer
    bad = %{grant() | audiences: :not_a_list}
    assert {:error, :invalid} = V2.grant_signing_input(bad, %{})

    # optional_nonce invalid-typed member
    payload = forged_payload_with("nonce", 5)
    assert {:error, :invalid} = V2.decode_proof(forged_proof_with_payload(payload), %{})
  end

  test "inherited-kind producer success and decode error arms close the remaining paths" do
    # equals/one_of producer success arms
    mixed = %{
      grant()
      | operations: [
          %BoundedAuthorityProtocol.V2.Operation{
            name: "transfer",
            selectors: [
              {:equals, ["region"], {:string, "us"}},
              {:one_of, ["tier"], [{:string, "gold"}, {:string, "silver"}]}
            ]
          }
        ]
    }

    assert {:ok, input} = V2.grant_signing_input(mixed, %{})
    decoded_payload = decode_segment(input.payload_segment)
    assert inspect(decoded_payload) =~ "equals"
    assert inspect(decoded_payload) =~ "one_of"

    # equals decode error arm: path member not an array
    compact =
      forged_grant_with_selector(%{"kind" => "equals", "path" => "not-an-array", "value" => 1})

    assert {:error, :invalid} = V2.decode_grant(compact, %{})

    # one_of decode error arm: values member not a list
    compact = forged_grant_with_selector(%{"kind" => "one_of", "path" => ["a"], "values" => 5})
    assert {:error, :invalid} = V2.decode_grant(compact, %{})

    # operation catch-all: a non-object operation entry
    payload = %{"name" => "transfer", "selectors" => [%{"kind" => "all"}]}
    {:ok, input2} = V2.grant_signing_input(grant(), %{})
    base = decode_segment(input2.payload_segment)
    operations = [payload, "not-an-object"]

    payload_segment =
      Base.url_encode64(json_bytes(Map.put(base, "operations", operations)), padding: false)

    message = input2.protected_segment <> "." <> payload_segment
    signature = :crypto.sign(:eddsa, :ed25519, message, [issuer_private(), :ed25519])

    assert {:error, :invalid} =
             V2.decode_grant(message <> "." <> Base.url_encode64(signature, padding: false), %{})

    # selector catch-all: a non-object selector entry
    operations2 = [%{"name" => "transfer", "selectors" => ["not-an-object"]}]

    payload_segment2 =
      Base.url_encode64(json_bytes(Map.put(base, "operations", operations2)), padding: false)

    message2 = input2.protected_segment <> "." <> payload_segment2
    signature2 = :crypto.sign(:eddsa, :ed25519, message2, [issuer_private(), :ed25519])

    assert {:error, :invalid} =
             V2.decode_grant(
               message2 <> "." <> Base.url_encode64(signature2, padding: false),
               %{}
             )

    # optional_nonce non-string typed member on the proof side
    assert {:error, :invalid} =
             V2.decode_proof(forged_proof_with_payload(forged_proof_member("nonce", true)), %{})

    # nonce_matches? catch-all: proof carries a nonce while the expectation does not require one
    {credentials, expected} = envelope_with_nonce("server-nonce-9")
    assert {:ok, _facts} = V2.check_envelope(credentials, expected)
    assert {:error, :invalid} = V2.check_envelope(credentials, %{expected | nonce: :not_required})
  end

  test "improper selector containers raise through the fixed guard and fail closed" do
    op = %BoundedAuthorityProtocol.V2.Operation{name: "transfer", selectors: [:all]}
    grant = %{grant() | operations: [op | :invalid_tail]}

    assert {:error, :invalid} = V2.grant_signing_input(grant, %{})
  end

  test "assembly revalidation fails closed on a well-formed signing input with invalid payload members" do
    {:ok, input} = V2.grant_signing_input(grant(), %{})

    bad_grant_payload = Base.url_encode64(~s({"aud":"a"}), padding: false)

    forged_grant = %BoundedAuthorityProtocol.V1.SigningInput{
      kind: :grant,
      protected_segment: input.protected_segment,
      payload_segment: bad_grant_payload,
      message: input.protected_segment <> "." <> bad_grant_payload
    }

    assert {:error, :invalid} = V2.assemble_compact(forged_grant, <<0::512>>, %{})

    # The proof-kind arm needs a real proof header (typ dpop+jwt) so assembly reaches
    # the revalidation step, with a payload that fails the proof decode.
    {grant_compact, _} = signed_grant()

    proof = %BoundedAuthorityProtocol.V2.Proof{
      holder_public_key: holder_public(),
      proof_id: "urn:example:proof:v2-1",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      issued_at: 1_100,
      nonce: nil,
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      grant_compact: grant_compact,
      cast_arguments: {:object, [{"amount", {:integer, 75}}]}
    }

    {:ok, proof_input} = V2.proof_signing_input(proof, %{})
    bad_proof_payload = Base.url_encode64(~s({"iat":1100}), padding: false)

    forged_proof = %BoundedAuthorityProtocol.V1.SigningInput{
      kind: :proof,
      protected_segment: proof_input.protected_segment,
      payload_segment: bad_proof_payload,
      message: proof_input.protected_segment <> "." <> bad_proof_payload
    }

    assert {:error, :invalid} = V2.assemble_compact(forged_proof, <<0::512>>, %{})
  end

  test "a mixed-kind grant decodes its one_of selector through the v2 parse path" do
    mixed = %{
      grant()
      | operations: [
          %BoundedAuthorityProtocol.V2.Operation{
            name: "transfer",
            selectors: [{:one_of, ["tier"], [{:string, "gold"}, {:string, "silver"}]}]
          }
        ]
    }

    {:ok, input} = V2.grant_signing_input(mixed, %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [issuer_private(), :ed25519])
    {:ok, compact} = V2.assemble_compact(input, signature)

    assert {:ok, decoded} = V2.decode_grant(compact, %{})
    assert decoded.operations == mixed.operations
  end

  test "an audience list with a non-string member fails at the strings decoder" do
    payload = forged_payload_with("aud", ["ok", 5])
    assert {:error, :invalid} = V2.decode_grant(forged_grant_with_payload(payload), %{})
  end

  test "malformed runtime inputs return the fixed error" do
    assert {:error, :invalid} = V2.decode_grant(:not_binary, %{})
    assert {:error, :invalid} = V2.decode_proof(:not_binary, %{})
    assert {:error, :invalid} = V2.grant_signing_input(:not_a_grant, %{})
    assert {:error, :invalid} = V2.proof_signing_input(:not_a_proof, %{})

    assert {:error, :invalid} =
             V2.verify_grant(:not_binary, trusted(legacy_major_key()), expected_grant())

    assert {:error, :invalid} = V2.check_envelope(%{}, %{})
    assert {:error, :invalid} = V2.verify_grant("a.b.c", :not_trusted, expected_grant())
  end

  defp grant do
    %BoundedAuthorityProtocol.V2.Grant{
      key_id: @issuer_key_id,
      issuer: @issuer,
      grant_id: "urn:example:grant:v2-1",
      audiences: [@audience],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: holder_thumbprint(),
      operations: [
        %BoundedAuthorityProtocol.V2.Operation{
          name: "transfer",
          selectors: [
            {:gte, ["amount"], {:integer, 50}},
            {:lte, ["amount"], {:integer, 5000}}
          ]
        }
      ]
    }
  end

  defp signed_grant(grant \\ grant()) do
    {:ok, input} = V2.grant_signing_input(grant, %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [issuer_private(), :ed25519])
    {:ok, compact} = V2.assemble_compact(input, signature)
    {compact, issuer_public()}
  end

  defp forged_grant_with_selector(selector) do
    grant = %{
      grant()
      | operations: [
          %BoundedAuthorityProtocol.V2.Operation{name: "transfer", selectors: [:all]}
        ]
    }

    {:ok, input} = V2.grant_signing_input(grant, %{})
    segments = String.split(input.payload_segment, ".", parts: 1)
    payload = decode_segment(hd(segments))

    payload = %{payload | "operations" => [%{"name" => "transfer", "selectors" => [selector]}]}
    payload_bytes = json_bytes(payload)
    payload_segment = Base.url_encode64(payload_bytes, padding: false)
    message = input.protected_segment <> "." <> payload_segment
    signature = :crypto.sign(:eddsa, :ed25519, message, [issuer_private(), :ed25519])
    message <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp legacy_major_grant do
    alias BoundedAuthorityProtocol.V1

    grant = %V1.Grant{
      key_id: @issuer_key_id,
      issuer: @issuer,
      grant_id: "urn:example:grant:v2-1",
      audiences: [@audience],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: holder_thumbprint(),
      operations: [%V1.Operation{name: "transfer", selectors: [:all]}]
    }

    {:ok, input} = V1.grant_signing_input(grant, %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [issuer_private(), :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    compact
  end

  defp legacy_major_key, do: issuer_public()

  defp issuer_public, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<1::256>>), 0)
  defp issuer_private, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<1::256>>), 1)
  defp holder_public, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<2::256>>), 0)
  defp holder_private, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<2::256>>), 1)

  defp holder_thumbprint do
    {:ok, jwk_bytes} = Jwk.encode_public(holder_public(), %{})
    {:ok, raw} = Jwk.thumbprint_raw(jwk_bytes, %{})
    raw
  end

  defp trusted(public), do: %TrustedIssuer{key_id: @issuer_key_id, public_key: public}

  defp expected_grant do
    %ExpectedGrant{
      issuer: @issuer,
      audience: @audience,
      evaluation_time: 1_500,
      clock_skew: 30,
      bounds: %{}
    }
  end

  defp envelope(amount) when is_integer(amount) do
    credentials_and_expected({:integer, amount})
  end

  defp float_envelope(amount) do
    credentials_and_expected({:float, amount}, float_bound_grant())
  end

  defp float_bound_grant do
    %{
      grant()
      | operations: [
          %BoundedAuthorityProtocol.V2.Operation{
            name: "transfer",
            selectors: [
              {:gte, ["amount"], {:float, -0.5}},
              {:lte, ["amount"], {:float, 10.5}}
            ]
          }
        ]
    }
  end

  defp credentials_and_expected(amount, grant \\ grant()) do
    {grant_compact, _} = signed_grant(grant)

    cast_arguments = {:object, [{"amount", amount}]}

    proof = %BoundedAuthorityProtocol.V2.Proof{
      holder_public_key: holder_public(),
      proof_id: "urn:example:proof:v2-1",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      issued_at: 1_400,
      nonce: "server-nonce-1",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      grant_compact: grant_compact,
      cast_arguments: cast_arguments
    }

    {:ok, input} = V2.proof_signing_input(proof, %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [holder_private(), :ed25519])
    {:ok, proof_compact} = V2.assemble_compact(input, signature)

    expected = %ExpectedRequest{
      trusted_issuer: trusted(issuer_public()),
      issuer: @issuer,
      audience: @audience,
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      cast_arguments: cast_arguments,
      evaluation_time: 1_500,
      clock_skew: 30,
      proof_max_age: 300,
      nonce: {:required, "server-nonce-1"},
      bounds: %{}
    }

    {struct!(Credentials, grant: grant_compact, proof: proof_compact), expected}
  end

  defp forged_payload_with(member, value) do
    {:ok, input} = V2.grant_signing_input(grant(), %{})
    payload = decode_segment(input.payload_segment)
    Map.put(payload, member, value)
  end

  defp forged_grant_with_payload(payload) do
    {:ok, input} = V2.grant_signing_input(grant(), %{})
    payload_segment = Base.url_encode64(json_bytes(payload), padding: false)
    message = input.protected_segment <> "." <> payload_segment
    signature = :crypto.sign(:eddsa, :ed25519, message, [issuer_private(), :ed25519])
    message <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp forged_proof_member(member, value) do
    {grant_compact, _} = signed_grant()

    proof = %BoundedAuthorityProtocol.V2.Proof{
      holder_public_key: holder_public(),
      proof_id: "urn:example:proof:v2-1",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      issued_at: 1_100,
      nonce: nil,
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      grant_compact: grant_compact,
      cast_arguments: {:object, [{"amount", {:integer, 75}}]}
    }

    {:ok, input} = V2.proof_signing_input(proof, %{})
    payload = decode_segment(input.payload_segment)
    Map.put(payload, member, value)
  end

  defp envelope_with_nonce(nonce) do
    {grant_compact, _} = signed_grant()

    proof = %BoundedAuthorityProtocol.V2.Proof{
      holder_public_key: holder_public(),
      proof_id: "urn:example:proof:v2-1",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      issued_at: 1_400,
      nonce: nonce,
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      grant_compact: grant_compact,
      cast_arguments: {:object, [{"amount", {:integer, 75}}]}
    }

    {:ok, input} = V2.proof_signing_input(proof, %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [holder_private(), :ed25519])
    {:ok, proof_compact} = V2.assemble_compact(input, signature)

    expected = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{key_id: "issuer-a", public_key: issuer_public()},
      issuer: "https://issuer.example.test",
      audience: "https://resource.example.test",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      cast_arguments: {:object, [{"amount", {:integer, 75}}]},
      evaluation_time: 1_500,
      clock_skew: 30,
      proof_max_age: 300,
      nonce: {:required, nonce},
      bounds: %{}
    }

    {struct!(Credentials, grant: grant_compact, proof: proof_compact), expected}
  end

  defp forged_proof_with_payload(payload) do
    {grant_compact, _} = signed_grant()

    proof = %BoundedAuthorityProtocol.V2.Proof{
      holder_public_key: holder_public(),
      proof_id: "urn:example:proof:v2-1",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      issued_at: 1_400,
      nonce: nil,
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      grant_compact: grant_compact,
      cast_arguments: {:object, [{"amount", {:integer, 75}}]}
    }

    {:ok, input} = V2.proof_signing_input(proof, %{})
    payload_segment = Base.url_encode64(json_bytes(payload), padding: false)
    message = input.protected_segment <> "." <> payload_segment
    signature = :crypto.sign(:eddsa, :ed25519, message, [holder_private(), :ed25519])
    message <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp decode_segment(segment) do
    bytes = Base.url_decode64!(segment, padding: false)
    {:ok, value} = Json.decode(bytes, %{})
    untag(value)
  end

  defp json_bytes(value), do: Jcs.encode(tag(value), %{}) |> ok!()

  defp tag(map) when is_map(map) do
    {:object,
     Enum.map(map, fn {key, value} ->
       {key, tag(value)}
     end)}
  end

  defp tag(list) when is_list(list) do
    {:array, Enum.map(list, &tag/1)}
  end

  defp tag(value) when is_integer(value), do: {:integer, value}
  defp tag(value) when is_float(value), do: {:float, value}
  defp tag(value) when is_binary(value), do: {:string, value}
  defp tag(value) when is_boolean(value), do: {:boolean, value}
  defp tag(nil), do: :null

  defp untag({:object, members}),
    do: Map.new(members, fn {key, value} -> {key, untag(value)} end)

  defp untag({:array, values}), do: Enum.map(values, &untag/1)
  defp untag({:integer, value}), do: value
  defp untag({:float, value}), do: value
  defp untag({:string, value}), do: value
  defp untag({:boolean, value}), do: value
  defp untag(:null), do: nil

  defp ok!({:ok, value}), do: value

  defp flip_segment(compact, index) do
    segments = String.split(compact, ".")
    segment = Enum.at(segments, index)
    <<first, rest::binary>> = segment
    replacement = if first == ?A, do: ?B, else: ?A
    List.replace_at(segments, index, <<replacement, rest::binary>>) |> Enum.join(".")
  end
end
