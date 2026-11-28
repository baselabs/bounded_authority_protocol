defmodule BoundedAuthorityProtocol.HolderCustodyAttestation.V1Test do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.HolderCustodyAttestation.V1
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.SigningInput

  @root "priv/conformance/attestation-profiles/holder-custody-attestation/v1"

  setup do
    profile = read_corpus("profile.json")
    %{"attestor" => attestor, "subject" => subject, "signing" => signing} = profile
    payload = signing["payload"]

    producer = %V1.HolderCustodyAttestation{
      attestor_key_id: attestor["key_id"],
      jti: payload["jti"],
      key_id: payload["key_id"],
      public_key: raw(payload["public_key"]),
      custody_class: payload["custody_class"],
      nbf: payload["nbf"],
      exp: payload["exp"]
    }

    expected = %V1.ExpectedAttestation{
      attestor: %HistoricalPublicKey{
        key_id: attestor["key_id"],
        public_key: raw(attestor["public_key"]),
        valid_from: attestor["valid_from"],
        valid_before: attestor["valid_before"]
      },
      subject_key_id: subject["key_id"],
      subject_public_key: raw(subject["public_key"]),
      now: profile["now"],
      bounds: %{}
    }

    %{producer: producer, compact: signing["compact"], expected: expected}
  end

  test "assembly preserves the exact known answer and revalidates hand-built input", c do
    {input, signature} = signing_input(c.compact)
    limits = %{anchor_bytes: byte_size(c.compact)}

    assert V1.attestation_signing_input(c.producer, limits) == {:ok, input}
    assert V1.assemble_compact(input, signature, limits) == {:ok, c.compact}

    too_small = %{anchor_bytes: byte_size(c.compact) - 1}
    assert V1.attestation_signing_input(c.producer, too_small) == {:error, :invalid}
    assert V1.assemble_compact(input, signature, too_small) == {:error, :invalid}

    assert V1.assemble_compact(%{input | kind: :role_attestation}, signature) ==
             {:error, :invalid}

    assert BoundedAuthorityProtocol.V1.assemble_compact(input, signature) == {:error, :invalid}
    assert BoundedAuthorityProtocol.V2.assemble_compact(input, signature) == {:error, :invalid}
    assert BoundedAuthorityProtocol.V3.assemble_compact(input, signature) == {:error, :invalid}

    cases = read_corpus("attestation-cases.json")

    for id <- ~w(unknown-custody-class wrong-typ noncanonical-payload noncanonical-scalar) do
      %{"compact" => compact} = Enum.find(cases, &(&1["id"] == id))
      {invalid_input, invalid_signature} = signing_input(compact)
      assert V1.assemble_compact(invalid_input, invalid_signature) == {:error, :invalid}, id
    end
  end

  test "the public calls refuse malformed values with a closed error", c do
    assert V1.attestation_signing_input(%{c.producer | custody_class: "other"}, %{}) ==
             {:error, :invalid}

    assert V1.decode_attestation(nil, %{}) == {:error, :invalid}
    assert V1.decode_attestation("", %{}) == {:error, :invalid}
    assert V1.verify_attestation(c.compact, %{c.expected | attestor: %{}}) == {:error, :invalid}
  end

  test "decoded custody is diagnostic and verified facts redact their values", c do
    assert {:ok, decoded} = V1.decode_attestation(c.compact, %{})
    assert decoded.verification == :not_evaluated
    assert inspect(decoded) =~ ~s(custody_class: "standard")

    assert {:ok, facts} = V1.verify_attestation(c.compact, c.expected)
    assert facts.trust == :not_evaluated
    assert facts.custody_class == "standard"

    assert inspect(facts) ==
             "#BoundedAuthorityProtocol.HolderCustodyAttestation.V1.AttestationFacts<redacted>"
  end

  test "the specification, requirement map and durable identifiers agree" do
    spec = File.read!("spec/bap-holder-custody-attestation-v1.md")
    coverage = File.read!("docs/design/holder-custody-attestation-requirement-map.md")

    durable =
      "test/fixtures/durable_identifier_holder_custody_attestation_requirements.txt"
      |> File.read!()
      |> String.split()
      |> MapSet.new()

    specified = ~r/\bREQ-HCA1-[A-Za-z0-9-]+\b/ |> Regex.scan(spec) |> List.flatten()

    mapped =
      for line <- String.split(coverage, "\n"),
          ["", ids, evidence, ""] <- [String.split(line, "|")],
          String.trim(evidence) != "",
          [id] <- Regex.scan(~r/`([A-Z]+-[A-Za-z0-9-]+)`/, ids, capture: :all_but_first),
          do: "REQ-HCA1-" <> id

    assert MapSet.new(specified) == durable
    assert MapSet.new(mapped) == durable
    refute MapSet.size(durable) == 0
  end

  defp signing_input(compact) do
    [protected, payload, signature] = String.split(compact, ".")

    {%SigningInput{
       kind: :holder_custody_attestation,
       protected_segment: protected,
       payload_segment: payload,
       message: protected <> "." <> payload
     }, raw(signature)}
  end

  defp read_corpus(path), do: @root |> Path.join(path) |> File.read!() |> :json.decode()
  defp raw(encoded), do: Base.url_decode64!(encoded, padding: false)
end
