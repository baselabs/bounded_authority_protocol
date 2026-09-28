defmodule BoundedAuthorityProtocol.ContentAssertion.CorpusTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion.V1
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @root "priv/conformance/attestation-profiles/content-assertion/v1"
  @index_sha256 "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876"
  @files ~w(profile.json digest-cases.json assertion-structure-cases.json assertion-verification-cases.json successor-cases.json content-base.raw content-maximum.raw content-over-limit.raw)

  test "independent signed corpus identity and all indexed bytes are pinned" do
    bytes = File.read!(Path.join(@root, "index.json"))
    assert hash(bytes) == @index_sha256
    index = :json.decode(bytes)
    assert index["profile"] == "bap-content-assertion/1"
    assert index["revision"] == 1
    assert Enum.map(index["files"], & &1["path"]) == @files
    assert Enum.sort(File.ls!(@root)) == Enum.sort(["index.json" | @files])
    assert index["assertion_cases"] == length(assertion_cases())
    assert index["digest_cases"] == length(read("digest-cases.json"))
    assert index["successor_cases"] == length(read("successor-cases.json"))

    for file <- index["files"] do
      assert hash(File.read!(Path.join(@root, file["path"]))) == file["sha256"]
    end
  end

  test "exact content bytes and bounds agree with independent digest cases" do
    for c <- read("digest-cases.json") do
      input = c["input"]

      content =
        if Map.has_key?(input, "content_file"),
          do: File.read!(Path.join(@root, input["content_file"])),
          else: raw(input["content_base64url"])

      result = V1.content_digest(content, bounds(input))
      assert verdict(result) == c["expected"]["verdict"], c["id"]
      if match?({:ok, _}, result), do: assert(elem(result, 1) == raw(c["expected"]["digest"]))
    end
  end

  test "independent assertions agree on decode, verify, exact producer bytes, and cross-rejection" do
    profile = read("profile.json")

    for c <- assertion_cases() do
      compact = c["compact"]
      decoded = V1.decode_assertion(compact, bounds(c))
      verified = V1.verify_assertion(compact, expected(profile, c))
      assert verdict(decoded) == c["expected"]["decode"], c["id"] <> " decode"
      assert verdict(verified) == c["expected"]["verify"], c["id"] <> " verify"

      legacy = %{
        "v1_grant" => BoundedAuthorityProtocol.V1.decode_grant(compact, %{}),
        "v2_grant" => BoundedAuthorityProtocol.V2.decode_grant(compact, %{}),
        "v3_grant" => BoundedAuthorityProtocol.V3.decode_grant(compact, %{}),
        "loopback" =>
          BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.decode_proof(
            compact,
            %{}
          ),
        "role_attestation" =>
          BoundedAuthorityProtocol.RoleAttestation.V1.decode_attestation(compact, %{})
      }

      for {name, result} <- legacy do
        assert verdict(result) == "valid" == name in Map.get(c, "legacy_accepts", []),
               c["id"] <> " " <> name
      end

      if match?({:ok, _}, decoded) do
        {:ok, value} = decoded

        values =
          value
          |> Map.from_struct()
          |> Map.drop([:version, :verification])

        {:ok, input} = V1.assertion_signing_input(struct!(V1.ContentAssertion, values), bounds(c))
        [header, payload, signature] = String.split(compact, ".")
        assert input.message == header <> "." <> payload, c["id"]
        assert {:ok, ^compact} = V1.assemble_compact(input, raw(signature), bounds(c))
        assert {:ok, :crypto.hash(:sha256, compact)} == V1.assertion_digest(compact, bounds(c))
      end
    end
  end

  test "separately verified predecessor and successor facts obey every relation case" do
    profile = read("profile.json")

    for c <- read("successor-cases.json") do
      previous =
        V1.verify_assertion(c["predecessor"]["compact"], expected(profile, c["predecessor"]))

      successor =
        V1.verify_assertion(c["successor"]["compact"], expected(profile, c["successor"]))

      assert verdict(previous) == c["expected"]["predecessor"], c["id"]
      assert verdict(successor) == c["expected"]["successor"], c["id"]

      relation =
        case {previous, successor} do
          {{:ok, previous_facts}, {:ok, successor_facts}} ->
            V1.verify_successor(
              override_facts(previous_facts, c["predecessor"]),
              override_facts(successor_facts, c["successor"]),
              bounds(c)
            )

          _ ->
            :not_run
        end

      assert verdict(relation) == c["expected"]["relation"], c["id"]
    end
  end

  defp override_facts(facts, input) do
    Enum.reduce(Map.get(input, "facts_overrides", %{}), facts, fn {field, value}, acc ->
      key = String.to_existing_atom(field)

      parsed =
        cond do
          key in [:verification, :trust] ->
            Map.fetch!(
              %{
                "not_evaluated" => :not_evaluated,
                "evaluated" => :evaluated,
                "signature_and_window" => :signature_and_window
              },
              value
            )

          key in [:digest, :profile_digest, :content_digest, :prev, :attestor_key_fingerprint] ->
            raw(value)

          true ->
            value
        end

      Map.put(acc, key, parsed)
    end)
  end

  defp expected(profile, c) do
    overrides = Map.get(c, "expected_overrides", %{})
    values = Map.merge(profile["expected"], overrides)
    key = profile["attestors"][Map.get(c, "attestor", "primary")]

    struct!(V1.ExpectedContentAssertion,
      issuer: values["issuer"],
      audience: values["audience"],
      subject: values["subject"],
      profile: values["profile"],
      profile_digest: raw(values["profile_digest"]),
      content_digest: raw(values["content_digest"]),
      now: values["now"],
      bounds: bounds(c),
      attestor: %HistoricalPublicKey{
        key_id: Map.get(overrides, "attestor_key_id", key["key_id"]),
        public_key: raw(Map.get(overrides, "attestor_public_key", key["public_key"])),
        valid_from: Map.get(overrides, "attestor_valid_from", key["valid_from"]),
        valid_before: Map.get(overrides, "attestor_valid_before", key["valid_before"])
      }
    )
  end

  defp bounds(c),
    do:
      Map.new(Map.get(c, "bounds", %{}), fn {key, value} ->
        {String.to_existing_atom(key), value}
      end)

  defp assertion_cases,
    do: read("assertion-structure-cases.json") ++ read("assertion-verification-cases.json")

  defp read(name), do: @root |> Path.join(name) |> File.read!() |> :json.decode()
  defp raw(value), do: Base.url_decode64!(value, padding: false)
  defp hash(value), do: Base.encode16(:crypto.hash(:sha256, value), case: :lower)
  defp verdict({:ok, _}), do: "valid"
  defp verdict(:ok), do: "valid"
  defp verdict(:not_run), do: "not_run"
  defp verdict({:error, :invalid}), do: "invalid"
end
