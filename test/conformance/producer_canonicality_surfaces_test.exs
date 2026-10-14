Code.require_file("../../test_support/ed25519_reference.ex", __DIR__)

defmodule BoundedAuthorityProtocol.Conformance.ProducerCanonicalitySurfacesTest do
  @moduledoc """
  Erratum 3: compact assembly and anchored-export encoding are producer surfaces. They refuse a
  signature that no conforming signer emits with the closed error, and they emit every accepted
  signature's bytes unchanged. Decode is untouched: a decoded compact is not a verified one.

  Templates are the certified corpora's valid compacts; every derived signature is computed
  here from `n`, `floor(n/2)` and `L` by arithmetic, and the small-order and non-canonical `R`
  sets come from the independent reference in `test_support/ed25519_reference.ex`.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp
  alias BoundedAuthorityProtocol.ContentAssertion
  alias BoundedAuthorityProtocol.RoleAttestation
  alias BoundedAuthorityProtocol.TestSupport.Ed25519Reference, as: Ref
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V2
  alias BoundedAuthorityProtocol.V3

  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @half_n div(@n, 2)
  @l Ref.l()
  @max 2 ** 256 - 1

  @small_order_r Enum.map(Ref.torsion_points(), &Ref.encode/1)
  @non_canonical_r Ref.non_canonical_encodings()

  # --- templates -------------------------------------------------------------------------

  defp corpus_case(path, predicate) do
    "priv/conformance"
    |> Path.join(path)
    |> File.read!()
    |> :json.decode()
    |> then(fn
      %{"cases" => cases} -> cases
      cases when is_list(cases) -> cases
    end)
    |> Enum.find(predicate)
  end

  defp valid?(case_obj), do: case_obj["expected"]["verdict"] == "valid"

  defp major_templates(major) do
    dir = "v#{major}/corpus/cases"

    [
      {:grant, corpus_case("#{dir}/grant-verify/verify.json", &valid?/1)["input"]["compact"]},
      {:proof, corpus_case("#{dir}/envelope/check.json", &valid?/1)["input"]["proof"]},
      {:boundary_anchor,
       corpus_case("#{dir}/boundary-anchor/verify.json", &valid?/1)["input"]["compact"]},
      {:key_transition,
       corpus_case("#{dir}/key-transition/verify.json", &valid?/1)["input"]["compact"]}
    ]
  end

  defp split(compact) do
    [protected, payload, signature] = String.split(compact, ".")
    {protected, payload, Base.url_decode64!(signature, padding: false)}
  end

  defp signing_input(kind, compact) do
    {protected, payload, _signature} = split(compact)

    %SigningInput{
      kind: kind,
      protected_segment: protected,
      payload_segment: payload,
      message: protected <> "." <> payload
    }
  end

  defp expected_compact(%SigningInput{} = input, signature),
    do: input.message <> "." <> Base.url_encode64(signature, padding: false)

  defp es256(r, s), do: <<r::unsigned-big-256, s::unsigned-big-256>>
  defp ed(r, s), do: <<r::binary-size(32), s::little-size(256)>>

  # --- ES256 (contract-major 3) -------------------------------------------------------------

  describe "ES256 assemble_compact (contract-major 3)" do
    test "refuses every out-of-range or high-S scalar and emits floor(n/2) unchanged" do
      for {kind, compact} <- major_templates(3) do
        input = signing_input(kind, compact)
        {_protected, _payload, <<r::256, s::256>> = original} = split(compact)
        assert s <= @half_n
        assert V3.assemble_compact(input, original) == {:ok, compact}

        refused = [
          {"high-S", es256(r, @n - s)},
          {"s = floor(n/2) + 1", es256(r, @half_n + 1)},
          {"r = 0", es256(0, s)},
          {"r = n", es256(@n, s)},
          {"r = 2^256 - 1", es256(@max, s)},
          {"s = 0", es256(r, 0)},
          {"s = n", es256(r, @n)},
          {"s = 2^256 - 1", es256(r, @max)}
        ]

        for {label, signature} <- refused do
          assert V3.assemble_compact(input, signature) == {:error, :invalid},
                 "#{kind} #{label}"

          assert V3.assemble_compact(input, signature, %{}) == {:error, :invalid},
                 "#{kind} #{label} /3"
        end

        boundary = es256(r, @half_n)
        assert V3.assemble_compact(input, boundary) == {:ok, expected_compact(input, boundary)}
        assert V3.assemble_compact(input, es256(@n - 1, s)) |> elem(0) == :ok
      end
    end

    test "decode is untouched: a high-S grant and proof still decode" do
      [{:grant, grant}, {:proof, proof} | _rest] = major_templates(3)

      for {compact, decode} <- [{grant, &V3.decode_grant/2}, {proof, &V3.decode_proof/2}] do
        {protected, payload, <<r::256, s::256>>} = split(compact)
        high = Base.url_encode64(es256(r, @n - s), padding: false)
        assert {:ok, _decoded} = decode.("#{protected}.#{payload}.#{high}", %{})
      end
    end
  end

  describe "ES256 encode_anchored_export (contract-major 3)" do
    test "refuses a high-S signature in each framed position" do
      template = export_template(3)
      assert {:ok, _encoded} = encode(3, template)

      for position <- ["start_anchor", "end_anchor", "transition"] do
        mutated =
          replace_signature(template, position, fn <<r::256, s::256>> -> es256(r, @n - s) end)

        assert encode(3, mutated) == {:error, :invalid}, position
      end
    end
  end

  # --- Ed25519 (contract-majors 1 and 2, local loopback, role attestation, content assertion)

  defp ed25519_surfaces do
    majors =
      for major <- [1, 2], {kind, compact} <- major_templates(major) do
        facade = if major == 1, do: V1, else: V2
        {"v#{major} #{kind}", signing_input(kind, compact), compact, &facade.assemble_compact/2}
      end

    loopback =
      corpus_case(
        "application-profiles/local-loopback-http/v1/proof-cases.json",
        &(&1["decode_local"] and &1["envelope_local"])
      )["compact"]

    attestation =
      corpus_case(
        "attestation-profiles/role-attestation/v1/attestation-cases.json",
        &(&1["decode"] and &1["verify"])
      )["compact"]

    assertion =
      corpus_case(
        "attestation-profiles/content-assertion/v1/assertion-structure-cases.json",
        &(&1["id"] == "valid-genesis")
      )["compact"]

    majors ++
      [
        {"loopback", signing_input(:local_loopback_http_proof, loopback), loopback,
         &LocalLoopbackHttp.V1.assemble_compact/2},
        {"role attestation", signing_input(:role_attestation, attestation), attestation,
         &RoleAttestation.V1.assemble_compact/2},
        {"content assertion", signing_input(:content_assertion, assertion), assertion,
         &ContentAssertion.V1.assemble_compact/2}
      ]
  end

  describe "Ed25519 assembly (every assembler)" do
    test "refuses S >= L, small-order R and non-canonical R; emits S = L - 1 unchanged" do
      surfaces = ed25519_surfaces()
      assert length(surfaces) == 11
      assert length(@small_order_r) == 8
      assert length(@non_canonical_r) == 40

      for {label, input, compact, assemble} <- surfaces do
        {_protected, _payload, <<r::binary-size(32), s::little-size(256)>> = original} =
          split(compact)

        assert assemble.(input, original) == {:ok, compact}, label

        for bad_s <- [@l, @l + 1, @max] do
          assert assemble.(input, ed(r, bad_s)) == {:error, :invalid}, "#{label} S=#{bad_s}"
        end

        for bad_r <- @small_order_r ++ @non_canonical_r do
          assert assemble.(input, ed(bad_r, s)) == {:error, :invalid},
                 "#{label} R=#{Base.encode16(bad_r, case: :lower)}"
        end

        boundary = ed(r, @l - 1)
        assert assemble.(input, boundary) == {:ok, expected_compact(input, boundary)}, label
      end
    end

    test "decode is untouched: an S = L grant still decodes under v1 and v2" do
      for {major, facade} <- [{1, V1}, {2, V2}] do
        [{:grant, grant} | _rest] = major_templates(major)
        {protected, payload, <<r::binary-size(32), _s::binary>>} = split(grant)
        bad = Base.url_encode64(ed(r, @l), padding: false)
        assert {:ok, _decoded} = facade.decode_grant("#{protected}.#{payload}.#{bad}", %{})
      end
    end
  end

  describe "Ed25519 encode_anchored_export" do
    test "refuses S = L and small-order R in each framed position" do
      for major <- [1, 2] do
        template = export_template(major)
        assert {:ok, _encoded} = encode(major, template)

        for position <- ["start_anchor", "end_anchor", "transition"],
            {label, mutate} <- [
              {"S = L", fn <<r::binary-size(32), _s::binary>> -> ed(r, @l) end},
              {"identity R",
               fn <<_r::binary-size(32), s::little-size(256)>> -> ed(hd(@small_order_r), s) end}
            ] do
          mutated = replace_signature(template, position, mutate)
          assert encode(major, mutated) == {:error, :invalid}, "v#{major} #{position} #{label}"
        end
      end
    end
  end

  # --- export helpers: the certified encode case, through the conformance runner's shapes ---

  defp export_template(major),
    do: corpus_case("v#{major}/corpus/cases/anchored-export/encode.json", &valid?/1)

  defp replace_signature(template, "transition", mutate) do
    update_in(template, ["input", "transitions"], fn [first | rest] ->
      [resign(first, mutate) | rest]
    end)
  end

  defp replace_signature(template, position, mutate),
    do: update_in(template, ["input", position], &resign(&1, mutate))

  defp resign(compact, mutate) do
    {protected, payload, signature} = split(compact)
    "#{protected}.#{payload}." <> Base.url_encode64(mutate.(signature), padding: false)
  end

  # The encode surface runs through the certified runner dispatch with exactly the corpus case
  # shape, so these tests and the corpus share one input builder.
  defp encode(major, case_obj) do
    alias BoundedAuthorityProtocol.Conformance.Corpus
    alias BoundedAuthorityProtocol.Conformance.Runner

    case_obj = Map.put(case_obj, "expected", %{"verdict" => "invalid"})

    corpus = %Corpus{
      index: %{},
      index_bytes: "",
      cases: [{"x", [Map.merge(case_obj, %{"major" => major})]}],
      raws: %{},
      case_ids: MapSet.new(),
      major: :producer_canonicality
    }

    [{"x", [%{agree: refused?}]}] = Runner.run(corpus)
    if refused?, do: {:error, :invalid}, else: {:ok, :encoded}
  end
end
