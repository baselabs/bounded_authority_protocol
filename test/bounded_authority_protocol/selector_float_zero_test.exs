defmodule BoundedAuthorityProtocol.SelectorFloatZeroTest do
  @moduledoc """
  Erratum 6 (selector float-zero soundness repair) on every contract-major.

  RFC 8785 serializes `0.0`, `-0.0` and every integral float as integer text, so a conforming
  producer never signs a float-tagged integral selector value. Verifiers must still accept
  non-JCS payload bytes, and before this repair they disagreed on a float-tagged zero inside an
  `equals` value or `one_of` member: the sign of zero changed the verdict in one implementation
  and not in another. Grant decode now rejects such a value (keyed on the decoded value, so every
  spelling of zero is covered), producers refuse every float-tagged integral selector value, and
  range bounds keep their numeric comparison.
  """
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.{Es256, V1, V2, V3}
  alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, TrustedIssuer}
  alias BoundedAuthorityProtocol.V3.EcJwk

  @issuer "https://issuer.example.test"
  @audience "https://resource.example.test"
  @target "https://resource.example.test/invoke"
  @invocation "550e8400-e29b-41d4-a716-446655440000"
  @zero_spellings ["0.0", "-0.0", "0e0", "-0e0", "-0E0", "-0e-5", "0.000", "1e-400", "-1e-400"]

  defp majors do
    [
      %{major: 1, mod: V1, grant: V1.Grant, op: V1.Operation, proof: V1.Proof, suite: :ed25519},
      %{major: 2, mod: V2, grant: V2.Grant, op: V2.Operation, proof: V2.Proof, suite: :ed25519},
      %{major: 3, mod: V3, grant: V3.Grant, op: V3.Operation, proof: V3.Proof, suite: :es256}
    ]
  end

  describe "verification: grant decode rejects float-tagged zero in equals and one_of values" do
    test "every spelling of zero, at the top level, nested, and in one_of members" do
      for m <- majors(), zero <- @zero_spellings do
        for selector <- [
              ~s({"kind":"equals","path":["x"],"value":#{zero}}),
              ~s({"kind":"equals","path":["x"],"value":[1,#{zero}]}),
              ~s({"kind":"equals","path":["x"],"value":{"a":{"b":#{zero}}}}),
              ~s({"kind":"one_of","path":["x"],"values":[1,#{zero}]}),
              ~s({"kind":"one_of","path":["x"],"values":[[#{zero}]]})
            ] do
          compact = raw_grant(m, selector)

          assert {:error, :invalid} = m.mod.decode_grant(compact, %{}),
                 "v#{m.major} #{selector}"
        end
      end
    end

    test "integer zero, non-integral floats and integral non-zero floats still decode" do
      for m <- majors(),
          value <- ["0", "-0", "0.5", "-2.25", "10.0", "1e1", "[0, 1.5]", ~s({"a":0})] do
        for selector <- [
              ~s({"kind":"equals","path":["x"],"value":#{value}}),
              ~s({"kind":"one_of","path":["x"],"values":[#{value}]})
            ] do
          assert {:ok, _decoded} = m.mod.decode_grant(raw_grant(m, selector), %{}),
                 "v#{m.major} #{selector}"
        end
      end
    end

    test "float-zero range bounds still decode on contract-majors 2 and 3" do
      for m <- majors(), m.major in [2, 3], zero <- @zero_spellings, kind <- ["lte", "gte"] do
        selector = ~s({"kind":"#{kind}","path":["x"],"value":#{zero}})
        assert {:ok, _decoded} = m.mod.decode_grant(raw_grant(m, selector), %{})
      end
    end

    test "a float-zero equals grant never verifies, whatever the host's zero" do
      for m <- majors(), zero <- ["0.0", "-0.0", "-0e0"], host <- [0.0, -0.0] do
        selector = ~s({"kind":"equals","path":["x"],"value":#{zero}})
        arguments = {:object, [{"x", {:float, host}}]}

        assert {:error, :invalid} = envelope(m, selector, arguments),
               "v#{m.major} #{zero} host #{inspect(host)}"
      end
    end
  end

  describe "controls that keep their verdicts" do
    test "a float-zero range bound compares numerically with a host -0.0 (v2, v3)" do
      for m <- majors(), m.major in [2, 3], zero <- ["0.0", "-0.0"], kind <- ["lte", "gte"] do
        selector = ~s({"kind":"#{kind}","path":["x"],"value":#{zero}})

        for host <- [0.0, -0.0] do
          assert {:ok, _facts} = envelope(m, selector, {:object, [{"x", {:float, host}}]}),
                 "v#{m.major} #{kind} #{zero} host #{inspect(host)}"
        end
      end
    end

    test "a host float zero never matches an integer zero selector" do
      for m <- majors(), host <- [0.0, -0.0] do
        selector = ~s({"kind":"equals","path":["x"],"value":0})
        assert {:error, :invalid} = envelope(m, selector, {:object, [{"x", {:float, host}}]})
      end
    end

    test "an integer zero selector matches a host integer zero" do
      for m <- majors() do
        selector = ~s({"kind":"equals","path":["x"],"value":0})
        assert {:ok, _facts} = envelope(m, selector, {:object, [{"x", {:integer, 0}}]})
      end
    end
  end

  describe "producers refuse float-tagged integral selector values" do
    test "equals, one_of and nested values on every contract-major" do
      for m <- majors(), float <- [0.0, -0.0, 10.0, -3.0, 4_503_599_627_370_496.0] do
        for selector <- [
              {:equals, ["x"], {:float, float}},
              {:equals, ["x"], {:array, [{:integer, 1}, {:float, float}]}},
              {:equals, ["x"], {:object, [{"a", {:float, float}}]}},
              {:one_of, ["x"], [{:integer, 1}, {:float, float}]}
            ] do
          assert {:error, :invalid} = m.mod.grant_signing_input(grant(m, [selector]), %{}),
                 "v#{m.major} #{inspect(selector)}"
        end
      end
    end

    test "range bounds on contract-majors 2 and 3" do
      for m <- majors(), m.major in [2, 3], float <- [0.0, -0.0, 10.0], kind <- [:lte, :gte] do
        assert {:error, :invalid} =
                 m.mod.grant_signing_input(grant(m, [{kind, ["x"], {:float, float}}]), %{})
      end
    end

    test "non-integral floats and integers are still signed" do
      for m <- majors(),
          value <- [{:float, 0.5}, {:float, -2.25}, {:integer, 0}, {:integer, 10}] do
        selectors =
          [{:equals, ["x"], value}, {:one_of, ["x"], [value]}] ++
            if m.major in [2, 3], do: [{:lte, ["x"], value}, {:gte, ["x"], value}], else: []

        assert {:ok, _input} = m.mod.grant_signing_input(grant(m, selectors), %{})
      end
    end
  end

  # -- helpers ---------------------------------------------------------------------------------

  defp grant(m, selectors) do
    struct!(m.grant,
      key_id: "issuer",
      issuer: @issuer,
      grant_id: "urn:example:grant:zero",
      audiences: [@audience],
      issued_at: 1000,
      not_before: 1000,
      expires_at: 2000,
      holder_thumbprint: :binary.copy(<<7>>, 32),
      operations: [struct!(m.op, name: "transfer", selectors: selectors)]
    )
  end

  # A grant whose payload bytes are written by hand (not JCS), carrying `selector_json` verbatim.
  defp raw_grant(m, selector_json, keys \\ nil) do
    {issuer, holder} = keys || {keypair(m.suite), keypair(m.suite)}
    {:ok, jkt} = thumbprint(m, elem(holder, 0))
    alg = if m.suite == :es256, do: "ES256", else: "EdDSA"
    protected = b64(~s({"alg":"#{alg}","kid":"issuer","typ":"ba+cap"}))

    payload =
      b64(
        ~s({"aud":["#{@audience}"],"cnf":{"jkt":"#{b64(jkt)}"},"exp":2000,"iat":1000,) <>
          ~s("iss":"#{@issuer}","jti":"urn:example:grant:zero","nbf":1000,) <>
          ~s("operations":[{"name":"transfer","selectors":[#{selector_json}]}],"v":#{m.major}})
      )

    message = protected <> "." <> payload
    message <> "." <> b64(sign(m.suite, message, elem(issuer, 1)))
  end

  defp envelope(m, selector_json, arguments) do
    issuer = keypair(m.suite)
    holder = keypair(m.suite)
    grant = raw_grant(m, selector_json, {issuer, holder})

    proof =
      struct!(m.proof,
        holder_public_key: elem(holder, 0),
        proof_id: "urn:example:proof:zero",
        method: "POST",
        target_uri: @target,
        issued_at: 1100,
        nonce: nil,
        invocation_id: @invocation,
        operation: "transfer",
        grant_compact: grant,
        cast_arguments: arguments
      )

    {:ok, input} = m.mod.proof_signing_input(proof, %{})
    {:ok, proof} = m.mod.assemble_compact(input, sign(m.suite, input.message, elem(holder, 1)))

    expected = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{key_id: "issuer", public_key: elem(issuer, 0)},
      issuer: @issuer,
      audience: @audience,
      method: "POST",
      target_uri: @target,
      invocation_id: @invocation,
      operation: "transfer",
      cast_arguments: arguments,
      evaluation_time: 1200,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: :not_required,
      bounds: %{}
    }

    m.mod.check_envelope(%Credentials{grant: grant, proof: proof}, expected)
  end

  defp keypair(:ed25519), do: :crypto.generate_key(:eddsa, :ed25519)
  defp keypair(:es256), do: :crypto.generate_key(:ecdh, :secp256r1)

  defp thumbprint(%{suite: :es256}, public),
    do: EcJwk.public_key_thumbprint_raw(public, %{})

  defp thumbprint(_m, public), do: V1.Jwk.public_key_thumbprint_raw(public, %{})

  defp sign(:ed25519, message, private),
    do: :crypto.sign(:eddsa, :none, message, [private, :ed25519])

  defp sign(:es256, message, private) do
    der = :crypto.sign(:ecdsa, :sha256, message, [private, :secp256r1])
    {:ok, raw} = Es256.der_to_raw(der)
    {:ok, low_s} = Es256.normalize_low_s(raw)
    low_s
  end

  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)
end
