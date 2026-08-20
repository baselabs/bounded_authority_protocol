defmodule BoundedAuthorityProtocol.VerificationPerformance do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1

  alias BoundedAuthorityProtocol.V1.{
    Bounds,
    Credentials,
    ExpectedGrant,
    ExpectedRequest,
    TrustedIssuer
  }

  @samples 20
  @maximum_microseconds 1_000_000
  @maximum_reductions 5_000_000
  @maximum_heap_growth_words 1_048_576

  def run! do
    fixture =
      Path.expand("../priv/conformance/v1/vectors/grant-holder-proof.json", __DIR__)
      |> File.read!()
      |> :json.decode()

    context = fixture["expected_context"]
    bounds = Bounds.maximum()

    trusted = %TrustedIssuer{
      key_id: context["trusted_issuer"]["key_id"],
      public_key:
        Base.url_decode64!(context["trusted_issuer"]["public_key_base64url"], padding: false)
    }

    expected_grant = %ExpectedGrant{
      issuer: context["issuer"],
      audience: context["audience"],
      evaluation_time: context["evaluation_time"],
      clock_skew: context["clock_skew"],
      bounds: bounds
    }

    arguments =
      {:object,
       [
         {"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}},
         {"limit", {:integer, 10}}
       ]}

    expected_request = %ExpectedRequest{
      trusted_issuer: trusted,
      issuer: context["issuer"],
      audience: context["audience"],
      method: context["method"],
      target_uri: context["target_uri"],
      invocation_id: context["invocation_id"],
      operation: context["operation"],
      cast_arguments: arguments,
      evaluation_time: context["evaluation_time"],
      clock_skew: context["clock_skew"],
      proof_max_age: context["proof_max_age"],
      nonce: {:required, context["nonce"]["required"]},
      bounds: bounds
    }

    credentials = %Credentials{
      grant: fixture["grant"]["compact"],
      proof: fixture["proof"]["compact"]
    }

    cases = [
      {"decode_grant", fn -> V1.decode_grant(credentials.grant, bounds) end},
      {"decode_proof", fn -> V1.decode_proof(credentials.proof, bounds) end},
      {"verify_grant", fn -> V1.verify_grant(credentials.grant, trusted, expected_grant) end},
      {"check_envelope", fn -> V1.check_envelope(credentials, expected_request) end},
      {"maximum_invalid_compact",
       fn -> V1.decode_grant(:binary.copy("A", bounds.compact_bytes), bounds) end}
    ]

    Enum.each(cases, fn {name, operation} ->
      samples = Enum.map(1..@samples, fn _sample -> measure(operation) end)
      worst_time = samples |> Enum.map(& &1.microseconds) |> Enum.max()
      worst_reductions = samples |> Enum.map(& &1.reductions) |> Enum.max()
      worst_heap_growth = samples |> Enum.map(& &1.heap_growth_words) |> Enum.max()

      require_bounded!(name, :microseconds, worst_time, @maximum_microseconds)
      require_bounded!(name, :reductions, worst_reductions, @maximum_reductions)

      require_bounded!(
        name,
        :heap_growth_words,
        worst_heap_growth,
        @maximum_heap_growth_words
      )

      IO.puts(
        "#{name}: worst_us=#{worst_time} worst_reductions=#{worst_reductions} " <>
          "worst_heap_growth_words=#{worst_heap_growth}"
      )
    end)

    IO.puts("verification portable timing/allocation bounds passed")
  end

  defp measure(operation) do
    :erlang.garbage_collect()
    {:reductions, reductions_before} = Process.info(self(), :reductions)
    {:total_heap_size, heap_before} = Process.info(self(), :total_heap_size)

    {microseconds, result} = :timer.tc(operation)

    unless match?({:ok, _value}, result) or result == {:error, :invalid} do
      raise "unexpected performance-case result"
    end

    {:reductions, reductions_after} = Process.info(self(), :reductions)
    {:total_heap_size, heap_after} = Process.info(self(), :total_heap_size)

    %{
      microseconds: microseconds,
      reductions: reductions_after - reductions_before,
      heap_growth_words: max(heap_after - heap_before, 0)
    }
  end

  defp require_bounded!(_name, _measure, actual, maximum) when actual <= maximum, do: :ok

  defp require_bounded!(name, measure, actual, maximum) do
    raise "#{name} #{measure} exceeded #{maximum}: #{actual}"
  end
end

BoundedAuthorityProtocol.VerificationPerformance.run!()
