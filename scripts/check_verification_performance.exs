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

  # Over-limit request arguments are rejected while the projection walks them, so the cost is a
  # budget's worth of nodes however large the host tree: about 2,100 reductions at most on every
  # major (measured 2026-11-09). An unbudgeted walk of the two-million-item tree costs millions.
  @over_limit_maximum_reductions 50_000

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

    over_limit_arguments = [
      {"wide", {:array, List.duplicate({:integer, 1}, 2_000_000)}},
      {"deep", Enum.reduce(1..200_000, {:integer, 1}, fn _level, inner -> {:array, [inner]} end)},
      {"members", {:object, Enum.map(1..1_000_000, &{"k#{&1}", :null})}}
    ]

    for facade <- [V1, BoundedAuthorityProtocol.V2, BoundedAuthorityProtocol.V3],
        {shape, value} <- over_limit_arguments do
      name = "#{inspect(facade)}.request_digest over-limit #{shape}"
      operation = fn -> facade.request_digest("op", value, bounds) end
      {:error, :invalid} = operation.()
      samples = Enum.map(1..@samples, fn _sample -> measure(operation) end)
      worst_reductions = samples |> Enum.map(& &1.reductions) |> Enum.max()
      require_bounded!(name, :reductions, worst_reductions, @over_limit_maximum_reductions)
      IO.puts("#{name}: worst_reductions=#{worst_reductions}")
    end

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
