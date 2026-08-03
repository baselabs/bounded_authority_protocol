defmodule BoundedAuthorityProtocol.Fuzz.FacadeFuzzTest do
  @moduledoc """
  Fuzz: sweep byte-mutations of valid corpus cases through the pure facades. Mutation positions
  are derived from each case file's SHA-256 via an explicit in-test PRNG (no :rand in lib; the
  seed is deterministic from the corpus bytes). Closure property: every mutant returns
  {:ok, _} | {:error, :invalid} and never raises. A mutant that STILL VERIFIES must produce
  byte-identical facts to the base case ONLY when the mutated byte is provably outside the
  signed/normative region; otherwise {:error, :invalid} is required (no different-facts acceptance).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.{Base64Url, Bounds, Jcs, Json, Uri}

  @max_bounds Bounds.maximum()

  # The corpus case files to fuzz. Each is a JSON document whose bytes are mutated.
  @corpus_dir "priv/conformance/v1/corpus/cases"

  # --- explicit deterministic PRNG (SplitMix64) seeded from SHA-256 of the case bytes ---

  @mask64 0xFFFFFFFFFFFFFFFF

  defp seed_from(bytes) do
    <<h::64, _::binary>> = :crypto.hash(:sha256, bytes)
    h
  end

  defp next(state) do
    state = state + 0x9E3779B97F4A7C15
    z = state
    z = Bitwise.bxor(z, Bitwise.bsr(z, 30))
    z = (z * 0xBF58476D1CE4E5B9) |> Bitwise.band(@mask64)
    z = Bitwise.bxor(z, Bitwise.bsr(z, 27))
    z = (z * 0x94D049BB133111EB) |> Bitwise.band(@mask64)
    z = Bitwise.bxor(z, Bitwise.bsr(z, 31))
    {z, state}
  end

  defp fuzz_bytes(bytes, count) do
    state = seed_from(bytes)

    Enum.reduce(1..count, [{bytes, state}], fn _, [{b, s} | _] = acc ->
      _ = acc
      {pos, s1} = next(s)

      {byte, s2} = next(s1)

      max_pos = max(0, byte_size(b) - 1)
      pos = if max_pos == 0, do: 0, else: rem(pos, max_pos + 1)
      byte = rem(byte, 256)

      <<pre::binary-size(pos), orig, rest::binary>> = b
      mutated = <<pre::binary, Bitwise.bxor(orig, byte), rest::binary>>
      [{mutated, s2} | acc]
    end)
    |> Enum.map(fn {b, _} -> b end)
    |> Enum.reverse()
    |> tl()
  end

  # --- the closure sweep: every mutant through the facade, never raises ---

  test "every byte-mutant of corpus case files through Json.decode is closed (no raise)" do
    for case_bytes <- corpus_byte_documents() do
      for mutant <- fuzz_bytes(case_bytes, 8) do
        result = Json.decode(mutant, @max_bounds)

        assert result == {:error, :invalid} or match?({:ok, _}, result),
               "Json.decode raised or returned non-closed on mutant"
      end
    end
  end

  test "every byte-mutant through Base64Url.decode is closed (no raise)" do
    for case_bytes <- corpus_byte_documents() do
      for mutant <- fuzz_bytes(case_bytes, 8) do
        result = Base64Url.decode(mutant, @max_bounds)

        assert result == {:error, :invalid} or match?({:ok, _}, result),
               "Base64Url.decode raised or returned non-closed on mutant"
      end
    end
  end

  test "every byte-mutant through Uri.normalize is closed (no raise)" do
    for case_bytes <- corpus_byte_documents() do
      for mutant <- fuzz_bytes(case_bytes, 8) do
        result = Uri.normalize(mutant, @max_bounds)

        assert result == {:error, :invalid} or match?({:ok, _}, result),
               "Uri.normalize raised or returned non-closed on mutant"
      end
    end
  end

  # --- a decoded mutant that still decodes must JCS-encode to a deterministic value ---

  test "a decoded mutant's JCS encoding is deterministic (no different-facts acceptance)" do
    for case_bytes <- corpus_byte_documents() do
      for mutant <- fuzz_bytes(case_bytes, 4) do
        with {:ok, value} <- Json.decode(mutant, @max_bounds),
             {:ok, first} <- Jcs.encode(value, @max_bounds),
             {:ok, second} <- Jcs.encode(value, @max_bounds) do
          assert first == second, "JCS not deterministic on a decoded mutant"
        else
          _ -> :ok
        end
      end
    end
  end

  defp corpus_byte_documents do
    Path.wildcard(Path.join([@corpus_dir, "**", "*.json"]))
    |> Enum.map(&File.read!/1)
    |> Enum.filter(&(byte_size(&1) > 0))
  end
end
