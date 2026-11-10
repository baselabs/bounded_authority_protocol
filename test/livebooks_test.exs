Code.require_file("../test_support/livebook_harness.ex", __DIR__)

defmodule BoundedAuthorityProtocol.LivebooksTest do
  @moduledoc """
  Runs every notebook under docs/livebooks against this checkout with the shared harness
  (test_support/livebook_harness.ex), which checks each code cell against the value its prose
  states. The package gate (`mix package.check`, part of `mix quality`) runs the same harness
  against the notebooks inside the unpacked release archive.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.TestSupport.LivebookHarness

  @directory Path.expand("../docs/livebooks", __DIR__)
  @notebooks @directory |> Path.join("*.livemd") |> Path.wildcard() |> Enum.sort()
  @strict_ed25519 Path.expand("../priv/conformance/strict-ed25519/cases/primitive", __DIR__)

  test "the notebook set is the three published notebooks" do
    assert Enum.map(@notebooks, &Path.basename/1) == [
             "bap-walkthrough.livemd",
             "chains-and-archives.livemd",
             "service-integration.livemd"
           ]
  end

  for path <- @notebooks do
    @path path
    test "#{Path.basename(path)} runs top to bottom with every stated value" do
      assert LivebookHarness.check_file(@path) == []
    end
  end

  # The docs-currency test pins the walkthrough's requirement to the release; every other
  # notebook must carry the identical setup cell, so the release edit changes them together.
  test "every notebook installs the package from Hex with the walkthrough's requirement" do
    setup =
      ~r/```elixir\nMix\.install\(\[\n  \{:bounded_authority_protocol, "~> [0-9.]+"\}\n\]\)\n```/

    [walkthrough_setup] = Regex.run(setup, File.read!(walkthrough()))

    for path <- @notebooks do
      assert Regex.run(setup, File.read!(path)) == [walkthrough_setup],
             "#{path} must open with the walkthrough's Mix.install setup cell"
    end
  end

  test "the walkthrough's inline forgery bytes are the certified strict-Ed25519 corpus values" do
    assert {:ok, binding} =
             LivebookHarness.run(File.read!(walkthrough()), walkthrough())

    forgeries = primitive_cases("key-only-forgeries.json")
    identity_case = Map.fetch!(forgeries, "key-only-v1-identity-a-basepoint-r-s1-0")
    noncanonical_case = Map.fetch!(forgeries, "key-only-v1-y-p-plus-1-prime-r-0")
    assert binding[:key_only_forgery] == identity_case.signature
    assert binding[:small_order_key] == identity_case.public_key
    assert binding[:noncanonical_key] == noncanonical_case.public_key
    assert noncanonical_case.signature == identity_case.signature

    # The notebook's L is the difference between the corpus's honest and S + L signatures.
    verify_cases = primitive_cases("verify-strict.json")
    <<r::binary-size(32), honest_s::little-size(256)>> = verify_cases["honest"].signature
    <<^r::binary-size(32), shifted_s::little-size(256)>> = verify_cases["s-plus-l"].signature
    assert binding[:l] == shifted_s - honest_s
  end

  describe "the harness is red-capable" do
    test "a wrong stated value is reported with the cell and the value" do
      source = notebook("1 + 1", "The cell returns `3`.")
      assert [error] = LivebookHarness.check(source, "planted.livemd")
      assert error =~ "planted.livemd: cell at line"
      assert error =~ "states it returns `3`, got 2"
    end

    test "a pattern that does not match is reported" do
      source = notebook(~s("abc"), ~s(The cell's value matches `"x" <> _`.))
      assert [error] = LivebookHarness.check(source, "planted.livemd")
      assert error =~ "its value matches"
    end

    test "a cell without a stated value is reported" do
      source =
        notebook("1 + 1", "The cell returns `2`.") <>
          "\n```elixir\n2 + 2\n```\n\nNo statement here.\n"

      assert [error] = LivebookHarness.check(source, "planted.livemd")
      assert error =~ "states no expected value"
    end

    test "a notebook with no expectations at all fails" do
      source = notebook("1 + 1", "Nothing is stated.")
      errors = LivebookHarness.check(source, "planted.livemd")
      assert "planted.livemd: states no expected values" in errors
    end

    test "a notebook without the setup cell first fails" do
      source = "# Title\n\n## 1. One\n\n```elixir\n1\n```\n\nThe cell returns `1`.\n"
      assert [error] = LivebookHarness.check(source, "planted.livemd")
      assert error =~ "exactly one Mix.install setup cell"
    end

    test "a raising cell stops the notebook and is reported" do
      source = notebook("raise \"boom\"", "The cell returns `:never`.")
      assert [error] = LivebookHarness.check(source, "planted.livemd")
      assert error =~ "raised"
      assert error =~ "boom"
    end

    test "an expectation block needs its introduction, and is checked when it has one" do
      block = ~s(<!-- livebook:{"force_markdown":true} -->\n\n```elixir\n%{a: 1}\n```\n)

      assert [error] =
               LivebookHarness.check(notebook("%{a: 1}", "Some text.\n\n" <> block), "p.livemd")

      assert error =~ "follows no"

      assert LivebookHarness.check(notebook("%{a: 1}", "The cell returns:\n\n" <> block), "p") ==
               []

      assert [error] =
               LivebookHarness.check(notebook("%{a: 2}", "The cell returns:\n\n" <> block), "p")

      assert error =~ "got %{a: 2}"
    end

    test "a planted wrong value in a published notebook is caught" do
      source =
        walkthrough()
        |> File.read!()
        |> String.replace("The cell returns `{32, 32}`", "The cell returns `{32, 31}`")

      assert [error] = LivebookHarness.check(source, walkthrough())
      assert error =~ "{32, 31}"
    end
  end

  defp walkthrough, do: Path.join(@directory, "bap-walkthrough.livemd")

  defp notebook(code, prose) do
    """
    # Planted

    ```elixir
    Mix.install([{:bounded_authority_protocol, "~> 0.0.0"}])
    ```

    ## 1. Cell

    ```elixir
    #{code}
    ```

    #{prose}
    """
  end

  defp primitive_cases(file) do
    [@strict_ed25519, file]
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
end
