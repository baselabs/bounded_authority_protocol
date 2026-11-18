System.put_env("BAP_LIVEBOOK_NO_MAIN", "1")
Code.require_file("../scripts/check_livebooks.exs", __DIR__)
System.delete_env("BAP_LIVEBOOK_NO_MAIN")

defmodule BoundedAuthorityProtocol.LivebookRunnerTest do
  use ExUnit.Case, async: false
  alias BoundedAuthorityProtocol.LivebookCheck

  test "registry is exact and every cell has a persisted semantic output" do
    for {name, entry} <- LivebookCheck.registry!(File.cwd!()) do
      cells = File.read!("docs/notebooks/#{name}") |> LivebookCheck.parse!(entry["outputs"])
      assert hd(cells).code =~ ~s(== #{LivebookCheck.version!(File.cwd!())})
    end
  end

  test "every cell is formatted plain code with its own persisted output" do
    for {name, entry} <- LivebookCheck.registry!(File.cwd!()),
        cell <- File.read!("docs/notebooks/#{name}") |> LivebookCheck.parse!(entry["outputs"]) do
      location = "docs/notebooks/#{name}:#{cell.line}"
      assert cell.code == IO.iodata_to_binary(Code.format_string!(cell.code)), location

      expressions =
        case Code.string_to_quoted!(cell.code) do
          {:__block__, _, expressions} -> expressions
          expression -> [expression]
        end

      for expression <- expressions do
        refute match?({:=, _, [_, {:__block__, _, _}]}, expression),
               "#{location}: put the calls at the top level"

        refute match?({:=, _, [true, {operator, _, _}]} when operator in [:==, :===], expression),
               "#{location}: match the call result instead of restating its output"
      end

      refute String.trim(cell.expected) == "", "#{location}: persist a nonempty result"
    end
  end

  test "unlisted files and registry entries without files are refused" do
    root = Path.join(System.tmp_dir!(), "bap-registry-#{System.unique_integer([:positive])}")
    directory = Path.join(root, "docs/notebooks")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(root) end)
    registry = Path.join(directory, "registry.json")
    File.write!(registry, ~s({"missing.livemd":{"outputs":2}}))

    assert_raise RuntimeError, ~r/registry differs/, fn -> LivebookCheck.registry!(root) end

    File.write!(Path.join(directory, "present.livemd"), planted("1 + 1", "2"))
    File.write!(registry, "{}")

    assert_raise RuntimeError, ~r/registry differs/, fn -> LivebookCheck.registry!(root) end
  end

  test "missing, wrong, raising and malformed cells fail closed in the runner" do
    source = planted("1 + 1", "2")
    cells = LivebookCheck.parse!(source, 2)
    assert {_, _} = LivebookCheck.evaluate!(tl(cells), "control.livemd")

    assert_raise RuntimeError, ~r/mismatch/, fn ->
      planted("1 + 1", "3")
      |> LivebookCheck.parse!(2)
      |> tl()
      |> LivebookCheck.evaluate!("wrong.livemd")
    end

    assert_raise RuntimeError, "boom", fn ->
      planted("raise \"boom\"", ":never")
      |> LivebookCheck.parse!(2)
      |> tl()
      |> LivebookCheck.evaluate!("raises.livemd")
    end

    assert_raise MatchError, fn ->
      planted(~s{true = String.starts_with?("abc", "x")}, "true")
      |> LivebookCheck.parse!(2)
      |> tl()
      |> LivebookCheck.evaluate!("pattern.livemd")
    end

    assert_raise RuntimeError, ~r/missing persisted output/, fn ->
      source
      |> String.replace("<!-- livebook:{\"output\":true} -->", "")
      |> LivebookCheck.parse!(2)
    end

    assert_raise RuntimeError, ~r/expected/, fn -> LivebookCheck.parse!("# Empty", 1) end
    assert_raise RuntimeError, ~r/unclosed/, fn -> LivebookCheck.parse!("```elixir\n1", 1) end

    assert_raise RuntimeError, ~r/setup cell must be first/, fn ->
      source |> String.replace("Mix.install([])", ":ok") |> LivebookCheck.parse!(2)
    end

    entry = LivebookCheck.registry!(File.cwd!())["bap-walkthrough.livemd"]

    cells =
      "docs/notebooks/bap-walkthrough.livemd"
      |> File.read!()
      |> LivebookCheck.parse!(entry["outputs"])
      |> tl()

    [first | rest] = cells

    assert_raise RuntimeError, ~r/persisted output mismatch/, fn ->
      LivebookCheck.evaluate!([%{first | expected: ":planted_wrong_value"} | rest], "real.livemd")
    end
  end

  test "proof-lifetime retention cannot satisfy the fresh-proof replay demonstration" do
    path = "docs/notebooks/service-integration.livemd"
    source = File.read!(path)

    mutated =
      String.replace(
        source,
        "until = facts.expires_at + expected.clock_skew",
        "until = facts.proof_issued_at + expected.proof_max_age + expected.clock_skew"
      )

    assert mutated != source
    entry = LivebookCheck.registry!(File.cwd!())["service-integration.livemd"]

    assert {_, _} =
             source
             |> LivebookCheck.parse!(entry["outputs"])
             |> tl()
             |> LivebookCheck.evaluate!(path)

    assert_raise MatchError, fn ->
      mutated |> LivebookCheck.parse!(entry["outputs"]) |> tl() |> LivebookCheck.evaluate!(path)
    end
  end

  test "the advanced journey uses certified forgery bytes" do
    path = "docs/notebooks/strict-crypto.livemd"
    entry = LivebookCheck.registry!(File.cwd!())["strict-crypto.livemd"]

    {binding, _} =
      File.read!(path)
      |> LivebookCheck.parse!(entry["outputs"])
      |> tl()
      |> LivebookCheck.evaluate!(path)

    cases = primitive_cases("key-only-forgeries.json")
    identity = cases["key-only-v1-identity-a-basepoint-r-s1-0"]
    noncanonical = cases["key-only-v1-y-p-plus-1-prime-r-0"]
    assert binding[:key_only_forgery] == identity.signature
    assert binding[:small_order_key] == identity.public_key
    assert binding[:noncanonical_key] == noncanonical.public_key
    assert noncanonical.signature == identity.signature
    verify = primitive_cases("verify-strict.json")
    <<r::binary-size(32), honest::little-size(256)>> = verify["honest"].signature
    <<^r::binary-size(32), shifted::little-size(256)>> = verify["s-plus-l"].signature
    assert binding[:l] == shifted - honest
  end

  defp planted(code, output) do
    """
    # Planted control

    ```elixir
    Mix.install([])
    ```

    <!-- livebook:{"output":true} -->

    ```
    :ok
    ```

    ```elixir
    #{code}
    ```

    <!-- livebook:{"output":true} -->

    ```
    #{output}
    ```
    """
  end

  defp primitive_cases(file) do
    Path.join("priv/conformance/strict-ed25519/cases/primitive", file)
    |> File.read!()
    |> :json.decode()
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
