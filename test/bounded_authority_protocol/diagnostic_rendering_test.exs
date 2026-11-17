defmodule BoundedAuthorityProtocol.DiagnosticRenderingTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.DiagnosticRendering

  test "a container at the budget has no ellipsis, and one over does" do
    exact = List.duplicate(:all, 200)
    body = Enum.join(List.duplicate(":all", 200), ", ")

    assert render(exact) == "[" <> body <> "]"
    assert render(exact ++ [:all]) == "[" <> body <> ", ...]"
    assert render(List.to_tuple(exact)) == "{" <> body <> "}"
    assert render(List.to_tuple(exact ++ [:all])) == "{" <> body <> ", ...}"

    fields = List.duplicate({:integer, 1}, 200)
    body = Enum.join(List.duplicate("integer: 1", 200), ", ")
    assert render(fields) == "[" <> body <> "]"
    assert render(fields ++ [{:integer, 1}]) == "[" <> body <> ", ...]"
  end

  test "nested containers return the remaining budget to their siblings" do
    prefix = List.duplicate(:all, 198)
    body = Enum.join(List.duplicate(":all", 198), ", ")

    assert render([prefix, [:all]]) == "[[" <> body <> "], [...]]"
    assert render([prefix, :all]) == "[[" <> body <> "], :all]"
    assert render([prefix, :all, :all]) == "[[" <> body <> "], :all, ...]"
    assert render([prefix ++ [:all], :all]) == "[[" <> body <> ", :all], ...]"
    assert render([prefix, []]) == "[[" <> body <> "], []]"
    assert render([prefix, {}]) == "[[" <> body <> "], {}]"
  end

  test "binary bytes share the budget while printable strings do not consume it" do
    prefix = List.duplicate(:all, 198)
    body = Enum.join(List.duplicate(":all", 198), ", ")

    assert render([prefix, <<0>>]) == "[[" <> body <> "], <<...>>]"
    assert render([prefix, "visible"]) == "[[" <> body <> ~s(], "visible"])
    assert render([prefix, ""]) == "[[" <> body <> ~s(], ""])
    assert render([prefix, "visible", :all]) == "[[" <> body <> ~s(], "visible", ...])

    bytes = :binary.copy(<<0>>, 200)
    body = Enum.join(List.duplicate("0", 200), ", ")
    assert render(bytes) == "<<" <> body <> ">>"
    assert render(bytes <> <<1>>) == "<<" <> body <> ", ...>>"
    assert render([<<0, 1>>, :all]) == "[<<0, 1>>, :all]"
  end

  test "printable limits count Unicode scalars rather than bytes or escaped characters" do
    for size <- [4095, 4096] do
      for character <- ["x", "é", "😀", "\n"] do
        text = String.duplicate(character, size)
        escaped = if character == "\n", do: String.duplicate("\\n", size), else: text
        assert render(text) == "\"" <> escaped <> "\""
      end
    end

    assert render(String.duplicate("x", 4097)) ==
             "\"" <> String.duplicate("x", 4096) <> "\" <> ..."

    assert render(String.duplicate("é", 4097)) ==
             "\"" <> String.duplicate("é", 4096) <> "\" <> ..."
  end

  test "an interpolation introducer consumes one printable unit for both characters" do
    prefix = String.duplicate("x", 4095)
    assert render(prefix <> <<35, 123>>) == "\"" <> prefix <> "\\\#{" <> "\""
    assert render(prefix <> <<35, 123, 120>>) == "\"" <> prefix <> "\\\#{" <> "\" <> ..."

    prefix = String.duplicate("x", 4094)

    assert render(prefix <> <<35, 123, 120, 125>>) ==
             "\"" <> prefix <> "\\\#{x" <> "\" <> ..."
  end

  test "printability is determined over the first 4096 codepoints" do
    prefix = String.duplicate("x", 4096)
    assert render(prefix <> <<0>>) == "\"" <> prefix <> "\" <> ..."

    assert render(String.duplicate("x", 4095) <> <<0>>) ==
             "<<" <> Enum.join(List.duplicate("120", 200), ", ") <> ", ...>>"
  end

  test "escaping after the printability prefix still quotes controls and invalid bytes" do
    prefix = :binary.copy(<<35, 123>>, 2048)
    escaped = :binary.copy(<<92, 35, 123>>, 2048)

    for {suffix, expected} <- [
          {<<0>>, ~S(\0)},
          {<<1, 6, 14, 26, 28, 31>>, ~S(\x01\x06\x0E\x1A\x1C\x1F)},
          {<<0x85::utf8>>, ~S(\x85)},
          {<<0xFFFE::utf8>>, ~S(\x{FFFE})},
          {<<255>>, ~S(\xFF)}
        ] do
      assert render(prefix <> suffix) == "\"" <> escaped <> expected <> "\""
    end
  end

  test "scalar notation preserves controls, invisible characters, tags, and floats" do
    assert render(<<7, 8, 9, 10, 11, 12, 13, 27, 34, 92, 127>>) ==
             ~S("\a\b\t\n\v\f\r\e\"\\\d")

    for codepoint <-
          [0xA0, 0x34F, 0x61C, 0xFEFF] ++
            Enum.to_list(0x2000..0x200F) ++
            Enum.to_list(0x2028..0x202E) ++
            Enum.to_list(0x205F..0x2064) ++
            Enum.to_list(0x2066..0x2069) ++
            Enum.to_list(0xFFF9..0xFFFC) do
      hex = codepoint |> Integer.to_string(16) |> String.pad_leading(4, "0")
      assert render(<<codepoint::utf8>>) == "\"\\u" <> hex <> "\""
    end

    for bytes <- [<<0>>, <<0xFF>>, <<0xC2, 0x85>>, <<0xEF, 0xBF, 0xBE>>] do
      expected = bytes |> :binary.bin_to_list() |> Enum.join(", ")
      assert render(bytes) == "<<" <> expected <> ">>"
    end

    assert render({nil, true, false, :null, -12, 1.0, -0.0, 1.0e-7, 1.0e20}) ==
             "{nil, true, false, :null, -12, 1.0, -0.0, 1.0e-7, 1.0e20}"

    assert render([{:integer, 1}, {:array, []}, {:object, [{"x", {:boolean, true}}]}]) ==
             ~s([integer: 1, array: [], object: [{"x", {:boolean, true}}]])
  end

  for major <- [
        BoundedAuthorityProtocol.V1,
        BoundedAuthorityProtocol.V2,
        BoundedAuthorityProtocol.V3
      ] do
    @major major

    test "#{inspect(major)} operation fields and selectors share the fixed budget" do
      operation =
        struct!(Module.concat(@major, Operation),
          name: "read",
          selectors: List.duplicate(:all, 198)
        )

      body = Enum.join(List.duplicate(":all", 198), ", ")
      prefix = ("%" <> Atom.to_string(@major)) |> String.replace("Elixir.", "")
      prefix = prefix <> ~s(.Operation{name: "read", selectors: [)
      assert inspect(operation) == prefix <> body <> "]}"
      assert inspect(operation, limit: 0, printable_limit: 0) == prefix <> body <> "]}"

      assert inspect(%{operation | selectors: operation.selectors ++ [:all]}) ==
               prefix <> body <> ", ...]}"

      # The name's nonprintable bytes exhaust the same budget before selectors.
      operation = %{operation | name: :binary.copy(<<0>>, 199), selectors: [:all]}

      assert inspect(operation) ==
               "%" <>
                 String.replace(Atom.to_string(@major), "Elixir.", "") <>
                 ".Operation{name: <<" <>
                 Enum.join(List.duplicate("0", 199), ", ") <> ">>, ...}"
    end
  end

  defp render(value), do: DiagnosticRendering.render(value)
end
