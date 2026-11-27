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

  test "multi-megabyte invalid binaries use only the capped byte prefix" do
    value = <<255>> <> :binary.copy(<<0>>, 4 * 1024 * 1024)
    expected = "<<255, " <> Enum.join(List.duplicate("0", 199), ", ") <> ", ...>>"
    assert render(value) == expected
    assert render(binary_part(value, 0, 201)) == expected
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

  test "float notation follows shortest round-trip digits and the notation boundary" do
    for {value, expected} <- [
          {1000.0, "1.0e3"},
          {0.00012, "1.2e-4"},
          {1_234_567.5, "1234567.5"},
          {100.0, "100.0"},
          {0.1, "0.1"},
          {9_007_199_254_740_992.0, "9.007199254740992e15"},
          {9_007_199_254_740_991.0, "9007199254740991.0"},
          {1.0e16, "1.0e16"},
          {1.0e22, "1.0e22"},
          {5.0e-324, "5.0e-324"},
          {1.797_693_134_862_315_7e308, "1.7976931348623157e308"},
          {-1.5e-7, "-1.5e-7"},
          {123_456.0, "123456.0"},
          {0.0, "0.0"},
          {-0.0, "-0.0"},
          {0.0001, "0.0001"},
          {1.0, "1.0"},
          {-1000.0, "-1.0e3"}
        ] do
      assert render(value) == expected
    end
  end

  test "values outside the grammar render as one value-free scalar" do
    values = [
      %{"x" => 1},
      %URI{path: "hidden"},
      self(),
      make_ref(),
      :erlang.list_to_port(~c"#Port<0.0>"),
      fn -> :hidden end,
      <<1::size(1)>>,
      [1 | :tail],
      [1, 2 | <<0>>],
      :"",
      :"has space",
      :"x\ny",
      :Uppercase,
      :é,
      :"a-b",
      :"a?b",
      :"a!!"
    ]

    for value <- values do
      assert render(value) == "#unrenderable"
      assert render({value, :all}) == "{#unrenderable, :all}"
    end

    assert render(:_) == ":_"
    assert render(:aB_9) == ":aB_9"
    assert render(:ready?) == ":ready?"
    assert render(:run!) == ":run!"

    assert render([{:valid, 1}, {:"not valid", 2}]) ==
             "[{:valid, 1}, {#unrenderable, 2}]"

    assert render([{:"a?b", :Uppercase}]) == "[{#unrenderable, #unrenderable}]"
    assert render([List.duplicate(:all, 198), %{}]) =~ "], #unrenderable]"
    assert render(List.duplicate(:all, 200) ++ [:tail] ++ [1 | :tail]) == "#unrenderable"
  end

  test "every structural field accepts an off-domain value without Inspect fallback" do
    modules =
      for major <- [
            BoundedAuthorityProtocol.V1,
            BoundedAuthorityProtocol.V2,
            BoundedAuthorityProtocol.V3
          ],
          kind <- [DecodedGrant, Operation, DecodedProof],
          do: Module.concat(major, kind)

    for module <- [
          BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation,
          BoundedAuthorityProtocol.HolderCustodyAttestation.V1.DecodedAttestation
          | modules
        ] do
      value = struct(module)

      for field <- Map.keys(Map.from_struct(value)), field != :nonce do
        changed = Map.put(value, field, %{"hidden" => 1})

        changed =
          if Map.has_key?(changed, :nonce), do: Map.put(changed, :nonce, "hidden"), else: changed

        output = inspect(changed)
        assert output =~ "#{field}: #unrenderable"
        refute output =~ "hidden"
        refute output =~ "Inspect.Error"
      end
    end
  end

  test "recognized structures with missing fields are unrenderable" do
    for module <- [
          BoundedAuthorityProtocol.V1.DecodedGrant,
          BoundedAuthorityProtocol.V2.Operation,
          BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation,
          BoundedAuthorityProtocol.HolderCustodyAttestation.V1.DecodedAttestation,
          BoundedAuthorityProtocol.V3.DecodedProof
        ] do
      assert render(%{__struct__: module}) == "#unrenderable"

      key =
        if module == BoundedAuthorityProtocol.V2.Operation, do: :selectors, else: :verification

      malformed = module |> struct() |> Map.delete(key)
      assert render(malformed) == "#unrenderable"
    end
  end

  for major <- [
        BoundedAuthorityProtocol.V1,
        BoundedAuthorityProtocol.V2,
        BoundedAuthorityProtocol.V3
      ] do
    @major major

    test "#{inspect(major)} malformed proof fields never expose a nonce" do
      proof = struct(Module.concat(@major, DecodedProof), nonce: "nonce-must-stay-hidden")

      for nonce <- ["nonce-must-stay-hidden", %{"nonce-must-stay-hidden" => 1}, fn -> :secret end] do
        rendered = inspect(%{proof | holder_public_key: %{"x" => 1}, nonce: nonce})
        assert rendered =~ "holder_public_key: #unrenderable"
        assert rendered =~ "nonce: :redacted"
        refute rendered =~ "nonce-must-stay-hidden"
        refute rendered =~ "Inspect.Error"
      end

      assert inspect(%{proof | nonce: nil}) =~ "nonce: nil"

      assert inspect(%{proof | holder_public_key: [1 | :tail]}) =~
               "holder_public_key: #unrenderable"
    end

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
