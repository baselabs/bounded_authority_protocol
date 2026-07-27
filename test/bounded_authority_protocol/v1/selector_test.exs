defmodule BoundedAuthorityProtocol.V1.SelectorTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Selector

  test "all accepts every tagged JSON root" do
    for value <- [
          :null,
          {:boolean, false},
          {:integer, 1},
          {:float, 1.0},
          {:string, "value"},
          {:array, []},
          {:object, []}
        ] do
      assert :ok = match([:all], value)
    end
  end

  test "equals compares nested objects semantically without making member order significant" do
    actual =
      {:object,
       [
         {"scope",
          {:object,
           [
             {"b", {:array, [{:integer, 1}, {:integer, 2}]}},
             {"a", {:boolean, true}}
           ]}}
       ]}

    expected =
      {:object,
       [
         {"a", {:boolean, true}},
         {"b", {:array, [{:integer, 1}, {:integer, 2}]}}
       ]}

    selector = {:equals, ["scope"], expected}
    assert :ok = match([selector], actual)
  end

  test "array order and tagged scalar identity remain exact" do
    arguments =
      {:object,
       [
         {"items", {:array, [{:integer, 1}, {:integer, 2}]}},
         {"value", {:integer, 1}}
       ]}

    assert {:error, :invalid} =
             match(
               [
                 {:equals, ["items"], {:array, [{:integer, 2}, {:integer, 1}]}}
               ],
               arguments
             )

    assert {:error, :invalid} =
             match([{:equals, ["value"], {:float, 1.0}}], arguments)
  end

  test "one-of uses semantic equality and all selectors are conjunctive" do
    arguments =
      {:object,
       [
         {"region", {:string, "us"}},
         {"account", {:object, [{"id", {:integer, 7}}]}}
       ]}

    selectors = [
      {:equals, ["region"], {:string, "us"}},
      {:one_of, ["account", "id"], [{:integer, 6}, {:integer, 7}]}
    ]

    assert :ok = match(selectors, arguments)

    assert {:error, :invalid} =
             match(
               selectors ++ [{:equals, ["region"], {:string, "eu"}}],
               arguments
             )
  end

  test "missing members, array traversal, and non-object roots fail closed" do
    arguments =
      {:object,
       [
         {"array", {:array, [{:object, [{"id", {:integer, 1}}]}]}},
         {"scalar", {:integer, 1}}
       ]}

    for selector <- [
          {:equals, ["missing"], :null},
          {:equals, ["array", "0"], {:integer, 1}},
          {:equals, ["scalar", "id"], {:integer, 1}}
        ] do
      assert {:error, :invalid} = match([selector], arguments)
    end

    assert {:error, :invalid} =
             match([{:equals, ["id"], {:integer, 1}}], {:integer, 1})
  end

  test "path, path-member, and one-of maxima pass exactly and reject maximum plus one" do
    path = Enum.map(1..32, &"m#{&1}")
    arguments = nested(path, {:integer, 7})

    assert :ok = match([{:equals, path, {:integer, 7}}], arguments)

    assert {:error, :invalid} =
             match(
               [{:equals, path ++ ["overflow"], {:integer, 7}}],
               arguments
             )

    member = String.duplicate("a", 128)

    assert :ok =
             match(
               [{:equals, [member], {:integer, 7}}],
               {:object, [{member, {:integer, 7}}]}
             )

    over_member = member <> "a"

    assert {:error, :invalid} =
             match(
               [{:equals, [over_member], {:integer, 7}}],
               {:object, [{over_member, {:integer, 7}}]}
             )

    values = Enum.map(1..256, &{:integer, &1})
    assert :ok = match([{:one_of, ["id"], values}], {:object, [{"id", {:integer, 256}}]})

    assert {:error, :invalid} =
             match(
               [{:one_of, ["id"], values ++ [{:integer, 257}]}],
               {:object, [{"id", {:integer, 256}}]}
             )
  end

  test "malformed selector terms return the fixed error" do
    for selectors <- [
          [],
          [:unknown],
          [{:equals, [], :null}],
          [{:equals, ["id"]}],
          [{:one_of, ["id"], []}],
          [%{"kind" => "all"}]
        ] do
      assert {:error, :invalid} = match(selectors, {:object, []})
    end
  end

  defp match(selectors, arguments),
    do: apply(Selector, :match_all, [selectors, arguments, %{}])

  defp nested(path, leaf) do
    Enum.reduce(Enum.reverse(path), leaf, fn member, child ->
      {:object, [{member, child}]}
    end)
  end
end
