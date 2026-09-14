defmodule BoundedAuthorityProtocol.V2.SelectorTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V2.Selector

  test "lte accepts same-tag values at and below the inclusive bound" do
    arguments = {:object, [{"id", {:integer, 50}}, {"amount", {:float, 5.5}}]}

    assert :ok = match([{:lte, ["id"], {:integer, 50}}], arguments)
    assert :ok = match([{:lte, ["id"], {:integer, 100}}], arguments)
    assert :ok = match([{:lte, ["amount"], {:float, 5.5}}], arguments)
    assert :ok = match([{:lte, ["amount"], {:float, 5.6}}], arguments)
  end

  test "gte accepts same-tag values at and above the inclusive bound" do
    arguments = {:object, [{"id", {:integer, 50}}, {"amount", {:float, 5.5}}]}

    assert :ok = match([{:gte, ["id"], {:integer, 50}}], arguments)
    assert :ok = match([{:gte, ["id"], {:integer, 1}}], arguments)
    assert :ok = match([{:gte, ["amount"], {:float, 5.5}}], arguments)
    assert :ok = match([{:gte, ["amount"], {:float, 5.4}}], arguments)
  end

  test "lte and gte reject values beyond the bound" do
    arguments = {:object, [{"id", {:integer, 50}}, {"amount", {:float, 5.5}}]}

    assert {:error, :invalid} = match([{:lte, ["id"], {:integer, 49}}], arguments)
    assert {:error, :invalid} = match([{:gte, ["id"], {:integer, 51}}], arguments)
    assert {:error, :invalid} = match([{:lte, ["amount"], {:float, 5.4}}], arguments)
    assert {:error, :invalid} = match([{:gte, ["amount"], {:float, 5.6}}], arguments)
  end

  test "cross-tag operands never match in either direction" do
    # ADR 0028 §2: extends REQ1-SELECTOR-no-tag-collapse from identity to ordering.
    arguments = {:object, [{"id", {:integer, 50}}, {"amount", {:float, 50.0}}]}

    for selector <- [
          {:lte, ["id"], {:float, 50.0}},
          {:gte, ["id"], {:float, 50.0}},
          {:lte, ["amount"], {:integer, 50}},
          {:gte, ["amount"], {:integer, 50}}
        ] do
      assert {:error, :invalid} = match([selector], arguments)
    end
  end

  test "non-numeric operands at the path fail closed for range kinds" do
    arguments =
      {:object,
       [
         {"text", {:string, "50"}},
         {"flag", {:boolean, true}},
         {"nothing", :null},
         {"items", {:array, [{:integer, 1}]}},
         {"nested", {:object, [{"id", {:integer, 1}}]}}
       ]}

    for selector <- [
          {:lte, ["text"], {:integer, 100}},
          {:gte, ["text"], {:integer, 1}},
          {:lte, ["flag"], {:integer, 100}},
          {:lte, ["nothing"], {:integer, 100}},
          {:lte, ["items"], {:integer, 100}},
          {:lte, ["nested"], {:integer, 100}}
        ] do
      assert {:error, :invalid} = match([selector], arguments)
    end
  end

  test "a non-numeric bound term fails closed without consulting the arguments" do
    arguments = {:object, [{"id", {:integer, 50}}]}

    for selector <- [
          {:lte, ["id"], {:string, "100"}},
          {:gte, ["id"], {:string, "1"}},
          {:lte, ["id"], :null},
          {:gte, ["id"], {:array, []}},
          {:lte, ["id"], {:object, []}},
          {:lte, ["id"], {:boolean, true}}
        ] do
      assert {:error, :invalid} = match([selector], arguments)
    end
  end

  test "missing path members fail closed exactly as for equals and one_of" do
    arguments = {:object, [{"id", {:integer, 50}}]}

    for selector <- [
          {:lte, ["missing"], {:integer, 100}},
          {:gte, ["missing"], {:integer, 1}},
          {:lte, ["id", "deeper"], {:integer, 100}}
        ] do
      assert {:error, :invalid} = match([selector], arguments)
    end
  end

  test "signed zero compares by numeric value in both directions" do
    # ADR 0028 §2: under IEEE 754 numeric comparison −0.0 = 0.0; signed zero
    # distinguishes no authority in either the comparison or JCS serialization.
    arguments = {:object, [{"minus", {:float, -0.0}}, {"plus", {:float, 0.0}}]}

    assert :ok = match([{:gte, ["minus"], {:float, 0.0}}], arguments)
    assert :ok = match([{:lte, ["minus"], {:float, 0.0}}], arguments)
    assert :ok = match([{:gte, ["plus"], {:float, -0.0}}], arguments)
    assert :ok = match([{:lte, ["plus"], {:float, -0.0}}], arguments)
  end

  test "extreme magnitudes compare exactly at the closed numeric domain edges" do
    # The operand domain is the closed numeric domain the bounded decoder admits:
    # integers and floats within ±9007199254740991 (REQ1-JSON-number-bounds;
    # `Bounds.float_magnitude` pins the float ceiling at the same magnitude).
    max_integer = 9_007_199_254_740_991
    max_float = 9_007_199_254_740_991.0

    arguments =
      {:object,
       [
         {"big", {:integer, max_integer}},
         {"small", {:integer, -max_integer}},
         {"wide", {:float, max_float}},
         {"tiny", {:float, -max_float}}
       ]}

    assert :ok = match([{:lte, ["big"], {:integer, max_integer}}], arguments)
    assert :ok = match([{:gte, ["big"], {:integer, max_integer}}], arguments)
    assert :ok = match([{:lte, ["small"], {:integer, -max_integer}}], arguments)
    assert {:error, :invalid} = match([{:lte, ["big"], {:integer, max_integer - 1}}], arguments)
    assert :ok = match([{:lte, ["wide"], {:float, max_float}}], arguments)
    assert :ok = match([{:gte, ["wide"], {:float, max_float}}], arguments)
    assert :ok = match([{:lte, ["tiny"], {:float, -max_float}}], arguments)
    assert {:error, :invalid} = match([{:lte, ["wide"], {:float, 9.0e15}}], arguments)
  end

  test "an interval is the conjunctive composition of two one-sided selectors" do
    arguments = {:object, [{"amount", {:integer, 75}}]}
    interval = [{:gte, ["amount"], {:integer, 50}}, {:lte, ["amount"], {:integer, 100}}]

    assert :ok = match(interval, arguments)
    assert :ok = match(interval, {:object, [{"amount", {:integer, 50}}]})
    assert :ok = match(interval, {:object, [{"amount", {:integer, 100}}]})

    for value <- [49, 101] do
      assert {:error, :invalid} = match(interval, {:object, [{"amount", {:integer, value}}]})
    end
  end

  test "crossed interval endpoints are unsatisfiable, never a special error" do
    # ADR 0028 §7: lo > hi is not a decode error — the conjunction simply never matches.
    arguments = {:object, [{"amount", {:integer, 75}}]}

    assert {:error, :invalid} =
             match(
               [{:gte, ["amount"], {:integer, 100}}, {:lte, ["amount"], {:integer, 50}}],
               arguments
             )
  end

  test "range kinds compose conjunctively with the v1 kinds" do
    arguments =
      {:object,
       [
         {"region", {:string, "us"}},
         {"amount", {:integer, 75}}
       ]}

    selectors = [
      {:equals, ["region"], {:string, "us"}},
      {:gte, ["amount"], {:integer, 50}},
      {:lte, ["amount"], {:integer, 100}}
    ]

    assert :ok = match(selectors, arguments)

    assert {:error, :invalid} =
             match(selectors ++ [{:equals, ["region"], {:string, "eu"}}], arguments)
  end

  test "float intervals bind on the float tag alone" do
    arguments = {:object, [{"amount", {:float, 7.5}}]}
    interval = [{:gte, ["amount"], {:float, 5.0}}, {:lte, ["amount"], {:float, 10.0}}]

    assert :ok = match(interval, arguments)
    assert {:error, :invalid} = match(interval, {:object, [{"amount", {:float, 10.5}}]})
  end

  test "path and selector maxima bind range kinds exactly as the v1 kinds" do
    path = Enum.map(1..32, &"m#{&1}")
    arguments = nested(path, {:integer, 7})

    assert :ok = match([{:lte, path, {:integer, 7}}], arguments)
    assert :ok = match([{:gte, path, {:integer, 7}}], arguments)

    assert {:error, :invalid} = match([{:lte, path ++ ["overflow"], {:integer, 7}}], arguments)

    member = String.duplicate("a", 128)

    assert :ok =
             match(
               [{:lte, [member], {:integer, 7}}],
               {:object, [{member, {:integer, 7}}]}
             )

    over_member = member <> "a"

    assert {:error, :invalid} =
             match(
               [{:gte, [over_member], {:integer, 7}}],
               {:object, [{over_member, {:integer, 7}}]}
             )

    selectors = Enum.map(1..64, &{:lte, ["id"], {:integer, &1}})
    assert :ok = match(selectors, {:object, [{"id", {:integer, 1}}]})

    assert {:error, :invalid} =
             match(
               selectors ++ [{:lte, ["id"], {:integer, 65}}],
               {:object, [{"id", {:integer, 1}}]}
             )
  end

  test "malformed range selector terms return the fixed error" do
    assert {:error, :invalid} = Selector.match_all(:not_a_list, :null, %{})

    for selectors <- [
          [],
          [:unknown],
          [{:lt, ["id"], {:integer, 5}}],
          [{:gt, ["id"], {:integer, 5}}],
          [{:lte, [], {:integer, 5}}],
          [{:gte, [], {:integer, 5}}],
          [{:lte, :not_a_path, {:integer, 5}}],
          [{:lte, ["id"]}],
          [{:gte, ["id"]}],
          [%{"kind" => "lte"}]
        ] do
      assert {:error, :invalid} = match(selectors, {:object, []})
    end
  end

  test "the inherited v1 kinds match through the v2 selector module" do
    arguments =
      {:object,
       [
         {"region", {:string, "us"}},
         {"tier", {:string, "gold"}},
         {"count", {:integer, 3}}
       ]}

    assert :ok = match([:all], arguments)
    assert :ok = match([{:equals, ["tier"], {:string, "gold"}}], arguments)
    assert :ok = match([{:one_of, ["count"], [{:integer, 3}, {:integer, 4}]}], arguments)

    assert {:error, :invalid} = match([{:one_of, ["count"], [{:integer, 4}]}], arguments)

    assert {:error, :invalid} =
             match([{:equals, ["tier"], {:string, "silver"}}], arguments)
  end

  test "equals and one_of missing-path arms fail closed through the v2 module" do
    arguments = {:object, [{"id", {:integer, 50}}]}

    assert {:error, :invalid} = match([{:equals, ["missing"], {:integer, 50}}], arguments)
    assert {:error, :invalid} = match([{:one_of, ["missing"], [{:integer, 50}]}], arguments)
  end

  test "semantic equality is inherited unchanged from the shared algebra" do
    assert Selector.semantic_equal?(:null, :null)
    assert Selector.semantic_equal?({:integer, 1}, {:integer, 1})
    assert Selector.semantic_equal?({:float, 1.0}, {:float, 1.0})
    refute Selector.semantic_equal?({:integer, 1}, {:float, 1.0})
  end

  defp match(selectors, arguments),
    do: Selector.match_all(selectors, arguments, %{})

  defp nested(path, leaf) do
    Enum.reduce(Enum.reverse(path), leaf, fn member, child ->
      {:object, [{member, child}]}
    end)
  end
end
