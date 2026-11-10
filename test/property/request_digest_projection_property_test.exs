defmodule BoundedAuthorityProtocol.Property.RequestDigestProjectionPropertyTest do
  @moduledoc """
  The request-digest projection enforces its budgets while it walks the host's argument tree.
  These properties compare it with the unbudgeted projection (the full tree projected first, then
  checked by `Jcs.encode/2`): the same inputs are accepted and the digest bytes are identical,
  under the maxima and under tightened depth, node, container and string bounds, on every
  contract-major. A separate test shows an over-limit tree is rejected without walking it.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs

  @facades [
    {BoundedAuthorityProtocol.V1, "BAP1-REQUEST"},
    {BoundedAuthorityProtocol.V2, "BAP2-REQUEST"},
    {BoundedAuthorityProtocol.V3, "BAP3-REQUEST"}
  ]

  defp scalar_gen do
    one_of([
      constant(:null),
      map(boolean(), &{:boolean, &1}),
      map(integer(-1_000..1_000), &{:integer, &1}),
      map(float(min: -1.0e6, max: 1.0e6), &{:float, &1}),
      map(string(:printable, max_length: 12), &{:string, &1})
    ])
  end

  defp value_gen do
    tree(scalar_gen(), fn child ->
      one_of([
        map(list_of(child, max_length: 5), &{:array, &1}),
        map(
          uniq_list_of(tuple({string(:alphanumeric, min_length: 1, max_length: 6), child}),
            uniq_fun: &elem(&1, 0),
            max_length: 5
          ),
          &{:object, &1}
        )
      ])
    end)
  end

  defp bounds_gen do
    optional_map(%{
      depth: integer(1..12),
      total_nodes: integer(1..200),
      array_items: integer(1..6),
      object_members: integer(1..6),
      string_bytes: integer(1..16),
      key_bytes: integer(1..8)
    })
  end

  # The projection as it was before the walk carried budgets: project everything, then let the
  # canonical encoder judge the projected tree.
  defp reference(prefix, operation, value, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, projected} <- typed(value),
         {:ok, canonical} <- Jcs.encode({:array, [{:string, operation}, projected]}, bounds) do
      {:ok, :crypto.hash(:sha256, [prefix, 0, canonical]) |> Base.url_encode64(padding: false)}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp typed(:null), do: {:ok, {:array, [{:string, "null"}]}}
  defp typed({:boolean, v}), do: {:ok, {:array, [{:string, "boolean"}, {:boolean, v}]}}
  defp typed({:integer, v}), do: {:ok, {:array, [{:string, "integer"}, {:integer, v}]}}
  defp typed({:float, v}), do: {:ok, {:array, [{:string, "float"}, {:float, v}]}}
  defp typed({:string, v}), do: {:ok, {:array, [{:string, "string"}, {:string, v}]}}

  defp typed({:array, values}),
    do: {:ok, {:array, [{:string, "array"}, {:array, Enum.map(values, &ok!(typed(&1)))}]}}

  defp typed({:object, members}) do
    projected = Enum.map(members, fn {key, value} -> {key, ok!(typed(value))} end)
    {:ok, {:array, [{:string, "object"}, {:object, projected}]}}
  end

  defp ok!({:ok, value}), do: value

  property "budgeted projection accepts exactly what the unbudgeted one accepts, byte for byte" do
    check all(
            value <- value_gen(),
            limits <- one_of([constant(%{}), bounds_gen()]),
            max_runs: 400
          ) do
      for {facade, prefix} <- @facades do
        assert facade.request_digest("op", value, limits) ==
                 reference(prefix, "op", value, limits),
               inspect({facade, value, limits})
      end
    end
  end

  test "every depth, node, container and string boundary agrees with the unbudgeted projection" do
    empty_array = {:array, []}
    empty_object = {:object, []}

    values = [
      :null,
      {:integer, 1},
      {:string, "abcdefgh"},
      empty_array,
      empty_object,
      {:array, [empty_array]},
      {:object, [{"k", empty_object}]},
      {:array, [{:integer, 1}, {:integer, 2}, {:integer, 3}]},
      {:object, [{"a", :null}, {"bb", {:string, "xy"}}]}
    ]

    limits =
      for(depth <- 1..8, do: %{depth: depth}) ++
        for(nodes <- 1..14, do: %{total_nodes: nodes}) ++
        for(items <- 1..4, do: %{array_items: items, object_members: items}) ++
        for(bytes <- 6..10, do: %{string_bytes: bytes}) ++
        for(bytes <- 1..3, do: %{key_bytes: bytes})

    for {facade, prefix} <- @facades, value <- values, limit <- limits do
      assert facade.request_digest("op", value, limit) == reference(prefix, "op", value, limit),
             inspect({facade, value, limit})
    end
  end

  test "an over-limit argument tree is rejected without walking it" do
    wide = {:array, List.duplicate({:integer, 1}, 2_000_000)}
    deep = Enum.reduce(1..200_000, {:integer, 1}, fn _level, inner -> {:array, [inner]} end)

    for {facade, _prefix} <- @facades, value <- [wide, deep] do
      # Load the facade and its modules first, so the timing measures only the walk.
      {:ok, _digest} = facade.request_digest("op", {:integer, 1}, %{})
      {microseconds, result} = :timer.tc(fn -> facade.request_digest("op", value, %{}) end)
      assert result == {:error, :invalid}
      # The unbudgeted walk takes about 260 ms on the wide tree; the budget stops after at most
      # `array_items` siblings or `depth` levels.
      assert microseconds < 50_000, "#{inspect(facade)} took #{microseconds}us"
    end
  end
end
