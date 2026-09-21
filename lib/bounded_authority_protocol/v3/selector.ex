defmodule BoundedAuthorityProtocol.V3.Selector do
  @moduledoc """
  Closed selector type used by `BoundedAuthorityProtocol.V3.Operation`.

  The v2 profile admits the two inclusive range kinds `lte` and `gte`
  ([ADR 0028](../../docs/adr/0028-range-selector-kinds.md)) alongside the v1
  kinds. Both operands of a range comparison must carry the same numeric tag;
  comparison is by numeric value on the decoder-bounded finite binary64 domain.
  Selector enforcement is performed through the verification façade.
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Selector, as: SharedSelector

  @type t ::
          :all
          | {:equals, [binary()], BoundedAuthorityProtocol.V1.Json.value()}
          | {:one_of, [binary()], [BoundedAuthorityProtocol.V1.Json.value()]}
          | {:lte, [binary()], BoundedAuthorityProtocol.V1.Json.value()}
          | {:gte, [binary()], BoundedAuthorityProtocol.V1.Json.value()}

  @doc false
  @spec match_all([t()], BoundedAuthorityProtocol.V1.Json.value(), Bounds.t() | map()) ::
          :ok | {:error, :invalid}
  def match_all(selectors, arguments, limits) when is_list(selectors) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- nonempty_bounded?(selectors, bounds.selectors),
         {:ok, _encoded} <- Jcs.encode(arguments, bounds),
         true <- Enum.all?(selectors, &matches?(&1, arguments, bounds)) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  def match_all(_selectors, _arguments, _limits), do: {:error, :invalid}

  @doc false
  @spec semantic_equal?(
          BoundedAuthorityProtocol.V1.Json.value(),
          BoundedAuthorityProtocol.V1.Json.value()
        ) :: boolean()
  defdelegate semantic_equal?(left, right), to: SharedSelector

  defp matches?(:all, _arguments, _bounds), do: true

  defp matches?({:equals, path, expected}, arguments, bounds) do
    valid_path?(path, bounds) and valid_json?(expected, bounds) and
      case traverse(arguments, path) do
        {:ok, actual} -> semantic_equal?(actual, expected)
        :error -> false
      end
  end

  defp matches?({:one_of, path, values}, arguments, bounds) do
    valid_path?(path, bounds) and nonempty_bounded?(values, bounds.one_of_values) and
      Enum.all?(values, &valid_json?(&1, bounds)) and
      case traverse(arguments, path) do
        {:ok, actual} -> Enum.any?(values, &semantic_equal?(actual, &1))
        :error -> false
      end
  end

  defp matches?({:lte, path, bound}, arguments, bounds) do
    valid_path?(path, bounds) and numeric_bound?(bound) and
      case traverse(arguments, path) do
        {:ok, actual} -> lte?(actual, bound)
        :error -> false
      end
  end

  defp matches?({:gte, path, bound}, arguments, bounds) do
    valid_path?(path, bounds) and numeric_bound?(bound) and
      case traverse(arguments, path) do
        {:ok, actual} -> gte?(actual, bound)
        :error -> false
      end
  end

  defp matches?(_selector, _arguments, _bounds), do: false

  defp numeric_bound?({:integer, value}), do: is_integer(value)
  defp numeric_bound?({:float, value}), do: is_float(value)
  defp numeric_bound?(_bound), do: false

  # Each arm's tag pattern is the same-tag domain: an {:integer, _} operand
  # never satisfies an {:float, _} bound and vice versa (ADR 0028 §2), so a
  # cross-tag pair falls through to false rather than comparing numerically.
  defp lte?({:integer, left}, {:integer, right}), do: left <= right
  defp lte?({:float, left}, {:float, right}), do: left <= right
  defp lte?(_left, _right), do: false

  defp gte?({:integer, left}, {:integer, right}), do: left >= right
  defp gte?({:float, left}, {:float, right}), do: left >= right
  defp gte?(_left, _right), do: false

  defp traverse(value, []), do: {:ok, value}

  defp traverse({:object, members}, [key | rest]) when is_list(members) and is_binary(key) do
    case List.keyfind(members, key, 0) do
      {^key, value} -> traverse(value, rest)
      nil -> :error
    end
  end

  defp traverse(_value, _path), do: :error

  defp valid_path?(path, bounds) when is_list(path) do
    nonempty_bounded?(path, bounds.path_segments) and
      Enum.all?(path, fn member ->
        is_binary(member) and byte_size(member) in 1..bounds.key_bytes and String.valid?(member)
      end)
  end

  defp valid_path?(_path, _bounds), do: false

  defp valid_json?(value, bounds), do: match?({:ok, _encoded}, Jcs.encode(value, bounds))

  defp nonempty_bounded?([_value | _rest] = values, maximum),
    do: bounded_count?(values, maximum, 0)

  defp nonempty_bounded?(_values, _maximum), do: false

  defp bounded_count?([], _maximum, _count), do: true
  defp bounded_count?(_values, maximum, count) when count >= maximum, do: false

  defp bounded_count?([_value | rest], maximum, count),
    do: bounded_count?(rest, maximum, count + 1)
end
