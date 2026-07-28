defmodule BoundedAuthorityProtocol.V1.Selector do
  @moduledoc """
  Closed selector type used by `BoundedAuthorityProtocol.V1.Operation`.

  Selector enforcement is performed through the verification façade.
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs

  @type t ::
          :all
          | {:equals, [binary()], BoundedAuthorityProtocol.V1.Json.value()}
          | {:one_of, [binary()], [BoundedAuthorityProtocol.V1.Json.value()]}

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
  def semantic_equal?(:null, :null), do: true
  def semantic_equal?({:boolean, left}, {:boolean, right}), do: left === right
  def semantic_equal?({:integer, left}, {:integer, right}), do: left === right
  def semantic_equal?({:float, left}, {:float, right}), do: left === right
  def semantic_equal?({:string, left}, {:string, right}), do: left === right

  def semantic_equal?({:array, left}, {:array, right})
      when is_list(left) and is_list(right) do
    length(left) == length(right) and
      Enum.zip(left, right) |> Enum.all?(fn {a, b} -> semantic_equal?(a, b) end)
  end

  def semantic_equal?({:object, left}, {:object, right})
      when is_list(left) and is_list(right) do
    unique_object?(left) and unique_object?(right) and length(left) == length(right) and
      Enum.all?(left, fn {key, value} ->
        case List.keyfind(right, key, 0) do
          {^key, other} -> semantic_equal?(value, other)
          nil -> false
        end
      end)
  end

  def semantic_equal?(_left, _right), do: false

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

  defp matches?(_selector, _arguments, _bounds), do: false

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

  defp unique_object?(members) do
    keys =
      Enum.map(members, fn
        {key, _value} when is_binary(key) -> key
        _invalid -> nil
      end)

    nil not in keys and MapSet.size(MapSet.new(keys)) == length(keys)
  end

  defp nonempty_bounded?([_value | _rest] = values, maximum),
    do: bounded_count?(values, maximum, 0)

  defp nonempty_bounded?(_values, _maximum), do: false

  defp bounded_count?([], _maximum, _count), do: true
  defp bounded_count?(_values, maximum, count) when count >= maximum, do: false

  defp bounded_count?([_value | rest], maximum, count),
    do: bounded_count?(rest, maximum, count + 1)
end
