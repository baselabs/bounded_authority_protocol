defmodule BoundedAuthorityProtocol.V1.FixedBytes do
  @moduledoc false

  @doc false
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(left, right)
      when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
      do: :crypto.hash_equals(left, right)

  def equal?(_left, _right), do: false
end
