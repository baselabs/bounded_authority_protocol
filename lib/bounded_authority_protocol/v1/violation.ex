defmodule BoundedAuthorityProtocol.V1.Violation do
  @moduledoc false
  defexception message: "invalid protocol input"

  @impl Exception
  def exception(_reason), do: %__MODULE__{}
end
