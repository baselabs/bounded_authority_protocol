defmodule BoundedAuthorityProtocol.V1.BoundsTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Violation

  test "callers can tighten but cannot widen or add bounds" do
    assert {:ok, %Bounds{depth: 32}} = Bounds.new()
    assert {:ok, %Bounds{depth: 4}} = Bounds.new(%{depth: 4})

    for {name, maximum} <- Bounds.maximum() |> Map.from_struct() do
      assert {:ok, %Bounds{} = exact} = Bounds.new(%{name => maximum})
      assert Map.fetch!(Map.from_struct(exact), name) == maximum
      assert {:ok, %Bounds{} = tightened} = Bounds.new(%{name => 1})
      assert Map.fetch!(Map.from_struct(tightened), name) == 1
      assert {:error, :invalid} = Bounds.new(%{name => 0})
      assert {:error, :invalid} = Bounds.new(%{name => maximum + 1})
    end

    assert {:error, :invalid} = Bounds.new(%{unknown: 1})
    assert {:error, :invalid} = Bounds.new(%{float_magnitude: 1.5})
    assert {:error, :invalid} = Bounds.new(:invalid)
  end

  test "a forged struct cannot widen any profile maximum" do
    maximum = Bounds.maximum()

    for {name, value} <- Map.from_struct(maximum) do
      forged = struct!(maximum, %{name => value + 1})
      assert {:error, :invalid} = Bounds.coerce(forged)
    end
  end

  test "the internal violation remains fixed and value-free" do
    assert %Violation{message: "invalid protocol input"} = Violation.exception("secret")

    assert "invalid protocol input" == Exception.message(%Violation{})
  end
end
