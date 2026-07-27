defmodule BoundedAuthorityProtocol.V1.BoundsTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Violation

  test "callers can tighten but cannot widen or add bounds" do
    assert {:ok, %Bounds{depth: 32}} = Bounds.new()
    assert {:ok, %Bounds{depth: 4}} = Bounds.new(%{depth: 4})
    assert {:error, :invalid} = Bounds.new(%{depth: 33})
    assert {:error, :invalid} = Bounds.new(%{depth: 0})
    assert {:error, :invalid} = Bounds.new(%{unknown: 1})
    assert {:error, :invalid} = Bounds.new(:invalid)
  end

  test "a forged struct cannot widen the profile" do
    forged = %{Bounds.maximum() | compact_bytes: 65_537}
    assert {:error, :invalid} = Bounds.coerce(forged)
  end

  test "the internal violation remains fixed and value-free" do
    assert %Violation{message: "invalid protocol input"} = Violation.exception("secret")

    assert "invalid protocol input" == Exception.message(%Violation{})
  end
end
