defmodule BoundedAuthorityProtocol.Architecture.PackageTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 240_000

  @root Path.expand("../..", __DIR__)

  test "the exact packed artifact compiles and loads in a fresh external consumer" do
    {output, status} =
      System.cmd("mix", ["run", "--no-start", Path.join(@root, "scripts/check_package.exs")],
        cd: @root,
        stderr_to_stdout: true
      )

    assert status == 0, output
    assert output =~ "package archive boundary passed"
    assert output =~ "Generated bounded_authority_protocol app"
    assert output =~ "Generated bounded_authority_protocol_consumer app"
  end
end
