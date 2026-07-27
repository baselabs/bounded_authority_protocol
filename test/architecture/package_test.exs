defmodule BoundedAuthorityProtocol.Architecture.PackageTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 600_000

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

  test "the dependency-license gate goes red when JSONSchex is removed from the tooling SBOM" do
    scratch =
      Path.join(System.tmp_dir!(), "bounded-authority-tooling-#{System.unique_integer()}.json")

    on_exit(fn -> File.rm(scratch) end)

    {generation_output, 0} =
      System.cmd(
        "mix",
        [
          "sbom.cyclonedx",
          "--exclude-system-dependencies",
          "--classification",
          "library",
          "--schema",
          "1.6",
          "--format",
          "json",
          "--output",
          scratch,
          "--force"
        ],
        cd: @root,
        env: [{"MIX_ENV", "test"}],
        stderr_to_stdout: true
      )

    assert generation_output =~ "creating #{scratch}"
    document = scratch |> File.read!() |> :json.decode()

    tampered =
      Map.update!(document, "components", fn components ->
        Enum.reject(components, &(&1["name"] == "jsonschex"))
      end)

    File.write!(scratch, :json.encode(tampered))

    {output, status} =
      System.cmd(
        "elixir",
        [Path.join(@root, "scripts/check_dependency_licenses.exs"), scratch],
        cd: @root,
        stderr_to_stdout: true
      )

    assert status != 0
    assert output =~ ~s(tooling SBOM is missing direct tools ["jsonschex"])
  end
end
